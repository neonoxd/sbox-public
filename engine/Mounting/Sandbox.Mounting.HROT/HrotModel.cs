using Sandbox;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

/// <summary>Loads a Quake II MD2 model used by HROT, frames and all.</summary>
/// <remarks>
/// Frame zero is the mesh; every later frame is a morph target named after the
/// MD2 frame name, so a consumer poses the model by weighting morphs rather
/// than by swapping meshes. HROT names its frames in the Quake II convention -
/// <c>run1</c>..<c>run17</c>, <c>0dead1</c>.. - so the sequence table is
/// recoverable from <c>Model.Morphs.Names</c> and is not transcribed anywhere.
///
/// The model is deliberately boneless. See the morph section of CLAUDE.md:
/// these vertices carry no blend weights, and giving them a skeleton to be
/// skinned against destroys the mesh.
/// </remarks>
class HrotModel( string pakDir, string fileName ) : ResourceLoader<HrotMount>
{
	const int Md2Ident = 844121161; // "IDP2"
	const int Md2Version = 8;

	public string PakDir { get; set; } = pakDir;
	public string FileName { get; set; } = fileName;

	BinaryReader Read() => new( Host.GetFileStream( PakDir, FileName ) );

	protected override object Load()
	{
		using var br = Read();
		if ( br.BaseStream == Stream.Null || br.BaseStream.Length < 68 )
			throw new InvalidDataException( $"Unable to read MD2: {FileName}" );

		var header = ReadHeader( br );
		ValidateHeader( header, br.BaseStream.Length );

		var skins = ReadSkins( br, header );
		var texCoords = ReadTexCoords( br, header, Host.ShouldFlipModelUvVertically( FileName ) );
		var triangles = ReadTriangles( br, header );
		var frames = ReadFrames( br, header );

		var texturePath = Host.ResolveModelTexture( PakDir, FileName, skins );
		var texture = texturePath is null ? null : Host.LoadTexture( PakDir, texturePath );
		if ( texturePath is null )
			Log.Warning( $"{FileName}: no model texture was found; using white." );

		var material = Material.Create( "model", HrotMount.SurfaceShader );
		material?.Set( "g_tColor", texture ?? Texture.White );

		// Binary alpha (blendigo, blendigo2 - ladders, railings, grates) wants
		// alpha testing; graded alpha (sklo.tga) wants blending. Which one is
		// decided from the pixels, not from a list of texture names.
		if ( texturePath is not null )
			HrotMount.ApplyAlphaMode( material, Host.TextureAlphaKind( PakDir, texturePath ) );

		var mesh = new Mesh( material );

		BuildMesh(
			frames[0].Positions, texCoords, triangles,
			out var vertices, out var indices, out var traceIndices, out var sources );

		mesh.CreateVertexBuffer( vertices.Count, vertices );
		mesh.CreateIndexBuffer( indices.Length, indices );

		// Bounds have to cover every frame, not just the one in the vertex
		// buffer. A model culled against its rest pose vanishes as soon as an
		// animation reaches outside it, and only from certain angles.
		mesh.Bounds = BBox.FromPoints( frames.SelectMany( x => x.Positions ) );

		AddFrameMorphs( mesh, frames, sources, indices );

		// No AddBone anywhere in here, on purpose - see the class remarks.
		var model = Model.Builder
			.WithName( Path )
			.AddMesh( mesh )
			.AddTraceMesh( frames[0].Positions, traceIndices )
			.Create();

		// The morph count is the one number that says the frames survived, and
		// a model that quietly kept none of them still renders perfectly - as
		// its rest pose, forever.
		var expected = frames.Length;
		if ( model.MorphCount != expected )
		{
			Log.Warning(
				$"{FileName}: {model.MorphCount} of {expected} frame morphs "
				+ "survived model creation; this model cannot animate fully." );
		}

		return model;
	}

	/// <summary>
	/// Adds every frame as a morph target named for that frame.
	/// </summary>
	/// <remarks>
	/// Deltas are measured against frame zero, which is the mesh itself, so
	/// weighting frame N at <c>1-t</c> and frame N+1 at <c>t</c> reproduces the
	/// lerp between them exactly. That is what makes MD2 interpolation fall out
	/// of the morph system rather than needing a shader.
	/// </remarks>
	static void AddFrameMorphs(
		Mesh mesh, Md2Frame[] frames, int[] sources, int[] indices )
	{
		var rest = PoseVertices( frames[0].Positions, sources, indices );
		var deltas = new List<MorphDelta>( sources.Length );

		// Morph names are the frame names, and Mesh.AddMorph is keyed by name -
		// so two frames sharing one would silently collapse into a single morph
		// and quietly shorten a sequence. No shipped HROT model does this, which
		// is exactly why an unnoticed one would be so hard to explain.
		var used = new HashSet<string>( StringComparer.OrdinalIgnoreCase );

		// Frame zero included, even though it is the mesh and its deltas are all
		// zero. Naming it costs one delta and makes "every frame is a morph"
		// true, so a sequence is its frame names and nothing else. Skipping it
		// would hide one frame of whichever sequence happens to start the file -
		// zombie.md2 would report melee as 13 frames when it has 14, and only
		// that one sequence would be short.
		for ( var f = 0; f < frames.Length; f++ )
		{
			var name = frames[f].Name;
			if ( string.IsNullOrWhiteSpace( name ) )
				name = $"frame{f}";

			if ( !used.Add( name ) )
			{
				Log.Warning(
					$"MD2 frame {f} repeats the name \"{name}\"; it would "
					+ "overwrite the earlier frame's morph and has been skipped." );
				continue;
			}

			// Frame zero is the rest pose, so posing it again would rebuild the
			// same normals - the expensive half of this loop - to subtract them
			// from themselves.
			var pose = f == 0 ? rest : PoseVertices( frames[f].Positions, sources, indices );

			deltas.Clear();
			for ( var v = 0; v < sources.Length; v++ )
			{
				var position = pose.Positions[v] - rest.Positions[v];
				var normal = pose.Normals[v] - rest.Normals[v];

				// A frame usually moves part of the model. Carrying deltas for
				// the vertices it leaves alone would cost as much again for
				// nothing, since a zero delta is what their absence means.
				if ( position.LengthSquared < 0.000001f && normal.LengthSquared < 0.000001f )
					continue;

				deltas.Add( new MorphDelta( v, position, normal ) );
			}

			// Frame zero and any frame identical to it produce no deltas, and
			// AddMorph rejects an empty span. One zero delta keeps the frame
			// addressable by name while displacing nothing, which is exactly
			// what such a frame means.
			if ( deltas.Count == 0 )
				deltas.Add( new MorphDelta( 0, Vector3.Zero, Vector3.Zero ) );

			mesh.AddMorph( name, CollectionsMarshal.AsSpan( deltas ) );
		}
	}

	/// <summary>
	/// Positions and generated normals for one frame, per built vertex.
	/// </summary>
	static (Vector3[] Positions, Vector3[] Normals) PoseVertices(
		Vector3[] positions, int[] sources, int[] indices )
	{
		var posed = new Vector3[sources.Length];
		for ( var v = 0; v < sources.Length; v++ )
			posed[v] = positions[sources[v]];

		// Normals are regenerated per frame rather than reused from the rest
		// pose. MD2 stores only an index into Quake II's normal table, and a
		// model lit by its rest pose while posed by another looks lit from the
		// wrong direction as it moves.
		//
		// Accumulated through the index buffer rather than per triangle corner:
		// BuildMesh welds corners that share a position and a UV, so a built
		// vertex can be reached from several triangles and must collect all of
		// their face normals. This is the same averaging BuildMesh does for
		// frame zero, and has to stay that way or every morph would carry a
		// normal delta measured against a differently-built rest normal.
		var normals = new Vector3[sources.Length];
		for ( var i = 0; i + 2 < indices.Length; i += 3 )
		{
			var a = indices[i];
			var b = indices[i + 1];
			var c = indices[i + 2];
			var faceNormal = Vector3.Cross( posed[b] - posed[a], posed[c] - posed[a] ).Normal;

			normals[a] += faceNormal;
			normals[b] += faceNormal;
			normals[c] += faceNormal;
		}

		for ( var v = 0; v < normals.Length; v++ )
		{
			normals[v] = normals[v].LengthSquared > 0.000001f
				? normals[v].Normal
				: Vector3.Up;
		}

		return (posed, normals);
	}

	static Md2Header ReadHeader( BinaryReader br )
	{
		return new Md2Header
		{
			Ident = br.ReadInt32(),
			Version = br.ReadInt32(),
			SkinWidth = br.ReadInt32(),
			SkinHeight = br.ReadInt32(),
			FrameSize = br.ReadInt32(),
			NumSkins = br.ReadInt32(),
			NumVerts = br.ReadInt32(),
			NumTexCoords = br.ReadInt32(),
			NumTriangles = br.ReadInt32(),
			NumGlCommands = br.ReadInt32(),
			NumFrames = br.ReadInt32(),
			OffsetSkins = br.ReadInt32(),
			OffsetTexCoords = br.ReadInt32(),
			OffsetTriangles = br.ReadInt32(),
			OffsetFrames = br.ReadInt32(),
			OffsetGlCommands = br.ReadInt32(),
			OffsetEnd = br.ReadInt32()
		};
	}

	static void ValidateHeader( Md2Header h, long streamLength )
	{
		if ( h.Ident != Md2Ident || h.Version != Md2Version )
			throw new InvalidDataException( "Invalid MD2 file format." );

		if ( h.SkinWidth <= 0 || h.SkinHeight <= 0 || h.NumVerts <= 0 || h.NumTriangles <= 0 || h.NumFrames <= 0 )
			throw new InvalidDataException( "MD2 header contains invalid dimensions or counts." );

		if ( h.NumVerts > 65535 || h.NumTexCoords > 65535 || h.NumTriangles > 1_000_000 || h.NumFrames > 100_000 )
			throw new InvalidDataException( "MD2 header contains unreasonable counts." );

		if ( h.OffsetSkins < 68 || h.OffsetTexCoords < 68 || h.OffsetTriangles < 68 || h.OffsetFrames < 68 || h.OffsetEnd > streamLength )
			throw new InvalidDataException( "MD2 header contains invalid offsets." );

		if ( h.FrameSize < 40 + h.NumVerts * 4 )
			throw new InvalidDataException( "MD2 frame size is too small." );

		// Every frame must lie within the file, not just frame zero.
		if ( h.OffsetFrames + (long)h.NumFrames * h.FrameSize > streamLength )
			throw new InvalidDataException( "MD2 frame data runs past the end of the file." );
	}

	static List<string> ReadSkins( BinaryReader br, Md2Header h )
	{
		var result = new List<string>( h.NumSkins );
		br.BaseStream.Position = h.OffsetSkins;

		for ( var i = 0; i < h.NumSkins; i++ )
		{
			var bytes = br.ReadBytes( 64 );
			if ( bytes.Length != 64 ) throw new EndOfStreamException();
			var zero = Array.IndexOf( bytes, (byte)0 );
			var length = zero >= 0 ? zero : bytes.Length;
			var value = Encoding.ASCII.GetString( bytes, 0, length ).Replace( '\\', '/' );
			if ( !string.IsNullOrWhiteSpace( value ) ) result.Add( value );
		}

		return result;
	}

	static Vector2[] ReadTexCoords( BinaryReader br, Md2Header h, bool flipVertically )
	{
		var result = new Vector2[h.NumTexCoords];
		br.BaseStream.Position = h.OffsetTexCoords;

		for ( var i = 0; i < result.Length; i++ )
		{
			var s = br.ReadInt16();
			var t = br.ReadInt16();

			// HROT contains MD2s exported using both UV conventions. Most use
			// image-space top-left coordinates, while some source models use
			// the traditional 3DS/OpenGL bottom-left V coordinate. The latter
			// are identified by comparison with their companion 3DS files.
			result[i] = new Vector2(
				(s + 0.5f) / h.SkinWidth,
				flipVertically
					? 1.0f - (t + 0.5f) / h.SkinHeight
					: (t + 0.5f) / h.SkinHeight
			);
		}

		return result;
	}

	static Md2Triangle[] ReadTriangles( BinaryReader br, Md2Header h )
	{
		var result = new Md2Triangle[h.NumTriangles];
		br.BaseStream.Position = h.OffsetTriangles;

		for ( var i = 0; i < result.Length; i++ )
		{
			result[i] = new Md2Triangle
			{
				V0 = br.ReadUInt16(), V1 = br.ReadUInt16(), V2 = br.ReadUInt16(),
				T0 = br.ReadUInt16(), T1 = br.ReadUInt16(), T2 = br.ReadUInt16()
			};

			if ( result[i].V0 >= h.NumVerts || result[i].V1 >= h.NumVerts || result[i].V2 >= h.NumVerts ||
				 result[i].T0 >= h.NumTexCoords || result[i].T1 >= h.NumTexCoords || result[i].T2 >= h.NumTexCoords )
				throw new InvalidDataException( "MD2 triangle references an out-of-range vertex or texture coordinate." );
		}

		return result;
	}

	/// <summary>
	/// Reads every frame. Each carries its own scale and translate, so a frame
	/// cannot be decoded with another's.
	/// </summary>
	static Md2Frame[] ReadFrames( BinaryReader br, Md2Header h )
	{
		var frames = new Md2Frame[h.NumFrames];

		for ( var f = 0; f < frames.Length; f++ )
		{
			// Seek per frame rather than reading straight through: FrameSize is
			// the header's stride and is not required to be exactly the bytes
			// this loop consumes.
			br.BaseStream.Position = h.OffsetFrames + (long)f * h.FrameSize;

			var scale = new Vector3( br.ReadSingle(), br.ReadSingle(), br.ReadSingle() );
			var translate = new Vector3( br.ReadSingle(), br.ReadSingle(), br.ReadSingle() );
			var nameBytes = br.ReadBytes( 16 );
			var zero = Array.IndexOf( nameBytes, (byte)0 );
			var name = Encoding.ASCII.GetString( nameBytes, 0, zero >= 0 ? zero : nameBytes.Length );

			var positions = new Vector3[h.NumVerts];
			for ( var i = 0; i < positions.Length; i++ )
			{
				var x = br.ReadByte();
				var y = br.ReadByte();
				var z = br.ReadByte();
				br.ReadByte(); // MD2 normal-table index; geometric normals are generated instead.

				positions[i] = new Vector3(
					x * scale.x + translate.x,
					y * scale.y + translate.y,
					z * scale.z + translate.z );
			}

			frames[f] = new Md2Frame { Name = name, Positions = positions };
		}

		return frames;
	}

	static void BuildMesh(
		Vector3[] positions,
		Vector2[] texCoords,
		Md2Triangle[] triangles,
		out List<SimpleVertex> vertices,
		out int[] indices,
		out int[] traceIndices,
		out int[] sources )
	{
		var vertexMap = new Dictionary<VertexKey, int>();
		var built = new List<BuiltVertex>();
		// Which MD2 vertex each built vertex came from. A vertex split across
		// several UVs becomes several built vertices that must all follow the
		// same source vertex through every frame, or the model tears along its
		// UV seams as it animates.
		var sourceList = new List<int>();
		indices = new int[triangles.Length * 3];
		traceIndices = new int[triangles.Length * 3];
		var cursor = 0;

		foreach ( var triangle in triangles )
		{
			// Reverse MD2 winding to match the Quake mount's mesh convention.
			var corners = new[]
			{
				((int)triangle.V2, (int)triangle.T2),
				((int)triangle.V1, (int)triangle.T1),
				((int)triangle.V0, (int)triangle.T0)
			};

			var p0 = positions[corners[0].Item1];
			var p1 = positions[corners[1].Item1];
			var p2 = positions[corners[2].Item1];
			var faceNormal = Vector3.Cross( p1 - p0, p2 - p0 ).Normal;

			for ( var corner = 0; corner < 3; corner++ )
			{
				var vertexIndex = corners[corner].Item1;
				var texCoordIndex = corners[corner].Item2;
				var uv = texCoords[texCoordIndex];
				var key = new VertexKey( vertexIndex, texCoordIndex );

				if ( !vertexMap.TryGetValue( key, out var builtIndex ) )
				{
					builtIndex = built.Count;
					built.Add( new BuiltVertex
					{
						Position = positions[vertexIndex],
						Uv = uv,
						Normal = Vector3.Zero
					} );
					vertexMap[key] = builtIndex;
					sourceList.Add( vertexIndex );
				}

				var current = built[builtIndex];
				current.Normal += faceNormal;
				built[builtIndex] = current;

				indices[cursor] = builtIndex;
				traceIndices[cursor] = vertexIndex;
				cursor++;
			}
		}

		vertices = new List<SimpleVertex>( built.Count );
		foreach ( var vertex in built )
		{
			var normal = vertex.Normal.LengthSquared > 0.000001f ? vertex.Normal.Normal : Vector3.Up;
			vertices.Add( new SimpleVertex( vertex.Position, normal, Vector3.Zero, vertex.Uv ) );
		}

		sources = [.. sourceList];
	}

	sealed class Md2Header
	{
		public int Ident, Version, SkinWidth, SkinHeight, FrameSize, NumSkins, NumVerts, NumTexCoords,
			NumTriangles, NumGlCommands, NumFrames, OffsetSkins, OffsetTexCoords, OffsetTriangles,
			OffsetFrames, OffsetGlCommands, OffsetEnd;
	}

	struct Md2Triangle
	{
		public ushort V0, V1, V2, T0, T1, T2;
	}

	sealed class Md2Frame
	{
		public string Name { get; init; }
		public Vector3[] Positions { get; init; }
	}

	readonly record struct VertexKey( int VertexIndex, int TexCoordIndex );

	struct BuiltVertex
	{
		public Vector3 Position;
		public Vector3 Normal;
		public Vector2 Uv;
	}
}
