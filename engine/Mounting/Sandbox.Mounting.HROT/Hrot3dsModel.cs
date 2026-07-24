using Sandbox;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

/// <summary>Loads the static 3D Studio meshes placed by HROT levels.</summary>
/// <remarks>
/// Registered twice. <paramref name="simulatable"/> selects which collision the
/// model carries, and the two are mutually exclusive because
/// <c>ModelCollider</c> builds shapes from *every* physics part rather than
/// choosing one:
///
/// <list type="bullet">
/// <item><b>false</b> - a concave collision mesh. Exact, and what the level's
/// own props want, since <c>HrotMap</c> marks their colliders static. It cannot
/// be simulated, so a dynamic body carrying it falls through the world.</item>
/// <item><b>true</b> - a single convex hull, for the <c>(PROP)</c> copies. Cruder,
/// but a dynamic <c>Rigidbody</c> needs a shape with volume.</item>
/// </list>
///
/// Giving one model both would solidify HROT's openwork props - ladders,
/// railings, grates, cages - wherever the level places them.
/// </remarks>
sealed class Hrot3dsModel( string pakDir, string fileName, bool simulatable = false )
	: ResourceLoader<HrotMount>
{
	// HROT's geometry is authored in metres; s&box world units are inches.
	const float UnitScale = 64.0f;

	protected override object Load()
	{
		var bytes = Host.GetFileBytes( pakDir, fileName );
		if ( bytes is null || bytes.Length < 6 )
			throw new InvalidDataException( $"Unable to read 3DS: {fileName}" );

		var document = ThreeDsDocument.Read( bytes );
		if ( document.Vertices.Count == 0 || document.Faces.Count == 0 )
			throw new InvalidDataException( $"3DS contains no mesh: {fileName}" );

		var textureName = document.TextureName;
		var resolvedName = textureName;
		var texture = !string.IsNullOrWhiteSpace( textureName )
			? Host.LoadTextureByStemAnywhere( textureName )
			: null;
		// Some shipped 3DS files contain stale or truncated source texture
		// names (mriz.3ds says "lendigo2.psd"). Prefer the embedded name when
		// it resolves, then fall back to HROT's runtime registration table.
		if ( texture is null )
		{
			resolvedName = Host.GetStaticModelTexture(
				System.IO.Path.GetFileNameWithoutExtension( fileName ) );
			texture = Host.LoadTextureByStemAnywhere( resolvedName );
		}

		// Flowing-water props (vzduchnavod, mlynvod) get HROT's animated water
		// shader instead of the static surface one, baked into the mesh. It has to
		// be baked here rather than set as a ModelRenderer.MaterialOverride: an
		// override pointing at a runtime material serializes to a null path, so the
		// prop reloads with its plain material and never animates. A material inside
		// a Model mesh survives, the same way the world water surface does.
		Material material;
		if ( HrotMount.WaterfallModelStems.Contains(
				System.IO.Path.GetFileNameWithoutExtension( fileName ) ) )
		{
			material = Material.Create( "model_water", HrotMount.WaterShader );
			material?.Set( "g_tColor", texture ?? Texture.White );
			material?.Set( "g_tDistMap",
				Host.LoadTextureByStemAnywhere( "vodanorm" ) ?? Texture.White );
			material?.Set( "g_flScrollSpeed", HrotMount.WaterfallScrollSpeed );
		}
		else
		{
			material = Material.Create( "model", HrotMount.SurfaceShader );
			material?.Set( "g_tColor", texture ?? Texture.White );

			// mriz.3ds (a grate) names "lendigo2.psd" - a truncated blendigo2 - so
			// the alpha test has to key off whichever stem actually resolved, not
			// off the name embedded in the file.
			HrotMount.ApplyAlphaMode(
				material, Host.TextureStemAlphaKindAnywhere( resolvedName ) );
		}

		BuildMesh(
			document,
			IsThinPlanarMesh( document.Vertices ),
			out var vertices,
			out var indices );
		var mesh = new Mesh( material ) { Bounds = BBox.FromPoints( vertices.Select( x => x.position ) ) };
		mesh.CreateVertexBuffer( vertices.Count, vertices );
		mesh.CreateIndexBuffer( indices.Count, indices );

		var collision = vertices.Select( x => x.position ).ToList();
		var builder = Model.Builder
			.WithName( Path )
			.AddMesh( mesh );

		if ( simulatable )
			builder.AddCollisionHull( collision );
		else
			builder.AddCollisionMesh( collision.ToArray(), indices.ToArray() );

		// The trace mesh is the real geometry either way - only the physics
		// shape is approximated for the simulatable copy.
		return builder
			.AddTraceMesh( collision, indices )
			.Create();
	}

	static bool IsThinPlanarMesh( IReadOnlyList<Vector3> positions )
	{
		if ( positions.Count == 0 )
			return false;

		var minimum = positions[0];
		var maximum = positions[0];
		foreach ( var position in positions )
		{
			minimum = Vector3.Min( minimum, position );
			maximum = Vector3.Max( maximum, position );
		}

		var size = maximum - minimum;
		var dimensions = new[] { MathF.Abs( size.x ), MathF.Abs( size.y ), MathF.Abs( size.z ) };
		Array.Sort( dimensions );
		return dimensions[0] <= 0.1f &&
			dimensions[1] >= 0.5f &&
			dimensions[2] >= 0.5f;
	}

	static void BuildMesh(
		ThreeDsDocument document,
		bool doubleSided,
		out List<SimpleVertex> vertices,
		out List<int> indices )
	{
		var sideCount = doubleSided ? 2 : 1;
		var vertexBuffer = new List<SimpleVertex>( document.Faces.Count * 3 * sideCount );
		var indexBuffer = new List<int>( document.Faces.Count * 3 * sideCount );

		foreach ( var face in document.Faces )
		{
			// HROT converts Z-up 3DS coordinates to its Y-up runtime as
			// (x, z, -y). The world conversion to s&box is (x, -z, y), so the
			// two axis changes cancel and the authored 3DS coordinates and
			// winding should be preserved here. Reflecting local Y moved
			// offset wall-mounted meshes onto the opposite wall.
			AddFace( face.A, face.B, face.C );
			if ( doubleSided )
				AddFace( face.C, face.B, face.A );

			void AddFace( int a, int b, int c )
			{
				var corners = new[] { a, b, c };
				var p0 = ConvertPosition( document.Vertices[corners[0]] );
				var p1 = ConvertPosition( document.Vertices[corners[1]] );
				var p2 = ConvertPosition( document.Vertices[corners[2]] );
				var normal = Vector3.Cross( p1 - p0, p2 - p0 ).Normal;
				var tangent = (p1 - p0).Normal;

				foreach ( var corner in corners )
				{
					var uv = corner < document.TexCoords.Count ? document.TexCoords[corner] : Vector2.Zero;
					vertexBuffer.Add( new SimpleVertex(
						ConvertPosition( document.Vertices[corner] ), normal, tangent, uv ) );
					indexBuffer.Add( indexBuffer.Count );
				}
			}
		}

		vertices = vertexBuffer;
		indices = indexBuffer;
	}

	static Vector3 ConvertPosition( Vector3 position )
		=> position * UnitScale;

	sealed class ThreeDsDocument
	{
		public List<Vector3> Vertices { get; } = [];
		public List<Vector2> TexCoords { get; } = [];
		public List<Face> Faces { get; } = [];
		public string TextureName { get; private set; }

		public static ThreeDsDocument Read( byte[] data )
		{
			var result = new ThreeDsDocument();
			result.ReadChunks( data, 0, data.Length );
			return result;
		}

		void ReadChunks( byte[] data, int start, int end )
		{
			var cursor = start;
			while ( cursor + 6 <= end )
			{
				var id = BitConverter.ToUInt16( data, cursor );
				var length = checked((int)BitConverter.ToUInt32( data, cursor + 2 ));
				if ( length < 6 || cursor + length > end ) break;
				var content = cursor + 6;
				var chunkEnd = cursor + length;

				switch ( id )
				{
					case 0x4D4D:
					case 0x3D3D:
					case 0x4100:
					case 0xAFFF:
					case 0xA200:
						ReadChunks( data, content, chunkEnd );
						break;
					case 0x4000:
						ReadChunks( data, FindStringEnd( data, content, chunkEnd ), chunkEnd );
						break;
					case 0x4110:
						ReadVertices( data, content );
						break;
					case 0x4120:
						ReadFaces( data, content );
						break;
					case 0x4140:
						ReadTexCoords( data, content );
						break;
					case 0xA300:
						TextureName ??= ReadString( data, content, chunkEnd );
						break;
				}

				cursor = chunkEnd;
			}
		}

		void ReadVertices( byte[] data, int offset )
		{
			var count = BitConverter.ToUInt16( data, offset );
			var baseVertex = Vertices.Count;
			offset += 2;
			for ( var i = 0; i < count; i++ )
			{
				Vertices.Add( new Vector3(
					BitConverter.ToSingle( data, offset ),
					BitConverter.ToSingle( data, offset + 4 ),
					BitConverter.ToSingle( data, offset + 8 ) ) );
				offset += 12;
			}
			_currentBaseVertex = baseVertex;
		}

		int _currentBaseVertex;

		void ReadFaces( byte[] data, int offset )
		{
			var count = BitConverter.ToUInt16( data, offset );
			offset += 2;
			for ( var i = 0; i < count; i++ )
			{
				Faces.Add( new Face(
					_currentBaseVertex + BitConverter.ToUInt16( data, offset ),
					_currentBaseVertex + BitConverter.ToUInt16( data, offset + 2 ),
					_currentBaseVertex + BitConverter.ToUInt16( data, offset + 4 ) ) );
				offset += 8;
			}
		}

		void ReadTexCoords( byte[] data, int offset )
		{
			var count = BitConverter.ToUInt16( data, offset );
			offset += 2;
			while ( TexCoords.Count < _currentBaseVertex )
				TexCoords.Add( Vector2.Zero );
			for ( var i = 0; i < count; i++ )
			{
				var u = BitConverter.ToSingle( data, offset );
				var v = BitConverter.ToSingle( data, offset + 4 );
				TexCoords.Add( new Vector2( u, 1.0f - v ) );
				offset += 8;
			}
		}

		static int FindStringEnd( byte[] data, int offset, int end )
		{
			while ( offset < end && data[offset++] != 0 ) { }
			return offset;
		}

		static string ReadString( byte[] data, int offset, int end )
		{
			var finish = offset;
			while ( finish < end && data[finish] != 0 ) finish++;
			return Encoding.ASCII.GetString( data, offset, finish - offset ).Replace( '\\', '/' );
		}
	}

	readonly record struct Face( int A, int B, int C );
}
