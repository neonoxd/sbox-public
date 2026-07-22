using Sandbox;
using System;
using System.Collections.Generic;
using System.Linq;
using MapDoor = Sandbox.Mapping.Door;

/// <summary>Door leaves: their geometry, and the objects that carry them.</summary>
/// <remarks>
/// Doors are entities rather than world surfaces - they move - so each leaf is
/// its own GameObject with a mesh built about its own origin, which is what lets
/// a component translate or rotate it.
///
/// The quad helpers here derive their UVs from a face and an atlas row count.
/// The world renderer has its own with explicit UVs; the two are not
/// interchangeable. See REVERSE_ENGINEERING.md section 11.
/// </remarks>
sealed partial class HrotMap
{
	const float WallSegmentHeight = 1.5625f * UnitScale;

	const float AtlasColumns = 32.0f;

	const float FloorAtlasRows = 32.0f;

	const float WallAtlasRows = 16.0f;

	/// <summary>
	/// Spawns one GameObject per door leaf, each with its own mesh.
	/// </summary>
	/// <remarks>
	/// Doors are entities, not world geometry: they move. Baking them into the
	/// world mesh made them immovable and unaddressable, so each leaf gets its
	/// own object with geometry built in local space around its own origin -
	/// which is what lets a component translate or rotate it later.
	///
	/// The travel vector, behaviour and shape are logged per leaf and are not
	/// stored on the object. Carrying them would need a component type, and a
	/// type defined in this mount assembly may not resolve for whatever loads
	/// the scene, so that choice is left open rather than guessed at.
	/// </remarks>
	int SpawnDoors()
	{
		var doors = Host.GetMapDoors( mapId );
		if ( doors.Count == 0 )
			return 0;

		var atlas = Host.LoadTextureAnywhere( "pack1.jpg" ) ?? Texture.White;
		var material = Material.Create( $"hrot_door_{mapId:00}", HrotMount.SurfaceShader );
		material?.Set( "g_tColor", atlas );

		var spawned = 0;
		// Door index -> its component, so linked pairs can be wired once every
		// leaf exists. A follower may be created before its partner.
		var components = new Dictionary<int, MapDoor>();

		for ( var i = 0; i < doors.Count; i++ )
		{
			var door = doors[i];

			// Debug: spawn a marker for EVERY door, including skipped ones.
			var skipped = door.AtlasX is < 0 or >= 32 || door.AtlasY is < 1 or > 16;
			// A door that sinks into the floor still travels. Measuring only
			// the horizontal component discarded 29 of them across the eight
			// mapped levels - including the gold-key door on map 5, whose
			// travel is (0, -2, 0).
			var noTravel = door.Travel.LengthSquared < 0.01f;
			if ( skipped || noTravel )
			{
				var skipLabel = skipped ? "noAtlas" : "noTravel";
				var skipGo = new GameObject( true, $"door_{i}_SKIPPED_{skipLabel}_atlas{door.AtlasX},{door.AtlasY}_mat{door.MaterialId}" );
				skipGo.WorldPosition = door.Position * UnitScale;
				Log.Info( $"  door[{i}] SKIPPED({skipLabel}) pos=({door.Position.x:F2},{door.Position.y:F2},{door.Position.z:F2}) travel=({door.Travel.x:F2},{door.Travel.y:F2},{door.Travel.z:F2}) linked={door.IsLinked} orient={door.Orientation} behav={door.Behavior} atlas=({door.AtlasX},{door.AtlasY})" );
				if ( skipped )
					continue;
			}

			if ( noTravel )
				continue;

			// The leaf, closed, sits at its own cell centre
			// (record +0x00, already decoded into door.Position). Linked leaves
			// therefore tile the full opening on their own: map 1's breakable
			// wall is two leaves in adjacent cells that meet at the shared seam.
			// D77C20's +0x18 refPoint applies a -travel * 0.5 shift that collapses
			// both linked leaves onto that seam; that point is the animation and
			// collision reference, not the closed face, so the static quad centres
			// on the cell position directly. (The +0x18 vertical 0.78125 =
			// WallSegmentHeight/2 face centre is likewise not used here, because
			// the quad bottom/top are derived from the raw floor position below.)
			// Geometry is built about the origin so the object can be moved.
			var vertices = new List<SimpleVertex>();
			var indices = new List<int>();
			AddDoorLeaf(
				vertices, indices, door, Vector3.Zero, 0.0f, WallSegmentHeight );
			if ( vertices.Count == 0 || indices.Count == 0 )
				continue;

			var positions = vertices.Select( x => x.position ).ToArray();
			var mesh = new Mesh( material )
			{
				Bounds = BBox.FromPoints( positions )
			};
			mesh.CreateVertexBuffer( vertices.Count, vertices );
			mesh.CreateIndexBuffer( indices.Count, indices );

			var model = Model.Builder
				.WithName( $"hrotdoor/{mapId:00}/{i:00}" )
				.AddMesh( mesh )
				.AddCollisionMesh( positions, indices.ToArray() )
				.AddTraceMesh( positions, indices.ToArray() )
				.Create();

			var leaf = new GameObject( true, $"hrot_door_{i:00}" );
			leaf.WorldPosition = door.Position * UnitScale;
			leaf.Tags.Add( "hrot_door" );
			leaf.Tags.Add( $"hrot_door_behaviour_{door.Behavior}" );
			if ( door.IsLinked )
			{
				leaf.Tags.Add( "hrot_door_linked" );
				// Within a linked pair the first leaf created leads and the
				// second follows; PartnerIndex names the other leaf's object.
				leaf.Tags.Add( door.IsFollower
					? "hrot_door_follower"
					: "hrot_door_leader" );
				leaf.Tags.Add( $"hrot_door_partner_{door.PartnerIndex:00}" );
			}

			leaf.AddComponent<ModelRenderer>().Model = model;
			leaf.AddComponent<ModelCollider>().Model = model;

			// HROT doors translate along a decoded travel vector; none rotates.
			// Travel is already in the mount's frame, like Position, so it only
			// needs the unit scale. Door applies SlideOffset in parent-local
			// space, and these leaves sit unrotated under the scene root, so
			// the world-space vector is the right one to hand it.
			var component = leaf.AddComponent<MapDoor>();
			component.Mode = MapDoor.DoorMode.Sliding;
			component.SlideOffset = door.Travel * UnitScale;
			components[i] = component;

			spawned++;

			Log.Info(
				$"  door[{i}] at {leaf.WorldPosition} shape={door.Shape} "
				+ $"behaviour={door.Behavior} travel=({door.Travel.x:F2},"
				+ $"{door.Travel.y:F2},{door.Travel.z:F2}) linked={door.IsLinked} "
				+ $"atlas=({door.AtlasX},{door.AtlasY})"
				+ (door.IsLinked
					? $" {(door.IsFollower ? "follower" : "leader")} of {door.PartnerIndex}"
					: string.Empty) );
		}

		LinkDoorPairs( doors, components );

		return spawned;
	}

	/// <summary>
	/// Wires each linked pair together through <see cref="MapDoor.LinkedDoor"/>.
	/// </summary>
	/// <remarks>
	/// Only the leader's link is set. Door's own <c>OnStart</c> back-fills the
	/// reverse - <c>if ( !LinkedDoor.LinkedDoor.IsValid() ) LinkedDoor.LinkedDoor
	/// = this;</c> - so setting both sides here would be redundant and would
	/// depend on its re-entrancy guards rather than on its intended use.
	///
	/// A leaf is absent from <paramref name="components"/> when it was skipped
	/// for having no atlas or no travel, so a partner lookup can legitimately
	/// miss. That is logged rather than passed over: a door that silently loses
	/// its partner still opens, just alone.
	/// </remarks>
	static void LinkDoorPairs(
		IReadOnlyList<HrotDoorPlacement> doors,
		Dictionary<int, MapDoor> components )
	{
		var linked = 0;
		foreach ( var (index, component) in components )
		{
			var door = doors[index];
			if ( !door.IsLinked )
				continue;

			// Checked for both sides, so a skipped *leader* is reported too -
			// only testing leaders would let a stranded follower pass silently.
			if ( !components.TryGetValue( door.PartnerIndex, out var partner ) )
			{
				Log.Warning(
					$"  door[{index}] is linked to {door.PartnerIndex}, which was "
					+ "not spawned; it will open alone." );
				continue;
			}

			if ( door.IsFollower )
				continue;

			component.LinkedDoor = partner;
			linked++;
		}

		if ( linked > 0 )
			Log.Info( $"  linked {linked} door pair(s)." );
	}

	// Every shape 0xD88A6C draws is a box; none is a quad. Shapes 0 and 1 are a
	// full cell wide and only 2*W thick, shape 2 is a square post.
	const float DoorPostHalfExtent = 0.175f;

	const float DoorThinHalfThickness = 0.026f;

	/// <summary>
	/// Port of the door leaf emitter <c>0x00D88A6C</c>.
	/// </summary>
	/// <remarks>
	/// Three shapes, selected by door record <c>+0x5C</c>: 0 is a box on one
	/// axis with faces a full cell wide plus two edge quads, 1 is the same box
	/// on the other axis, and 2 is a 0.35 x 0.35 square post with a horizontal
	/// cap on top.
	///
	/// The edge quads use a hardcoded atlas tile (column 2, row 7) rather than
	/// either of the door's own pairs, and the cap uses (31, 2). Both are
	/// literals in the original.
	///
	/// W comes from the loop at <c>0x00D77FA0</c>: 0.25 while record
	/// <c>+0x58</c> holds 1000, otherwise 0.026. D77C20's behaviour jump table
	/// at <c>0x00D77D42</c> seeds that 1000 on cases 5, 6 and 7, but live
	/// memory shows <c>+0x58</c> at 0 on every door of a running map, so the
	/// thick case is transient state and never the resting geometry.
	/// </remarks>
	static void AddDoorLeaf(
		List<SimpleVertex> vertices,
		List<int> indices,
		HrotDoorPlacement door,
		Vector3 center,
		float bottom,
		float top )
	{
		var front = new HrotMapFace( true, door.AtlasX, door.AtlasY, [], 0 );
		var back = new HrotMapFace( true, door.SideAtlasX, door.SideAtlasY, [], 0 );

		void Side( HrotMapFace face, float ax, float ay, float bx, float by )
			=> AddWallQuad(
				vertices, indices, face, WallAtlasRows,
				new Vector3( ax, ay, bottom ), new Vector3( bx, by, bottom ),
				new Vector3( bx, by, top ), new Vector3( ax, ay, top ) );

		if ( door.Shape == 2 )
		{
			var e = DoorPostHalfExtent * UnitScale;
			var x0 = center.x - e;
			var x1 = center.x + e;
			var y0 = center.y - e;
			var y1 = center.y + e;

			// Three faces take the front pair and one the back, which is
			// asymmetric but is what the original does.
			Side( front, x0, y1, x1, y1 );
			Side( back, x1, y0, x0, y0 );
			Side( front, x0, y0, x0, y1 );
			Side( front, x1, y1, x1, y0 );

			// The cap goes through the same horizontal emitter the stair treads
			// use, with its own hardcoded tile.
			AddQuad(
				vertices, indices, new HrotMapFace( true, 31, 2, [], 0 ),
				FloorAtlasRows,
				new Vector3( x0, y0, top ), new Vector3( x1, y0, top ),
				new Vector3( x1, y1, top ), new Vector3( x0, y1, top ) );
			return;
		}

		// Always the thin W. 0x00D77FA0 picks the thick 0.25 only while record
		// +0x58 holds 1000, and although D77C20's behaviour branches 5, 6 and 7
		// seed it with exactly that, live memory shows +0x58 back at 0 on every
		// door once a map is running - it is a transient, not a description of
		// the leaf. Deriving thickness from the behaviour byte made leaves
		// slabs that are flat in game.
		var w = DoorThinHalfThickness * UnitScale;
		var half = 0.5f * UnitScale;
		var edge = new HrotMapFace( true, 2, 7, [], 0 );

		if ( door.Shape == 1 )
		{
			// Faces perpendicular to X, leaf spanning Y.
			Side( front, center.x + w, center.y - half, center.x + w, center.y + half );
			Side( back, center.x - w, center.y + half, center.x - w, center.y - half );
			Side( edge, center.x - w, center.y + half, center.x + w, center.y + half );
			Side( edge, center.x + w, center.y - half, center.x - w, center.y - half );
			return;
		}

		// Faces perpendicular to Y, leaf spanning X.
		Side( front, center.x - half, center.y + w, center.x + half, center.y + w );
		Side( back, center.x + half, center.y - w, center.x - half, center.y - w );
		Side( edge, center.x + half, center.y + w, center.x + half, center.y - w );
		Side( edge, center.x - half, center.y - w, center.x - half, center.y + w );
	}

	static void AddQuad(
		List<SimpleVertex> vertices,
		List<int> indices,
		HrotMapFace face,
		float atlasRows,
		Vector3 p0,
		Vector3 p1,
		Vector3 p2,
		Vector3 p3,
		bool flipVertical = false,
		float verticalStart = 0.0f,
		float verticalEnd = 1.0f,
		bool quarterTurnUvs = false )
	{
		var normal = Vector3.Cross( p1 - p0, p2 - p0 ).Normal;
		if ( normal.LengthSquared < 0.5f )
			return;

		var tangent = (p1 - p0).Normal;
		var uv = AtlasUv( face, atlasRows );
		var lowerV = flipVertical
			? uv.Bottom + (uv.Top - uv.Bottom) * verticalStart
			: uv.Top + (uv.Bottom - uv.Top) * verticalStart;
		var upperV = flipVertical
			? uv.Bottom + (uv.Top - uv.Bottom) * verticalEnd
			: uv.Top + (uv.Bottom - uv.Top) * verticalEnd;
		var first = vertices.Count;
		var uv0 = quarterTurnUvs ? new Vector2( uv.Left, upperV ) : new( uv.Left, lowerV );
		var uv1 = quarterTurnUvs ? new Vector2( uv.Left, lowerV ) : new( uv.Right, lowerV );
		var uv2 = quarterTurnUvs ? new Vector2( uv.Right, lowerV ) : new( uv.Right, upperV );
		var uv3 = quarterTurnUvs ? new Vector2( uv.Right, upperV ) : new( uv.Left, upperV );
		vertices.Add( new SimpleVertex( p0, normal, tangent, uv0 ) );
		vertices.Add( new SimpleVertex( p1, normal, tangent, uv1 ) );
		vertices.Add( new SimpleVertex( p2, normal, tangent, uv2 ) );
		vertices.Add( new SimpleVertex( p3, normal, tangent, uv3 ) );
		indices.Add( first + 0 );
		indices.Add( first + 1 );
		indices.Add( first + 2 );
		indices.Add( first + 0 );
		indices.Add( first + 2 );
		indices.Add( first + 3 );
	}

	static void AddWallQuad(
		List<SimpleVertex> vertices,
		List<int> indices,
		HrotMapFace face,
		float atlasRows,
		Vector3 p0,
		Vector3 p1,
		Vector3 p2,
		Vector3 p3,
		float verticalStart = 0.0f,
		float verticalEnd = 1.0f )
	{
		// HROT's explicit edge walls are shared by sectors and are visible
		// from either side (doorways, tunnels and outdoor transitions are
		// common examples). Preserve both faces instead of guessing which
		// adjacent sector is the visual interior.
		AddQuad(
			vertices, indices, face, atlasRows,
			p0, p1, p2, p3, true, verticalStart, verticalEnd );
		AddQuad(
			vertices, indices, face, atlasRows,
			p1, p0, p3, p2, true, verticalStart, verticalEnd );
	}

	static AtlasRect AtlasUv( HrotMapFace face, float atlasRows )
	{
		// HROT's atlas X is zero-based, but Y is one-based. Horizontal
		// floor/ceiling tiles are 64x64 (32 rows); vertical wall tiles are
		// 64x128 (16 rows). The original renderer also uses a quarter-pixel
		// inset to avoid bleeding between atlas entries.
		var x = Math.Clamp( face.AtlasX, 0, 31 ) / AtlasColumns;
		var y = (Math.Clamp( face.AtlasY, 1, (int)atlasRows ) - 1) / atlasRows;
		var width = 1.0f / AtlasColumns;
		var height = 1.0f / atlasRows;
		return new AtlasRect(
			x + TileInset,
			y + TileInset,
			x + width - TileInset,
			y + height - TileInset );
	}

	readonly record struct AtlasRect( float Left, float Top, float Right, float Bottom );
}
