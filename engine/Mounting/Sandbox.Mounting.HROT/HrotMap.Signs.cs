using Sandbox;
using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>Wall signs: a GameObject each, with their activation volume.</summary>
/// <remarks>
/// A sign is two independent things authored at the same spot, and the mount
/// keeps both on one object:
///
/// <list type="bullet">
/// <item>a <b>decal</b> - the quad showing a rectangle of the level's decal
/// sheet. The text is painted into the sheet, not drawn from glyphs.</item>
/// <item>a <b>box</b> - the volume HROT uses to show the English translation
/// while the player is near it.</item>
/// </list>
///
/// Neither implies the other. Signs painted into the wall atlas or carried by a
/// prop model already render and have only a box; a decal can exist with no box.
/// Both cases get an object here, so the full set is addressable later.
///
/// See the wall sign section of REVERSE_ENGINEERING.md.
/// </remarks>
sealed partial class HrotMap
{
	/// <summary>
	/// How close a decal and a box must be, in HROT metres, to be the same sign.
	/// </summary>
	/// <remarks>
	/// A box sits just off the wall its decal is on, so the two are never at the
	/// same point. Map 1's pairs are all within a few centimetres and the
	/// nearest unrelated sign is metres away, so this is not delicately placed.
	/// </remarks>
	const float SignPairingDistance = 1.5f;

	int SpawnSigns()
	{
		var decals = Host.GetMapDecals( MapId, out var undecodableDecals );
		var boxes = Host.GetMapSignBoxes( MapId, out var undecodableBoxes );

		// The number accepted says nothing about what exists, so what could not
		// be read is worth reporting on its own.
		if ( undecodableDecals > 0 || undecodableBoxes > 0 )
		{
			Log.Warning(
				$"HROT map {MapId:00}: {undecodableDecals} sign quad(s) and "
				+ $"{undecodableBoxes} activation box(es) had computed arguments "
				+ "and are missing." );
		}

		if ( decals.Count == 0 && boxes.Count == 0 )
			return 0;

		var sheet = Host.GetMapDecalSheet( MapId );
		var texture = Host.LoadTextureByStemAnywhere( sheet );
		if ( texture is null )
			Log.Warning( $"HROT map {MapId:00}: decal sheet \"{sheet}\" was not found." );

		var material = Material.Create(
			$"hrot_signs_{MapId:00}", HrotMount.SurfaceShader );
		material?.Set( "g_tColor", texture ?? Texture.White );

		var unpaired = new List<HrotSignBox>( boxes );
		var spawned = 0;

		foreach ( var decal in decals )
		{
			var box = NearestBox( unpaired, decal );
			if ( box is not null )
				unpaired.Remove( box.Value );

			SpawnSign( material, decal, box, ++spawned );
		}

		// Boxes whose sign is part of the wall atlas or of a prop. They render
		// already, so these carry the volume and nothing else - without them the
		// translation would only ever be reachable for signs that needed a quad.
		foreach ( var box in unpaired )
			SpawnSign( material, null, box, ++spawned );

		return spawned;
	}

	static HrotSignBox? NearestBox(
		List<HrotSignBox> boxes, HrotDecalPlacement decal )
	{
		HrotSignBox? best = null;
		var bestDistance = SignPairingDistance;

		foreach ( var box in boxes )
		{
			var distance = MathF.Sqrt(
				MathF.Pow( box.Position.x - decal.CellX, 2.0f ) +
				MathF.Pow( box.Position.z - decal.CellZ, 2.0f ) );

			if ( distance > bestDistance )
				continue;

			bestDistance = distance;
			best = box;
		}

		return best;
	}

	void SpawnSign(
		Material material,
		HrotDecalPlacement? decal,
		HrotSignBox? box,
		int index )
	{
		var name = box is { } named
			? $"hrot_sign_{index:00}_string_{named.StringId}"
			: $"hrot_sign_{index:00}";

		var go = new GameObject( true, name );
		go.Tags.Add( "hrot_sign" );

		if ( decal is { } quad )
		{
			// The object sits at the quad and the mesh is built around the
			// origin, so the transform is the thing to move if a sign needs
			// nudging rather than the decoded rectangle.
			go.WorldPosition = PanelToWorld( quad.CellX, quad.Y, quad.CellZ );
			go.AddComponent<ModelRenderer>().Model = BuildSignModel( material, quad );
		}
		else
		{
			go.WorldPosition = PanelToWorld(
				box.Value.Position.x, box.Value.Position.y, box.Value.Position.z );
			go.Tags.Add( "hrot_sign_scenery" );
		}

		if ( box is not { } volume )
			return;

		go.Tags.Add( "hrot_sign_readable" );

		var trigger = go.AddComponent<BoxCollider>();
		trigger.IsTrigger = true;

		// A box, not a sphere: one half-extent is always thin because the volume
		// hugs the wall, and the thin axis is what keeps the trigger from
		// reaching through into the room behind.
		trigger.Scale = new Vector3(
			volume.HalfExtents.x, volume.HalfExtents.z, volume.HalfExtents.y )
			* 2.0f * UnitScale;

		// The volume is authored independently of the quad, so it is placed from
		// its own centre rather than assumed concentric with the sign.
		trigger.Center = PanelToWorld(
			volume.Position.x, volume.Position.y, volume.Position.z )
			- go.WorldPosition;
	}

	/// <summary>
	/// A one-quad model for a sign, built around the object's own origin.
	/// </summary>
	Model BuildSignModel( Material material, HrotDecalPlacement decal )
	{
		// Already half-extents - 0xD89B5C emits centre +/- these, so they are
		// not halved again here.
		var halfWidth = decal.HalfWidth;
		var halfHeight = decal.HalfHeight;

		// PanelToWorld sends this component to s&box up, so the larger value is
		// the top edge and takes V0, the sheet's top row; reversing it renders
		// the sign upside down.
		var top = halfHeight;
		var bottom = -halfHeight;

		// Facings 0 and 1 sit on a Z-facing wall and span X; 2 and 3 sit on an
		// X-facing wall and span Z. Each pair runs its span the opposite way so
		// the text is not mirrored when read from its own side.
		var (leftX, leftZ, rightX, rightZ) = decal.Facing switch
		{
			0 => (-halfWidth, 0.0f, halfWidth, 0.0f),
			1 => (halfWidth, 0.0f, -halfWidth, 0.0f),
			2 => (0.0f, -halfWidth, 0.0f, halfWidth),
			_ => (0.0f, halfWidth, 0.0f, -halfWidth),
		};

		var vertices = new List<SimpleVertex>();
		var indices = new List<int>();

		AddSurfaceQuad( vertices, indices,
			LocalToWorld( leftX, top, leftZ ), new Vector2( decal.U0, decal.V0 ),
			LocalToWorld( rightX, top, rightZ ), new Vector2( decal.U1, decal.V0 ),
			LocalToWorld( rightX, bottom, rightZ ), new Vector2( decal.U1, decal.V1 ),
			LocalToWorld( leftX, bottom, leftZ ), new Vector2( decal.U0, decal.V1 ),
			doubleSided: true );

		var mesh = new Mesh( material )
		{
			Bounds = BBox.FromPoints( vertices.Select( x => x.position ) )
		};
		mesh.CreateVertexBuffer( vertices.Count, vertices );
		mesh.CreateIndexBuffer( indices.Count, indices );

		// No collision or trace mesh. A sign is paint on a wall, and either
		// would make it block movement and take hits in front of the surface it
		// is drawn on.
		return Model.Builder
			.WithName( $"hrot_sign/{MapId:00}/{decal.CellX:0.##}_{decal.CellZ:0.##}" )
			.AddMesh( mesh )
			.Create();
	}

	/// <summary>
	/// The same axis change as <see cref="PanelToWorld"/>, without the world
	/// offset - these coordinates are relative to the sign's own origin.
	/// </summary>
	static Vector3 LocalToWorld( float x, float height, float z )
		=> new Vector3( x, -z, height ) * UnitScale;
}
