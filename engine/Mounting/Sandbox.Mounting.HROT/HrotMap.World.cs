using Sandbox;
using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>World surfaces, ported from HROT's own renderer.</summary>
/// <remarks>
/// The port target is the routine at <c>0x00D8AC18</c> in the retail
/// executable: the only function that walks the whole 101x101 grid while
/// reading both the stair direction (<c>+0x1D6</c>) and the wall baseline
/// (<c>+0x1D5</c>). See REVERSE_ENGINEERING.md section 11 for the decode, and
/// sections 9-10 for the cell layout, atlas convention and coordinate transform.
///
/// Faithfulness is the goal, including any quirks of the original.
/// </remarks>
sealed partial class HrotMap
{
	// Floors and ceilings are 64x64 tiles in the 2048x2048 pack1 atlas, so both
	// atlas axes step by 1/32. Walls are 64x128 and step by 1/16 vertically.
	const float FloorAtlasStep = 0.03125f;
	// Walls are 64x128, so 32 atlas columns by 16 rows: the vertical step is
	// 1/16 while the horizontal step stays 1/32.
	const float WallAtlasStep = 0.0625f;
	// One vertical wall band, straight out of 0xD8D2FC.
	const float WallBandHeight = 1.5625f;
	// Tolerances and span from the derive pass at 0x00D424E9.
	const float CeilingBandEpsilon = 0.02f;
	const float CeilingBandSpan = 1.40625f;

	/// <summary>
	/// The per-cell flags HROT derives at load time rather than storing in the
	/// map: <c>0x07</c>, <c>0x08</c> and <c>0x1D7</c>.
	/// </summary>
	/// <remarks>
	/// See REVERSE_ENGINEERING.md 11.5 and 11.2. These are what decide whether a
	/// cell needs a floor or ceiling riser, and they are computed once from a
	/// four-neighbour comparison - not re-derived per surface.
	/// </remarks>
	sealed class DerivedFlags
	{
		readonly bool[] floorRiser;
		readonly bool[] ceilingRiser;
		readonly byte[] ceilingBands;
		readonly float[] overlayHeight;

		public bool NeedsFloorRiser( int row, int column ) => floorRiser[Index( row, column )];
		public bool NeedsCeilingRiser( int row, int column ) => ceilingRiser[Index( row, column )];
		public int CeilingBands( int row, int column ) => ceilingBands[Index( row, column )];
		public float OverlayHeight( int row, int column ) => overlayHeight[Index( row, column )];

		static int Index( int row, int column )
			=> row * HrotExecutableMapData.GridSize + column;

		/// <summary>
		/// Port of <c>0x00D42360</c> and the ceiling-band classifier at
		/// <c>0x00D424E9</c>, driven by the full-grid walk ending at
		/// <c>0x00D4267F</c>.
		/// </summary>
		public DerivedFlags( HrotMapGrid grid )
		{
			var size = HrotExecutableMapData.GridSize;
			floorRiser = new bool[size * size];
			ceilingRiser = new bool[size * size];
			ceilingBands = new byte[size * size];
			overlayHeight = new float[size * size];

			for ( var row = 0; row < size; row++ )
			{
				for ( var column = 0; column < size; column++ )
				{
					var cell = grid.Cell( column, row );
					var bands = ClassifyCeilingBands( grid, cell, row, column );
					ceilingBands[Index( row, column )] = bands;
					overlayHeight[Index( row, column )] = ClassifyOverlayHeight( cell, bands );

					// The original calls the derive function once per
					// orthogonal neighbour, in this order, each of which may
					// only set flags - so the result is an OR over the four.
					Accumulate( grid, cell, row, column, row - 1, column );
					Accumulate( grid, cell, row, column, row + 1, column );
					Accumulate( grid, cell, row, column, row, column + 1 );
					Accumulate( grid, cell, row, column, row, column - 1 );
				}
			}
		}

		void Accumulate(
			HrotMapGrid grid,
			HrotMapCell cell,
			int row,
			int column,
			int neighbourRow,
			int neighbourColumn )
		{
			var size = HrotExecutableMapData.GridSize;
			if ( neighbourRow < 0 || neighbourColumn < 0 ||
				neighbourRow >= size || neighbourColumn >= size )
				return;

			var neighbour = grid.Cell( neighbourColumn, neighbourRow );

			// The original's liquid clause - `if A[0x19] > 0 or B[0x19] > 0`,
			// setting both flags - is unreachable in a static export: 0x19 is
			// never written by a map constructor. Omitted rather than ported
			// as dead code. See REVERSE_ENGINEERING.md 11.5.

			// Substituted, not ported: the original gates the rest on
			// B[0x01], which nothing in the map data ever sets and the cell
			// initializer clears. It reads as "B is a real in-map cell", and
			// without some stand-in every void cell past the map edge counts
			// as open sky and rings the whole map in spurious risers.
			if ( !IsRealCell( neighbour ) )
				return;

			var index = Index( row, column );

			if ( neighbour.FloorHeight < cell.FloorHeight )
				floorRiser[index] = true;

			if ( !neighbour.HasCeiling ||
				neighbour.CeilingHeight > cell.CeilingHeight )
				ceilingRiser[index] = true;
		}

		/// <summary>
		/// Classifies how many wall bands sit between the cell's baseline and
		/// its ceiling. <c>0</c> suppresses ceiling risers entirely.
		/// </summary>
		static byte ClassifyCeilingBands(
			HrotMapGrid grid,
			HrotMapCell cell,
			int row,
			int column )
		{
			if ( !cell.HasCeiling )
				return 0;

			var top = cell.WallBaseHeight + WallBandHeight;
			var ceiling = cell.CeilingHeight;

			if ( top - CeilingBandEpsilon > ceiling )
				return 1;

			if ( top + CeilingBandSpan > ceiling &&
				top + CeilingBandEpsilon < ceiling )
				return 2;

			return 0;
		}

		/// <summary>
		/// Cell field <c>0x14</c>, the height the overlay quad at
		/// <c>0xD87FC0</c> is drawn at.
		/// </summary>
		/// <remarks>
		/// The derive pass computes two intermediates - <c>0x1D8</c>, half the
		/// distance from the ceiling to the relevant band top, and
		/// <c>0x1DC = ceiling + 0x1D8</c> - then seeds <c>0x14</c> with their
		/// sum, which reduces to <c>ceiling + |bandTop - ceiling|</c>: the
		/// ceiling height mirrored about the band top. It is only written for
		/// cells that have a ceiling, and only once, because the original
		/// guards it with a <c>&lt; -1000</c> test against the <c>-2000</c>
		/// initial value.
		/// </remarks>
		static float ClassifyOverlayHeight( HrotMapCell cell, byte bands )
		{
			if ( !cell.HasCeiling )
				return float.NegativeInfinity;

			var ceiling = cell.CeilingHeight;
			var top = cell.WallBaseHeight + WallBandHeight;

			return bands switch
			{
				0 => ceiling,
				1 => ceiling + MathF.Abs( top - ceiling ),
				// Band type 2 measures to the top of the tallest auxiliary
				// stack on any of the four faces, via 0x00D42280.
				_ => ceiling + MathF.Abs(
					top + MaxAuxiliaryBands( cell ) * WallBandHeight - ceiling ),
			};
		}

		static int MaxAuxiliaryBands( HrotMapCell cell )
			=> Math.Max(
				Math.Max( cell.East.AuxiliaryCount, cell.West.AuxiliaryCount ),
				Math.Max( cell.South.AuxiliaryCount, cell.North.AuxiliaryCount ) );

		/// <summary>
		/// Stands in for cell field <c>0x01</c>, which no map constructor
		/// writes.
		/// </summary>
		/// <remarks>
		/// Verified against live memory: reproduces <c>0x01</c> on all 10201
		/// cells of both map 1 and map 2. Two terms were found by comparing
		/// against the running game rather than by reasoning, and neither is
		/// obvious from the map data alone:
		/// <list type="bullet">
		/// <item>auxiliary records - four cells on map 1 carry stacked wall
		/// bands with no active base wall, floor or ceiling;</item>
		/// <item>the overlay flag <c>0x10</c> - five cells on map 2, and 35 on
		/// map 5, carry nothing but that.</item>
		/// </list>
		/// </remarks>
		static bool IsRealCell( HrotMapCell cell )
			=> cell.HasFloor || cell.HasCeiling || cell.HasOverlay ||
				cell.East.Active || cell.West.Active ||
				cell.South.Active || cell.North.Active ||
				cell.East.AuxiliaryCount > 0 || cell.West.AuxiliaryCount > 0 ||
				cell.South.AuxiliaryCount > 0 || cell.North.AuxiliaryCount > 0;
	}

	Model BuildWorldModel( HrotMapGrid grid )
	{
		var vertices = new List<SimpleVertex>();
		var indices = new List<int>();
		var glassVertices = new List<SimpleVertex>();
		var glassIndices = new List<int>();
		var waterVertices = new List<SimpleVertex>();
		var waterIndices = new List<int>();
		EmitWorldSurfaces( grid, vertices, indices );

		EmitGlassPanels( glassVertices, glassIndices );

		EmitWater( grid, waterVertices, waterIndices );

		if ( vertices.Count == 0 || indices.Count == 0 )
		{
			// No world geometry; the scene still loads with lighting and props.
			Log.Info(
				$"HROT map {MapId} (native renderer) emitted no world geometry yet." );
			return null;
		}

		var atlas = Host.LoadTextureAnywhere( "pack1.jpg" ) ?? Texture.White;
		var material = Material.Create( $"hrot_world_native_{MapId:00}", HrotMount.SurfaceShader );
		material?.Set( "g_tColor", atlas );
		var bounds = BBox.FromPoints( vertices.Select( x => x.position ) );
		var mesh = new Mesh( material ) { Bounds = bounds };
		mesh.CreateVertexBuffer( vertices.Count, vertices );
		mesh.CreateIndexBuffer( indices.Count, indices );

		var collision = vertices.Select( x => x.position ).ToArray();
		var collisionIndices = indices.ToArray();
		var builder = Model.Builder
			.WithName( $"hrotmap_native/{MapId:00}" )
			.AddMesh( mesh )
			.AddCollisionMesh( collision, collisionIndices )
			.AddTraceMesh( collision, collisionIndices );

		if ( glassVertices.Count > 0 && glassIndices.Count > 0 )
		{
			var glassTexture = Host.LoadTextureAnywhere( "sklo.tga" );
			var glassMaterial = Material.Create(
				$"hrot_world_native_glass_{MapId:00}", HrotMount.SurfaceShader );
			glassMaterial?.Set( "g_tColor", glassTexture ?? Texture.White );
			glassMaterial?.SetFeature( "F_TRANSLUCENT", 1 );

			var glassMesh = new Mesh( glassMaterial )
			{
				Bounds = BBox.FromPoints( glassVertices.Select( x => x.position ) )
			};
			glassMesh.CreateVertexBuffer( glassVertices.Count, glassVertices );
			glassMesh.CreateIndexBuffer( glassIndices.Count, glassIndices );
			builder.AddMesh( glassMesh );

			var glassCollision = glassVertices.Select( x => x.position ).ToArray();
			var glassCollisionIndices = glassIndices.ToArray();
			builder.AddCollisionMesh( glassCollision, glassCollisionIndices );
			builder.AddTraceMesh( glassCollision, glassCollisionIndices );
		}

		if ( waterVertices.Count > 0 && waterIndices.Count > 0 )
		{
			var waterTexture = Host.LoadTextureAnywhere( "voda1.jpg" ) ??
				Host.LoadTextureByStemAnywhere( "voda1" );
			var waterMaterial = Material.Create(
				$"hrot_world_native_water_{MapId:00}", HrotMount.SurfaceShader );
			waterMaterial?.Set( "g_tColor", waterTexture ?? Texture.White );

			// Deliberately opaque. voda1.jpg has no alpha channel, so marking
			// the material translucent cannot make it see-through - it only
			// disables depth writes (sbox_pixel.fxc keys that off S_TRANSLUCENT),
			// which is strictly worse for a surface this large. HROT itself
			// draws water with glColor3f and no blend, so opaque is also what
			// the original does; see REVERSE_ENGINEERING.md 11.7.

			var waterMesh = new Mesh( waterMaterial )
			{
				Bounds = BBox.FromPoints( waterVertices.Select( x => x.position ) )
			};
			waterMesh.CreateVertexBuffer( waterVertices.Count, waterVertices );
			waterMesh.CreateIndexBuffer( waterIndices.Count, waterIndices );
			builder.AddMesh( waterMesh );

			// No collision or trace mesh: water is swum through, not stood on.
			// The floor underneath already carries both.
			Log.Info(
				$"HROT map {MapId} emitted {waterIndices.Count / 12} water quads " +
				$"(texture {(waterTexture is null ? "MISSING" : "voda1")})." );
		}
		else
		{
			// Logged so a genuinely dry map is distinguishable from a water
			// pass that decoded nothing.
			Log.Info( $"HROT map {MapId} has no water cells." );
		}

		return builder.Create();
	}

	/// <summary>
	/// Port of the transparent panel draw <c>0x00D8FABC</c>.
	/// </summary>
	/// <remarks>
	/// These panels are not grid cells. They come from 40-byte records written
	/// by the level constructors through <c>0x00D4D690</c>, so they sit outside
	/// the per-cell traversal entirely and need their own pass and their own
	/// <c>sklo.tga</c> material. Record layout and atlas strides are in
	/// REVERSE_ENGINEERING.md.
	///
	/// Only the panel quad itself is emitted here - not the reveal, front upper
	/// face and base riser around the one-cell-deep recess it sits in. The
	/// ported traversal may already emit those from the auxiliary bands and
	/// risers, so synthesising them here too would risk the double-covered
	/// boundary this port exists to eliminate.
	/// </remarks>
	void EmitGlassPanels(
		List<SimpleVertex> vertices,
		List<int> indices )
	{
		const float horizontalStride = 0.125f;
		const float verticalStride = 0.25f;
		const float glassInset = 1.0f / 1024.0f;
		const float sourceBandHeight = 1.5625f;

		foreach ( var panel in Host.GetMapGlassPanels( MapId ) )
		{
			var left = panel.AtlasX * horizontalStride + glassInset;
			var right = (panel.AtlasX + 1) * horizontalStride - glassInset;

			// Short panels clip the bottom of the selected band rather than
			// squashing the whole 128-pixel row into the shorter span.
			var clipped =
				(sourceBandHeight - panel.Height) / sourceBandHeight * verticalStride;

			// Mirrored on V for the same reason as the world atlas (6.13):
			// HROT uploads the bottom-origin TGA straight to GL.
			var topV = (panel.AtlasY - 1) * verticalStride + glassInset + clipped;
			var bottomV = panel.AtlasY * verticalStride - glassInset;

			var x = panel.X;
			var z = panel.Z;
			var bottom = panel.Bottom;
			var top = panel.Bottom + panel.Height;

			// Orientations 0/1 span the first horizontal axis and 2/3 the
			// second; each pair reverses the atlas direction.
			switch ( panel.Orientation )
			{
				case 0:
					Quad( x + 1.0f, top, z, right, x, top, z, left,
						x, bottom, z, left, x + 1.0f, bottom, z, right );
					break;
				case 1:
					Quad( x, top, z, right, x + 1.0f, top, z, left,
						x + 1.0f, bottom, z, left, x, bottom, z, right );
					break;
				case 2:
					Quad( x, top, z + 1.0f, right, x, top, z, left,
						x, bottom, z, left, x, bottom, z + 1.0f, right );
					break;
				default:
					Quad( x, top, z, right, x, top, z + 1.0f, left,
						x, bottom, z + 1.0f, left, x, bottom, z, right );
					break;
			}

			void Quad(
				float x0, float y0, float z0, float u0,
				float x1, float y1, float z1, float u1,
				float x2, float y2, float z2, float u2,
				float x3, float y3, float z3, float u3 )
				=> AddSurfaceQuad( vertices, indices,
					PanelToWorld( x0, y0, z0 ), new Vector2( u0, topV ),
					PanelToWorld( x1, y1, z1 ), new Vector2( u1, topV ),
					PanelToWorld( x2, y2, z2 ), new Vector2( u2, bottomV ),
					PanelToWorld( x3, y3, z3 ), new Vector2( u3, bottomV ),
					doubleSided: true );
		}
	}

	/// <summary>
	/// Panel records store coordinates already in the mount's transposed frame,
	/// so unlike grid cells they take the literal HROT-to-s&amp;box transform.
	/// </summary>
	static Vector3 PanelToWorld( float x, float height, float z )
		=> new Vector3( x, -z, height ) * UnitScale;

	/// <summary>
	/// Port of HROT's per-cell world surface pass
	/// (<c>0x00D8B3A2-0x00D8C000</c>, inside <c>0x00D8AC18</c>).
	/// </summary>
	/// <remarks>
	/// The original walks rows in the outer loop and columns in the inner one,
	/// with the cell pointer held at base+1 - so every field offset in a
	/// disassembly of this function reads one lower than the offsets in
	/// REVERSE_ENGINEERING.md section 9. The offsets used here are section-9
	/// offsets.
	///
	/// The original bounds both loops with a visible-window rectangle read from
	/// globals at 0x17D5FF0..0x17D5FFC rather than walking 0..100. That is a
	/// render-time culling concern with no meaning for a static export, so the
	/// full grid is walked here.
	///
	/// Emission order is the original's. Only the surfaces whose leaf emitters
	/// have been decoded are present so far; see REVERSE_ENGINEERING.md section 11.
	/// </remarks>
	static void EmitWorldSurfaces(
		HrotMapGrid grid,
		List<SimpleVertex> vertices,
		List<int> indices )
	{
		var derived = new DerivedFlags( grid );

		for ( var row = 0; row < HrotExecutableMapData.GridSize; row++ )
		{
			for ( var column = 0; column < HrotExecutableMapData.GridSize; column++ )
			{
				// Grid memory is [column + row*101], so the column is the first
				// index. HROT's own world vector puts the column on X and the
				// row on Z, but this mount transposes that - props resolve their
				// cell as Cell(cellZ, cellX) and place at (cellX, -cellZ). The
				// transpose is uniform and therefore invisible, but geometry
				// ported straight from HROT's axes would land 90 degrees out
				// from the inherited props. HrotToWorld below applies the
				// mount's convention, not the original's.
				var cell = grid.Cell( column, row );

				// The original also gates the whole cell on 0x01 and 0x03, and
				// the flat floor on 0x1D4. None of the three is ever written by
				// any map constructor - they are runtime cull state, like the
				// visible-window globals - so replaying them would emit nothing
				// at all. See REVERSE_ENGINEERING.md section 9 (runtime fields).

				// The original runs this before the floor section.
				if ( cell.HasOverlay )
					EmitOverlay( vertices, indices, derived, row, column );

				// The original tests floor-active before anything else in this
				// block and skips to the ceiling section when it is clear.
				if ( cell.HasFloor )
				{
					EmitFlatFloor( vertices, indices, cell, row, column );
					EmitFloorRisers(
						vertices, indices, derived, cell, row, column );

					// The stair dispatch sits between the floor risers and the
					// ceiling section in the original's order.
					if ( cell.StairDirection != 0 )
						EmitStairs( vertices, indices, cell, row, column );
				}

				if ( cell.HasCeiling )
				{
					EmitCeiling( vertices, indices, cell, row, column );
					EmitCeilingRisers(
						vertices, indices, derived, cell, row, column );
				}

				EmitBaseWallBands( vertices, indices, cell, row, column );
				EmitAuxiliaryBands( vertices, indices, cell, row, column );
			}
		}
	}

	/// <summary>
	/// Port of the flat floor quad emitter <c>0x00D87DD0</c>.
	/// </summary>
	/// <remarks>
	/// Called once per floor-active cell, before the stair dispatch, so stair
	/// cells get a flat quad as well as their sloped one. The emitter's own
	/// <c>0x1D4</c> gate would suppress that, but no map constructor ever
	/// writes <c>0x1D4</c>, so it cannot be replayed and stair cells are
	/// expected to show a doubled floor until the stair pass lands.
	/// </remarks>
	static void EmitFlatFloor(
		List<SimpleVertex> vertices,
		List<int> indices,
		HrotMapCell cell,
		int row,
		int column )
	{
		EmitHorizontalQuad(
			vertices, indices, cell.Floor,
			column, column + 1, row, row + 1, cell.FloorHeight );
	}

	/// <summary>
	/// One axis-aligned horizontal quad. Shared by the flat floor
	/// (<c>0xD87DD0</c>) and the stair tread (<c>0xD881AC</c>), which use the
	/// same corner order and the same whole-tile texture coordinates, and
	/// differ only in extent.
	/// </summary>
	/// <summary>
	/// Port of the water pass <c>0x00D8FFE5</c> and its emitter
	/// <c>0xD8F3CC</c>.
	/// </summary>
	/// <remarks>
	/// Water is its own surface class, not a floor. A cell has water when
	/// <c>0x09</c> is non-zero, and <c>0x0C</c> is the absolute surface height -
	/// independent of the floor below, which is what makes props stand on the
	/// bottom while being partly submerged. Both are ordinary map data. See
	/// REVERSE_ENGINEERING.md 11.7.
	///
	/// The original walks the grid through a pointer pre-offset to <c>0x09</c>
	/// and also gates on <c>0x01</c> and <c>0x03</c>. Both are runtime state, so
	/// a static export ignores them exactly as the other passes do.
	///
	/// Texture coordinates come from cell *parity*, not from an atlas entry:
	/// the tile repeats over 2x2 cells rather than once per cell.
	///
	/// One decoded detail is deliberately **not** applied: HROT tints the
	/// surface with <c>glColor3f</c> by water type - <c>(0, 0.91, 0.8)</c> for
	/// type 1 and <c>(0, 0.9, 0.55)</c> for type 2, the latter only on map 9.
	/// The <c>simple_color</c> shader exposes nothing but <c>g_tColor</c>, so
	/// there is nothing to apply it through. The tint is recorded here and in
	/// 6.25 so it can be applied once there is a shader that takes one.
	/// </remarks>
	void EmitWater(
		HrotMapGrid grid,
		List<SimpleVertex> vertices,
		List<int> indices )
	{
		for ( var row = 0; row < HrotExecutableMapData.GridSize; row++ )
		{
			for ( var column = 0; column < HrotExecutableMapData.GridSize; column++ )
			{
				// Cell( x, y ) indexes y * GridSize + x, so the column comes
				// first. Passing (row, column) here reads the grid transposed,
				// which still finds the same *number* of water cells and emits
				// them all in the wrong places.
				var cell = grid.Cell( column, row );
				if ( !cell.HasWater )
					continue;

				var height = cell.WaterHeight;

				// texcoord2f( s, t ) with s from the column's parity and t from
				// the row's. Note s runs *against* the column axis: the
				// column+1 corners take the low half, not the high one.
				var sLow = (column & 1) == 0 ? 0.0f : 0.5f;
				var sHigh = sLow + 0.5f;
				var tLow = (row & 1) == 0 ? 0.0f : 0.5f;
				var tHigh = tLow + 0.5f;

				// The original's four vertices, in its order, so the surface
				// faces the way HROT wound it. Emitted double-sided because the
				// player swims: unlike a floor, this plane is genuinely seen
				// from below. HROT relies on its GL cull state, which has not
				// been read out of the executable - see 6.12 for the same
				// question on walls.
				AddSurfaceQuad(
					vertices, indices,
					HrotToWorld( column + 1, height, row + 1 ), new Vector2( sLow, tLow ),
					HrotToWorld( column, height, row + 1 ), new Vector2( sHigh, tLow ),
					HrotToWorld( column, height, row ), new Vector2( sHigh, tHigh ),
					HrotToWorld( column + 1, height, row ), new Vector2( sLow, tHigh ),
					doubleSided: true );
			}
		}
	}

	static void EmitHorizontalQuad(
		List<SimpleVertex> vertices,
		List<int> indices,
		HrotMapFace face,
		float x0,
		float x1,
		float z0,
		float z1,
		float height )
	{
		var (a0, a1, b0, b1) = TileSpans( face );
		AddSurfaceQuad(
			vertices, indices,
			HrotToWorld( x1, height, z1 ), new Vector2( b1, a0 ),
			HrotToWorld( x0, height, z1 ), new Vector2( b1, a1 ),
			HrotToWorld( x0, height, z0 ), new Vector2( b0, a1 ),
			HrotToWorld( x1, height, z0 ), new Vector2( b0, a0 ) );
	}

	/// <summary>
	/// Port of the ceiling quad emitter <c>0x00D87C28</c>.
	/// </summary>
	/// <remarks>
	/// Identical texture coordinates to the floor, walked around a different
	/// corner - which is what gives floors and ceilings their opposite winding
	/// and their differing texture orientation. Preserved as-is.
	/// </remarks>
	static void EmitCeiling(
		List<SimpleVertex> vertices,
		List<int> indices,
		HrotMapCell cell,
		int row,
		int column )
	{
		var height = cell.CeilingHeight;
		var (a0, a1, b0, b1) = TileSpans( cell.Ceiling );
		AddSurfaceQuad(
			vertices, indices,
			HrotToWorld( column, height, row ), new Vector2( b1, a0 ),
			HrotToWorld( column, height, row + 1 ), new Vector2( b1, a1 ),
			HrotToWorld( column + 1, height, row + 1 ), new Vector2( b0, a1 ),
			HrotToWorld( column + 1, height, row ), new Vector2( b0, a0 ) );
	}

	/// <summary>
	/// The direction codes <c>0xD884E0</c> switches on. Each names the plane a
	/// quad lies in, so a boundary is one <c>(cell, face)</c> pair: the west
	/// face of a cell and the east face of its column-1 neighbour are the same
	/// surface. See REVERSE_ENGINEERING.md 11.2.
	/// </summary>
	enum WallFace
	{
		West = 0,
		East = 1,
		South = 2,
		North = 3,
	}

	/// <summary>
	/// Port of the wall quad emitter <c>0x00D884E0</c>, all four branches.
	/// </summary>
	/// <remarks>
	/// <paramref name="v0"/> and <paramref name="v1"/> are per-quad texture
	/// offsets applied to the bottom and top edges, in atlas fractions. Whole
	/// tiles - base bands and auxiliary bands - pass zero for both; the risers
	/// pass computed fractions. This one argument pair is what the inferred
	/// renderer re-derived, differently and wrongly, in all four of its fascia
	/// emitters.
	///
	/// Quads are emitted double-sided. The original emits one vertex sequence
	/// per plane and relies on its own cull state, which has not been read out
	/// of the executable - but the ownership rule settles it regardless: since
	/// a boundary between two sectors is emitted exactly once, it has to be
	/// visible from both sides.
	/// </remarks>
	static void EmitWall(
		List<SimpleVertex> vertices,
		List<int> indices,
		WallFace face,
		int atlasX,
		int atlasY,
		float row,
		float column,
		float z0,
		float z1,
		float v0 = 0.0f,
		float v1 = 0.0f )
	{
		// HROT computes `1.0 - atlasY * step`, which bakes in OpenGL's
		// bottom-left texture origin. s&box samples from the top left, so the
		// V axis is mirrored here: `(atlasY - 1) * step`, with the top and
		// bottom edge expressions exchanged accordingly. Applying the
		// original's arithmetic literally selects atlas row `rows + 1 - y`
		// instead of `y` - a coherent but wrong tile. The horizontal axis
		// needs no such adjustment.
		var ty = (atlasY - 1) * WallAtlasStep;
		var tx = atlasX * FloorAtlasStep;
		var top = ty + TileInset + v1;
		var bottom = ty + WallAtlasStep - TileInset - v0;
		var left = tx + TileInset;
		var right = tx + FloorAtlasStep - TileInset;

		switch ( face )
		{
			case WallFace.West:
				AddSurfaceQuad( vertices, indices,
					HrotToWorld( column, z1, row + 1 ), new Vector2( right, top ),
					HrotToWorld( column, z1, row ), new Vector2( left, top ),
					HrotToWorld( column, z0, row ), new Vector2( left, bottom ),
					HrotToWorld( column, z0, row + 1 ), new Vector2( right, bottom ),
					doubleSided: true );
				return;

			case WallFace.East:
				AddSurfaceQuad( vertices, indices,
					HrotToWorld( column + 1, z1, row ), new Vector2( right, top ),
					HrotToWorld( column + 1, z1, row + 1 ), new Vector2( left, top ),
					HrotToWorld( column + 1, z0, row + 1 ), new Vector2( left, bottom ),
					HrotToWorld( column + 1, z0, row ), new Vector2( right, bottom ),
					doubleSided: true );
				return;

			case WallFace.South:
				// Quirk, reproduced deliberately: this branch alone omits the
				// tile inset on its third vertex - 0x00D8887B reads
				// `fld TY; fadd v0` where every other vertex in every other
				// branch reads `fld TY; fadd INSET; fadd v0`. It bleeds a
				// quarter pixel of the neighbouring atlas tile into one corner
				// of every south-facing wall in the game. Mirrored like the
				// rest of the V axis, the missing inset lands on the far edge.
				AddSurfaceQuad( vertices, indices,
					HrotToWorld( column + 1, z1, row + 1 ), new Vector2( right, top ),
					HrotToWorld( column, z1, row + 1 ), new Vector2( left, top ),
					HrotToWorld( column, z0, row + 1 ), new Vector2( left, ty + WallAtlasStep - v0 ),
					HrotToWorld( column + 1, z0, row + 1 ), new Vector2( right, bottom ),
					doubleSided: true );
				return;

			case WallFace.North:
				AddSurfaceQuad( vertices, indices,
					HrotToWorld( column, z1, row ), new Vector2( right, top ),
					HrotToWorld( column + 1, z1, row ), new Vector2( left, top ),
					HrotToWorld( column + 1, z0, row ), new Vector2( left, bottom ),
					HrotToWorld( column, z0, row ), new Vector2( right, bottom ),
					doubleSided: true );
				return;
		}
	}

	/// <summary>
	/// Port of the overlay quad emitter <c>0x00D87FC0</c>, gated on cell field
	/// <c>0x10</c>.
	/// </summary>
	/// <remarks>
	/// A cell-sized horizontal quad at the derived height <c>0x14</c>, wound
	/// like the flat floor so it faces up. Unlike every other surface its atlas
	/// coordinates are not per-cell: they come from two globals at
	/// <c>0x17D3FCC</c> and <c>0x17D3FD0</c>, each written exactly once, with a
	/// constant <c>1</c>. So every one of these quads uses tile (1, 1).
	///
	/// What it represents is not yet established - a global tile at a height
	/// mirrored above the ceiling, on 41-226 flagged cells across maps 2, 4, 5
	/// and 6 only. Porting it is the cheapest way to find out, so it is emitted
	/// and left to be identified visually.
	/// </remarks>
	static void EmitOverlay(
		List<SimpleVertex> vertices,
		List<int> indices,
		DerivedFlags derived,
		int row,
		int column )
	{
		var height = derived.OverlayHeight( row, column );
		if ( !float.IsFinite( height ) )
			return;

		EmitHorizontalQuad(
			vertices, indices, new HrotMapFace( true, 1, 1, null, 0 ),
			column, column + 1, row, row + 1, height );
	}

	/// <summary>
	/// Port of the stair dispatch on cell field <c>0x1D6</c>, cases 1-4.
	/// </summary>
	/// <remarks>
	/// HROT's stairs are not ramps. <c>0xD881AC</c> emits a **flat** quad -
	/// its height parameter is constant across all four vertices - covering
	/// half the cell, raised one 0.15625 tread above the stored floor height.
	/// Its last two arguments are the z and x extents of that half. Cases 1 and
	/// 2 split the cell on the column axis, 3 and 4 on the row axis, which
	/// matches the mirror transform at <c>0x00D85B4D</c> pairing 1&lt;-&gt;2 and
	/// 3&lt;-&gt;4.
	///
	/// The tread quad is textured with the whole floor tile despite covering
	/// half a cell, so the material is squashed 2:1. That is the original's
	/// behaviour and is preserved.
	///
	/// Each case then emits three skirt walls one tread high: the step riser on
	/// the boundary between the two halves, and two sides. The sides are
	/// positioned with a 0.995 offset rather than 1.0 - a z-fighting nudge -
	/// and are emitted a full cell wide even though the raised half is only
	/// half a cell, so they overhang into the neighbour by 0.5. In a flight the
	/// overhang is buried inside the next step. Reproduced as-is.
	/// </remarks>
	static void EmitStairs(
		List<SimpleVertex> vertices,
		List<int> indices,
		HrotMapCell cell,
		int row,
		int column )
	{
		const float tread = 0.15625f;
		const float nudge = 0.995f;

		var height = cell.FloorHeight + tread;
		var z0 = cell.FloorHeight;
		var z1 = height;

		switch ( cell.StairDirection )
		{
			case 1: // raised half is +column
				Tread( column + 0.5f, column + 1.0f, row, row + 1.0f );
				Skirt( WallFace.East, cell.West, row, column - 0.5f );
				Skirt( WallFace.North, cell.South, row + nudge, column + 0.5f );
				Skirt( WallFace.South, cell.North, row - nudge, column + 0.5f );
				return;

			case 2: // raised half is -column
				Tread( column, column + 0.5f, row, row + 1.0f );
				Skirt( WallFace.West, cell.East, row, column + 0.5f );
				Skirt( WallFace.North, cell.South, row + nudge, column - 0.5f );
				Skirt( WallFace.South, cell.North, row - nudge, column - 0.5f );
				return;

			case 3: // raised half is +row
				Tread( column, column + 1.0f, row + 0.5f, row + 1.0f );
				Skirt( WallFace.South, cell.North, row - 0.5f, column );
				Skirt( WallFace.West, cell.East, row + 0.5f, column + nudge );
				Skirt( WallFace.East, cell.West, row + 0.5f, column - nudge );
				return;

			case 4: // raised half is -row
				Tread( column, column + 1.0f, row, row + 0.5f );
				Skirt( WallFace.North, cell.South, row + 0.5f, column );
				Skirt( WallFace.West, cell.East, row - 0.5f, column + nudge );
				Skirt( WallFace.East, cell.West, row - 0.5f, column - nudge );
				return;
		}

		void Tread( float x0, float x1, float treadZ0, float treadZ1 )
			=> EmitHorizontalQuad(
				vertices, indices, cell.Floor, x0, x1, treadZ0, treadZ1, height );

		void Skirt( WallFace face, HrotMapFace source, float atRow, float atColumn )
			=> EmitWall(
				vertices, indices, face,
				source.AtlasX, source.AtlasY, atRow, atColumn, z0, z1,
				// The original passes v0 = 0 and v1 = 0.05625, taking a
				// tread-height slice off one end of the band tile.
				0.0f, 0.05625f );
	}

	/// <summary>
	/// The four floor risers - the strip between the wall baseline and a floor
	/// that stands above it.
	/// </summary>
	/// <remarks>
	/// This is the emitter whose ownership rule the whole port exists to
	/// settle. A riser is emitted for a side only when that side has **no**
	/// wall record, and it goes out as the opposing face of the neighbour cell,
	/// so the boundary plane has exactly one owner. See REVERSE_ENGINEERING.md
	/// 11.2.
	/// </remarks>
	static void EmitFloorRisers(
		List<SimpleVertex> vertices,
		List<int> indices,
		DerivedFlags derived,
		HrotMapCell cell,
		int row,
		int column )
	{
		if ( !derived.NeedsFloorRiser( row, column ) )
			return;

		var z0 = cell.WallBaseHeight;
		var top = z0 + WallBandHeight;
		var z1 = cell.FloorHeight;
		if ( z1 <= z0 )
			return;

		// The top edge samples partway down the band tile, by however much of
		// the band the raised floor covers.
		var v1 = (top - z1) / WallBandHeight * WallAtlasStep;

		// Order is the original's: west, east, north, south. Each goes out as
		// the opposing face at the neighbour's coordinates.
		Emit( cell.West, WallFace.East, row, column - 1 );
		Emit( cell.East, WallFace.West, row, column + 1 );
		Emit( cell.North, WallFace.South, row - 1, column );
		Emit( cell.South, WallFace.North, row + 1, column );

		void Emit( HrotMapFace source, WallFace face, int atRow, int atColumn )
		{
			// The original also emits when the cell is liquid, deliberately
			// double-covering the boundary. 0x19 is never map data, so that
			// clause is unreachable here - see REVERSE_ENGINEERING.md 11.5.
			if ( source.Active )
				return;

			EmitWall(
				vertices, indices, face,
				source.AtlasX, source.AtlasY, atRow, atColumn, z0, z1, 0.0f, v1 );
		}
	}

	/// <summary>
	/// The four ceiling risers - the strip between a ceiling and the wall band
	/// above it. This is what closes the gap over a doorway.
	/// </summary>
	static void EmitCeilingRisers(
		List<SimpleVertex> vertices,
		List<int> indices,
		DerivedFlags derived,
		HrotMapCell cell,
		int row,
		int column )
	{
		if ( !derived.NeedsCeilingRiser( row, column ) )
			return;

		var bands = derived.CeilingBands( row, column );
		if ( bands == 0 )
			return;

		var baseHeight = cell.WallBaseHeight;
		var z0 = cell.CeilingHeight;
		float z1, v0;

		if ( bands == 1 )
		{
			z1 = baseHeight + WallBandHeight;
			v0 = (z0 - baseHeight) / WallBandHeight * WallAtlasStep;
		}
		else
		{
			z1 = baseHeight + WallBandHeight * 2.0f;
			v0 = (z0 - baseHeight - WallBandHeight) / WallBandHeight * WallAtlasStep;
		}

		Emit( cell.West, WallFace.East, row, column - 1 );
		Emit( cell.East, WallFace.West, row, column + 1 );
		Emit( cell.North, WallFace.South, row - 1, column );
		Emit( cell.South, WallFace.North, row + 1, column );

		void Emit( HrotMapFace source, WallFace face, int atRow, int atColumn )
		{
			if ( source.Active )
				return;

			EmitWall(
				vertices, indices, face,
				source.AtlasX, source.AtlasY, atRow, atColumn, z0, z1, v0, 0.0f );
		}
	}

	/// <summary>
	/// The four base wall bands, each occupying band 0 above the cell's
	/// baseline. Emitted only where the corresponding face is active - that
	/// test is the boundary-ownership rule.
	/// </summary>
	static void EmitBaseWallBands(
		List<SimpleVertex> vertices,
		List<int> indices,
		HrotMapCell cell,
		int row,
		int column )
	{
		var z0 = cell.WallBaseHeight;
		var z1 = z0 + WallBandHeight;

		// Emission order is the original's: east, west, south, north.
		EmitFace( WallFace.East, cell.East );
		EmitFace( WallFace.West, cell.West );
		EmitFace( WallFace.South, cell.South );
		EmitFace( WallFace.North, cell.North );

		void EmitFace( WallFace face, HrotMapFace source )
		{
			if ( !source.Active )
				return;

			EmitWall(
				vertices, indices, face,
				source.AtlasX, source.AtlasY, row, column, z0, z1 );
		}
	}

	/// <summary>
	/// The four auxiliary band walks, which stack extra wall bands above the
	/// base one. Band <c>i</c> spans <c>[base + i*1.5625, base + (i+1)*1.5625]</c>
	/// starting at <c>i = 1</c>, so band 0 is the base wall's.
	/// </summary>
	/// <remarks>
	/// Unlike the risers these are ungated - no wall-active test and no
	/// neighbour offset, always the cell's own coordinates. The numbered
	/// skipped segment leaves its band open, which is how windows, ladder
	/// exits and barred openings are cut.
	/// </remarks>
	static void EmitAuxiliaryBands(
		List<SimpleVertex> vertices,
		List<int> indices,
		HrotMapCell cell,
		int row,
		int column )
	{
		var baseHeight = cell.WallBaseHeight;

		EmitBands( WallFace.East, cell.East );
		EmitBands( WallFace.West, cell.West );
		EmitBands( WallFace.South, cell.South );
		EmitBands( WallFace.North, cell.North );

		void EmitBands( WallFace face, HrotMapFace source )
		{
			for ( var i = 1; i <= source.AuxiliaryCount; i++ )
			{
				if ( i == source.SkippedSegment )
					continue;

				var material = source.Segment( i - 1 );
				var z0 = baseHeight + i * WallBandHeight;
				EmitWall(
					vertices, indices, face,
					material.AtlasX, material.AtlasY,
					row, column, z0, z0 + WallBandHeight );
			}
		}
	}

	/// <summary>
	/// The inset atlas spans of one 64x64 tile, in the original's arithmetic.
	/// </summary>
	/// <remarks>
	/// HROT computes <c>1.0 - atlasY/32</c> and <c>atlasX/32</c> and passes them
	/// to glTexCoord2f in that order, so its first texture axis is driven by the
	/// atlas row. Callers here pair them the other way round, for the same reason
	/// the world axes are transposed: the mount is internally consistent rather
	/// than literal. The <c>a</c> pair is the atlas-row span, the <c>b</c> pair
	/// the column.
	/// </remarks>
	static (float A0, float A1, float B0, float B1) TileSpans( HrotMapFace face )
	{
		// Mirrored on the atlas-row axis for the same reason as EmitWall: the
		// original's `1.0 - atlasY * step` encodes OpenGL's bottom-left origin.
		// A0 and A1 keep their meaning relative to the original's vertex order,
		// so the call sites are unchanged - only which edge each names flips.
		var a = (face.AtlasY - 1) * FloorAtlasStep;
		var b = face.AtlasX * FloorAtlasStep;
		return (
			a + FloorAtlasStep - TileInset,
			a + TileInset,
			b + TileInset,
			b + FloorAtlasStep - TileInset);
	}

	/// <summary>
	/// HROT is Y-up with the column on X and the row on Z; s&amp;box is Z-up.
	/// This applies the mount's transposed convention - see EmitWorldSurfaces.
	/// </summary>
	static Vector3 HrotToWorld( float column, float height, float row )
		=> new Vector3( row, -column, height ) * UnitScale;

	/// <summary>
	/// Emits one quad as two triangles, winding taken from the original's
	/// vertex order so that surfaces face the way HROT drew them.
	/// </summary>
	static void AddSurfaceQuad(
		List<SimpleVertex> vertices,
		List<int> indices,
		Vector3 p0, Vector2 uv0,
		Vector3 p1, Vector2 uv1,
		Vector3 p2, Vector2 uv2,
		Vector3 p3, Vector2 uv3,
		bool doubleSided = false )
	{
		var normal = Vector3.Cross( p1 - p0, p2 - p0 ).Normal;
		if ( normal.LengthSquared < 0.5f )
			return;

		var tangent = (p1 - p0).Normal;
		AddFacing( normal, tangent, p0, uv0, p1, uv1, p2, uv2, p3, uv3 );
		if ( doubleSided )
			AddFacing( -normal, -tangent, p1, uv1, p0, uv0, p3, uv3, p2, uv2 );

		void AddFacing(
			Vector3 n, Vector3 t,
			Vector3 q0, Vector2 t0, Vector3 q1, Vector2 t1,
			Vector3 q2, Vector2 t2, Vector3 q3, Vector2 t3 )
		{
			var first = vertices.Count;
			vertices.Add( new SimpleVertex( q0, n, t, t0 ) );
			vertices.Add( new SimpleVertex( q1, n, t, t1 ) );
			vertices.Add( new SimpleVertex( q2, n, t, t2 ) );
			vertices.Add( new SimpleVertex( q3, n, t, t3 ) );
			indices.Add( first );
			indices.Add( first + 1 );
			indices.Add( first + 2 );
			indices.Add( first );
			indices.Add( first + 2 );
			indices.Add( first + 3 );
		}
	}
}
