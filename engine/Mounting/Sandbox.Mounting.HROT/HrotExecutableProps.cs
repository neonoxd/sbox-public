using Sandbox;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

/// <summary>One placed static prop.</summary>
/// <remarks>
/// <see cref="Scale"/> is per-axis, not uniform. HROT scales a prop two ways: the
/// uniform helper <c>0x00DBDD64</c>, and by writing individual components of the
/// placed object's Scale coordinates (<c>0x00492D18</c>, see
/// <see cref="HrotExecutableStack"/>).
///
/// 40 placements across 15 maps carry a per-axis scale. The constructors contain
/// 229 calls to that setter, but 183 are in map 104 and follow Delphi and GLScene
/// constructors rather than a placement - those scale objects that are not static
/// props.
/// </remarks>
readonly record struct HrotPropPlacement(
	int ModelId, Vector3 Position, float Yaw, Vector3 Scale )
{
	/// <summary>
	/// At the model's authored size - the specialized fixture helpers place their
	/// lamps unscaled.
	/// </summary>
	public HrotPropPlacement( int modelId, Vector3 position, float yaw )
		: this( modelId, position, yaw, Vector3.One )
	{
	}
}

readonly record struct HrotGlassPanel(
	float X,
	float Z,
	float Bottom,
	float Height,
	int AtlasX,
	int AtlasY,
	int Orientation );

readonly record struct HrotDoorPlacement(
	Vector3 Position,
	Vector3 Travel,
	int MaterialId,
	int Orientation,
	int Behavior,
	int AtlasX,
	int AtlasY,
	int SideAtlasX,
	int SideAtlasY,
	bool IsLinked,
	// Record +0x54 = -1 and +0x74 = partner index. D77C20 alternates a global
	// toggle at 0x17D51CD across linked doors, so within each linked pair the
	// first created is the leader and the second the follower. Only meaningful
	// when IsLinked.
	bool IsFollower,
	int PartnerIndex,
	// Record +0x5C. D77C20 sets it to 1 when travel X is exactly 0 and 0
	// otherwise, and constructors may overwrite it - including with 2, a value
	// the derivation never produces. Live memory shows 0 on 15 doors, 1 on 10
	// and 2 on exactly the two map-1 leaves that render as slabs rather than
	// planes. See REVERSE_ENGINEERING.md section 12 (Doors).
	int Shape );

/// <summary>
/// A wall sign: a quad showing a rectangle of the level's decal sheet.
/// </summary>
/// <remarks>
/// The text is painted into the sheet, not drawn from glyphs - see the wall
/// sign section of REVERSE_ENGINEERING.md. <see cref="Facing"/> is an axis
/// enum, not an angle: 0 and 1 are the two Z-facing walls, 2 and 3 the two
/// X-facing.
/// </remarks>
readonly record struct HrotDecalPlacement(
	float CellX,
	float CellZ,
	float Y,
	float HalfWidth,
	float HalfHeight,
	int Facing,
	float U0,
	float V0,
	float U1,
	float V1 );

/// <summary>
/// The volume that shows a sign's English translation while the player is near.
/// </summary>
/// <remarks>
/// A box, not a radius: one half-extent is always thin because it hugs the
/// wall. Independent of <see cref="HrotDecalPlacement"/> - a sign painted into
/// the wall atlas or carried by a prop still has one of these, which is why
/// there are more boxes than decals.
/// </remarks>
readonly record struct HrotSignBox(
	Vector3 Position,
	Vector3 HalfExtents,
	int StringId );

/// <summary>Where the player starts a level, and which way they face.</summary>
/// <remarks>
/// <see cref="Position"/> is in HROT's frame and already cell-centred.
/// <see cref="Yaw"/> is HROT's own angle, one of four values a hundredth of a
/// degree off the axis - the game never authors an exact 0 or 90.
/// </remarks>
readonly record struct HrotPlayerSpawn( Vector3 Position, float Yaw );

/// <summary>Recovers constant static-prop calls from each level constructor.</summary>
static class HrotExecutableProps
{
	// Shared with HrotExecutableSounds so the PE walk exists once.
	internal readonly record struct Section( uint VirtualAddress, uint VirtualSize, uint RawAddress, uint RawSize );
	readonly record struct ConstructorRange( uint Start, uint End );

	static readonly Dictionary<int, ConstructorRange> Constructors = new()
	{
		[0] = new( 0x00542CAC, 0x0054595C ),
		[1] = new( 0x00596EF0, 0x00599FD0 ),
		[2] = new( 0x005EC248, 0x005EF5B4 ),
		[4] = new( 0x0064E0A8, 0x00651AF8 ),
		[5] = new( 0x006AA680, 0x006AD7A4 ),
		[6] = new( 0x00700404, 0x00704C30 ),
		[7] = new( 0x0074E914, 0x007519A4 ),
		[8] = new( 0x0079C6DC, 0x0079FA18 ),
		[9] = new( 0x007D9F0C, 0x007DCF50 ),
		[10] = new( 0x0082CFA0, 0x0083026C ),
		[11] = new( 0x00874CDC, 0x00877AE0 ),
		[12] = new( 0x008A55EC, 0x008A819C ),
		[13] = new( 0x008A55EC, 0x008A819C ),
		[14] = new( 0x008F3690, 0x008F6A04 ),
		[15] = new( 0x0092A7C8, 0x0092BC60 ),
		[16] = new( 0x008A55EC, 0x008A819C ),
		[17] = new( 0x009C058C, 0x009C20B8 ),
		[20] = new( 0x00A09C48, 0x00A0CD8C ),
		[21] = new( 0x00A1F05C, 0x00A1F8A4 ),
		[22] = new( 0x00A882F0, 0x00A8AE44 ),
		[23] = new( 0x00ACC354, 0x00ACFC6C ),
		[24] = new( 0x00AE20F4, 0x00AE2DC0 ),
		[25] = new( 0x00B9BA18, 0x00B9F338 ),
		[26] = new( 0x00BCDA08, 0x00BD0900 ),
		[27] = new( 0x00C03774, 0x00C061BC ),
		[28] = new( 0x00C3727C, 0x00C39DB0 ),
		[29] = new( 0x00C7D558, 0x00C80770 ),
		[100] = new( 0x00C83FD8, 0x00C841E8 ),
		[101] = new( 0x00C97A28, 0x00C982F8 ),
		[102] = new( 0x00CAA088, 0x00CAAC50 ),
		[103] = new( 0x00CBD2C4, 0x00CBE070 ),
		[104] = new( 0x00D40814, 0x00D5D388 )
	};

	/// <summary>The prop-constructor range for a map, for decoders elsewhere.</summary>
	/// <remarks>
	/// <see cref="HrotExecutableSounds"/> reads the music layers out of the same
	/// constructors. Handing it the range keeps one copy of the table: a
	/// transcribed second copy is how <c>dump_signs.py</c> came to report seven
	/// maps' worth of signs as the whole game.
	/// </remarks>
	internal static bool TryGetConstructor( int mapId, out uint start, out uint end )
	{
		if ( Constructors.TryGetValue( mapId, out var constructor ) )
		{
			(start, end) = (constructor.Start, constructor.End);
			return true;
		}

		(start, end) = (0, 0);
		return false;
	}

	const uint PlaceAtHeight = 0x00DBDF04;
	const uint PlaceOnFloor = 0x00DBDDE0;
	const uint PlaceAboveFloor = 0x00DBDE24;
	const uint PlaceAtCell = 0x00DBE468;
	const uint PlaceFloorLamp = 0x00D5CDF4;
	const uint PlaceLampPost = 0x00D5CE0C;
	const uint PlaceRaisedLamp = 0x00D5CF20;
	const uint PlaceCeilingFluorescent = 0x00D5CD48;
	const uint PlaceCeilingBakelite = 0x00D5CFE8;
	const uint PlaceCeilingChandelier = 0x00D5D08C;
	const uint PlaceCeilingChandelier2 = 0x00D5D120;
	const uint ScaleLastPlaced = 0x00DBDD64;
	const uint PlaceGlassPanel = 0x00D4D690;
	const uint PlaceDoor = 0x00D77C20;
	const uint PlaceDecal = 0x00D4D500;
	const uint PlaceSignBox = 0x00D98380;
	const uint PlacePlayerStart = 0x00DBE4AC;
	const uint SetPlayerAngle = 0x004A326C;

	// The player object's pointer. Position is fields +4, +8 and +0xC.
	const uint PlayerPointer = 0x00DE7C74;

	// 0xDBE558, the half cell DBE4AC adds to X and Z.
	const float PlayerStartCentre = 0.5f;

	// DBE4AC's facing table at 0xDBE4F0, indexed by EAX. HROT never authors an
	// exact axis angle - every one is a hundredth of a degree off.
	static readonly float[] SpawnYaws = [-89.99f, 90.01f, 0.01f, 179.99f];

	// The level's decal sheet name lives behind the pointer at DE80FC and is
	// assigned with Delphi's LStrAsg. Most maps never assign it and inherit a
	// default this decoder cannot see, so DefaultDecalSheet is empirical: the
	// sheet whose rectangles read as words on every non-assigning map checked.
	const uint AssignString = 0x004049A0;
	const uint DecalSheetPointer = 0x00DE80FC;
	const string DefaultDecalSheet = "vyzdoba";

	// D4D500's own constants: the sheet is 512 square, inset by half a texel,
	// and the world size comes from the pixel size through two 80-bit extended
	// floats at 0xD4D668 and 0xD4D674. The height one is negative in the
	// executable because the sheet's V axis opposes world up; the sign is
	// applied where the quad is built, so this is its magnitude.
	const float DecalSheetSize = 512.0f;
	const float DecalInset = 0.5f / 512.0f;
	const float DecalWidthScale = 0.003774f;
	const float DecalHeightScale = 0.004100f;

	// 0xD4D680 and 0xD4D684: half a cell to centre the free axis and lift the
	// sign, and the gap it stands off its wall by.
	const float DecalCentre = 0.5f;
	const float DecalStandoff = 0.015f;

	public static List<HrotPropPlacement> Read( string executablePath, int mapId, HrotMapGrid grid )
	{
		var result = new List<HrotPropPlacement>();
		if ( !Constructors.TryGetValue( mapId, out var constructor ) )
			return result;

		try
		{
			var data = File.ReadAllBytes( executablePath );
			if ( !TryReadPe( data, out var imageBase, out var sections ) ||
				!TryVirtualAddressToOffset( constructor.Start, imageBase, sections, data.Length, out var start ) ||
				!TryVirtualAddressToOffset( constructor.End, imageBase, sections, data.Length, out var end ) )
				return result;

			// Arguments this backward reader cannot see: a float parked in a stack
			// slot with `mov [esp],imm` and re-read by a later placement through
			// `push [esp+4]`, where the write can precede the previous call. The
			// forward simulation resolves those; it is consulted *only* where the
			// backward read fails, so every site that already decoded is untouched.
			var recovered = HrotExecutableStack.Recover(
				data, start, end, imageBase, sections );

			for ( var i = start; i + 9 <= end; i++ )
			{
				// Most props go through one of the generic placement wrappers
				// below. Ceiling lights use two specialized helpers instead:
				// D5CD48 creates zarivka and D5CFE8 creates bakelit(_dmg).
				if ( data[i] == 0xE8 )
				{
					var specialCallNextAddress =
						OffsetToVirtualAddress( i + 5, imageBase, sections );
					if ( specialCallNextAddress != 0 )
					{
						var specialTarget = unchecked((uint)(
							(long)specialCallNextAddress +
							BitConverter.ToInt32( data, i + 1 ) ));

						if ( specialTarget is PlaceCeilingFluorescent or PlaceCeilingBakelite &&
							TryReadSpecialPlacementPushes(
								data, start, i, out var firstPush, out var secondPush,
								out var damaged ) )
						{
							// Like HROT's generic placement wrappers, these
							// specialized helpers receive their authored
							// coordinates in call-site push order: X, then Z.
							// Their internal Delphi parameter order is an
							// implementation detail and must not be used to
							// swap the map axes here.
							var x = firstPush;
							var z = secondPush;
							var cell = grid.Cell(
								(int)MathF.Floor( z ),
								(int)MathF.Floor( x ) );

							if ( cell.HasCeiling )
							{
								var fluorescent =
									specialTarget == PlaceCeilingFluorescent;
								var modelId = fluorescent
									? 13
									: damaged ? 131 : 130;
								var ceilingOffset = fluorescent ? 0.055f : 0.1f;

								result.Add( new HrotPropPlacement(
									modelId,
									new Vector3(
										x, -z, cell.CeilingHeight - ceilingOffset ),
									0.0f ) );
							}

							continue;
						}

						if ( TryReadSpecialLightPlacement(
							data, start, i, specialTarget, imageBase, sections,
							grid, out var lightPlacement ) )
						{
							result.Add( lightPlacement );
							continue;
						}
					}
				}

				if ( data[i] != 0x66 || data[i + 1] != 0xB8 || data[i + 4] != 0xE8 )
					continue;

				var callNextAddress = OffsetToVirtualAddress( i + 9, imageBase, sections );
				if ( callNextAddress == 0 ) continue;
				var target = unchecked((uint)((long)callNextAddress + BitConverter.ToInt32( data, i + 5 )));
				var id = BitConverter.ToUInt16( data, i + 2 );
				var uniform = TryReadPostPlacementScale(
					data, i + 9, end, imageBase, sections, out var recoveredScale )
					? recoveredScale
					: 1.0f;
				var scale = new Vector3( uniform, uniform, uniform );

				// HROT also scales individual axes, by writing components of the
				// placed object's Scale coordinates. Those arrive in HROT's
				// component order; the mesh keeps its authored 3DS coordinates and
				// 3DS -> HROT is (x, y, z) -> (x, z, -y), so HROT (0, 1, 2) maps
				// to s&box (X, Z, Y).
				var placementCall = OffsetToVirtualAddress( i + 4, imageBase, sections );
				if ( placementCall != 0 &&
					recovered.Scales.TryGetValue( placementCall, out var axis ) )
					scale *= new Vector3( axis[0], axis[2], axis[1] );

				if ( target == PlaceAtCell &&
					TryReadCellPlacement( data, start, i, out var cellX, out var cellZ, out var cellYaw ) )
				{
					var x = cellX + 0.5f;
					var z = cellZ + 0.5f;
					var cell = grid.Cell( cellZ, cellX );
					result.Add( new HrotPropPlacement(
						id,
						new Vector3( x, -z, cell.FloorHeight ),
						cellYaw,
						scale ) );
					continue;
				}

				var argumentCount = target is PlaceAtHeight or PlaceAboveFloor ? 4 : target == PlaceOnFloor ? 3 : 0;
				if ( argumentCount == 0 )
					continue;

				if ( !TryReadPushesBackwards( data, start, i, argumentCount, imageBase, sections, out var args ) )
				{
					// The call is the E8 at i+4; the forward pass keys on it.
					var callAddress = OffsetToVirtualAddress( i + 4, imageBase, sections );
					if ( callAddress == 0 ||
						!recovered.Arguments.TryGetValue( callAddress, out args ) ||
						args is null || args.Length != argumentCount )
						continue;
				}

				if ( target == PlaceAtHeight )
				{
					// HROT coordinates are x, vertical, z, yaw. Its grid uses
					// z as the inner/column index and x as the row index.
					// HROT is right-handed Y-up, so conversion to s&box's
					// right-handed Z-up system is (x, -z, y).
					result.Add( new HrotPropPlacement(
						id,
						new Vector3( args[0], -args[2], args[1] ),
						args[3],
						scale ) );
				}
				else if ( target == PlaceAboveFloor )
				{
					// This wrapper calls PlaceOnFloor(x, z, yaw), then raises
					// the spawned object's vertical axis by the second pushed
					// argument. HROT uses it for suspended and stacked props.
					var x = args[0];
					var z = args[2];
					var cell = grid.Cell( (int)MathF.Floor( z ), (int)MathF.Floor( x ) );
					result.Add( new HrotPropPlacement(
						id,
						new Vector3( x, -z, cell.FloorHeight + args[1] ),
						args[3],
						scale ) );
				}
				else
				{
					var x = args[0];
					var z = args[1];
					var cell = grid.Cell( (int)MathF.Floor( z ), (int)MathF.Floor( x ) );
					result.Add( new HrotPropPlacement(
						id,
						new Vector3( x, -z, cell.FloorHeight ),
						args[2],
						scale ) );
				}
			}
		}
		catch
		{
			// Static world remains usable when a changed constructor is unknown.
		}

		return result;
	}

	public static List<HrotGlassPanel> ReadGlassPanels(
		string executablePath, int mapId )
	{
		var result = new List<HrotGlassPanel>();
		if ( !Constructors.TryGetValue( mapId, out var constructor ) )
			return result;

		try
		{
			var data = File.ReadAllBytes( executablePath );
			if ( !TryReadPe( data, out var imageBase, out var sections ) ||
				!TryVirtualAddressToOffset(
					constructor.Start, imageBase, sections, data.Length, out var start ) ||
				!TryVirtualAddressToOffset(
					constructor.End, imageBase, sections, data.Length, out var end ) )
				return result;

			for ( var i = start; i + 5 <= end; i++ )
			{
				if ( data[i] != 0xE8 )
					continue;

				var callNextAddress =
					OffsetToVirtualAddress( i + 5, imageBase, sections );
				if ( callNextAddress == 0 )
					continue;

				var target = unchecked((uint)(
					(long)callNextAddress + BitConverter.ToInt32( data, i + 1 ) ));
				if ( target != PlaceGlassPanel )
					continue;

				// D4D690 receives nine stack arguments followed by ECX/EDX
				// register arguments. Constant panels use an uninterrupted
				// sequence of PUSH imm32/imm8 instructions before the short
				// register-setup tail.
				//
				// Rows of bays - the metro entrance on map 1, for one - are
				// instead emitted from a counted loop whose first argument is
				// an affine function of the loop counter. Those are read by
				// TryReadCallInstances below.
				// D4D690 stores the fifth pushed argument at record +20 and
				// incoming ECX at +24. D8FABC supplies those values to a
				// Delphi renderer wrapper whose stack parameters are emitted
				// left-to-right: +24 selects the 1/8-wide U column, while +20
				// selects the 1/4-high V row.
				var atlasX = ReadRegisterIntegerBeforeCall(
					data, start, i, 0xC9, 0xB9 );
				var orientation = ReadRegisterIntegerBeforeCall(
					data, start, i, 0xD2, 0xBA );

				void AddPanel( uint[] values )
				{
					var x = BitConverter.Int32BitsToSingle(
						unchecked((int)values[0]) );
					var z = BitConverter.Int32BitsToSingle(
						unchecked((int)values[1]) );
					var bottom = BitConverter.Int32BitsToSingle(
						unchecked((int)values[2]) );
					var height = BitConverter.Int32BitsToSingle(
						unchecked((int)values[3]) );
					var atlasY = unchecked((int)values[4]);

					if ( !float.IsFinite( x ) || !float.IsFinite( z ) ||
						!float.IsFinite( bottom ) || !float.IsFinite( height ) ||
						x < -4096.0f || x > 4096.0f ||
						z < -4096.0f || z > 4096.0f ||
						bottom < -4096.0f || bottom > 4096.0f ||
						height <= 0.0f || height > 64.0f ||
						atlasX < 0 || atlasX > 7 ||
						atlasY < 0 || atlasY > 7 ||
						orientation < 0 || orientation > 3 )
						return;

					result.Add( new HrotGlassPanel(
						x, z, bottom, height, atlasX, atlasY, orientation ) );
				}

				if ( TryReadCallInstances(
					data, start, end, i, 9, imageBase, sections, out var instances ) )
				{
					foreach ( var instance in instances )
						AddPanel( instance );
				}
			}
		}
		catch
		{
			// The static map remains usable if a future executable changes.
		}

		return result;
	}

	/// <summary>
	/// Recovers the wall signs a level constructor places.
	/// </summary>
	/// <remarks>
	/// <code>
	/// push cellX, cellZ, y, x0, y0, x1, y1, scale
	/// mov dl, facing
	/// call 0x00D4D500
	/// </code>
	///
	/// The helper divides the rectangle by 512, flips V and insets by half a
	/// texel, and derives world size from the pixel size. Those conversions are
	/// done here so the record is ready to emit.
	///
	/// A sign with no decal is not missing: signs painted into the wall atlas or
	/// carried by a prop already render, and only need their subtitle box. That
	/// is why this returns fewer records than there are readable signs.
	/// </remarks>
	public static List<HrotDecalPlacement> ReadDecals(
		string executablePath, int mapId, out int undecodable )
	{
		var result = new List<HrotDecalPlacement>();
		undecodable = 0;
		if ( !Constructors.TryGetValue( mapId, out var constructor ) )
			return result;

		try
		{
			var data = File.ReadAllBytes( executablePath );
			if ( !TryReadPe( data, out var imageBase, out var sections ) ||
				!TryVirtualAddressToOffset(
					constructor.Start, imageBase, sections, data.Length, out var start ) ||
				!TryVirtualAddressToOffset(
					constructor.End, imageBase, sections, data.Length, out var end ) )
				return result;

			for ( var i = start; i + 5 <= end; i++ )
			{
				if ( data[i] != 0xE8 )
					continue;

				var callNextAddress =
					OffsetToVirtualAddress( i + 5, imageBase, sections );
				if ( callNextAddress == 0 )
					continue;

				var target = unchecked((uint)(
					(long)callNextAddress + BitConverter.ToInt32( data, i + 1 ) ));
				if ( target != PlaceDecal )
					continue;

				// Not TryReadPushesBackwards directly: register setup sits
				// between the last push and the CALL, so walking straight back
				// from the call byte lands mid-instruction and decodes nothing.
				// TryReadSpecialFloatPushes tries each candidate boundary.
				if ( !TryReadSpecialFloatPushes(
					data, start, i, 8, imageBase, sections, out var arguments ) )
				{
					// Counted rather than passed over. A sign that silently
					// fails to decode leaves a blank wall and no error, and the
					// number accepted says nothing about what exists - the
					// caller reports this so a decoder gap cannot masquerade as
					// a level with fewer signs.
					undecodable++;
					continue;
				}

				var facing = ReadDecalFacing( data, start, i );

				var x0 = arguments[3];
				var y0 = arguments[4];
				var x1 = arguments[5];
				var y1 = arguments[6];
				var scale = arguments[7];

				// D4D500 places the sign from the facing, at 0xD4D5B8: the
				// mounted axis goes to a cell edge with a standoff and the free
				// axis is centred. Verified against live memory - facing 1 with
				// authored (78, 60, -8.975) predicts (78.5, 60.985, -8.475),
				// which is exactly what the running game holds.
				var x = arguments[0];
				var z = arguments[1];

				switch ( facing & 0xFF )
				{
					case 0: x += DecalCentre; z += DecalStandoff; break;
					case 1: x += DecalCentre; z += 1.0f - DecalStandoff; break;
					case 2: z += DecalCentre; x += 1.0f - DecalStandoff; break;
					default: z += DecalCentre; x += DecalStandoff; break;
				}

				result.Add( new HrotDecalPlacement(
					CellX: x,
					CellZ: z,
					Y: arguments[2] + DecalCentre,
					// Half-extents, not sizes. The emitter at 0xD89B5C builds
					// every one of its four branches as centre +/- this value,
					// so halving it again is a sign at half size.
					HalfWidth: (x1 - x0) * DecalWidthScale * scale,
					HalfHeight: (y1 - y0) * DecalHeightScale * scale,
					Facing: facing & 0xFF,
					// V is NOT flipped, though D4D500 computes 1 - v/512. That
					// flip exists because HROT uploads a bottom-origin image
					// straight to GL; s&box samples from the top left, so
					// porting it samples a different band of the sheet and the
					// sign shows fragments of whatever lives there. The
					// rectangles are image-space coordinates and are used as
					// such - see the CLAUDE.md rule about porting values that
					// compensate for a host convention.
					U0: x0 / DecalSheetSize + DecalInset,
					V0: y0 / DecalSheetSize + DecalInset,
					U1: x1 / DecalSheetSize - DecalInset,
					V1: y1 / DecalSheetSize - DecalInset ) );
			}
		}
		catch
		{
			// A changed constructor must not take the rest of the scene with it.
		}

		return result;
	}

	/// <summary>
	/// The decal sheet a level assigns, or the default when it assigns none.
	/// </summary>
	/// <remarks>
	/// Only eleven maps assign one. The rest inherit a default that is set
	/// where this decoder cannot follow - the name lives behind a pointer, so
	/// its initial value comes from that object's construction rather than from
	/// any literal in a constructor.
	/// </remarks>
	public static string ReadDecalSheet( string executablePath, int mapId )
	{
		if ( !Constructors.TryGetValue( mapId, out var constructor ) )
			return DefaultDecalSheet;

		try
		{
			var data = File.ReadAllBytes( executablePath );
			if ( !TryReadPe( data, out var imageBase, out var sections ) ||
				!TryVirtualAddressToOffset(
					constructor.Start, imageBase, sections, data.Length, out var start ) ||
				!TryVirtualAddressToOffset(
					constructor.End, imageBase, sections, data.Length, out var end ) )
				return DefaultDecalSheet;

			// mov eax, [DE80FC] ; mov edx, <string> ; call LStrAsg
			for ( var i = start; i + 16 <= end; i++ )
			{
				if ( data[i] != 0xA1 ||
					BitConverter.ToUInt32( data, i + 1 ) != DecalSheetPointer ||
					data[i + 5] != 0xBA ||
					data[i + 10] != 0xE8 )
					continue;

				var callNextAddress =
					OffsetToVirtualAddress( i + 15, imageBase, sections );
				if ( callNextAddress == 0 )
					continue;

				var target = unchecked((uint)(
					(long)callNextAddress + BitConverter.ToInt32( data, i + 11 ) ));
				if ( target != AssignString )
					continue;

				var stringAddress = BitConverter.ToUInt32( data, i + 6 );
				if ( TryReadDelphiString( data, stringAddress, imageBase, sections, out var name ) )
					return name;
			}
		}
		catch
		{
		}

		return DefaultDecalSheet;
	}

	/// <summary>
	/// Recovers where the player starts the level.
	/// </summary>
	/// <remarks>
	/// The player object lives behind the pointer at <c>0xDE7C74</c>, and its
	/// position is fields <c>+4</c>, <c>+8</c> and <c>+0xC</c>. Constructors set
	/// it in one of two ways, and both have to be read - only four maps use the
	/// call, so decoding that alone would leave 28 levels with no spawn:
	///
	/// <list type="number">
	/// <item><b>Inline</b>, which most maps use: three
	/// <c>mov [eax+n], imm32</c> writes through the pointer, with the cell
	/// centring already applied.</item>
	/// <item><b>Through <c>0xDBE4AC</c></b>: three pushed floats, which that
	/// helper offsets by half a cell on X and Z before storing.</item>
	/// </list>
	///
	/// Either way the facing follows as a float pushed to the angle setter at
	/// <c>0x4A326C</c> - directly when inline, or picked from a four-entry table
	/// by <c>EAX</c> when called.
	/// </remarks>
	public static HrotPlayerSpawn? ReadPlayerSpawn( string executablePath, int mapId )
	{
		if ( !Constructors.TryGetValue( mapId, out var constructor ) )
			return null;

		try
		{
			var data = File.ReadAllBytes( executablePath );
			if ( !TryReadPe( data, out var imageBase, out var sections ) ||
				!TryVirtualAddressToOffset(
					constructor.Start, imageBase, sections, data.Length, out var start ) ||
				!TryVirtualAddressToOffset(
					constructor.End, imageBase, sections, data.Length, out var end ) )
				return null;

			return TryReadInlineSpawn( data, start, end, imageBase, sections )
				?? TryReadCalledSpawn( data, start, end, imageBase, sections );
		}
		catch
		{
			return null;
		}
	}

	/// <summary>
	/// <c>mov eax,[player]; mov [eax+4],x</c> repeated for <c>+8</c> and
	/// <c>+0xC</c>.
	/// </summary>
	static HrotPlayerSpawn? TryReadInlineSpawn(
		byte[] data,
		int start,
		int end,
		uint imageBase,
		IReadOnlyList<Section> sections )
	{
		// The three writes are consecutive but not a fixed stride, so this walks
		// a cursor rather than indexing by one.
		for ( var i = start; i + 15 <= end; i++ )
		{
			var cursor = i;
			if ( !TryReadPlayerFieldWrite( data, ref cursor, 0x04, out var x ) ||
				!TryReadPlayerFieldWrite( data, ref cursor, 0x08, out var y ) ||
				!TryReadPlayerFieldWrite( data, ref cursor, 0x0C, out var z ) )
				continue;

			return new HrotPlayerSpawn(
				new Vector3( x, y, z ),
				ReadSpawnYaw( data, cursor, end, imageBase, sections ) );
		}

		return null;
	}

	/// <summary>
	/// One <c>mov eax,[player]</c> followed by a write to the given field.
	/// </summary>
	/// <remarks>
	/// Two encodings, and both are needed. A non-zero value is a plain
	/// <c>mov dword ptr [eax+n], imm32</c>; a zero is emitted as
	/// <c>xor edx, edx</c> then <c>mov dword ptr [eax+n], edx</c>, which is two
	/// bytes shorter. Reading only the immediate form skips every map whose
	/// player starts at height zero.
	/// </remarks>
	static bool TryReadPlayerFieldWrite(
		byte[] data, ref int cursor, byte field, out float value )
	{
		value = 0.0f;

		if ( cursor + 5 > data.Length ||
			data[cursor] != 0xA1 ||
			BitConverter.ToUInt32( data, cursor + 1 ) != PlayerPointer )
			return false;

		var write = cursor + 5;

		// mov dword ptr [eax+field], imm32
		if ( write + 7 <= data.Length &&
			data[write] == 0xC7 && data[write + 1] == 0x40 && data[write + 2] == field )
		{
			value = BitConverter.Int32BitsToSingle( BitConverter.ToInt32( data, write + 3 ) );
			cursor = write + 7;
			return true;
		}

		// xor edx, edx ; mov dword ptr [eax+field], edx
		if ( write + 5 <= data.Length &&
			(data[write] == 0x31 || data[write] == 0x33) && data[write + 1] == 0xD2 &&
			data[write + 2] == 0x89 && data[write + 3] == 0x50 && data[write + 4] == field )
		{
			value = 0.0f;
			cursor = write + 5;
			return true;
		}

		return false;
	}

	/// <summary>Three pushed floats and a facing index, through 0xDBE4AC.</summary>
	static HrotPlayerSpawn? TryReadCalledSpawn(
		byte[] data,
		int start,
		int end,
		uint imageBase,
		IReadOnlyList<Section> sections )
	{
		for ( var i = start; i + 5 <= end; i++ )
		{
			if ( data[i] != 0xE8 )
				continue;

			var callNextAddress = OffsetToVirtualAddress( i + 5, imageBase, sections );
			if ( callNextAddress == 0 )
				continue;

			var target = unchecked((uint)(
				(long)callNextAddress + BitConverter.ToInt32( data, i + 1 ) ));
			if ( target != PlacePlayerStart )
				continue;

			if ( !TryReadSpecialFloatPushes(
				data, start, i, 3, imageBase, sections, out var arguments ) )
				continue;

			// DBE4AC adds half a cell to X and Z on the way in; the inline form
			// stores values that already include it, so it is applied here to
			// keep both paths producing the same thing.
			var facing = ReadSpawnFacingIndex( data, start, i );
			return new HrotPlayerSpawn(
				new Vector3(
					arguments[0] + PlayerStartCentre,
					arguments[1],
					arguments[2] + PlayerStartCentre ),
				facing >= 0 && facing < SpawnYaws.Length ? SpawnYaws[facing] : 0.0f );
		}

		return null;
	}

	/// <summary>
	/// The facing index passed in EAX to <c>0xDBE4AC</c>.
	/// </summary>
	/// <remarks>
	/// <b>EAX, not EDX</b> - so the decal facing reader, which looks for EDX,
	/// cannot be reused here. Index 0 is correct for map 1 but wrong for maps 0,
	/// 2 and 101, so a decode that defaults to 0 passes on map 1 alone.
	/// </remarks>
	static int ReadSpawnFacingIndex( byte[] data, int start, int callOffset )
	{
		for ( var probe = callOffset - 1;
			probe >= Math.Max( start, callOffset - 24 );
			probe-- )
		{
			// mov eax, imm32
			if ( data[probe] == 0xB8 && probe + 5 <= callOffset )
				return BitConverter.ToInt32( data, probe + 1 );

			// mov al, imm8
			if ( data[probe] == 0xB0 && probe + 2 <= callOffset )
				return data[probe + 1];

			// xor eax, eax
			if ( (data[probe] == 0x31 || data[probe] == 0x33) &&
				probe + 2 <= callOffset && data[probe + 1] == 0xC0 )
				return 0;
		}

		return 0;
	}

	/// <summary>The float pushed to the angle setter just after the position.</summary>
	/// <remarks>
	/// Finds the angle-setter call first and reads back to its push, rather than
	/// taking the first push in range: only a value matching one of
	/// <see cref="SpawnYaws"/> is accepted.
	/// </remarks>
	static float ReadSpawnYaw(
		byte[] data,
		int offset,
		int end,
		uint imageBase,
		IReadOnlyList<Section> sections )
	{
		var limit = Math.Min( end, offset + 192 );

		for ( var i = offset; i + 5 <= limit; i++ )
		{
			if ( data[i] != 0xE8 )
				continue;

			var callNextAddress = OffsetToVirtualAddress( i + 5, imageBase, sections );
			if ( callNextAddress == 0 )
				continue;

			var target = unchecked((uint)(
				(long)callNextAddress + BitConverter.ToInt32( data, i + 1 ) ));
			if ( target != SetPlayerAngle )
				continue;

			// Register setup sits between the push and the call, so walk back
			// through the candidate boundaries the same way the argument reader
			// does elsewhere in this file.
			for ( var candidate = i; candidate >= Math.Max( offset, i - 24 ); candidate-- )
			{
				if ( candidate - 5 < offset || data[candidate - 5] != 0x68 )
					continue;

				var value = BitConverter.Int32BitsToSingle(
					BitConverter.ToInt32( data, candidate - 4 ) );

				if ( Array.Exists( SpawnYaws, yaw => MathF.Abs( yaw - value ) < 0.001f ) )
					return value;
			}

			return 0.0f;
		}

		return 0.0f;
	}

	/// <summary>
	/// Recovers the subtitle boxes a level constructor places.
	/// </summary>
	/// <remarks>
	/// <code>
	/// push x, y, z, halfX, halfY, halfZ, arg7
	/// mov dx, stringId
	/// call 0x00D98380
	/// </code>
	///
	/// The seventh argument is integral and unidentified; it is not read here.
	/// </remarks>
	public static List<HrotSignBox> ReadSignBoxes(
		string executablePath, int mapId, out int undecodable )
	{
		var result = new List<HrotSignBox>();
		undecodable = 0;
		if ( !Constructors.TryGetValue( mapId, out var constructor ) )
			return result;

		try
		{
			var data = File.ReadAllBytes( executablePath );
			if ( !TryReadPe( data, out var imageBase, out var sections ) ||
				!TryVirtualAddressToOffset(
					constructor.Start, imageBase, sections, data.Length, out var start ) ||
				!TryVirtualAddressToOffset(
					constructor.End, imageBase, sections, data.Length, out var end ) )
				return result;

			for ( var i = start; i + 5 <= end; i++ )
			{
				if ( data[i] != 0xE8 )
					continue;

				var callNextAddress =
					OffsetToVirtualAddress( i + 5, imageBase, sections );
				if ( callNextAddress == 0 )
					continue;

				var target = unchecked((uint)(
					(long)callNextAddress + BitConverter.ToInt32( data, i + 1 ) ));
				if ( target != PlaceSignBox )
					continue;

				if ( !TryReadSpecialFloatPushes(
					data, start, i, 7, imageBase, sections, out var arguments ) )
				{
					undecodable++;
					continue;
				}

				result.Add( new HrotSignBox(
					new Vector3( arguments[0], arguments[1], arguments[2] ),
					new Vector3( arguments[3], arguments[4], arguments[5] ),
					ReadSignStringId( data, start, i ) ) );
			}
		}
		catch
		{
		}

		return result;
	}

	/// <summary>
	/// The string id passed in DX before a subtitle-box call.
	/// </summary>
	/// <remarks>
	/// Ids run past 255, so constructors load them as <c>mov dx, imm16</c> - a
	/// <c>66 BA</c> operand-size prefixed form. Reading only the 8-bit or 32-bit
	/// encodings truncates every id above 255 to whatever its low byte happens
	/// to be, which resolves to a real but unrelated string.
	/// </remarks>
	static int ReadSignStringId( byte[] data, int start, int callOffset )
	{
		for ( var probe = callOffset - 1;
			probe >= Math.Max( start, callOffset - 32 );
			probe-- )
		{
			// mov dx, imm16
			if ( data[probe] == 0x66 && probe + 4 <= callOffset &&
				data[probe + 1] == 0xBA )
				return BitConverter.ToUInt16( data, probe + 2 );

			// mov dl, imm8
			if ( data[probe] == 0xB2 && probe + 2 <= callOffset )
				return data[probe + 1];

			// mov edx, imm32
			if ( data[probe] == 0xBA && probe + 5 <= callOffset )
				return BitConverter.ToInt32( data, probe + 1 );

			if ( (data[probe] == 0x33 || data[probe] == 0x31) &&
				probe + 2 <= callOffset && data[probe + 1] == 0xD2 )
				return 0;
		}

		return 0;
	}

	/// <summary>
	/// The facing byte passed in DL before a decal call.
	/// </summary>
	/// <remarks>
	/// Constructors load it as <c>mov dl, imm8</c> (<c>B2</c>) - an 8-bit load
	/// that <see cref="TryReadRegisterValue"/> does not recognise, since it only
	/// reads the 32-bit <c>B8+r</c> form, so it is read directly here.
	///
	/// Zero is a real facing, so absence and zero are deliberately the same
	/// answer: <c>xor edx, edx</c> is how the constructors write it.
	/// </remarks>
	static int ReadDecalFacing( byte[] data, int start, int callOffset )
	{
		for ( var probe = callOffset - 1;
			probe >= Math.Max( start, callOffset - 32 );
			probe-- )
		{
			// mov dl, imm8
			if ( data[probe] == 0xB2 && probe + 2 <= callOffset )
				return data[probe + 1];

			// mov edx, imm32
			if ( data[probe] == 0xBA && probe + 5 <= callOffset )
				return BitConverter.ToInt32( data, probe + 1 );

			// xor edx, edx
			if ( (data[probe] == 0x33 || data[probe] == 0x31) &&
				probe + 2 <= callOffset && data[probe + 1] == 0xD2 )
				return 0;
		}

		return 0;
	}

	static bool TryReadDelphiString(
		byte[] data,
		uint address,
		uint imageBase,
		IReadOnlyList<Section> sections,
		out string value )
	{
		value = null;
		if ( !TryVirtualAddressToOffset( address, imageBase, sections, data.Length, out var offset ) )
			return false;

		if ( offset < 4 )
			return false;

		var length = BitConverter.ToInt32( data, offset - 4 );
		if ( length <= 0 || length > 128 || offset + length > data.Length )
			return false;

		value = System.Text.Encoding.ASCII.GetString( data, offset, length );
		return true;
	}

	public static List<HrotDoorPlacement> ReadDoors(
		string executablePath, int mapId )
	{
		var result = new List<HrotDoorPlacement>();
		// Mirrors the toggle at 0x17D51CD, which only linked doors touch.
		var pendingLink = false;
		if ( !Constructors.TryGetValue( mapId, out var constructor ) )
			return result;

		try
		{
			var data = File.ReadAllBytes( executablePath );
			if ( !TryReadPe( data, out var imageBase, out var sections ) ||
				!TryVirtualAddressToOffset(
					constructor.Start, imageBase, sections, data.Length, out var start ) ||
				!TryVirtualAddressToOffset(
					constructor.End, imageBase, sections, data.Length, out var end ) )
				return result;

			for ( var i = start; i + 5 <= end; i++ )
			{
				if ( data[i] != 0xE8 )
					continue;

				var callNextAddress =
					OffsetToVirtualAddress( i + 5, imageBase, sections );
				if ( callNextAddress == 0 )
					continue;

				var target = unchecked((uint)(
					(long)callNextAddress + BitConverter.ToInt32( data, i + 1 ) ));
				// Doors hit the same wall as glass panels: some call sites
				// compute one of their arguments through a register rather than
				// pushing a literal, so they go through TryReadCallInstances.
				if ( target != PlaceDoor || !TryReadCallInstances(
					data, start, end, i, 17, imageBase, sections, out var instances ) )
					continue;

				foreach ( var arguments in instances )
				{

				float FloatArgument( int index ) =>
					BitConverter.Int32BitsToSingle( unchecked((int)arguments[index]) );
				// D77C20 passes the position/travel components to the Vector3
				// constructor at 0x4613F4, which assigns X from the first-pushed
				// argument and Z from the last. In call-site (furthest-first)
				// order that makes X=arg0, vertical=arg1, Z=arg2 for position and
				// X=arg3, vertical=arg4, Z=arg5 for travel - the same first-push
				// = HROT x (row) convention the static props use. Reading X and Z
				// from the opposite ends transposes every door across the map
				// diagonal.
				var x = FloatArgument( 0 );
				var vertical = FloatArgument( 1 );
				var z = FloatArgument( 2 );
				var travelX = FloatArgument( 3 );
				var travelVertical = FloatArgument( 4 );
				var travelZ = FloatArgument( 5 );
				if ( !float.IsFinite( x ) || !float.IsFinite( vertical ) ||
					!float.IsFinite( z ) || !float.IsFinite( travelX ) ||
					!float.IsFinite( travelVertical ) || !float.IsFinite( travelZ ) )
					continue;

				// D77C20 uses Delphi register parameters for orientation (CL)
				// and behavior (DL), followed by seventeen stack arguments
				// (confirmed by its ret 0x44). The constructor sites push their
				// authored Z/Y/X position first, followed by Z/Y/X travel. The
				// backwards decoder keeps that call-site order. Convert HROT's
				// Y-up system to s&box Z-up in the same way as static props.
				//
				// The atlas coordinates are two consecutive (X, Y) pairs stored
				// at record +0x64/+0x68 (front) and +0x6c/+0x70 (back), sourced
				// from args 7,8 and 9,10 respectively. Verified across all 623
				// decodable doors: arg7/arg9 are the atlas column (0..31) and
				// arg8/arg10 the atlas row (1..16).
				var linked = arguments[11] != 0;
				var follower = linked && pendingLink;
				var index = result.Count;
				if ( linked )
					pendingLink = !pendingLink;

				result.Add( new HrotDoorPlacement(
					// D77C20 adds 0.5 (constant at 0xD77F78) to both horizontal
					// components before storing the closed position.
					new Vector3( x + 0.5f, -(z + 0.5f), vertical ),
					new Vector3( travelX, -travelZ, travelVertical ),
					unchecked((int)arguments[16]),
					ReadRegisterIntegerBeforeCall( data, start, i, 0xC9, 0xB9 ),
					ReadRegisterIntegerBeforeCall( data, start, i, 0xD2, 0xBA ),
					unchecked((int)arguments[7]),
					unchecked((int)arguments[8]),
					unchecked((int)arguments[9]),
					unchecked((int)arguments[10]),
					linked,
					follower,
					linked ? (follower ? index - 1 : index + 1) : -1,
					ReadDoorShape( data, i, end, travelX ) ) );
				}
			}
		}
		catch
		{
			// Door decoding is additive; static world reconstruction can
			// continue if a later executable changes its constructor layout.
		}

		return result;
	}

	/// <summary>
	/// Reads a row of glass panels emitted from a counted loop whose first
	/// argument is an affine function of the loop counter.
	/// </summary>
	/// <remarks>
	/// This matches one specific shape rather than evaluating arbitrary code,
	/// because that is the only shape the shipped constructors use:
	/// <code>
	///   xor  ebx, ebx
	/// top:
	///   mov  [esp+n], ebx
	///   fild [esp+n]
	///   fsubr/fadd/fsub/fmul dword [constant]
	///   fstp [esp]            ; argument 1
	///   push ... x8           ; arguments 2..9
	///   call 0xD4D690
	///   inc  ebx
	///   cmp  ebx, count
	///   jne  top
	/// </code>
	/// Anything that does not match is left alone, so widening this later is
	/// additive rather than a rewrite.
	/// </remarks>
	/// <summary>
	/// One argument to D4D690: a literal, or an affine function
	/// <c>offset + scale * i</c> of the enclosing loop counter.
	/// </summary>
	readonly record struct PanelArgument(
		uint Literal,
		float Offset,
		float Scale,
		int Register )
	{
		public bool Computed => Register >= 0;

		public uint Bits( int registerValue )
			=> Computed
				? unchecked((uint)BitConverter.SingleToInt32Bits(
					Offset + Scale * registerValue ))
				: Literal;
	}

	/// <summary>
	/// Reads an x87 80-bit extended constant out of the image.
	/// </summary>
	static bool TryReadExtendedConstant(
		byte[] data, int offset, out float value )
	{
		value = 0.0f;
		if ( offset < 0 || offset + 10 > data.Length )
			return false;

		var mantissa = BitConverter.ToUInt64( data, offset );
		var exponent = BitConverter.ToUInt16( data, offset + 8 );
		var sign = (exponent & 0x8000) != 0 ? -1.0 : 1.0;
		exponent &= 0x7FFF;
		if ( exponent is 0 or 0x7FFF )
			return false;

		value = (float)(sign * mantissa * Math.Pow( 2.0, exponent - 16383 - 63 ));
		return float.IsFinite( value );
	}

	/// <summary>
	/// Resolves the value a register holds at a call, from the nearest
	/// preceding <c>MOV r32, imm32</c> or <c>XOR r,r</c>.
	/// </summary>
	static bool TryReadRegisterValue(
		byte[] data, int start, int callOffset, int register, out int value )
	{
		value = 0;
		for ( var probe = callOffset - 1;
			probe >= Math.Max( start, callOffset - 160 );
			probe-- )
		{
			if ( data[probe] == 0xB8 + register && probe + 5 <= callOffset )
			{
				value = BitConverter.ToInt32( data, probe + 1 );
				return true;
			}

			if ( (data[probe] == 0x33 || data[probe] == 0x31) &&
				probe + 2 <= callOffset &&
				data[probe + 1] == 0xC0 + register * 9 )
			{
				value = 0;
				return true;
			}
		}

		return false;
	}

	/// <summary>
	/// Parses the nine arguments backwards from a D4D690 call, accepting at
	/// most one computed block among them.
	/// </summary>
	/// <summary>
	/// The axis a door leaf spans, from record +0x5C.
	/// </summary>
	/// <remarks>
	/// D77C20 derives it as <c>travelX == 0</c>, but a constructor may
	/// overwrite the field right after the call - <c>MOV byte [reg+reg*4+0x5C],
	/// imm8</c>. Vertically-travelling doors have no travel axis at all, so
	/// without that override they would all default the same way.
	/// </remarks>
	static int ReadDoorShape(
		byte[] data, int callOffset, int end, float travelX )
	{
		// MOV byte [reg + reg*4 + 0x5C], imm8 assembles with an 8-bit
		// displacement: C6 44 <sib> 5C <imm8> - not a disp32 form, so the
		// immediate is at +4.
		// The window must be tight. Constructors place door calls as little as
		// 0x39 bytes apart, so a generous forward scan runs past the end of
		// this door's own setup and picks up the *next* door's override. The
		// emitted sequence is a fixed 25 bytes, and any further CALL ends this
		// door's block, so bound on both.
		for ( var probe = callOffset + 5;
			probe + 5 <= Math.Min( end, callOffset + 40 );
			probe++ )
		{
			if ( data[probe] == 0xE8 )
				break;

			if ( data[probe] == 0xC6 && data[probe + 1] == 0x44 &&
				data[probe + 3] == 0x5C )
				return data[probe + 4];
		}

		return travelX == 0.0f ? 1 : 0;
	}

	/// <summary>
	/// Resolves every instance of a constructor call: one for a plain literal
	/// call site, N for a counted loop, one for a register-computed constant.
	/// Shared by glass panels and doors, which use identical call shapes.
	/// </summary>
	static bool TryReadCallInstances(
		byte[] data,
		int start,
		int end,
		int callOffset,
		int count,
		uint imageBase,
		List<Section> sections,
		out List<uint[]> instances )
	{
		instances = null;

		if ( TryReadImmediatePushBits( data, start, callOffset, count, out var literal ) )
		{
			instances = [literal];
			return true;
		}

		if ( !TryReadCallArguments(
			data, start, callOffset, count, imageBase, sections, out var parsed ) )
			return false;

		// Each computed argument carries its own source register. One of them
		// may be a loop counter; the rest are constants hoisted into registers
		// before the call, and resolve from their nearest preceding load.
		var counter = -1;
		var bound = 0;
		var initial = 0;
		if ( TryFindLoopTrailer(
				data, start, end, callOffset, out var loopCounter, out bound, out var top ) &&
			parsed.Any( a => a.Register == loopCounter ) &&
			TryReadRegisterValue( data, start, top, loopCounter, out initial ) &&
			bound > initial && bound - initial <= 64 )
		{
			counter = loopCounter;
		}

		var fixedValues = new Dictionary<int, int>();
		foreach ( var argument in parsed )
		{
			if ( !argument.Computed || argument.Register == counter ||
				fixedValues.ContainsKey( argument.Register ) )
				continue;

			if ( !TryReadRegisterValue(
				data, start, callOffset, argument.Register, out var value ) )
				return false;

			fixedValues[argument.Register] = value;
		}

		instances = [];
		var iterations = counter >= 0 ? bound - initial : 1;
		for ( var step = 0; step < iterations; step++ )
		{
			var resolved = new uint[count];
			for ( var argument = 0; argument < count; argument++ )
			{
				var current = parsed[argument];
				var value = !current.Computed ? 0
					: current.Register == counter ? initial + step
					: fixedValues[current.Register];
				resolved[argument] = current.Bits( value );
			}

			instances.Add( resolved );
		}

		return true;
	}

	/// <summary>
	/// Finds the <c>INC / CMP / JNE</c> trailer of the loop a call sits in.
	/// </summary>
	/// <remarks>
	/// The trailer is not necessarily adjacent to the call. Glass panel loops
	/// put it immediately after, but door loops run ~30 bytes of record setup
	/// first, so adjacency cannot be assumed. The jump must go backwards past
	/// the call for this to be the loop the call belongs to.
	/// </remarks>
	static bool TryFindLoopTrailer(
		byte[] data,
		int start,
		int end,
		int callOffset,
		out int counter,
		out int bound,
		out int top )
	{
		counter = 0;
		bound = 0;
		top = 0;

		for ( var probe = callOffset + 5;
			probe + 6 <= Math.Min( end, callOffset + 128 );
			probe++ )
		{
			if ( data[probe] < 0x40 || data[probe] > 0x47 ||
				data[probe + 1] != 0x83 ||
				data[probe + 2] < 0xF8 || data[probe + 2] > 0xFF ||
				data[probe + 4] != 0x75 ||
				(data[probe] & 0x07) != (data[probe + 2] & 0x07) )
				continue;

			var target = probe + 6 + unchecked((sbyte)data[probe + 5]);
			if ( target > callOffset || target < start )
				continue;

			counter = data[probe] & 0x07;
			bound = data[probe + 3];
			top = target;
			return true;
		}

		return false;
	}

	static bool TryReadCallArguments(
		byte[] data,
		int start,
		int callOffset,
		int count,
		uint imageBase,
		List<Section> sections,
		out PanelArgument[] arguments )
	{
		arguments = null;

		// Register setup sits between the last argument and the call.
		for ( var candidate = callOffset;
			candidate >= Math.Max( start, callOffset - 24 );
			candidate-- )
		{
			var cursor = candidate;
			var decoded = new PanelArgument[count];
			var computed = 0;
			var valid = true;

			for ( var argument = count - 1; argument >= 0; argument-- )
			{
				if ( cursor - 5 >= start && data[cursor - 5] == 0x68 )
				{
					decoded[argument] = new PanelArgument(
						BitConverter.ToUInt32( data, cursor - 4 ), 0, 0, -1 );
					cursor -= 5;
				}
				else if ( cursor - 2 >= start && data[cursor - 2] == 0x6A )
				{
					decoded[argument] = new PanelArgument(
						unchecked((uint)(sbyte)data[cursor - 1]), 0, 0, -1 );
					cursor -= 2;
				}
				else if ( TryReadComputedArgument(
					data, start, cursor, imageBase, sections,
					out var offset, out var scale, out var register,
					out var consumed ) )
				{
					decoded[argument] = new PanelArgument( 0, offset, scale, register );
					cursor = consumed;
					computed++;
				}
				else
				{
					valid = false;
					break;
				}
			}

			if ( !valid || computed == 0 )
				continue;

			arguments = decoded;
			return true;
		}

		return false;
	}

	/// <summary>
	/// Recognises a single loop-counter expression pushed as a float.
	/// </summary>
	/// <remarks>
	/// The block always ends <c>add esp,-4 / fstp [esp] / wait</c>. Before that
	/// it may carry one FPU operation against an image constant, then the FILD
	/// of the spilled counter, the spill itself, and optionally a LEA that
	/// offsets the counter first.
	/// </remarks>
	static bool TryReadComputedArgument(
		byte[] data,
		int start,
		int cursor,
		uint imageBase,
		List<Section> sections,
		out float offset,
		out float scale,
		out int register,
		out int consumed )
	{
		offset = 0.0f;
		scale = 1.0f;
		register = -1;
		consumed = cursor;

		// wait / fstp dword ptr [esp] / add esp, -4
		if ( cursor - 8 < start ||
			data[cursor - 1] != 0x9B ||
			data[cursor - 4] != 0xD9 || data[cursor - 3] != 0x1C ||
			data[cursor - 2] != 0x24 ||
			data[cursor - 7] != 0x83 || data[cursor - 6] != 0xC4 ||
			data[cursor - 5] != 0xFC )
			return false;

		var probe = cursor - 7;

		// Optional FLD TBYTE [k] / F<op>P against an 80-bit constant. Delphi
		// emits this instead of the 32-bit form when the literal was written
		// with more precision than a float carries.
		if ( probe - 8 >= start &&
			data[probe - 8] == 0xDB && data[probe - 7] == 0x2D &&
			data[probe - 2] == 0xDE )
		{
			var extendedAddress = BitConverter.ToUInt32( data, probe - 6 );
			if ( !TryVirtualAddressToOffset(
					extendedAddress, imageBase, sections, data.Length, out var extendedAt ) ||
				!TryReadExtendedConstant( data, extendedAt, out var extended ) )
				return false;

			switch ( data[probe - 1] )
			{
				case 0xC1: offset += extended; break;                          // faddp
				case 0xE9: offset = extended - offset; scale = -scale; break;  // fsubp
				case 0xE1: offset -= extended; break;                          // fsubrp
				case 0xC9: offset *= extended; scale *= extended; break;       // fmulp
				default: return false;
			}

			probe -= 8;
		}

		// Optional D8 /r disp32 against a float in the image.
		if ( probe - 6 >= start && data[probe - 6] == 0xD8 )
		{
			var modrm = data[probe - 5];
			if ( modrm is 0x05 or 0x25 or 0x2D or 0x0D )
			{
				var address = BitConverter.ToUInt32( data, probe - 4 );
				if ( !TryVirtualAddressToOffset(
					address, imageBase, sections, data.Length, out var at ) )
					return false;

				var constant = BitConverter.ToSingle( data, at );
				if ( !float.IsFinite( constant ) )
					return false;

				switch ( modrm )
				{
					case 0x05: offset += constant; break;                 // fadd
					case 0x25: offset -= constant; break;                 // fsub
					case 0x2D: offset = constant - offset; scale = -scale; break; // fsubr
					case 0x0D: offset *= constant; scale *= constant; break;      // fmul
				}

				probe -= 6;
			}
		}

		// FILD of the spilled counter: [esp] or [esp+disp8].
		if ( probe - 3 >= start &&
			data[probe - 3] == 0xDB && data[probe - 2] == 0x04 &&
			data[probe - 1] == 0x24 )
		{
			probe -= 3;
		}
		else if ( probe - 4 >= start &&
			data[probe - 4] == 0xDB && data[probe - 3] == 0x44 &&
			data[probe - 2] == 0x24 )
		{
			probe -= 4;
		}
		else
		{
			return false;
		}

		// The spill: MOV [esp] or [esp+disp8], r32.
		int spilled;
		if ( probe - 3 >= start && data[probe - 3] == 0x89 &&
			(data[probe - 2] & 0xC7) == 0x04 && data[probe - 1] == 0x24 )
		{
			spilled = (data[probe - 2] >> 3) & 0x07;
			probe -= 3;
		}
		else if ( probe - 4 >= start && data[probe - 4] == 0x89 &&
			(data[probe - 3] & 0xC7) == 0x44 && data[probe - 2] == 0x24 )
		{
			spilled = (data[probe - 3] >> 3) & 0x07;
			probe -= 4;
		}
		else
		{
			return false;
		}

		register = spilled;

		// A LEA may have offset the source register before the spill.
		if ( probe - 3 >= start && data[probe - 3] == 0x8D &&
			((data[probe - 2] >> 3) & 0x07) == spilled &&
			(data[probe - 2] & 0xC0) == 0x40 )
		{
			offset += unchecked((sbyte)data[probe - 1]) * scale;
			register = data[probe - 2] & 0x07;
			probe -= 3;
		}

		consumed = probe;
		return true;
	}

	static bool TryReadImmediatePushBits(
		byte[] data,
		int start,
		int callOffset,
		int count,
		out uint[] values )
	{
		values = new uint[count];

		// Register setup between the final PUSH and CALL is at most a handful
		// of instructions at the known constructor sites.
		for ( var candidate = callOffset;
			candidate >= Math.Max( start, callOffset - 24 );
			candidate-- )
		{
			var cursor = candidate;
			var decoded = new uint[count];
			var valid = true;

			for ( var argument = count - 1; argument >= 0; argument-- )
			{
				if ( cursor - 5 >= start && data[cursor - 5] == 0x68 )
				{
					decoded[argument] =
						BitConverter.ToUInt32( data, cursor - 4 );
					cursor -= 5;
				}
				else if ( cursor - 2 >= start && data[cursor - 2] == 0x6A )
				{
					decoded[argument] = unchecked((uint)
						(sbyte)data[cursor - 1]);
					cursor -= 2;
				}
				else
				{
					valid = false;
					break;
				}
			}

			if ( !valid )
				continue;

			values = decoded;
			return true;
		}

		return false;
	}

	static bool TryReadSpecialLightPlacement(
		byte[] data,
		int start,
		int callOffset,
		uint target,
		uint imageBase,
		IReadOnlyList<Section> sections,
		HrotMapGrid grid,
		out HrotPropPlacement placement )
	{
		placement = default;

		var argumentCount = target switch
		{
			PlaceFloorLamp => 2,
			PlaceLampPost => 2,
			PlaceRaisedLamp => 3,
			PlaceCeilingChandelier => 3,
			PlaceCeilingChandelier2 => 2,
			_ => 0
		};
		if ( argumentCount == 0 ||
			!TryReadSpecialFloatPushes(
				data, start, callOffset, argumentCount,
				imageBase, sections, out var args ) )
			return false;

		var x = args[0];
		var z = args[1];
		var cell = grid.Cell(
			(int)MathF.Floor( z ),
			(int)MathF.Floor( x ) );
		var yaw = ReadRegisterIntegerBeforeCall(
			data, start, callOffset, 0xD2, 0xBA );

		switch ( target )
		{
			case PlaceFloorLamp:
				placement = new HrotPropPlacement(
					1, new Vector3( x, -z, cell.FloorHeight ), 0.0f );
				return true;

			case PlaceLampPost:
			{
				// CL selects the single-arm form. The original constructor
				// also attaches one or two separate bulb meshes; the fixture
				// body and its generated point light carry the useful scene
				// representation until composite child transforms are decoded.
				var singleArm = ReadRegisterIntegerBeforeCall(
					data, start, callOffset, 0xC1, 0xB9 ) != 0;
				placement = new HrotPropPlacement(
					singleArm ? 337 : 234,
					new Vector3( x, -z, cell.FloorHeight ),
					yaw );
				return true;
			}

			case PlaceRaisedLamp:
				placement = new HrotPropPlacement(
					8,
					new Vector3( x, -z, cell.FloorHeight + args[2] ),
					yaw );
				return true;

			case PlaceCeilingChandelier:
				if ( !cell.HasCeiling )
					return false;
				placement = new HrotPropPlacement(
					12,
					new Vector3( x, -z, cell.CeilingHeight - 0.21f - args[2] ),
					0.0f );
				return true;

			case PlaceCeilingChandelier2:
				if ( !cell.HasCeiling )
					return false;
				placement = new HrotPropPlacement(
					331,
					new Vector3( x, -z, cell.CeilingHeight - 0.7f ),
					0.0f );
				return true;
		}

		return false;
	}

	static bool TryReadSpecialFloatPushes(
		byte[] data,
		int start,
		int callOffset,
		int count,
		uint imageBase,
		IReadOnlyList<Section> sections,
		out float[] values )
	{
		values = new float[count];
		// Register setup commonly sits between the final pushed argument and
		// CALL. Start at each candidate boundary and let the normal backwards
		// decoder handle both literal and x87-computed float pushes.
		for ( var candidate = callOffset; candidate >= Math.Max( start, callOffset - 24 ); candidate-- )
		{
			var readCursor = candidate;
			if ( !TryReadPushesBackwards(
				data, start, readCursor, count, imageBase, sections, out var decoded ) )
				continue;

			if ( decoded.Any( value =>
				!float.IsFinite( value ) || value < -4096.0f || value > 4096.0f ) )
				continue;

			values = decoded;
			return true;
		}

		return false;
	}

	static int ReadRegisterIntegerBeforeCall(
		byte[] data,
		int start,
		int callOffset,
		byte byteRegisterOpcode,
		byte dwordRegisterOpcode )
	{
		var value = 0;
		var minimum = Math.Max( start, callOffset - 24 );
		for ( var i = minimum; i < callOffset; i++ )
		{
			// xor reg,reg emitted for zero. D2 is EDX's ModRM and C9 is ECX's.
			var xorModRm = byteRegisterOpcode == 0xD2 ? (byte)0xD2 : (byte)0xC9;
			if ( i + 1 < callOffset &&
				(data[i] is 0x31 or 0x33) && data[i + 1] == xorModRm )
			{
				value = 0;
				i++;
			}
			else if ( i + 1 < callOffset &&
				data[i] == (byte)(byteRegisterOpcode == 0xD2 ? 0xB2 : 0xB1) )
			{
				value = data[i + 1];
				i++;
			}
			else if ( i + 4 < callOffset && data[i] == dwordRegisterOpcode )
			{
				value = BitConverter.ToInt32( data, i + 1 );
				i += 4;
			}
		}
		return value;
	}

	static bool TryReadPostPlacementScale(
		byte[] data,
		int offset,
		int end,
		uint imageBase,
		IReadOnlyList<Section> sections,
		out float scale )
	{
		scale = 1.0f;

		// HROT applies per-instance uniform scale to the object returned by a
		// placement helper:
		//   call Place...
		//   push <float scale>
		//   call ScaleLastPlaced
		if ( offset < 0 || offset + 10 > end ||
			data[offset] != 0x68 || data[offset + 5] != 0xE8 )
			return false;

		var callNextAddress =
			OffsetToVirtualAddress( offset + 10, imageBase, sections );
		if ( callNextAddress == 0 )
			return false;

		var target = unchecked((uint)(
			(long)callNextAddress + BitConverter.ToInt32( data, offset + 6 ) ));
		if ( target != ScaleLastPlaced )
			return false;

		scale = BitConverter.Int32BitsToSingle(
			BitConverter.ToInt32( data, offset + 1 ) );
		return float.IsFinite( scale ) && scale > 0.0f;
	}

	static bool TryReadSpecialPlacementPushes(
		byte[] data,
		int start,
		int callOffset,
		out float firstPush,
		out float secondPush,
		out bool damaged )
	{
		firstPush = secondPush = 0.0f;
		damaged = false;

		// These call sites contain a couple of register setup instructions
		// between their arguments and CALL, so the generic adjacent-push
		// decoder cannot be used. Locate the two literal float pushes in the
		// short call-site window instead.
		var found = 0;
		var nearestPushEnd = callOffset;
		var minimum = Math.Max( start, callOffset - 32 );
		for ( var i = callOffset - 5; i >= minimum; i-- )
		{
			if ( data[i] != 0x68 || i + 5 > callOffset )
				continue;

			var value = BitConverter.Int32BitsToSingle(
				BitConverter.ToInt32( data, i + 1 ) );
			if ( !float.IsFinite( value ) ||
				value < -4096.0f || value > 4096.0f )
				continue;

			if ( found == 0 )
			{
				// Walking backwards encounters the second push first.
				secondPush = value;
				nearestPushEnd = i + 5;
				found = 1;
			}
			else
			{
				firstPush = value;
				found = 2;
				break;
			}
		}

		if ( found != 2 )
			return false;

		// D5CFE8 uses EDX as the damaged-state flag. Decode the forms emitted
		// by Delphi at these call sites; false is also the safe default.
		for ( var i = nearestPushEnd; i < callOffset; i++ )
		{
			if ( i + 1 < callOffset &&
				((data[i] == 0x31 && data[i + 1] == 0xD2) ||
				 (data[i] == 0x33 && data[i + 1] == 0xD2)) )
			{
				damaged = false;
				i++;
			}
			else if ( i + 1 < callOffset && data[i] == 0xB2 )
			{
				damaged = data[i + 1] != 0;
				i++;
			}
			else if ( i + 4 < callOffset && data[i] == 0xBA )
			{
				damaged = BitConverter.ToInt32( data, i + 1 ) != 0;
				i += 4;
			}
		}

		return true;
	}

	static bool TryReadCellPlacement(
		byte[] data, int start, int end, out int x, out int z, out float yaw )
	{
		x = z = 0;
		yaw = 0.0f;
		if ( end - 10 < start || data[end - 10] != 0xB9 || data[end - 5] != 0xBA )
			return false;

		z = BitConverter.ToInt32( data, end - 9 );
		x = BitConverter.ToInt32( data, end - 4 );
		var cursor = end - 10;
		if ( cursor - 2 >= start && data[cursor - 2] == 0x6A )
		{
			yaw = (sbyte)data[cursor - 1];
			return true;
		}

		if ( cursor - 5 >= start && data[cursor - 5] == 0x68 )
		{
			yaw = BitConverter.ToInt32( data, cursor - 4 );
			return true;
		}

		return false;
	}

	static bool TryReadPushesBackwards(
		byte[] data,
		int start,
		int end,
		int count,
		uint imageBase,
		IReadOnlyList<Section> sections,
		out float[] values )
	{
		values = new float[count];
		var cursor = end;

		for ( var argument = count - 1; argument >= 0; argument-- )
		{
			if ( TryReadImmediatePushBackwards( data, start, ref cursor, out var value ) ||
				TryReadComputedFloatPushBackwards(
					data, start, ref cursor, imageBase, sections, out value ) )
			{
				values[argument] = value;
			}
			else
			{
				return false;
			}
		}

		return true;
	}

	static bool TryReadImmediatePushBackwards(
		byte[] data, int start, ref int cursor, out float value )
	{
		if ( cursor - 5 >= start && data[cursor - 5] == 0x68 )
		{
			value = BitConverter.Int32BitsToSingle( BitConverter.ToInt32( data, cursor - 4 ) );
			cursor -= 5;
			return true;
		}

		if ( cursor - 2 >= start && data[cursor - 2] == 0x6A )
		{
			var bits = unchecked((uint)(sbyte)data[cursor - 1]);
			value = BitConverter.Int32BitsToSingle( unchecked((int)bits) );
			cursor -= 2;
			return true;
		}

		value = 0;
		return false;
	}

	static bool TryReadComputedFloatPushBackwards(
		byte[] data,
		int start,
		ref int cursor,
		uint imageBase,
		IReadOnlyList<Section> sections,
		out float value )
	{
		// Delphi commonly materializes constant constructor arguments through
		// the x87 stack:
		//   mov [esp(+n)], esi/edi
		//   fild [esp(+n)]
		//   fld tbyte ptr [constant]
		//   faddp
		//   add esp,-4 / fstp [esp] / wait
		// Recovering this pattern covers the decorative prop groups that are
		// absent when only literal PUSH instructions are accepted.
		var end = cursor;
		if ( end - 1 >= start && data[end - 1] == 0x9B ) end--;
		if ( end - 3 < start || data[end - 3] != 0xD9 || data[end - 2] != 0x1C || data[end - 1] != 0x24 )
		{
			value = 0;
			return false;
		}
		end -= 3;
		if ( end - 3 < start || data[end - 3] != 0x83 || data[end - 2] != 0xC4 || data[end - 1] != 0xFC )
		{
			value = 0;
			return false;
		}
		end -= 3;
		if ( end - 2 < start || data[end - 2] != 0xDE || data[end - 1] != 0xC1 )
		{
			value = 0;
			return false;
		}
		end -= 2;
		if ( end - 6 < start || data[end - 6] != 0xDB || data[end - 5] != 0x2D )
		{
			value = 0;
			return false;
		}

		var constantAddress = BitConverter.ToUInt32( data, end - 4 );
		if ( !TryVirtualAddressToOffset(
			constantAddress, imageBase, sections, data.Length, out var constantOffset ) ||
			constantOffset + 10 > data.Length )
		{
			value = 0;
			return false;
		}
		end -= 6;

		byte registerOpcode;
		int expressionStart;
		if ( end - 3 >= start &&
			data[end - 3] == 0xDB && data[end - 2] == 0x04 && data[end - 1] == 0x24 )
		{
			registerOpcode = 0xBE; // ESI
			expressionStart = end - 3;
			if ( expressionStart - 3 < start ||
				data[expressionStart - 3] != 0x89 ||
				data[expressionStart - 2] != 0x34 ||
				data[expressionStart - 1] != 0x24 )
			{
				value = 0;
				return false;
			}
			expressionStart -= 3;
		}
		else if ( end - 4 >= start &&
			data[end - 4] == 0xDB && data[end - 3] == 0x44 && data[end - 2] == 0x24 )
		{
			var stackOffset = data[end - 1];
			registerOpcode = 0xBF; // EDI
			expressionStart = end - 4;
			if ( expressionStart - 4 < start ||
				data[expressionStart - 4] != 0x89 ||
				data[expressionStart - 3] != 0x7C ||
				data[expressionStart - 2] != 0x24 ||
				data[expressionStart - 1] != stackOffset )
			{
				value = 0;
				return false;
			}
			expressionStart -= 4;
		}
		else
		{
			value = 0;
			return false;
		}

		if ( !TryFindRegisterConstant( data, start, expressionStart, registerOpcode, out var integer ) )
		{
			value = 0;
			return false;
		}

		value = integer + ReadExtended80( data, constantOffset );
		cursor = expressionStart;
		return float.IsFinite( value );
	}

	static bool TryFindRegisterConstant(
		byte[] data, int start, int end, byte opcode, out int value )
	{
		var minimum = Math.Max( start, end - 2048 );
		for ( var i = end - 5; i >= minimum; i-- )
		{
			if ( data[i] != opcode ) continue;
			value = BitConverter.ToInt32( data, i + 1 );
			return true;
		}

		value = 0;
		return false;
	}

	static float ReadExtended80( byte[] data, int offset )
	{
		var significand = BitConverter.ToUInt64( data, offset );
		var signAndExponent = BitConverter.ToUInt16( data, offset + 8 );
		var exponent = signAndExponent & 0x7FFF;
		if ( exponent == 0 && significand == 0 ) return 0;

		var sign = (signAndExponent & 0x8000) == 0 ? 1.0 : -1.0;
		var fraction = significand / 9223372036854775808.0;
		return (float)(sign * fraction * Math.Pow( 2.0, exponent - 16383 ));
	}

	internal static bool TryReadPe( byte[] data, out uint imageBase, out List<Section> sections )
	{
		imageBase = 0;
		sections = [];
		if ( data.Length < 0x100 || BitConverter.ToUInt16( data, 0 ) != 0x5A4D ) return false;
		var pe = checked((int)BitConverter.ToUInt32( data, 0x3C ));
		if ( pe < 0 || pe + 24 > data.Length || BitConverter.ToUInt32( data, pe ) != 0x00004550 ) return false;
		var count = BitConverter.ToUInt16( data, pe + 6 );
		var optionalSize = BitConverter.ToUInt16( data, pe + 20 );
		var optional = pe + 24;
		if ( optional + optionalSize > data.Length || BitConverter.ToUInt16( data, optional ) != 0x10B ) return false;
		imageBase = BitConverter.ToUInt32( data, optional + 28 );
		var table = optional + optionalSize;
		for ( var i = 0; i < count; i++ )
		{
			var offset = table + i * 40;
			if ( offset + 40 > data.Length ) return false;
			sections.Add( new Section(
				BitConverter.ToUInt32( data, offset + 12 ), BitConverter.ToUInt32( data, offset + 8 ),
				BitConverter.ToUInt32( data, offset + 20 ), BitConverter.ToUInt32( data, offset + 16 ) ) );
		}
		return true;
	}

	internal static bool TryVirtualAddressToOffset(
		uint address, uint imageBase, IReadOnlyList<Section> sections, int length, out int offset )
	{
		var rva = address - imageBase;
		foreach ( var section in sections )
		{
			var size = Math.Max( section.VirtualSize, section.RawSize );
			if ( rva < section.VirtualAddress || rva >= section.VirtualAddress + size ) continue;
			var value = section.RawAddress + rva - section.VirtualAddress;
			if ( value < length )
			{
				offset = (int)value;
				return true;
			}
		}
		offset = 0;
		return false;
	}

	internal static uint OffsetToVirtualAddress( int offset, uint imageBase, IReadOnlyList<Section> sections )
	{
		foreach ( var section in sections )
			if ( offset >= section.RawAddress && offset < section.RawAddress + section.RawSize )
				return imageBase + section.VirtualAddress + (uint)offset - section.RawAddress;
		return 0;
	}
}
