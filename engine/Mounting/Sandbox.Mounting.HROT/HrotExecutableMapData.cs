using System;
using System.Collections.Generic;
using System.IO;

/// <summary>
/// Reconstructs HROT's compiled 101x101 map grid from the constant writes in
/// each level's world constructor. HROT does not ship separate map files.
/// </summary>
static class HrotExecutableMapData
{
	public const int GridSize = 101;
	public const int CellSize = 0x1E0;

	readonly record struct Section( uint VirtualAddress, uint VirtualSize, uint RawAddress, uint RawSize );
	readonly record struct ConstructorRange( uint Start, uint End );

	// Retail HROT level dispatch. End is the start of the separate
	// prop/gameplay constructor, which deliberately is not decoded here.
	//
	// Verified against the dispatch itself at 0x00D5DF39: it reads the map id
	// from the signed byte at 0x017B9460, bounds it to 0..0x68, indexes the
	// byte table at 0x00D5DF56, and jumps through the table at 0x00D5DFBF.
	// Every entry below matches the arm that table selects.
	//
	// Two things that fall out of it and look like mistakes but are not:
	//  - Maps 12, 13 and 16 share one arm, so they really do replay identical
	//    world geometry. They are still distinct levels with distinct names
	//    (Rathaus, Orloj, Epilogue) - see HrotMapNames.
	//  - The dispatch also has a map 99, whose arm calls 0x00D9A40C instead of
	//    a level constructor. It is not a shipped level and is not listed here.
	static readonly Dictionary<int, ConstructorRange> WorldConstructors = new()
	{
		[0] = new( 0x004F98CC, 0x00542CAC ),
		[1] = new( 0x0054595C, 0x00596EF0 ),
		[2] = new( 0x00599FD0, 0x005EC248 ),
		[4] = new( 0x005EF5B4, 0x0064E0A8 ),
		[5] = new( 0x00651AF8, 0x006AA680 ),
		[6] = new( 0x006AD7A4, 0x00700404 ),
		[7] = new( 0x00704C30, 0x0074E914 ),
		[8] = new( 0x007519A4, 0x0079C6DC ),
		[9] = new( 0x0079FA18, 0x007D9F0C ),
		[10] = new( 0x007DCF50, 0x0082CFA0 ),
		[11] = new( 0x0083026C, 0x00874CDC ),
		[12] = new( 0x00877AE0, 0x008A55EC ),
		[13] = new( 0x00877AE0, 0x008A55EC ),
		[14] = new( 0x008A819C, 0x008F3690 ),
		[15] = new( 0x008F6A04, 0x0092A7C8 ),
		[16] = new( 0x00877AE0, 0x008A55EC ),
		[17] = new( 0x0092BC60, 0x009C058C ),
		[20] = new( 0x009C20B8, 0x00A09C48 ),
		[21] = new( 0x00A0CD8C, 0x00A1F05C ),
		[22] = new( 0x00A1F8A4, 0x00A882F0 ),
		[23] = new( 0x00A8AE44, 0x00ACC354 ),
		[24] = new( 0x00ACFC6C, 0x00AE20F4 ),
		[25] = new( 0x00AE2DC0, 0x00B9BA18 ),
		[26] = new( 0x00B9F338, 0x00BCDA08 ),
		[27] = new( 0x00BD0900, 0x00C03774 ),
		[28] = new( 0x00C061BC, 0x00C3727C ),
		[29] = new( 0x00C39DB0, 0x00C7D558 ),
		[100] = new( 0x00C80770, 0x00C83FD8 ),
		[101] = new( 0x00C841E8, 0x00C97A28 ),
		[102] = new( 0x00C982F8, 0x00CAA088 ),
		[103] = new( 0x00CAAC50, 0x00CBD2C4 ),
		[104] = new( 0x00CBE070, 0x00D40814 )
	};

	public static IReadOnlyCollection<int> MapIds => WorldConstructors.Keys;

	// Level name decode. Three structures chain together; see the remarks on
	// HrotMapNames and REVERSE_ENGINEERING.md section 8 (Level dispatch and names).
	const uint LevelNameByteTable = 0x00DA4960;
	const uint LevelNameJumpTable = 0x00DA49C9;
	const uint StringJumpTable = 0x00DAA004;
	const int MaxLevelNameMapId = 0x68;

	/// <summary>
	/// Reads every level name by replaying HROT's own <c>GetLevelName</c>.
	/// Returns an empty map if the executable does not match the retail build.
	/// </summary>
	public static Dictionary<int, string> ReadMapNames( string executablePath )
	{
		var result = new Dictionary<int, string>();
		if ( string.IsNullOrWhiteSpace( executablePath ) || !File.Exists( executablePath ) )
			return result;

		try
		{
			var data = File.ReadAllBytes( executablePath );
			if ( !TryReadPe( data, out var imageBase, out var sections ) )
				return result;

			bool TryOffset( uint address, out int offset )
				=> TryVirtualAddressToOffset( address, imageBase, sections, data.Length, out offset );

			// An arm of GetLevelName is `mov edx,esi; mov ax,imm16; call`, so
			// the string id is a 16-bit immediate at a fixed position.
			bool TryStringId( uint arm, out ushort stringId )
			{
				stringId = 0;
				if ( !TryOffset( arm, out var offset ) || offset + 6 > data.Length )
					return false;
				if ( data[offset] != 0x8B || data[offset + 1] != 0xD6 ||
					data[offset + 2] != 0x66 || data[offset + 3] != 0xB8 )
					return false;
				stringId = ReadUInt16( data, offset + 4 );
				return true;
			}

			// An arm of the localisation switch is
			// `mov eax,[ebp+8]; mov eax,[eax-8]; mov edx,imm32; call`.
			bool TryLiteralAddress( uint arm, out uint literal )
			{
				literal = 0;
				if ( !TryOffset( arm, out var offset ) || offset + 11 > data.Length )
					return false;
				if ( data[offset] != 0x8B || data[offset + 1] != 0x45 || data[offset + 2] != 0x08 ||
					data[offset + 3] != 0x8B || data[offset + 4] != 0x40 || data[offset + 5] != 0xF8 ||
					data[offset + 6] != 0xBA )
					return false;
				literal = ReadUInt32( data, offset + 7 );
				return true;
			}

			for ( var mapId = 0; mapId <= MaxLevelNameMapId; mapId++ )
			{
				if ( !TryOffset( (uint)(LevelNameByteTable + mapId), out var caseOffset ) )
					continue;

				var caseIndex = data[caseOffset];
				if ( !TryOffset( (uint)(LevelNameJumpTable + caseIndex * 4), out var armOffset ) ||
					armOffset + 4 > data.Length )
					continue;

				if ( !TryStringId( ReadUInt32( data, armOffset ), out var stringId ) )
					continue;

				if ( !TryOffset( (uint)(StringJumpTable + stringId * 4), out var stringArmOffset ) ||
					stringArmOffset + 4 > data.Length )
					continue;

				if ( !TryLiteralAddress( ReadUInt32( data, stringArmOffset ), out var literal ) ||
					!TryOffset( literal, out var textOffset ) || textOffset < 4 )
					continue;

				var length = ReadInt32( data, textOffset - 4 );
				if ( length <= 0 || length > 128 || textOffset + length > data.Length )
					continue;

				result[mapId] = TransliterateCp1250( data, textOffset, length );
			}

			// Map 1 is Kosmonautu Station independently of this decode - it is
			// the map carrying the metro sign prop, the metro stairs and the
			// "kosmonauti" ladder. If that fails, the hardcoded addresses above
			// belong to a different build and nothing here can be trusted.
			if ( !result.TryGetValue( 1, out var anchor ) || !anchor.StartsWith( "Kosmonaut" ) )
				return [];
		}
		catch
		{
			// A changed executable leaves scenes unnamed, but they still load.
			return [];
		}

		return result;
	}

	// The names carry Czech diacritics in codepage 1250. Scene titles stay
	// ASCII, and this avoids depending on a codepage provider being registered.
	static string TransliterateCp1250( byte[] data, int offset, int length )
	{
		var builder = new System.Text.StringBuilder( length );
		for ( var i = 0; i < length; i++ )
		{
			var value = data[offset + i];
			builder.Append( value switch
			{
				< 0x80 => (char)value,
				0x8A or 0x9A => 's',   // S/s caron
				0x8D or 0x9D => 't',   // T/t caron
				0x8E or 0x9E => 'z',   // Z/z caron
				0x8F or 0x9F => 'z',   // Z/z acute
				0xC8 or 0xE8 => 'c',   // C/c caron
				0xCF or 0xEF => 'd',   // D/d caron
				0xD2 or 0xF2 => 'n',   // N/n caron
				0xD8 or 0xF8 => 'r',   // R/r caron
				0xC1 or 0xE1 => 'a',
				0xC9 or 0xE9 => 'e',
				0xCC or 0xEC => 'e',   // E/e caron
				0xCD or 0xED => 'i',
				0xD3 or 0xF3 => 'o',
				0xDA or 0xFA => 'u',
				0xD9 or 0xF9 => 'u',   // U/u ring - Kosmonautu
				0xDD or 0xFD => 'y',
				_ => '?'
			} );
		}

		return builder.ToString();
	}

	public static HrotMapGrid Read( string executablePath, int mapId )
	{
		if ( !WorldConstructors.TryGetValue( mapId, out var constructor ) )
			return null;

		try
		{
			var data = File.ReadAllBytes( executablePath );
			if ( !TryReadPe( data, out var imageBase, out var sections ) ||
				!TryVirtualAddressToOffset( constructor.Start, imageBase, sections, data.Length, out var start ) ||
				!TryVirtualAddressToOffset( constructor.End, imageBase, sections, data.Length, out var end ) ||
				end <= start )
				return null;

			var grid = CreateInitializedGrid();
			var writes = ApplyWorldWrites( data, start, end, grid );
			return writes == 0 ? null : new HrotMapGrid( mapId, grid, writes );
		}
		catch
		{
			return null;
		}
	}

	static byte[] CreateInitializedGrid()
	{
		var grid = new byte[GridSize * GridSize * CellSize];
		for ( var cell = 0; cell < GridSize * GridSize; cell++ )
		{
			var offset = cell * CellSize;
			grid[offset + 6] = 1;
			WriteUInt32( grid, offset + 0x28, 0x3FC80000 ); // 1.5625f
			WriteUInt32( grid, offset + 0x14, 0xC4FA0000 ); // -2000.0f
		}
		return grid;
	}

	static int ApplyWorldWrites( byte[] executable, int start, int end, byte[] grid )
	{
		var writes = 0;

		for ( var i = start; i < end; i++ )
		{
			// mov byte ptr [eax+disp32], imm8
			if ( i + 7 <= end && executable[i] == 0xC6 && executable[i + 1] == 0x80 )
			{
				var displacement = ReadInt32( executable, i + 2 );
				if ( IsWorldField( displacement, 1, grid.Length ) )
				{
					grid[displacement] = executable[i + 6];
					writes++;
				}
				continue;
			}

			// mov dword ptr [eax+disp32], imm32
			if ( i + 10 <= end && executable[i] == 0xC7 && executable[i + 1] == 0x80 )
			{
				var displacement = ReadInt32( executable, i + 2 );
				if ( IsWorldField( displacement, 4, grid.Length ) )
				{
					Array.Copy( executable, i + 6, grid, displacement, 4 );
					writes++;
				}
				continue;
			}

			// Delphi emits cleared EDX into grid fields as mov [eax+disp],edx.
			// Every such write in the world constructors is preceded by an
			// xor edx,edx and represents a constant zero.
			if ( i + 6 <= end && executable[i] == 0x89 && executable[i + 1] == 0x90 )
			{
				var displacement = ReadInt32( executable, i + 2 );
				if ( IsWorldField( displacement, 4, grid.Length ) )
				{
					Array.Clear( grid, displacement, 4 );
					writes++;
				}
			}
		}

		return writes;
	}

	static bool IsWorldField( int displacement, int width, int gridLength )
	{
		if ( displacement < 0 || displacement + width > gridLength )
			return false;

		var field = displacement % CellSize;
		if ( field is
			0x06 or
			// Water. 0x09 is the type (1 or 2, 0 = none) and gates the water
			// pass at 0x00D8FFE5; 0x0C is the surface height. Both are map
			// data and were discarded here until the pass was decoded - see
			// REVERSE_ENGINEERING.md 11.7.
			0x09 or 0x0C or
			// Gates the overlay quad at 0xD87FC0. Written on maps 2, 4, 5 and 6.
			0x10 or
			0x1C or 0x20 or 0x24 or 0x28 or
			0x2C or 0x30 or 0x34 or 0x38 or
			0x3C or 0x40 or 0x44 or 0x48 or
			0x4C or 0x50 or 0x54 or 0x58 or
			0x5C or 0x60 or 0x64 or 0x68 or
			0x6C or 0x70 or 0x74 or 0x78 or
			0x1D5 or 0x1D6 )
			return true;

		// Four 84-byte directional wall-segment records. These encode
		// windows, ladder exits, stacked textures and portal openings.
		return IsAuxiliaryField( field, 0x7C ) ||
			IsAuxiliaryField( field, 0xD0 ) ||
			IsAuxiliaryField( field, 0x124 ) ||
			IsAuxiliaryField( field, 0x178 );
	}

	static bool IsAuxiliaryField( int field, int start )
		=> field >= start && field < start + 0x54;

	static bool TryReadPe( byte[] data, out uint imageBase, out List<Section> sections )
	{
		imageBase = 0;
		sections = [];
		if ( data.Length < 0x100 || ReadUInt16( data, 0 ) != 0x5A4D )
			return false;

		var peOffset = checked((int)ReadUInt32( data, 0x3C ));
		if ( peOffset < 0 || peOffset + 24 > data.Length || ReadUInt32( data, peOffset ) != 0x00004550 )
			return false;

		var sectionCount = ReadUInt16( data, peOffset + 6 );
		var optionalHeaderSize = ReadUInt16( data, peOffset + 20 );
		var optionalOffset = peOffset + 24;
		if ( optionalOffset + optionalHeaderSize > data.Length || ReadUInt16( data, optionalOffset ) != 0x10B )
			return false;

		imageBase = ReadUInt32( data, optionalOffset + 28 );
		var sectionTable = optionalOffset + optionalHeaderSize;
		for ( var i = 0; i < sectionCount; i++ )
		{
			var offset = sectionTable + i * 40;
			if ( offset + 40 > data.Length ) return false;
			sections.Add( new Section(
				ReadUInt32( data, offset + 12 ),
				ReadUInt32( data, offset + 8 ),
				ReadUInt32( data, offset + 20 ),
				ReadUInt32( data, offset + 16 ) ) );
		}

		return sections.Count > 0;
	}

	static bool TryVirtualAddressToOffset(
		uint address, uint imageBase, IReadOnlyList<Section> sections, int dataLength, out int offset )
	{
		var rva = address - imageBase;
		foreach ( var section in sections )
		{
			var length = Math.Max( section.VirtualSize, section.RawSize );
			if ( rva < section.VirtualAddress || rva >= section.VirtualAddress + length ) continue;
			var value = section.RawAddress + rva - section.VirtualAddress;
			if ( value < dataLength )
			{
				offset = (int)value;
				return true;
			}
		}

		offset = 0;
		return false;
	}

	static ushort ReadUInt16( byte[] data, int offset ) => BitConverter.ToUInt16( data, offset );
	static uint ReadUInt32( byte[] data, int offset ) => BitConverter.ToUInt32( data, offset );
	static int ReadInt32( byte[] data, int offset ) => BitConverter.ToInt32( data, offset );
	static void WriteUInt32( byte[] data, int offset, uint value ) => BitConverter.GetBytes( value ).CopyTo( data, offset );
}

/// <summary>
/// Shipped level names, for scene metadata.
/// </summary>
/// <remarks>
/// Ported from HROT's own <c>GetLevelName</c> at 0x00DA4939, not inferred.
/// That function indexes a byte table at 0x00DA4960 by map id (bounds 0..0x68),
/// uses the result to select an arm through the jump table at 0x00DA49C9, and
/// each arm loads one string id through <c>LoadString(id, dest)</c> at
/// 0x00DB9AA0. The ids resolve against the 644-entry localisation switch whose
/// jump table is at 0x00DAA004; its arms hold the Delphi literals that begin at
/// file offset 0x009AF0F8. The literals are in source order, not map-id order:
/// map 0 is Vysehrad Castle, not Intro, and the eight episode-1 names are spread
/// over ids 0-10 rather than sitting contiguously.
///
/// Names are transliterated from cp1250 to ASCII. "Underground stream" and
/// "George of Podiebrad" carry the game's own casing and spelling.
///
/// Maps 100-104 are the Endless mode arenas rather than story levels, and 100
/// resolves to the UI string "Press key". That is genuinely what HROT returns
/// for it, and since this is decoded rather than transcribed it needs no
/// judgement call either way.
///
/// The names are **not** stored here. They are read from the executable at
/// mount time by <see cref="HrotExecutableMapData.ReadMapNames"/>, so a build
/// whose table differs reports its own names rather than these. A map with no
/// decoded name falls back to "Map NN" - which is also what happens wholesale
/// if the anchor check fails, because an unrecognised build's addresses cannot
/// be trusted to point at names at all.
/// </remarks>
static class HrotMapNames
{
	public static string Get( IReadOnlyDictionary<int, string> names, int mapId )
		=> names is not null && names.TryGetValue( mapId, out var name ) && !string.IsNullOrWhiteSpace( name )
			? name
			: $"Map {mapId:00}";
}

sealed class HrotMapGrid( int mapId, byte[] data, int writeCount )
{
	public int MapId { get; } = mapId;
	public int WriteCount { get; } = writeCount;

	public HrotMapCell Cell( int x, int y )
	{
		if ( x < 0 || y < 0 || x >= HrotExecutableMapData.GridSize || y >= HrotExecutableMapData.GridSize )
			return default;

		return new HrotMapCell( data, (y * HrotExecutableMapData.GridSize + x) * HrotExecutableMapData.CellSize );
	}
}

readonly struct HrotMapCell( byte[] data, int offset )
{
	// HROT is Y-up. The engine's floor-height query reads +0x38, while
	// +0x28 is the upper plane.
	public bool HasFloor => ReadByte( 0x34 ) != 0;
	public bool HasCeiling => ReadByte( 0x24 ) != 0;
	// Gates the horizontal overlay quad drawn by 0xD87FC0.
	public bool HasOverlay => ReadByte( 0x10 ) != 0;
	// Water type: 1 or 2, 0 for none. HROT tints the surface by it, and only
	// map 9 (Sewage Treatment Plant) uses type 2. See REVERSE_ENGINEERING.md 11.7.
	public int WaterType => ReadByte( 0x09 );
	public bool HasWater => ReadByte( 0x09 ) != 0;
	// Absolute height of the water surface, independent of the floor below it.
	public float WaterHeight => ReadSingle( 0x0C );
	public float FloorHeight => ReadSingle( 0x38 );
	public float CeilingHeight => ReadSingle( 0x28 );
	// HROT renders vertical wall bands from this signed, quantized baseline,
	// independently of the cell's potentially sloped/offset floor planes.
	public float WallBaseHeight => (sbyte)ReadByte( 0x1D5 ) * 1.5625f;
	// Values 1..4 select which half of the cell is one 0.15625-unit
	// stair tread above the stored floor height.
	public int StairDirection => ReadByte( 0x1D6 ) is >= 1 and <= 4
		? ReadByte( 0x1D6 )
		: 0;
	public HrotMapFace Floor => Face( 0x2C, 0x34 );
	public HrotMapFace Ceiling => Face( 0x1C, 0x24 );
	public HrotMapFace East => Face( 0x3C, 0x44, 0x7C );
	public HrotMapFace West => Face( 0x4C, 0x54, 0xD0 );
	public HrotMapFace South => Face( 0x5C, 0x64, 0x124 );
	public HrotMapFace North => Face( 0x6C, 0x74, 0x178 );

	HrotMapFace Face( int materialOffset, int activeOffset, int auxiliaryOffset = -1 )
	{
		var rawCount = auxiliaryOffset >= 0 ? (sbyte)ReadByte( auxiliaryOffset ) : (sbyte)0;
		// Each directional auxiliary record is 84 bytes: four header bytes
		// followed by ten (atlas X, atlas Y) material pairs. HROT uses all ten
		// bands in tall shafts, and six for the barred opening above the fourth
		// map-1 ladder, so the count is capped at ten rather than lower.
		var count = rawCount > 0 ? Math.Min( rawCount, (sbyte)10 ) : 0;
		var skippedSegment = auxiliaryOffset >= 0 ? (sbyte)ReadByte( auxiliaryOffset + 1 ) : (sbyte)0;
		var segments = count == 0 ? [] : new HrotMapMaterial[count];

		for ( var i = 0; i < count; i++ )
		{
			var atlasX = ReadInt32( auxiliaryOffset + 4 + i * 8 );
			var atlasY = ReadInt32( auxiliaryOffset + 8 + i * 8 );
			segments[i] = atlasX is >= 0 and < 32 && atlasY is >= 1 and <= 16
				? new HrotMapMaterial( atlasX, atlasY )
				: new HrotMapMaterial( ReadInt32( materialOffset ), ReadInt32( materialOffset + 4 ) );
		}

		return new HrotMapFace(
			ReadByte( activeOffset ) != 0,
			ReadInt32( materialOffset ),
			ReadInt32( materialOffset + 4 ),
			segments,
			skippedSegment is >= 1 and <= 10 ? skippedSegment : 0 );
	}

	byte ReadByte( int field ) => data is null ? (byte)0 : data[offset + field];
	int ReadInt32( int field ) => data is null ? 0 : BitConverter.ToInt32( data, offset + field );
	float ReadSingle( int field ) => data is null ? 0 : BitConverter.ToSingle( data, offset + field );
}

readonly record struct HrotMapMaterial( int AtlasX, int AtlasY );

readonly record struct HrotMapFace(
	bool Active,
	int AtlasX,
	int AtlasY,
	HrotMapMaterial[] Segments,
	int SkippedSegment )
{
	public int AuxiliaryCount => Segments?.Length ?? 0;
	public HrotMapMaterial Segment( int index ) => Segments[index];
}
