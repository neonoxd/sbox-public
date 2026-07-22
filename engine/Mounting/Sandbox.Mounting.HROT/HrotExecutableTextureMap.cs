using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

/// <summary>
/// Recovers model-to-texture assignments which HROT stores in HROT.exe rather
/// than in its MD2 files. This is intentionally a small PE/x86 pattern reader,
/// not a general disassembler.
/// </summary>
static class HrotExecutableTextureMap
{
	readonly record struct Section( uint VirtualAddress, uint VirtualSize, uint RawAddress, uint RawSize );

	public static CaseInsensitiveDictionary<string> Read( string executablePath )
	{
		var result = new CaseInsensitiveDictionary<string>();
		if ( string.IsNullOrWhiteSpace( executablePath ) || !File.Exists( executablePath ) )
			return result;

		try
		{
			var data = File.ReadAllBytes( executablePath );
			if ( data.Length < 0x100 || ReadUInt16( data, 0 ) != 0x5A4D )
				return result;

			var peOffset = checked((int)ReadUInt32( data, 0x3C ));
			if ( peOffset < 0 || peOffset + 24 > data.Length || ReadUInt32( data, peOffset ) != 0x00004550 )
				return result;

			var sectionCount = ReadUInt16( data, peOffset + 6 );
			var optionalHeaderSize = ReadUInt16( data, peOffset + 20 );
			var optionalOffset = peOffset + 24;
			if ( optionalOffset + optionalHeaderSize > data.Length )
				return result;

			var optionalMagic = ReadUInt16( data, optionalOffset );
			if ( optionalMagic != 0x10B ) // HROT is a 32-bit PE image.
				return result;

			var imageBase = ReadUInt32( data, optionalOffset + 28 );
			var sectionTable = optionalOffset + optionalHeaderSize;
			var sections = new List<Section>( sectionCount );

			for ( var i = 0; i < sectionCount; i++ )
			{
				var offset = sectionTable + i * 40;
				if ( offset + 40 > data.Length ) break;

				sections.Add( new Section(
					ReadUInt32( data, offset + 12 ),
					ReadUInt32( data, offset + 8 ),
					ReadUInt32( data, offset + 20 ),
					ReadUInt32( data, offset + 16 )
				) );
			}

			if ( sections.Count == 0 )
				return result;

			string ReadString( uint virtualAddress )
			{
				if ( !TryVirtualAddressToOffset( virtualAddress, imageBase, sections, data.Length, out var offset ) )
					return null;

				var end = offset;
				while ( end < data.Length && end - offset < 128 && data[end] != 0 )
				{
					if ( data[end] < 32 || data[end] > 126 ) return null;
					end++;
				}

				return end > offset && end < data.Length
					? Encoding.ASCII.GetString( data, offset, end - offset )
					: null;
			}

			void Add( string model, string texture )
			{
				if ( string.IsNullOrWhiteSpace( model ) || string.IsNullOrWhiteSpace( texture ) )
					return;

				result[Path.GetFileNameWithoutExtension( model )] = Path.GetFileNameWithoutExtension( texture );
			}

			// Static/world model registration:
			// mov ecx, texture; mov edx, model; mov ax, id; call RegisterModel
			ExtractStaticAssignments( data, ReadString, Add );

			// First-person weapon registration:
			// push texture; mov ecx, model; mov dl, slot; ... call RegisterWeapon
			ExtractWeaponAssignments( data, ReadString, Add );

			// Actor initialization:
			// mov edx, model; call LoadModel; ... mov edx, texture; call SetTexture
			// Extract this last because an animated MD2 can share its basename
			// with a static/world model (for example ryba). For an MD2 request,
			// the actor assignment is the authoritative one.
			ExtractActorAssignments( data, imageBase, sections, ReadString, Add );
		}
		catch
		{
			// A changed or unsupported executable should not prevent mounting.
		}

		return result;
	}

	static void ExtractActorAssignments(
		byte[] data,
		uint imageBase,
		IReadOnlyList<Section> sections,
		Func<uint, string> readString,
		Action<string, string> add )
	{
		// HROT's model loader and texture setter are identifiable by the many
		// repeated "mov edx, string; call" pairs in the main code section.
		var pairs = new Dictionary<uint, List<(int Offset, string Value)>>();

		for ( var i = 0; i + 10 < data.Length; i++ )
		{
			if ( data[i] != 0xBA || data[i + 5] != 0xE8 ) continue;
			var value = readString( ReadUInt32( data, i + 1 ) );
			if ( value is null ) continue;
			if ( !TryOffsetToVirtualAddress( i + 10, imageBase, sections, out var nextInstruction ) ) continue;

			var target = unchecked((uint)((long)nextInstruction + ReadInt32( data, i + 6 )));
			if ( !pairs.TryGetValue( target, out var list ) )
				pairs[target] = list = [];
			list.Add( (i, value) );
		}

		// The two relevant routines occur as an unusually frequent ordered
		// pair: model-loading call followed within 100 bytes by texture setter.
		uint modelTarget = 0;
		uint textureTarget = 0;
		var bestPairCount = 0;

		foreach ( var (candidateModelTarget, modelCalls) in pairs )
		{
			if ( modelCalls.Count < 10 ) continue;

			foreach ( var (candidateTextureTarget, textureCalls) in pairs )
			{
				if ( candidateTextureTarget == candidateModelTarget ) continue;
				var count = 0;

				foreach ( var modelCall in modelCalls )
				{
					if ( textureCalls.Exists( x => x.Offset > modelCall.Offset && x.Offset <= modelCall.Offset + 256 ) )
						count++;
				}

				if ( count <= bestPairCount ) continue;
				bestPairCount = count;
				modelTarget = candidateModelTarget;
				textureTarget = candidateTextureTarget;
			}
		}

		if ( bestPairCount < 5 || !pairs.TryGetValue( modelTarget, out var confirmedModels ) ||
			!pairs.TryGetValue( textureTarget, out var confirmedTextures ) )
			return;

		foreach ( var modelCall in confirmedModels )
		{
			var textureCall = confirmedTextures.Find( x => x.Offset > modelCall.Offset && x.Offset <= modelCall.Offset + 256 );
			if ( textureCall != default )
				add( modelCall.Value, textureCall.Value );
		}
	}

	static void ExtractStaticAssignments( byte[] data, Func<uint, string> readString, Action<string, string> add )
	{
		for ( var i = 0; i + 19 < data.Length; i++ )
		{
			if ( data[i] != 0xB9 || data[i + 5] != 0xBA ) continue;

			var texture = readString( ReadUInt32( data, i + 1 ) );
			var model = readString( ReadUInt32( data, i + 6 ) );
			if ( texture is null || model is null ) continue;

			// The following instruction loads the numeric model id into AX.
			if ( data[i + 10] != 0x66 || data[i + 11] != 0xB8 ) continue;
			if ( data[i + 14] != 0xE8 ) continue;
			add( model, texture );
		}
	}

	static void ExtractWeaponAssignments( byte[] data, Func<uint, string> readString, Action<string, string> add )
	{
		for ( var i = 0; i + 20 < data.Length; i++ )
		{
			if ( data[i] != 0x68 || data[i + 5] != 0xB9 ) continue;

			var texture = readString( ReadUInt32( data, i + 1 ) );
			var model = readString( ReadUInt32( data, i + 6 ) );
			if ( texture is null || model is null ) continue;

			// Weapon slot is loaded into DL (or cleared with xor edx, edx),
			// followed by "mov eax, [ebp-4]; call RegisterWeapon".
			var slotLength = data[i + 10] switch
			{
				0xB2 => 2,
				0x32 when data[i + 11] == 0xD2 => 2,
				_ => 0
			};

			if ( slotLength == 0 ) continue;
			var moveOffset = i + 10 + slotLength;
			if ( moveOffset + 8 >= data.Length ||
				data[moveOffset] != 0x8B || data[moveOffset + 1] != 0x45 ||
				data[moveOffset + 2] != 0xFC || data[moveOffset + 3] != 0xE8 )
				continue;

			add( model, texture );
		}
	}

	static bool TryVirtualAddressToOffset(
		uint address,
		uint imageBase,
		IReadOnlyList<Section> sections,
		int dataLength,
		out int offset )
	{
		var rva = address - imageBase;
		foreach ( var section in sections )
		{
			var length = Math.Max( section.VirtualSize, section.RawSize );
			if ( rva < section.VirtualAddress || rva >= section.VirtualAddress + length ) continue;

			var value = section.RawAddress + (rva - section.VirtualAddress);
			if ( value >= dataLength ) break;
			offset = (int)value;
			return true;
		}

		offset = 0;
		return false;
	}

	static bool TryOffsetToVirtualAddress(
		int offset,
		uint imageBase,
		IReadOnlyList<Section> sections,
		out uint address )
	{
		foreach ( var section in sections )
		{
			if ( offset < section.RawAddress || offset >= section.RawAddress + section.RawSize ) continue;
			address = imageBase + section.VirtualAddress + (uint)offset - section.RawAddress;
			return true;
		}

		address = 0;
		return false;
	}

	static ushort ReadUInt16( byte[] data, int offset ) => BitConverter.ToUInt16( data, offset );
	static uint ReadUInt32( byte[] data, int offset ) => BitConverter.ToUInt32( data, offset );
	static int ReadInt32( byte[] data, int offset ) => BitConverter.ToInt32( data, offset );
}
