using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

/// <summary>A static model registration, and the model it breaks into.</summary>
/// <remarks>
/// <c>RegisterModel</c> at <c>0xDBE7E0</c> takes six pushed arguments before
/// the texture, model and id. The fourth - read back as a word at
/// <c>[ebp+0x10]</c> - is the id of this model's <b>damaged variant</b>, or
/// <c>0</c> for a prop that does not break:
///
/// <code>
/// 181 rozvadec           -> 200 rozvadec_dmg
/// 331 lustr2             -> 332 lustr2_dmg
/// 108/109/110 wc_*       -> 111 wc_dmg
/// </code>
///
/// It is the damaged-variant id, not a sound id: the two ranges overlap (200 is
/// also <c>1khz.wav</c>, 111 also <c>vrtulnik.wav</c>), so a numeric match
/// against the sound table is not evidence. See the warning in
/// <c>Tools/dump_sounds.py</c>.
/// </remarks>
readonly record struct HrotStaticModelRegistration(
	int Id, string Model, string Texture, int DamagedModelId = 0 );

/// <summary>Reads HROT's numeric static-model registration table.</summary>
static class HrotExecutableStaticModels
{
	const uint ModelRegister = 0x00DBE7E0;

	readonly record struct Section( uint VirtualAddress, uint VirtualSize, uint RawAddress, uint RawSize );

	public static Dictionary<int, HrotStaticModelRegistration> Read( string executablePath )
	{
		var result = new Dictionary<int, HrotStaticModelRegistration>();
		if ( string.IsNullOrWhiteSpace( executablePath ) || !File.Exists( executablePath ) )
			return result;

		try
		{
			var data = File.ReadAllBytes( executablePath );
			if ( !TryReadPe( data, out var imageBase, out var sections ) )
				return result;

			string ReadString( uint address )
			{
				if ( !TryVirtualAddressToOffset( address, imageBase, sections, data.Length, out var offset ) )
					return null;

				var end = offset;
				while ( end < data.Length && end - offset < 128 && data[end] != 0 )
				{
					var value = data[end];
					var valid = value is >= (byte)'a' and <= (byte)'z' or
						>= (byte)'A' and <= (byte)'Z' or
						>= (byte)'0' and <= (byte)'9' or
						(byte)'_' or (byte)'-' or (byte)'.' or (byte)'/' or (byte)'\\';
					if ( !valid ) return null;
					end++;
				}

				return end > offset && end < data.Length
					? Encoding.ASCII.GetString( data, offset, end - offset )
					: null;
			}

			// mov ecx, texture; mov edx, model; mov ax, id; call RegisterModel
			for ( var i = 0; i + 19 < data.Length; i++ )
			{
				if ( data[i] != 0xB9 || data[i + 5] != 0xBA ||
					data[i + 10] != 0x66 || data[i + 11] != 0xB8 ||
					data[i + 14] != 0xE8 )
					continue;

				var texture = ReadString( ReadUInt32( data, i + 1 ) );
				var model = ReadString( ReadUInt32( data, i + 6 ) );
				if ( string.IsNullOrWhiteSpace( texture ) || string.IsNullOrWhiteSpace( model ) )
					continue;

				// The byte shape alone is not enough - it occurs elsewhere in the
				// executable - so the call must land on RegisterModel. That
				// brings the match down to exactly the 840 real registrations.
				var next = OffsetToVirtualAddress( i + 19, imageBase, sections );
				if ( next == 0 )
					continue;

				var target = unchecked((uint)(
					(long)next + BitConverter.ToInt32( data, i + 15 ) ));
				if ( target != ModelRegister )
					continue;

				var id = ReadUInt16( data, i + 12 );
				result[id] = new HrotStaticModelRegistration(
					id, model, texture, ReadDamagedModelId( data, i ) );
			}
		}
		catch
		{
			// Changed executables leave static props unavailable, but maps load.
		}

		return result;
	}

	/// <summary>
	/// The damaged model a registration names, or 0 if the prop does not break.
	/// </summary>
	/// <remarks>
	/// Six arguments are pushed before the <c>mov ecx, texture</c> that starts
	/// the registration, and the sound is the fourth in source order. They mix
	/// <c>68 imm32</c> and <c>6A imm8</c> encodings - the compiler picks the
	/// short form for anything under 128, so a fixed stride reads garbage for
	/// exactly the props whose ids are small.
	///
	/// A registration whose six pushes cannot be read is treated as unbreakable
	/// rather than skipped: the model itself is still perfectly usable, and
	/// losing it over an unreadable argument would trade a missing detail for a
	/// missing prop.
	/// </remarks>
	static int ReadDamagedModelId( byte[] data, int registrationOffset )
	{
		const int ArgumentCount = 6;
		const int DamagedArgument = 3;

		var values = new int[ArgumentCount];
		var cursor = registrationOffset;

		for ( var argument = ArgumentCount - 1; argument >= 0; argument-- )
		{
			if ( cursor - 5 >= 0 && data[cursor - 5] == 0x68 )
			{
				values[argument] = BitConverter.ToInt32( data, cursor - 4 );
				cursor -= 5;
				continue;
			}

			if ( cursor - 2 >= 0 && data[cursor - 2] == 0x6A )
			{
				values[argument] = (sbyte)data[cursor - 1];
				cursor -= 2;
				continue;
			}

			return 0;
		}

		var damaged = values[DamagedArgument];
		return damaged > 0 && damaged < 1024 ? damaged : 0;
	}

	static uint OffsetToVirtualAddress(
		int offset, uint imageBase, IReadOnlyList<Section> sections )
	{
		foreach ( var section in sections )
		{
			if ( offset < section.RawAddress ||
				offset >= section.RawAddress + section.RawSize )
				continue;

			return imageBase + section.VirtualAddress + (uint)(offset - section.RawAddress);
		}

		return 0;
	}

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
		var table = optionalOffset + optionalHeaderSize;
		for ( var i = 0; i < sectionCount; i++ )
		{
			var offset = table + i * 40;
			if ( offset + 40 > data.Length ) return false;
			sections.Add( new Section(
				ReadUInt32( data, offset + 12 ), ReadUInt32( data, offset + 8 ),
				ReadUInt32( data, offset + 20 ), ReadUInt32( data, offset + 16 ) ) );
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
}
