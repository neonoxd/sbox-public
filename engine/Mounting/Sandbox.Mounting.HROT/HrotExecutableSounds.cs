using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

/// <summary>Recovers HROT's sound id to filename table.</summary>
/// <remarks>
/// Every WAV is registered once:
///
/// <code>
/// mov edx, &lt;"name.wav"&gt;
/// mov eax, &lt;id&gt;
/// call 0x00DCAF38
/// </code>
///
/// 419 registrations over ids 1..427, against 423 WAVs in the PAK - a few ship
/// unregistered. `Tools/dump_sounds.py` prints the same table.
///
/// <b>A sound id is not usable as a search key.</b> The range overlaps the
/// static-model ids and nearly every flag and count a constructor passes, so
/// "this register holds a valid sound id" matches almost anything. Finding what
/// emits a sound took an anchor from the running game instead - a named prop
/// that could be heard humming.
/// </remarks>
/// <summary>A looping sound a prop model emits, with HROT's own falloff.</summary>
/// <remarks>
/// <c>Far</c> and <c>Near</c> are in HROT metres: silent at or beyond
/// <c>Far</c>, full volume within <c>Near</c>, linear between.
/// </remarks>
readonly record struct HrotModelSound(
	int SoundId, string Sound, float Far, float Near, float Gain );

/// <summary>The looping music layers a map points the mixer at.</summary>
/// <remarks>
/// HROT's music is three simultaneous layers rather than one track per map, so
/// <c>mus_9</c> and <c>mus_9_a</c> are parts of one cue and not alternates -
/// which is why several maps name the same <c>_a</c> track in two slots.
/// <c>Intermission</c> is a fourth slot the level-end screen uses.
///
/// Ids are 0 where the constructor sets no track. Only <c>Layer1</c> is
/// spawned: the others fade in on state the mount does not have.
/// </remarks>
readonly record struct HrotMapMusic(
	int Layer1, int Layer2, int Layer3, int Intermission );

static class HrotExecutableSounds
{
	const uint RegisterSound = 0x00DCAF38;

	// The prop update switches on the model id through Delphi's two-level
	// form, and the emitters live in its cases:
	//
	//   movzx eax, word [ebx-0x70]        ; model id
	//   mov   al,  byte [eax + 0xD6E7D3]  ; model -> case index
	//   jmp   dword [eax*4 + 0xD6EB2C]    ; case -> code
	//
	// Inside a case: push distance, far, near, gain ; mov eax, soundId ;
	// call 0xDCF7A4, which is volume = (far - distance) / (far - near).
	// Music layer pointers. A map's prop constructor stores a sound id through
	// each one:
	//
	//   mov eax, dword ptr [0x00DE7C38]
	//   mov dword ptr [eax], 0x150        ; 336 = mus_21
	//
	// and the mixer at 0x00DCB721 plays every layer whose gain is above zero:
	//
	//   fld   dword ptr [ebx + 0x430]     ; layer gain
	//   fcomp dword ptr [0x00DCB92C]      ; 0.0
	//   jbe   next
	//   push  dword ptr [ebx + 0x430]
	//   push  0x3F800000
	//   mov   eax, dword ptr [0x00DE7C38]
	//   mov   eax, dword ptr [eax]        ; the sound id
	//   mov   dl, 1                       ; looping
	//   call  0x00DCF710
	//
	// Three of those blocks sit in a row, with gains at +0x430, +0x438 and
	// +0x440.
	//
	// This is a dword store *through a pointer*, not a register holding the
	// music id - a search for the latter finds only prop placers, where `ax`
	// is the model id.
	static readonly (uint Pointer, int Layer)[] MusicLayers =
	{
		(0x00DE7C38, 0),
		(0x00DE7C90, 1),
		(0x00DE7EA4, 2),
		(0x00DE7FC8, 3),
	};

	const uint ModelCaseTable = 0x00D6E7D3;
	const uint ModelJumpTable = 0x00D6EB2C;
	const uint PlayAttenuated = 0x00DCF7A4;
	const int MaxModelId = 0x358;
	const int CaseCount = 224;
	const int CaseSpan = 0x400;

	public static Dictionary<int, string> Read( string executablePath )
	{
		var result = new Dictionary<int, string>();

		try
		{
			var data = File.ReadAllBytes( executablePath );
			if ( !HrotExecutableProps.TryReadPe( data, out var imageBase, out var sections ) )
				return result;

			// mov edx, imm32 ; mov eax, imm32 ; call rel32
			for ( var i = 0; i + 15 <= data.Length; i++ )
			{
				if ( data[i] != 0xBA || data[i + 5] != 0xB8 || data[i + 10] != 0xE8 )
					continue;

				var next = HrotExecutableProps.OffsetToVirtualAddress( i + 15, imageBase, sections );
				if ( next == 0 )
					continue;

				var target = unchecked((uint)(
					(long)next + BitConverter.ToInt32( data, i + 11 ) ));
				if ( target != RegisterSound )
					continue;

				var name = ReadString(
					data, BitConverter.ToUInt32( data, i + 1 ), imageBase, sections );
				if ( string.IsNullOrWhiteSpace( name ) )
					continue;

				result[BitConverter.ToInt32( data, i + 6 )] = name;
			}
		}
		catch
		{
			// Sounds are decoration; a changed executable must not stop a map.
		}

		return result;
	}

	/// <summary>Recovers the music layers each map points the mixer at.</summary>
	/// <remarks>
	/// See <see cref="MusicLayers"/> for the shape this reads and the mixer that
	/// consumes it. <c>Tools/dump_music.py</c> prints the same table beside the
	/// level names, and its <c>--check</c> pass reports every write to these
	/// four globals without filtering to known music ids - the control that says
	/// they are the music slots rather than four addresses that happened to
	/// match. The only non-<c>mus_</c> value across the whole image is
	/// <c>disko2.wav</c> on Strahov Stadium, a diegetic disco.
	/// </remarks>
	public static Dictionary<int, HrotMapMusic> ReadMapMusic( string executablePath )
	{
		var result = new Dictionary<int, HrotMapMusic>();

		try
		{
			var data = File.ReadAllBytes( executablePath );
			if ( !HrotExecutableProps.TryReadPe( data, out var imageBase, out var sections ) )
				return result;

			for ( var mapId = 0; mapId <= 104; mapId++ )
			{
				if ( !HrotExecutableProps.TryGetConstructor( mapId, out var start, out var end ) )
					continue;

				if ( !HrotExecutableProps.TryVirtualAddressToOffset(
						start, imageBase, sections, data.Length, out var begin ) ||
					!HrotExecutableProps.TryVirtualAddressToOffset(
						end, imageBase, sections, data.Length, out var finish ) )
					continue;

				var tracks = new int[4];

				// A1 <pointer32>  C7 00 <soundId32>
				for ( var i = begin; i + 11 <= finish; i++ )
				{
					if ( data[i] != 0xA1 || data[i + 5] != 0xC7 || data[i + 6] != 0x00 )
						continue;

					var pointer = BitConverter.ToUInt32( data, i + 1 );
					foreach ( var (candidate, layer) in MusicLayers )
					{
						if ( candidate != pointer )
							continue;

						tracks[layer] = BitConverter.ToInt32( data, i + 7 );
						break;
					}
				}

				if ( tracks[0] != 0 || tracks[1] != 0 || tracks[2] != 0 || tracks[3] != 0 )
					result[mapId] = new HrotMapMusic(
						tracks[0], tracks[1], tracks[2], tracks[3] );
			}
		}
		catch
		{
			// Music is decoration; a changed executable must not stop a map.
		}

		return result;
	}

	/// <summary>
	/// Recovers which models emit a looping sound, and how far it carries.
	/// </summary>
	/// <remarks>
	/// This is code, not a table: HROT plays these from the prop's update case,
	/// recomputing the volume from the player's distance every frame. So the
	/// mapping has to come from the switch, and the radii from the call site.
	///
	/// It is worth the trouble because the result reads as obviously right -
	/// <c>zarivka</c> buzzes, <c>umyvadlo</c> runs water, <c>metro</c> is a
	/// train, and the three <c>rozvadec</c> variants share a mains hum.
	/// </remarks>
	public static Dictionary<int, HrotModelSound> ReadModelSounds( string executablePath )
	{
		var result = new Dictionary<int, HrotModelSound>();

		try
		{
			var data = File.ReadAllBytes( executablePath );
			if ( !HrotExecutableProps.TryReadPe( data, out var imageBase, out var sections ) )
				return result;

			var sounds = Read( executablePath );

			if ( !HrotExecutableProps.TryVirtualAddressToOffset(
					ModelCaseTable, imageBase, sections, data.Length, out var caseTable ) ||
				!HrotExecutableProps.TryVirtualAddressToOffset(
					ModelJumpTable, imageBase, sections, data.Length, out var jumpTable ) )
				return result;

			var targets = new uint[CaseCount];
			var starts = new SortedSet<uint>();
			for ( var i = 0; i < CaseCount; i++ )
			{
				targets[i] = BitConverter.ToUInt32( data, jumpTable + i * 4 );
				starts.Add( targets[i] );
			}

			var byCase = new Dictionary<int, HrotModelSound>();

			for ( var model = 0; model <= MaxModelId; model++ )
			{
				if ( caseTable + model >= data.Length )
					break;

				var index = data[caseTable + model];
				if ( index >= CaseCount )
					continue;

				if ( !byCase.TryGetValue( index, out var found ) )
				{
					found = ReadCaseSound(
						data, targets[index], starts, sounds, imageBase, sections );
					byCase[index] = found;
				}

				if ( found.SoundId != 0 )
					result[model] = found;
			}
		}
		catch
		{
			// Ambience is decoration; a changed executable must not stop a map.
		}

		return result;
	}

	/// <summary>The first attenuated play call inside one switch case.</summary>
	static HrotModelSound ReadCaseSound(
		byte[] data,
		uint entry,
		SortedSet<uint> starts,
		Dictionary<int, string> sounds,
		uint imageBase,
		IReadOnlyList<HrotExecutableProps.Section> sections )
	{
		// A case runs until the next one begins, so a play call belonging to a
		// neighbouring case is not attributed to this model.
		var end = entry + CaseSpan;
		foreach ( var start in starts )
		{
			if ( start > entry && start < end )
				end = start;
		}

		if ( !HrotExecutableProps.TryVirtualAddressToOffset(
				entry, imageBase, sections, data.Length, out var begin ) ||
			!HrotExecutableProps.TryVirtualAddressToOffset(
				end, imageBase, sections, data.Length, out var finish ) )
			return default;

		for ( var i = begin; i + 5 <= finish; i++ )
		{
			if ( data[i] != 0xE8 )
				continue;

			var next = HrotExecutableProps.OffsetToVirtualAddress( i + 5, imageBase, sections );
			if ( next == 0 )
				continue;

			var target = unchecked((uint)((long)next + BitConverter.ToInt32( data, i + 1 ) ));
			if ( target != PlayAttenuated )
				continue;

			var soundId = 0;
			var probe = i;
			for ( var back = i - 1; back > i - 12 && back >= begin; back-- )
			{
				if ( data[back] == 0xB8 && back + 5 <= i )
				{
					soundId = BitConverter.ToInt32( data, back + 1 );
					probe = back;
					break;
				}

				if ( data[back] == 0x66 && data[back + 1] == 0xB8 && back + 4 <= i )
				{
					soundId = BitConverter.ToUInt16( data, back + 2 );
					probe = back;
					break;
				}
			}

			if ( soundId == 0 || !sounds.TryGetValue( soundId, out var name ) )
				continue;

			// push distance, far, near, gain - the last three are constants
			// when the emitter is a fixed prop.
			var values = new float[3];
			var cursor = probe;
			var read = 0;
			for ( var argument = 2; argument >= 0; argument-- )
			{
				if ( cursor - 5 < begin || data[cursor - 5] != 0x68 )
					break;

				values[argument] = BitConverter.Int32BitsToSingle(
					BitConverter.ToInt32( data, cursor - 4 ) );
				cursor -= 5;
				read++;
			}

			// Without the radii there is nothing sensible to give a
			// SoundPointComponent, so those cases are left silent rather than
			// guessed at.
			if ( read < 3 || values[0] <= 0.0f )
				continue;

			return new HrotModelSound( soundId, name, values[0], values[1], values[2] );
		}

		return default;
	}

	static string ReadString(
		byte[] data,
		uint address,
		uint imageBase,
		IReadOnlyList<HrotExecutableProps.Section> sections )
	{
		if ( !HrotExecutableProps.TryVirtualAddressToOffset(
			address, imageBase, sections, data.Length, out var offset ) || offset < 4 )
			return null;

		var length = BitConverter.ToInt32( data, offset - 4 );
		if ( length <= 0 || length > 128 || offset + length > data.Length )
			return null;

		return Encoding.ASCII.GetString( data, offset, length );
	}
}
