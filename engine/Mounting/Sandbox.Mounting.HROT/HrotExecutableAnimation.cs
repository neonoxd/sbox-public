using System;
using System.Collections.Generic;
using System.IO;

/// <summary>The Euler axis of the object orientation struct a spin turns.</summary>
/// <remarks>
/// HROT keeps a prop's orientation at <c>[obj+0x200]</c> with Euler angles at
/// <c>+0x20</c>, <c>+0x24</c> and <c>+0x28</c>, rebuilt lazily into an axis-angle
/// rotation matrix (Rodrigues, <c>0x0045E778</c>) about a per-angle axis:
/// <list type="bullet">
/// <item><c>+0x24</c> turns about the object's <b>Up</b> vector (<c>[obj+0x58]</c>)
/// - it is <b>yaw</b>, and its setter <c>0x4A326C</c> is the very one the
/// player-start facing goes through, so it maps to s&amp;box yaw the way
/// <see cref="HrotMap"/> already turns a placement yaw into a rotation.</item>
/// <item><c>+0x20</c> turns about <c>Direction x Up</c> (<c>[obj+0x54] x [obj+0x58]</c>,
/// cross product <c>0x0045D764</c>) - the object's <b>Right</b> axis. It is
/// <b>pitch</b>: a horizontal axis perpendicular to the way the prop faces (a
/// paddlewheel spin, not a face-on one). The axis is decoded; only its s&amp;box
/// sign is left to confirm by eye, per "orientations never port unchanged".</item>
/// </list>
/// </remarks>
enum HrotSpinAxis
{
	/// <summary>Orientation offset <c>+0x24</c>: yaw, about the object's Up (setter <c>0x4A326C</c>).</summary>
	Yaw,

	/// <summary>Orientation offset <c>+0x20</c>: pitch, about the object's Right = Direction x Up (setter <c>0x4A2DDC</c>).</summary>
	Axis20,
}

/// <summary>A constant rotation a prop model applies to itself every sim tick.</summary>
/// <remarks>
/// <b><see cref="DegreesPerTick"/> is per fixed sim tick, and HROT ticks at
/// 100 Hz</b>, so the angular velocity is <c>DegreesPerTick * 100</c> deg/s.
/// The increment carries no delta-time scaling, but the spin is <em>not</em>
/// framerate-dependent: HROT drives a GLScene <c>TGLCadencer</c> whose
/// <c>FixedDeltaTime</c> is 0 (variable), and runs its own fixed-step
/// accumulator - the per-tick object walker at <c>0x00D4F7FC</c> is followed by
/// <c>inc [0x17D76A8]</c>, a sim-tick counter that reads a rock-steady 100 Hz
/// live (and the fixed step <c>0.01</c> is bracketed by the <c>0.009</c>/
/// <c>0.011</c> clamp constants in that code). The relative rates are HROT's own
/// too - the intact fan 565 at 4.0 versus the damaged 566 at 1.5.
/// </remarks>
readonly record struct HrotModelSpin( HrotSpinAxis Axis, float DegreesPerTick );

/// <summary>
/// Recovers which prop models spin constantly, on which axis and how fast.
/// </summary>
/// <remarks>
/// This is code, not a table. A spinning prop's update case - reached through the
/// same per-model switch the ambient sounds come out of
/// (<see cref="HrotExecutableSounds.ReadModelSounds"/>) - reads one Euler angle,
/// adds a constant, and writes it back:
///
/// <code>
/// mov eax, [ebx-0x74]        ; the object
/// call &lt;angle getter&gt;
/// fadd dword [const]         ; += degrees this tick  (D8 05 &lt;addr32&gt;)
/// add esp,-4 / fstp [esp] / wait
/// mov eax, [ebx-0x74]
/// call &lt;angle setter&gt;        ; E8 &lt;rel32&gt; to 0x4A326C (yaw) or 0x4A2DDC
/// </code>
///
/// The write-back setter names the axis, so the case is identified by a
/// <c>fadd dword [const]</c> whose constant is a small positive angle, followed
/// within a few instructions by a call to one of the two known angle setters.
/// <c>Tools/dump_model_spins.py</c> disassembles the same cases and prints the
/// same 13 models; a disagreement means one side is wrong.
/// </remarks>
static class HrotExecutableAnimation
{
	const uint ModelCaseTable = 0x00D6E7D3;
	const uint ModelJumpTable = 0x00D6EB2C;
	const int MaxModelId = 0x358;
	const int CaseCount = 224;
	const int CaseSpan = 0x400;

	// The angle setters, each writing one Euler offset of the orientation struct.
	// Hardcoded like every other address here: build-specific, and a moved setter
	// simply drops the spin rather than inventing one, because the target must
	// match exactly.
	const uint SetYaw = 0x004A326C;      // orientation +0x24
	const uint SetAxis20 = 0x004A2DDC;   // orientation +0x20

	// How far past the fadd the write-back call may sit. The real idiom puts it
	// about 16 bytes later (add esp,-4 / fstp [esp] / wait / mov eax,[ebx-0x74]);
	// a small margin covers instruction-scheduling differences between cases.
	const int SetterSearch = 0x18;

	/// <summary>Model id to the spins its update case applies (usually one).</summary>
	public static Dictionary<int, IReadOnlyList<HrotModelSpin>> ReadModelSpins(
		string executablePath )
	{
		var result = new Dictionary<int, IReadOnlyList<HrotModelSpin>>();

		try
		{
			var data = File.ReadAllBytes( executablePath );
			if ( !HrotExecutableProps.TryReadPe( data, out var imageBase, out var sections ) )
				return result;

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

			var byCase = new Dictionary<int, IReadOnlyList<HrotModelSpin>>();

			for ( var model = 0; model <= MaxModelId; model++ )
			{
				if ( caseTable + model >= data.Length )
					break;

				var index = data[caseTable + model];
				if ( index >= CaseCount )
					continue;

				if ( !byCase.TryGetValue( index, out var found ) )
				{
					found = ReadCaseSpins(
						data, targets[index], starts, imageBase, sections );
					byCase[index] = found;
				}

				if ( found.Count > 0 )
					result[model] = found;
			}
		}
		catch
		{
			// A spin is decoration; a changed executable must not stop a map.
		}

		return result;
	}

	/// <summary>The constant rotations one switch case applies.</summary>
	static IReadOnlyList<HrotModelSpin> ReadCaseSpins(
		byte[] data,
		uint entry,
		SortedSet<uint> starts,
		uint imageBase,
		IReadOnlyList<HrotExecutableProps.Section> sections )
	{
		// A case runs until the next one begins, so a spin belonging to a
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
			return Array.Empty<HrotModelSpin>();

		List<HrotModelSpin> spins = null;

		for ( var i = begin; i + 6 <= finish; i++ )
		{
			// fadd dword ptr [addr32]
			if ( data[i] != 0xD8 || data[i + 1] != 0x05 )
				continue;

			if ( !HrotExecutableProps.TryVirtualAddressToOffset(
					BitConverter.ToUInt32( data, i + 2 ),
					imageBase, sections, data.Length, out var constOffset ) ||
				constOffset + 4 > data.Length )
				continue;

			var degrees = BitConverter.Int32BitsToSingle(
				BitConverter.ToInt32( data, constOffset ) );

			// A per-tick spin rate is a small positive angle. Anything else is a
			// fadd that is not a rotation - or an operand outside the image.
			if ( !( degrees > 0.0f && degrees <= 90.0f ) )
				continue;

			if ( !TryFindSetter( data, i + 6, Math.Min( i + 6 + SetterSearch, finish ),
					imageBase, sections, out var axis ) )
				continue;

			( spins ??= new List<HrotModelSpin>() ).Add(
				new HrotModelSpin( axis, degrees ) );
		}

		return (IReadOnlyList<HrotModelSpin>)spins ?? Array.Empty<HrotModelSpin>();
	}

	/// <summary>
	/// Scans a short window for an <c>E8 rel32</c> call to a known angle setter.
	/// </summary>
	static bool TryFindSetter(
		byte[] data,
		int from,
		int to,
		uint imageBase,
		IReadOnlyList<HrotExecutableProps.Section> sections,
		out HrotSpinAxis axis )
	{
		axis = default;

		for ( var i = from; i + 5 <= to; i++ )
		{
			if ( data[i] != 0xE8 )
				continue;

			var next = HrotExecutableProps.OffsetToVirtualAddress( i + 5, imageBase, sections );
			if ( next == 0 )
				continue;

			var target = unchecked((uint)((long)next + BitConverter.ToInt32( data, i + 1 ) ));

			switch ( target )
			{
				case SetYaw:
					axis = HrotSpinAxis.Yaw;
					return true;
				case SetAxis20:
					axis = HrotSpinAxis.Axis20;
					return true;
			}
		}

		return false;
	}
}
