using System;
using System.Collections.Generic;

/// <summary>
/// Recovers placement arguments and per-axis scales the backward reader cannot,
/// by simulating the constructor forward with a model of <c>esp</c> and stack
/// memory.
/// </summary>
/// <remarks>
/// <see cref="HrotExecutableProps"/> matches byte patterns *backward* from a
/// placement call, collecting literal pushes. That misses two things:
///
/// <list type="bullet">
/// <item>category A of the decoder-gap census (REVERSE_ENGINEERING.md 12): HROT
/// parks a float with <c>mov [esp],imm</c> and every sibling placement re-reads
/// it through <c>push [esp+4]</c>. The callees pop their own arguments, so the
/// slot survives across calls and the write can precede the *previous* call -
/// out of reach of any bounded backward search.</item>
/// <item><b>per-axis scale.</b> After placing, HROT reaches the object it just
/// created and writes one component of its Scale coordinates:
/// <c>mov eax,[eax+0x5C]; mov edx,component; call 0x492D18</c>. 40 placements
/// carry one; components HROT never writes stay 1.</item>
/// </list>
///
/// <b>Everything here fails to "unknown" rather than to a plausible number.</b>
/// An unrecognised instruction, or a call to anything but a known helper, drops
/// the tracked values; a site whose arguments are not all resolved is simply not
/// returned. Category D of the census (arguments read from another entity at
/// runtime) must never be "recovered" - those positions are genuinely not in the
/// executable.
///
/// <c>Tools/dump_stack_args.py</c> is the same simulation over capstone and is
/// the cross-check.
/// </remarks>
static class HrotExecutableStack
{
	/// <summary>Placement helpers and how many floats each takes on the stack.</summary>
	/// <remarks>
	/// The model id arrives in AX, so it is not a stack argument, and push order
	/// is argument order.
	/// </remarks>
	static readonly Dictionary<uint, int> Placements = new()
	{
		[0x00DBDDE0] = 3,   // PlaceOnFloor      (x, z, yaw)
		[0x00DBDE24] = 4,   // PlaceAboveFloor   (x, vertical offset, z, yaw)
		[0x00DBDF04] = 4,   // PlaceAtHeight     (x, y, z, yaw)
		[0x00DBE468] = 3,   // PlaceAtCell
	};

	/// <summary>
	/// Uniform scale. Not a placement - it must not become the object a following
	/// scale component attaches to.
	/// </summary>
	const uint ScaleUniform = 0x00DBDD64;

	/// <summary>
	/// <c>SetCoordComponent(coords, index, value)</c> - writes
	/// <c>[coords + 0x20 + index*4]</c>, the same vector layout the orientation
	/// struct uses. Reached through the placed object's Scale at <c>+0x5C</c>.
	/// </summary>
	const uint SetCoordComponent = 0x00492D18;

	/// <summary>Everything one constructor gives up to a forward walk.</summary>
	internal sealed class Recovered
	{
		/// <summary>Placement arguments, keyed by the call's virtual address.</summary>
		public Dictionary<uint, float[]> Arguments { get; } = [];

		/// <summary>
		/// Per-axis scale in HROT's component order, keyed by the placement call
		/// it followed. Components HROT never sets stay 1.
		/// </summary>
		public Dictionary<uint, float[]> Scales { get; } = [];
	}

	public static Recovered Recover(
		byte[] data,
		int start,
		int end,
		uint imageBase,
		IReadOnlyList<HrotExecutableProps.Section> sections )
	{
		var found = new Recovered();

		try
		{
			// Stack memory keyed by esp-relative address; null means "not traced".
			var memory = new Dictionary<int, float?>();
			var esp = 0;
			// The last immediate loaded into EDX - the scale setter takes its
			// component there rather than on the stack.
			int? edx = null;
			// The placement a following scale component belongs to.
			uint placement = 0;

			var i = start;
			while ( i < end )
			{
				var length = HrotX86.Length( data, i );
				if ( length <= 0 )
				{
					// Embedded string data, or a form the decoder does not know.
					// Resynchronise on the next placement anchor rather than
					// walking on at a guessed boundary - a wrong boundary is how
					// a forward pass starts inventing values.
					memory.Clear();
					esp = 0;
					edx = null;
					placement = 0;
					i = NextAnchor( data, i + 1, end );
					continue;
				}

				Step( data, i, length, imageBase, sections,
					memory, ref esp, ref edx, ref placement, found );
				i += length;
			}
		}
		catch
		{
			// Recovered props are a bonus on top of what the backward reader
			// already finds; a changed executable must not stop a map loading.
		}

		return found;
	}

	/// <summary>The next `mov ax, imm16` + `call` placement anchor, or `end`.</summary>
	static int NextAnchor( byte[] data, int from, int end )
	{
		for ( var i = from; i + 9 <= end; i++ )
		{
			if ( data[i] == 0x66 && data[i + 1] == 0xB8 && data[i + 4] == 0xE8 )
				return i;
		}

		return end;
	}

	static void Step(
		byte[] data,
		int i,
		int length,
		uint imageBase,
		IReadOnlyList<HrotExecutableProps.Section> sections,
		Dictionary<int, float?> memory,
		ref int esp,
		ref int? edx,
		ref uint placement,
		Recovered found )
	{
		var op = data[i];

		// mov edx, imm32 / xor edx, edx - the scale setter's component
		if ( op == 0xBA && length >= 5 )
		{
			edx = BitConverter.ToInt32( data, i + 1 );
			return;
		}

		if ( (op == 0x33 || op == 0x31) && length >= 2 && data[i + 1] == 0xD2 )
		{
			edx = 0;
			return;
		}

		if ( op == 0x68 )                                   // push imm32
		{
			Push( memory, ref esp,
				BitConverter.Int32BitsToSingle( BitConverter.ToInt32( data, i + 1 ) ) );
			return;
		}

		if ( op == 0x6A )                                   // push imm8 (0 is 0.0f)
		{
			Push( memory, ref esp,
				BitConverter.Int32BitsToSingle( (sbyte)data[i + 1] ) );
			return;
		}

		// push dword [esp] / [esp+disp8]
		if ( op == 0xFF && length >= 3 && data[i + 2] == 0x24 )
		{
			if ( data[i + 1] == 0x34 )
			{
				Push( memory, ref esp, Read( memory, esp, 0 ) );
				return;
			}

			if ( data[i + 1] == 0x74 && length >= 4 )
			{
				Push( memory, ref esp, Read( memory, esp, (sbyte)data[i + 3] ) );
				return;
			}
		}

		// mov dword [esp (+disp8)], imm32 - the category A write
		if ( op == 0xC7 && length >= 3 && data[i + 2] == 0x24 )
		{
			if ( data[i + 1] == 0x04 && length >= 7 )
			{
				memory[esp] = BitConverter.Int32BitsToSingle(
					BitConverter.ToInt32( data, i + 3 ) );
				return;
			}

			if ( data[i + 1] == 0x44 && length >= 8 )
			{
				memory[esp + (sbyte)data[i + 3]] = BitConverter.Int32BitsToSingle(
					BitConverter.ToInt32( data, i + 4 ) );
				return;
			}
		}

		if ( op == 0x83 && length >= 3 && (data[i + 1] == 0xC4 || data[i + 1] == 0xEC) )
		{
			var delta = (sbyte)data[i + 2];
			esp += data[i + 1] == 0xC4 ? delta : -delta;
			return;
		}

		if ( op >= 0x50 && op <= 0x57 )                     // push r32
		{
			Push( memory, ref esp, null );
			return;
		}

		if ( op >= 0x58 && op <= 0x5F )                     // pop r32
		{
			memory.Remove( esp );
			esp += 4;
			return;
		}

		// fstp/fst dword [esp (+disp8)] - an x87 result this pass did not trace
		if ( (op == 0xD9 || op == 0xDD) && length >= 3 && data[i + 2] == 0x24 )
		{
			if ( data[i + 1] is 0x1C or 0x14 )
			{
				memory[esp] = null;
				return;
			}

			if ( data[i + 1] is 0x5C or 0x54 && length >= 4 )
			{
				memory[esp + (sbyte)data[i + 3]] = null;
				return;
			}
		}

		if ( op != 0xE8 )
			return;

		var next = HrotExecutableProps.OffsetToVirtualAddress( i + 5, imageBase, sections );
		if ( next == 0 )
			return;

		var target = unchecked((uint)((long)next + BitConverter.ToInt32( data, i + 1 )));

		if ( Placements.TryGetValue( target, out var count ) )
		{
			var callAddress = HrotExecutableProps.OffsetToVirtualAddress(
				i, imageBase, sections );

			var args = new float[count];
			var resolved = true;
			for ( var a = 0; a < count; a++ )
			{
				var value = Read( memory, esp, (count - 1 - a) * 4 );
				if ( value is null )
				{
					resolved = false;
					break;
				}

				args[a] = value.Value;
			}

			if ( resolved && callAddress != 0 )
				found.Arguments[callAddress] = args;

			// Scale components that follow attach to this object even when the
			// arguments themselves did not resolve - the backward reader may have
			// read them perfectly well.
			placement = callAddress;

			Pop( memory, ref esp, count );
			return;
		}

		if ( target == ScaleUniform )
		{
			Pop( memory, ref esp, 1 );      // handled by the backward reader
			return;
		}

		if ( target == SetCoordComponent )
		{
			var value = Read( memory, esp, 0 );
			if ( placement != 0 && value is not null &&
				edx is >= 0 and <= 2 )
			{
				if ( !found.Scales.TryGetValue( placement, out var scale ) )
				{
					scale = [1.0f, 1.0f, 1.0f];
					found.Scales[placement] = scale;
				}

				scale[edx.Value] = value.Value;
			}

			Pop( memory, ref esp, 1 );      // ret 4
			return;
		}

		// An unknown callee may leave anything in the slots we care about, and may
		// itself be the object a following scale component belongs to. Dropping the
		// placement enforces "only known helpers may stand between a placement and
		// its scale write", which holds for all 40 real sites. Map 104's 183 scale
		// writes follow Delphi and GLScene constructors rather than placements, and
		// would otherwise attach to whichever prop was placed last.
		memory.Clear();
		placement = 0;
		edx = null;
	}

	static void Push( Dictionary<int, float?> memory, ref int esp, float? value )
	{
		esp -= 4;
		memory[esp] = value;
	}

	static void Pop( Dictionary<int, float?> memory, ref int esp, int count )
	{
		for ( var a = 0; a < count; a++ )
		{
			memory.Remove( esp );
			esp += 4;
		}
	}

	static float? Read( Dictionary<int, float?> memory, int esp, int displacement )
		=> memory.TryGetValue( esp + displacement, out var value ) ? value : null;
}
