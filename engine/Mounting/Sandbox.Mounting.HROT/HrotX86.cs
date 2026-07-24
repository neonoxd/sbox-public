using System.Collections.Generic;

/// <summary>
/// A 32-bit x86 instruction-length decoder, enough to walk HROT's constructors
/// forward.
/// </summary>
/// <remarks>
/// The prop readers match byte patterns *backward* from a call, which cannot see
/// a value written before the previous call - category A of the decoder-gap
/// census (REVERSE_ENGINEERING.md 12). Recovering those needs a forward walk, and
/// a forward walk needs instruction lengths.
///
/// <b>It returns 0 for anything it does not recognise rather than guessing</b>,
/// because a mis-measured instruction desynchronises the walk and every length
/// after it. A caller must treat 0 as "stop here".
///
/// `Tools/hrot_lendec.py` is the same decoder in Python, and its `--check`
/// compares every boundary in all 32 prop constructors against capstone: 120163
/// instructions, <b>0 mismatches</b>, 722 unknown - and every unknown is embedded
/// string data ("end", "map") that capstone decoded as instructions, not code.
/// That is the evidence this subset is complete for this build; re-run it after a
/// game update, because it is a claim about HROT's compiled code, not about x86.
/// </remarks>
static class HrotX86
{
	static readonly HashSet<byte> Prefixes =
	[
		0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3,
	];

	static readonly HashSet<byte> ModRmOnly =
	[
		0x00, 0x01, 0x02, 0x03, 0x08, 0x09, 0x0A, 0x0B,
		0x10, 0x11, 0x12, 0x13, 0x18, 0x19, 0x1A, 0x1B,
		0x20, 0x21, 0x22, 0x23, 0x28, 0x29, 0x2A, 0x2B,
		0x30, 0x31, 0x32, 0x33, 0x38, 0x39, 0x3A, 0x3B,
		0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8D, 0x8F,
		0xD0, 0xD1, 0xD2, 0xD3,
		0xD8, 0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF,   // x87
		0xFE, 0xFF,
	];

	static readonly HashSet<byte> ModRmImm8 = [0x6B, 0x80, 0x83, 0xC0, 0xC1, 0xC6];
	static readonly HashSet<byte> ModRmImm32 = [0x69, 0x81, 0xC7];

	/// <summary>Opcodes with no modrm, and how many bytes follow.</summary>
	static readonly Dictionary<byte, int> Fixed = BuildFixed();

	static Dictionary<byte, int> BuildFixed()
	{
		var map = new Dictionary<byte, int>
		{
			[0x06] = 0, [0x07] = 0, [0x0E] = 0, [0x16] = 0, [0x17] = 0,
			[0x1E] = 0, [0x1F] = 0, [0x27] = 0, [0x2F] = 0, [0x37] = 0, [0x3F] = 0,
			[0x60] = 0, [0x61] = 0, [0x90] = 0, [0x98] = 0, [0x99] = 0, [0x9B] = 0,
			[0x9C] = 0, [0x9D] = 0, [0x9E] = 0, [0x9F] = 0,
			[0xA4] = 0, [0xA5] = 0, [0xA6] = 0, [0xA7] = 0, [0xAA] = 0, [0xAB] = 0,
			[0xAC] = 0, [0xAD] = 0, [0xAE] = 0, [0xAF] = 0,
			[0xC3] = 0, [0xC9] = 0, [0xCB] = 0, [0xCC] = 0, [0xCE] = 0, [0xCF] = 0,
			[0xD7] = 0,
			[0xF4] = 0, [0xF5] = 0, [0xF8] = 0, [0xF9] = 0, [0xFA] = 0,
			[0xFB] = 0, [0xFC] = 0, [0xFD] = 0,
			[0x3C] = 1, [0x6A] = 1, [0xA8] = 1, [0xCD] = 1, [0xD4] = 1, [0xD5] = 1,
			[0xE0] = 1, [0xE1] = 1, [0xE2] = 1, [0xE3] = 1, [0xEB] = 1,
			[0xC2] = 2, [0xCA] = 2,
			[0x68] = 4, [0xA0] = 4, [0xA1] = 4, [0xA2] = 4, [0xA3] = 4,
			[0xA9] = 4, [0xE8] = 4, [0xE9] = 4,
		};

		for ( var op = 0x40; op < 0x60; op++ )      // inc/dec/push/pop r32
			map[(byte)op] = 0;
		for ( var op = 0x70; op < 0x80; op++ )      // jcc rel8
			map[(byte)op] = 1;
		for ( var op = 0xB0; op < 0xB8; op++ )      // mov r8, imm8
			map[(byte)op] = 1;

		return map;
	}

	/// <summary>modrm (+sib +disp) size, or -1 when the buffer is truncated.</summary>
	static int ModRmLength( byte[] code, int i )
	{
		if ( i >= code.Length )
			return -1;

		var modrm = code[i];
		var mod = modrm >> 6;
		var rm = modrm & 7;
		var size = 1;

		if ( mod != 3 && rm == 4 )                  // SIB
		{
			if ( i + 1 >= code.Length )
				return -1;
			var sib = code[i + 1];
			size++;
			if ( mod == 0 && (sib & 7) == 5 )
				size += 4;
		}

		if ( mod == 1 )
			size += 1;
		else if ( mod == 2 )
			size += 4;
		else if ( mod == 0 && rm == 5 )
			size += 4;

		return size;
	}

	/// <summary>
	/// Length of the instruction at <paramref name="index"/>, or 0 when this
	/// decoder does not recognise it - which the caller must treat as "stop".
	/// </summary>
	public static int Length( byte[] code, int index )
	{
		var start = index;
		var i = index;
		var operand16 = false;

		while ( i < code.Length && Prefixes.Contains( code[i] ) )
		{
			if ( code[i] == 0x66 )
				operand16 = true;
			i++;
		}

		if ( i >= code.Length )
			return 0;

		var op = code[i];
		i++;

		if ( op == 0x0F )
		{
			if ( i >= code.Length )
				return 0;
			var op2 = code[i];
			i++;

			if ( op2 >= 0x80 && op2 <= 0x8F )        // jcc rel32
				return i + 4 - start;

			if ( op2 == 0xB6 || op2 == 0xB7 || op2 == 0xBE || op2 == 0xBF ||
				op2 == 0xAF || (op2 >= 0x90 && op2 <= 0x9F) )
			{
				var n = ModRmLength( code, i );
				return n < 0 ? 0 : i + n - start;
			}

			return 0;
		}

		if ( op >= 0xB8 && op <= 0xBF )              // mov r32/r16, imm
			return i + (operand16 ? 2 : 4) - start;

		// arithmetic block 0x00-0x3F: low 3 bits 4 = al,imm8; 5 = eax,imm32
		if ( op < 0x40 && ((op & 7) == 4 || (op & 7) == 5) )
			return i + ((op & 7) == 4 ? 1 : (operand16 ? 2 : 4)) - start;

		if ( ModRmOnly.Contains( op ) )
		{
			var n = ModRmLength( code, i );
			return n < 0 ? 0 : i + n - start;
		}

		if ( ModRmImm8.Contains( op ) )
		{
			var n = ModRmLength( code, i );
			return n < 0 ? 0 : i + n + 1 - start;
		}

		if ( ModRmImm32.Contains( op ) )
		{
			var n = ModRmLength( code, i );
			return n < 0 ? 0 : i + n + (operand16 ? 2 : 4) - start;
		}

		if ( op == 0xF6 || op == 0xF7 )              // grp3: /0 and /1 carry an imm
		{
			var n = ModRmLength( code, i );
			if ( n < 0 )
				return 0;
			var reg = (code[i] >> 3) & 7;
			var extra = reg is 0 or 1
				? (op == 0xF6 ? 1 : (operand16 ? 2 : 4))
				: 0;
			return i + n + extra - start;
		}

		return Fixed.TryGetValue( op, out var fixedExtra )
			? i + fixedExtra - start
			: 0;
	}
}
