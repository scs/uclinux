/*
** Convert float32 to float.
*/

.section program;
.align 2;

_fl32_to_fl:
	R2 = R0 | R1;
	CC = R2 == 0;
	IF CC JUMP finished;

	// save the sign
	R2 = R1 >> 31;
	R2 <<= 31;
	P0 = R2;

	// Compute exponent
	R3 = 126;
	R0 = R0 + R3;

	// Check for mantissa == -1
	R2 = 0;
	BITSET(R2, 31);	// 0x80000000
	CC = R2 == R1;
	IF CC JUMP minusone;

	// Negate mantissa if sign bit set
	CC = P0 < 0;
	R2 = - R1;
	IF CC R1 = R2;

assemble:
	R1 <<= 2;	// remove sign and hidden bit
	R1 >>= 9;	// leave room for exponent
	R0 <<= 23;
	R2 = P0;
	R0 = R2 | R0;
	R0 = R1 | R0;
finished:
	RTS;
minusone:
	R0 += 1;
	R1.H = 0x4000;
	R1.L = 0;
	JUMP assemble;
._fl32_to_fl.end:
.global _fl32_to_fl;
.type _fl32_to_fl, STT_FUNC;
