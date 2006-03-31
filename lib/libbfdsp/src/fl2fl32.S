/*
** Convert a float to Float32.
*/

.section program;
.align 2;
_fl_to_fl32:
	R1 = R0 << 1;
	CC = R1 == 0;			// if +0.0 or -0.0
	IF CC R0 = R1;			// then set both to
	IF CC JUMP finished;		// zero and return.

	// Extract sign
	R3 = R0 >> 31;
	R3 <<= 31;
	P0 = R3;

	R1 = R0;
	BITSET(R1, 23);
	R1 <<= 8;
	R1 >>= 1;
	
	// Extract exponent
	R2 = R0 << 1;
	R2 >>= 24;
	R3 = 126;
	R0 = R2 - R3;

#if defined(__ADSPBF535__) || defined(__AD6532__)
	R2 = 0;
	R2 = R2 - R1 (S);
#else
	R2 = - R1 (S);
#endif
	CC = P0 < 0;
	IF CC R1 = R2;
finished:
	RTS;
._fl_to_fl32.end:
.global _fl_to_fl32;
.type _fl_to_fl32, STT_FUNC;
