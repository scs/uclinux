/*
** Float32 compare.
*/

.section program;
.align 2;

_cmp_fl32:
	P0 = R7;
	R3 = [SP+12];
	R7 = R1 | R3;
	CC = R7 < 0;
	IF CC JUMP diff_signs;

	R7 = P0;
	R0 = R0 - R2;	// diff between exponents
	R1 = R1 - R3;	// diff between mantissas
	CC = R0 == 0;	// If exponents are different, they decide
	IF CC R0 = R1;	// otherwise, mantissas decide
	R2 = -R0;
	CC = R3 < 0;	// If Y neg (and hence X neg), neg result
	IF CC R0 = R2;
	RTS;
diff_signs:
	R7 = P0;
	R1 >>>= 31;
	R0 = R1;
	R0 += 1;
	RTS;
._cmp_fl32.end:
.global _cmp_fl32;
.type _cmp_fl32, STT_FUNC;
