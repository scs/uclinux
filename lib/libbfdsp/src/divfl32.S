/*
** Float32 division
** XXX Not a real implementation - this doesn't do fractional division.
** XXX It's only here to give an estimate of the cycles required.
*/

.section program;
.extern ___udiv32;
.align 2;
_div_fl32:
	LINK 0;
	[--SP] = (R7:6);
	R3 = [SP+12];	// manY
	SP += -12;

	// Check Identities
	R7 = R2 | R3;
	CC = R7 == 0;
	IF CC JUMP div_by_zero;

	R7 = R1 ^ R3;	// Note sign
	R6 = R0 - R2;	// Compute exponent
	R0 = ABS R1;	// Load params to div with
	R1 = ABS R3;	// positive mantissas
	CALL.X ___udiv32;		// divide manX, manY
	R1 = R0;
	R0 = R6;

	// If we hadn't cheated with a function call, we'd
	// check for overflow now.

	// check for zero result.

	CC = R1 == 0;
	IF CC R0 = R1;
	IF CC JUMP finished;

	// If signs had differed, change sign of result.
	CC = R7 < 0;
	R2 = -R1;
	IF CC R1 = R2;
#if defined(__WORKAROUND_SIGNBITS) || defined(__WORKAROUND_DREG_COMP_LATENCY)
	NOP;
#endif
	// Now normalise
	R2.L = SIGNBITS R1;
	R2 = R2.L (X);
	R1 <<= R2;
	R0 = R0 - R2;

finished:
	SP += 12;
	(R7:6) = [SP++];
	UNLINK;
	RTS;

div_by_zero:
	(R7:6) = [SP++];
	UNLINK;
	R1 = 0;
	R0 = R1;
	BITSET(R0, 31);	// 0x8000000000000
	RTS;
._div_fl32.end:
.global _div_fl32;
.type _div_fl32, STT_FUNC;
