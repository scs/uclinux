/*
** Float32 abs
*/

.section program;
.align 2;
_abs_fl32:
	R1 = ABS R1;
	RTS;
._abs_fl32.end:
.global _abs_fl32;
.type _abs_fl32, STT_FUNC;
