/*
** Float32 negate
*/

.text;
.align 2;
_negate_fl32:
	R1 = -R1;
	RTS;
._negate_fl32.end:
.global _negate_fl32;
.type _negate_fl32, STT_FUNC;
