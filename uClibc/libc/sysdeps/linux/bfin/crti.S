.file "initfini.c";

	.section .init
.global _init;
.type _init, STT_FUNC;
.align 2
_init:
	LINK 0;
	[SP--] = (R7:0,P5:0)
	SP += -12;

	.section .fini
.global _init;
.type _fini, STT_FUNC;
	.align 2
_fini:
	LINK 0;
	[SP--] = (R7:0,P5:0)
	SP += -12;
