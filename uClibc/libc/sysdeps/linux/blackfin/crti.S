// gcc version 2.95.3 20010315 (release) nisa version 1.0.0 opt -O0
gcc_compiled$:

.text;
.align 2
.global _dummy;
.type _dummy, STT_FUNC;
_dummy:
	LINK 4;
	[--sp] = ( p5:5 );
	[FP +-4] =R0 ;
	R0  =[FP +-4];
	cc =R0 ==0;
	if cc jump L$L$3;
	P5  =[FP +-4];
	call (P5 );
L$L$3:
L$L$2:
	( p5:5 ) = [sp++];
	UNLINK;
	rts;

	
.align 2
.type _call_gmon_start, STT_FUNC;
_call_gmon_start:
	LINK 4;
	[--sp] = ( p5:5 );
	R0.L  = ___gmon_start__; R0.H  = ___gmon_start__;
	[FP +-4] =R0 ;
	R0  =[FP +-4];
	cc =R0 ==0;
	if cc jump L$L$5;
	P5  =[FP +-4];
	call (P5 );
L$L$5:
L$L$4:
	( p5:5 ) = [sp++];
	UNLINK;
	rts;


	.section .init
.align 2
.global _init;
.type _init, STT_FUNC;
_init:
	LINK 0;
	call _call_gmon_start;
	
	.section .init
L$L$6:
	UNLINK;
	rts;
	
	.section .fini
.align 2
.global _fini;
.type _fini, STT_FUNC;
_fini:
	LINK 0;
	
	call _i_am_not_a_leaf;
	
	.section .fini
L$L$7:
	UNLINK;
	rts;
	
