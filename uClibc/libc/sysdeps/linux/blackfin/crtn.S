/*	.file	"initfini.c"*/
	.section .init
	.align	2
	.globl	_init
	.type	_init, STT_FUNC;
	rts;
	.size	_init, .-_init
	
	.section .fini
	.align	2
	.globl	_fini
	.type	_fini, STT_FUNC;
	rts;
	.size	_fini, .-_fini
	
	.ident	"GCC: (GNU) 3.3.2"
