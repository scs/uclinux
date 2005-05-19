
	.section .init
	SP += 12;
	(R7:0,P5:0) = [SP++]; 
	UNLINK;
	rts;
	.size	_init, .-_init

	.section .fini
	SP += 12;
	(R7:0,P5:0) = [SP++]; 
	UNLINK;
	rts;
	.size	_fini, .-_fini
	.ident	"GCC: (GNU) 3.4.1"
