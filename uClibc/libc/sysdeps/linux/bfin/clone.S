/* Adapted from glibc */
/* Copyright (C) 1996, 1997 Free Software Foundation, Inc. */

/* clone is even more special than fork as it mucks with stacks
   and invokes a function in the right context after its all over.  */

#include <asm/errno.h>
#include <sys/syscall.h>

/* int _clone(int (*fn)(void *arg), void *child_stack, int flags, void *arg); */

.text
.align 4
.type	___clone,STT_FUNC;
.globl	___clone;
___clone:
	/* Sanity check arguments.  */
	R0 = -EINVAL;
	R1 = [SP+4];
	cc = R1 == 0;
	if cc jump __syscall_error;
	R1 = [SP+8];
	CC = R1 == 0;
	if cc jump __syscall_error;
	
	R1 = [SP+16];
	R0 = [SP+12];
	R5 = __NR_clone;
	EXCPT 0;
	JUMP.L thread_start;
	RTS;

thread_start:
	R5 = __NR_exit;
	EXCPT 0;


