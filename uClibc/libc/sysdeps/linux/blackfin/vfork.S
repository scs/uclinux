
#include <asm/unistd.h>
	.text
	.globl _vfork
	.type	 _vfork,STT_FUNC;
	.align 4
_vfork:
	[--sp] = r5;
	r5 = __NR_vfork;
	excpt 0;
	r5 = [sp++];
	rts;
