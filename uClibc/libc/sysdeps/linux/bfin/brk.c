
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>

/* This must be initialized data because commons can't have aliases.  */
void * ___brk_addr = 0;

int brk (void *addr)
{
    void *newbrk;

	__asm__ __volatile__(
		"P0 = %2;\n\t"
		"R0 = %1;\n\t"
		"excpt 0;\n\t"
		"%0 = R0;\n\t"
		: "=r"(newbrk)
		: "r"(addr), "i" (__NR_brk): "P0" );

    ___brk_addr = newbrk;

    if (newbrk < addr)
    {
	__set_errno (ENOMEM);
	return -1;
    }

    return 0;
}
