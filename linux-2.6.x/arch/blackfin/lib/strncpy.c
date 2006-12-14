#include <linux/types.h>

char *strncpy(char *dest, const char *src, size_t n)
{
	char *xdest = dest;
	char temp = 0;

	if (n == 0)
		return xdest;

	__asm__ __volatile__
	    ("1:\t%3 = B [%1++] (Z);\n\t"
	     "B [%0++] = %3;\n\t"
	     "CC = %3;\n\t"
	     "if ! cc jump 2f;\n\t"
	     "%2 += -1;\n\t"
	     "CC = %2 == 0;\n\t"
	     "if ! cc jump 1b (bp);\n"
        "2:\n"
	: "+&a" (dest), "+&a" (src), "+&da" (n), "=&d" (temp)
	     ::"memory", "CC");
	return xdest;
}

