#include <linux/types.h>

int strncmp(const char *cs, const char *ct, size_t count)
{
	char __res1, __res2;

	if (!count)
		return 0;
	__asm__
       ("1:\t%3 = B[%0++] (Z);\n\t"        /* get *cs */
		"%4 = B[%1++] (Z);\n\t"	/* get *ct */
		"CC = %3 == %4;\n\t"	/* compare a byte */
		"if ! cc jump 3f;\n\t"	/* not equal, break out */
		"CC = %3;\n\t"	/* at end of cs? */
		"if ! cc jump 4f;\n\t"	/* yes, all done */
		"%2 += -1;\n\t"	/* no, adjust count */
	"CC = %2 == 0;\n\t"
        "if ! cc jump 1b;\n"                 /* more to do, keep going */
		"2:\t%3 = 0;\n\t"	/* strings are equal */
        "jump.s    4f;\n"
        "3:\t%3 = %3 - %4;\n"          /* *cs - *ct */
        "4:"
	: "+&a" (cs), "+&a" (ct), "+&da" (count), "=&d" (__res1), "=&d" (__res2)
      : :	"CC");
	return __res1;
}

