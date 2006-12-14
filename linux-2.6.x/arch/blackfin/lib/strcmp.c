
int strcmp(const char *cs, const char *ct)
{
	char __res1, __res2;

	__asm__
       ("1:\t%2 = B[%0++] (Z);\n\t" /* get *cs */
		"%3 = B[%1++] (Z);\n\t"	/* get *ct */
		"CC = %2 == %3;\n\t"	/* compare a byte */
		"if ! cc jump 2f;\n\t"	/* not equal, break out */
		"CC = %2;\n\t"	/* at end of cs? */
		"if cc jump 1b (bp);\n\t"	/* no, keep going */
		"jump.s 3f;\n"	/* strings are equal */
		"2:\t%2 = %2 - %3;\n"	/* *cs - *ct */
        "3:\n"
	: "+&a" (cs), "+&a" (ct), "=&d" (__res1), "=&d" (__res2)
      : :	"CC");

	return __res1;
}

