
char *strcpy(char *dest, const char *src)
{
	char *xdest = dest;
	char temp = 0;

	__asm__ __volatile__
	    ("1:\t%2 = B [%1++] (Z);\n\t"
	     "B [%0++] = %2;\n\t"
	     "CC = %2;\n\t"
        "if cc jump 1b (bp);\n"
	: "+&a" (dest), "+&a" (src), "=&d" (temp)
	     ::"memory", "CC");
	return xdest;
}

