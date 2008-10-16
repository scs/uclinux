#include <stdio.h>

int helloworld(char *str) __attribute__ ((l2));

int helloworld(char *str)
{
	int i,r;
	i = 0;
	r = i+2;
	printf("%s", str);
	return r;
}

