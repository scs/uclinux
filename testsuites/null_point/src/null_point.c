#include <stdio.h>

int main ()
{
	int * p = NULL;
	printf("No null point check: *p is %d\n", *p);

	return 0;
}
