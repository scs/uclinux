#include <stdio.h>
#include <stdlib.h>
#include "helloworld.h"

int test()
{
	int in;
	in = 2;
	printf("[STACK] get internal variable in at [0x%x]:", &in);
	if (((unsigned long)&in > TEST_STACK_CACHE_HIGH) || \
			((unsigned long)&in < TEST_STACK_CACHE_LOW)) {
		printf("	TEST FAIL\n");
	} else {
		printf("	TEST PASS\n");
	}
	return(0);
}

int main()
{
	test();
	exit(0);
}
