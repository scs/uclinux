#include <stdio.h>
#include "helloworld.h"

static int ret __attribute__((l2));

int testl2(int i) __attribute__((l2));

int testl2(int i)
{
	ret=i+1;
	return ret;
}

int main(int argc, char *argv[])
{
	int r;
	r=helloworld("hello\n");
	/* Check for instruction address */
	printf("[INS] get %d from helloworld(0x%x):", r, ((unsigned long *)helloworld)[0]);
	if (((((unsigned long *)helloworld)[0]) > TEST_L2_HIGH) || \
			((((unsigned long *)helloworld)[0]) < TEST_L2_LOW)) {
		printf("	TEST FAIL\n");
	} else {
		printf("	TEST PASS\n");
	}

	r=testl2(10);
	printf("[INS] get %d from testl2(0x%x):", r, ((unsigned long *)testl2)[0]);
	if (((((unsigned long *)testl2)[0]) > TEST_L2_HIGH) || \
			((((unsigned long *)testl2)[0]) < TEST_L2_LOW)) {
		printf("	TEST FAIL\n");
	} else {
		printf("	TEST PASS\n");
	}
	printf("[DATA] global data ret at 0x%x:", &ret);
	if (((unsigned long)&ret > TEST_L2_HIGH) || ((unsigned long)&ret < TEST_L2_LOW)) {
		printf("	TEST FAIL\n");
	} else {
		printf("	TEST PASS\n");
	}
	printf("[INS] main at 0x%x:", ((unsigned long *)main)[0]);
	if (((((unsigned long *)main)[0]) < TEST_L2_HIGH) && \
			((((unsigned long *)main)[0]) > TEST_L2_LOW)) {
		printf("	TEST FAIL\n");
	} else {
		printf("	TEST PASS\n");
	}
		
	return  0;
}
