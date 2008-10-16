#include <stdio.h>
#include "helloworld.h"

static int ret __attribute__((l1_data_A));

int testl1(int i) __attribute__((l1_text));

int testl1(int i)
{
	ret=i+1;
	return ret;
}

int main(int argc, char *argv[])
{
	int r;
	r=helloworld("hello\n");

        unsigned long mask=1;  //only run on core A
        sched_setaffinity(getpid(), sizeof(mask), &mask);

	/* Check for instruction address */
	printf("[INS] get %d from helloworld(0x%x):", r, ((unsigned long *)helloworld)[0]);
	if (((((unsigned long *)helloworld)[0]) > TEST_INS_CACHE_HIGH) || \
			((((unsigned long *)helloworld)[0]) < TEST_INS_CACHE_LOW)) {
		printf("	TEST FAIL\n");
	} else {
		printf("	TEST PASS\n");
	}

	r=testl1(10);
	printf("[INS] get %d from testl1(0x%x):", r, ((unsigned long *)testl1)[0]);
	if (((((unsigned long *)testl1)[0]) > TEST_INS_CACHE_HIGH) || \
			((((unsigned long *)testl1)[0]) < TEST_INS_CACHE_LOW)) {
		printf("	TEST FAIL\n");
	} else {
		printf("	TEST PASS\n");
	}
	printf("[DATA] global data ret at 0x%x:", &ret);
	if (((unsigned long)&ret > TEST_DATA_CACHE_HIGH) || ((unsigned long)&ret < TEST_DATA_CACHE_LOW)) {
		printf("	TEST FAIL\n");
	} else {
		printf("	TEST PASS\n");
	}
	printf("[INS] main at 0x%x:", ((unsigned long *)main)[0]);
	if (((((unsigned long *)main)[0]) < TEST_INS_CACHE_HIGH) && \
			((((unsigned long *)main)[0]) > TEST_INS_CACHE_LOW)) {
		printf("	TEST FAIL\n");
	} else {
		printf("	TEST PASS\n");
	}
		
	return  0;
}
