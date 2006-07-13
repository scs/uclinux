/*************************************************************************
 * dot.c
 *
 * based on : David Rowe <http://www.rowetel.com/blog/?p=5>
 *            11/5/06
 *
 * Test program to measure execution cycles of signal processing operations
 * on the Blackfin.  Thanks to Jean-Marc Valin of Speex for helping with
 * Blackfin code samples and comments.
 *
 * Changed a bit by Robin Getz <rgetz@blackfin.uclinux.org>
 *
 **************************************************************************
 * Distributed under the GPL
 */

#include <stdio.h>

#define N 100			/* size of vectors                           */
#define M 10			/* number of times to repeat tests           */

int before;			/* cycle counter value just before test loop */
int after;			/* cycle counter value just after test loop  */

/* find dot product of two vectors, C version */

int dot_generic(short *x, short *y, int len)
{
	int i, dot;

	dot = 0;
	for (i = 0; i < len; i++)
		dot += x[i] * y[i];

	return dot;
}

/* find dot product of two vectors */

int dot_asm(short *x, short *y, int len)
{
	int dot;

	/*
	 * Isn't it cool how you can mix C and assembler?  And gcc just
	 * takes care of all the fiddly little details.  
	 * Very nice 
	 */

	__asm__("I0 = %3;\n\t" 
		"I1 = %4;\n\t" 
		"A1 = A0 = 0;\n\t" 
		"R0 = [I0++] || R1 = [I1++];\n\t" 
		"LOOP dot%= LC0 = %5 >> 1;\n\t" 
		"LOOP_BEGIN dot%=;\n\t" 
		"A1 += R0.H * R1.H, A0 += R0.L * R1.L || R0 = [I0++] || R1 = [I1++];\n\t" 
		"LOOP_END dot%=;\n\t" 
		"R0 = (A0 += A1);\n\t" 
		"%0 = R0 >> 1;\n\t"	/* correct for left shift during multiply */
      		: "=&d"(dot), "=&d"(before), "=&d"(after)
		: "a"(x), "a"(y), "a"(len)
      		: "I0", "I1", "A1", "A0", "R0", "R1");
	return dot;
}


/* 
 * find dot product of two vectors, built in cycles measurement
 */
int dot_asm_cycles(short *x, short *y, int len)
{
	int dot;

	__asm__("I0 = %3;\n\t" 
		"I1 = %4;\n\t"
		"A1 = A0 = 0;\n\t" 
		"R0 = [I0++] || R1 = [I1++];\n\t" 
		"R2 = CYCLES;\n\t" 
		"%1 = R2;\n\t" 
		"LOOP dot%= LC0 = %5 >> 1;\n\t" 
		"LOOP_BEGIN dot%=;\n\t" 
		"A1 += R0.H * R1.H, A0 += R0.L * R1.L || R0 = [I0++] || R1 = [I1++];\n\t" 
		"LOOP_END dot%=;\n\t" 
		"R2 = CYCLES;\n\t" 
		"%2 = R2;\n\t" 
		"R0 = (A0 += A1);\n\t" 
		"%0 = R0 >> 1;\n\t"	/* correct for left shift during multiply */
		: "=&d"(dot), "=&d"(before), "=&d"(after)
		: "a"(x), "a"(y), "a"(len)
		: "I0", "I1", "A1", "A0", "R0", "R1", "R2");

	return dot;
}

/* C-callable function to return value of CYCLES register */

int cycles()
{
	int ret;

	__asm__ __volatile__("%0 = CYCLES;\n\t"
		:"=d"(ret));

	return ret;
}

int test0(void)
{
	int k;
	unsigned int before, after;
	unsigned int time[M];

	for (k = 0; k < M; k++) {
		before = cycles();
		after = cycles();
		time[k] = after - before;
	}

	printf("Test 0: Cycles only\n");
	for (k = 0; k < M; k++)
		printf("%u ", time[k]);
	printf("\n");
	return time[k];
}

int test1()
{
	short x[N];
	short y[N];
	int i, k, ret;
	unsigned int before, after;
	unsigned int time[M];

	for (i = 0; i < N; i++) {
		x[i] = 1;
		y[i] = 1;
	}

	for (k = 0; k < M; k++) {
		before = cycles();
		ret = dot_generic(x, y, N);
		after = cycles();
		time[k] = after - before;
	}

	printf("Test 1: Vanilla C\n");
	printf("  ret = %d: run time:\n  ", ret);
	for (k = 0; k < M; k++)
		printf("%u ", time[k]);
	printf("\n");
	return ret;
}

int test2()
{
	short x[N];
	short y[N];
	int i, k, ret;
	unsigned int before, after;
	unsigned int time[M];

	for (i = 0; i < N; i++) {
		x[i] = 1;
		y[i] = 1;
	}

	for (k = 0; k < M; k++) {
		before = cycles();
		ret = dot_asm(x, y, N);
		after = cycles();
		time[k] = after - before;
	}

	printf("Test 2: data in external memory, outboard cycles function\n");
	printf("  ret = %d: run time:\n  ", ret);
	for (k = 0; k < M; k++)
		printf("%u ", time[k]);
	printf("\n");
	return ret;
}

int test3()
{
	short x[N];
	short y[N];
	int i, k, ret;
	unsigned int time[M];

	for (i = 0; i < N; i++) {
		x[i] = 1;
		y[i] = 1;
	}

	for (k = 0; k < M; k++) {
		ret = dot_asm_cycles(x, y, N);
		time[k] = after - before;
	}

	printf("Test 3: data in external memory, inboard cycles\n");
	printf("  ret = %d: run time:\n ", ret);
	for (k = 0; k < M; k++)
		printf("%u ", time[k]);
	printf("\n");
	return ret;
}

int test4()
{
	/* I know, I know - this is very naughty :-) */
	short *x = (short *)0xff904000 - N * sizeof(short);	/* Top of Data B SRAM */
	short *y = (short *)0xff804000 - N * sizeof(short);	/* Top of Data A SRAM */

	int i, k, ret;
	unsigned int time[M];

	for (i = 0; i < N; i++) {
		x[i] = 1;
		y[i] = 1;
	}

	for (k = 0; k < M; k++) {
		ret = dot_asm_cycles(x, y, N);
		time[k] = after - before;
	}

	printf("Test 4: data in internal memory, inboard cycles\n");
	printf("  ret = %d: run time:\n  ", ret);
	for (k = 0; k < M; k++)
		printf("%u ", time[k]);
	printf("\n");
	return ret;
}

int main(void)
{
	printf("Theoretical best case is N/2 = %d cycles\n", N / 2);
asm("foo0:\n");
	test0();
asm("foo1:\n");
	test1();
asm("foo2:\n");
	test2();
asm("foo3:\n");
	test3();
asm("foo4:\n");
	test4();
asm("foo5:\n");
asm("fooa:\n");
	test0();
asm("foob:\n");
	test1();
asm("fooc:\n");
	test2();
asm("food:\n");
	test3();
asm("fooe:\n");
	test4();
asm("foof:\n");

	return 0;
}
