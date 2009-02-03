#include <sys/time.h>
#include <sys/resource.h>
#include <math.h>
#include <stdio.h>
#include "edn.h"
#include "data.h"

/* seconds that each loop should run */
#define LOOPS 10

double timeval_subtract (struct timeval x, struct timeval y)
{
	struct timeval result;
	double expired;

	/* Perform the carry for the later subtraction by updating y. */
	if (x.tv_usec < y.tv_usec) {
		int nsec = (y.tv_usec - x.tv_usec) / 1000000 + 1;
		y.tv_usec -= 1000000 * nsec;
		y.tv_sec += nsec;
	}

	if (x.tv_usec - y.tv_usec > 1000000) {
		int nsec = (x.tv_usec - y.tv_usec) / 1000000;
		y.tv_usec += 1000000 * nsec;
		y.tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
		tv_usec is certainly positive. */
	result.tv_sec = x.tv_sec - y.tv_sec;
	result.tv_usec = x.tv_usec - y.tv_usec;

	expired = fabs((float)result.tv_sec + ((float)result.tv_usec)/1000000.0);

	return expired;
}

#define time_func(funct) 					\
{							\
	struct rusage start, stop;			\
	long count=0, i;				\
	double expired_time;				\
										\
	printf("testing \"" #funct "\"\n");							\
	/* Do two things - make cache hot, and see how many loops in		\
	 * 1 second */								\
	getrusage(RUSAGE_SELF, &start);						\
	while (1) {								\
		count++;							\
		funct;						\
		getrusage(RUSAGE_SELF, &stop);					\
		if (timeval_subtract(stop.ru_utime, start.ru_utime) >= 1.0)	\
			break;							\
	}									\
										\
	/* Do things about n seconds worth, and time it */			\
	getrusage(RUSAGE_SELF, &start);						\
	for (i = 0; i < count * LOOPS ; i++) {					\
		funct;						\
	}									\
	getrusage(RUSAGE_SELF, &stop);						\
	expired_time = timeval_subtract(stop.ru_utime, start.ru_utime);		\
										\
printf("  Did %li loops in %f seconds : useconds per loop = %f\n", (count * LOOPS), \
	 expired_time, (expired_time*1000000) / (count * LOOPS));		\
										\
}

int main(void)
{
	short c = 0x3;
	short output[200];
	long int d = 0xAAAA;
	int e[1] = {0xEEEE};

	/*
         * Declared as memory variable so it doesn't get optimized out
         */

	time_func(vec_mpy1(a, b, c));

	time_func(c = mac(a, b, (long int) c, (long int *) output));

	time_func(fir(a, b, output));

	time_func(fir_no_red_ld(a, b, output));

	time_func(d = latsynth(a, b, N, d));

	time_func(iir1(a, b, &output[100], output));

	time_func(e[0] = codebook(d, 1, 17, e[0], d, a, c, 1));

	time_func(jpegdct(a, b));

	return 0;
}

