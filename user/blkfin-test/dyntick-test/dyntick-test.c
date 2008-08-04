/*
 * Tests timers to make sure dynamic tick works properly
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>

#define MAX_SLEEP	(10)		/* seconds */
#define MAX_LATENCY	(100 * 1000)	/* usecs */

int test_sleep(unsigned int msec_len)
{
	sleep(msec_len / 1000);
	return 0;
}

int test_select(unsigned int msec_len)
{
	struct timeval tv_sel;

	tv_sel.tv_sec = msec_len / 1000;
	tv_sel.tv_usec = (msec_len % 1000) * 1000;

	return select(0, NULL, NULL, NULL, &tv_sel);
}

int test_usleep(unsigned int msec_len)
{
	usleep(msec_len * 1000);
}

/* This modified from some GNU exsample _not_ to hose y */
int timeval_subtract(struct timeval *result,
		     const struct timeval *x,
		     const struct timeval *y)
{
	struct timeval tmp;

	tmp.tv_sec = y->tv_sec;
	tmp.tv_usec = y->tv_usec;

	/* Perform the carry for the later subtraction */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		tmp.tv_usec -= 1000000 * nsec;
		tmp.tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		tmp.tv_usec += 1000000 * nsec;
		tmp.tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	   tv_usec is certainly positive. */
	result->tv_sec = x->tv_sec - tmp.tv_sec;
	result->tv_usec = x->tv_usec - tmp.tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < tmp.tv_sec;
}

int do_test(char * name, int (* test)(unsigned int len),
	    unsigned int len, int count)
{
	int i, ret;
	struct timeval tv_in;
	struct timeval tv_beg;
	struct timeval tv_end;
	struct timeval tv_len;
	struct timeval tv_lat;
	struct timezone tz;
	char * status = "OK";
	char * latency_type = "";

	tv_in.tv_sec = len / 1000;
	tv_in.tv_usec = (len % 1000) * 1000;

	gettimeofday(&tv_beg, &tz);
	for (i = 0; i < count; i++) {
		ret = test(len);
	}
	gettimeofday(&tv_end, &tz);

	ret = timeval_subtract(&tv_len, &tv_end, &tv_beg);
	if (ret)
		status = "ERROR";

	ret = timeval_subtract(&tv_lat, &tv_len, &tv_in);
	if (ret) {
		latency_type = "-";
		timeval_subtract(&tv_lat, &tv_in, &tv_len);
	}

	if (tv_lat.tv_sec > 0 || tv_lat.tv_usec > MAX_LATENCY)
		status = "ERROR";

	printf("  Test: %6s %4ums time: %2u.%06us "
	       "latency: %1s%u.%06us status: %s\n",
	       name,
	       (len * count),
	       (unsigned int)tv_len.tv_sec,
	       (unsigned int)tv_len.tv_usec,
	       latency_type,
	       (unsigned int)tv_lat.tv_sec,
	       (unsigned int)tv_lat.tv_usec,
	       status);

	return ret;
}

int main(void)
{
	unsigned int i;
	int max_secs = MAX_SLEEP;

	printf("Testing sub-second select and usleep\n");
	for (i = 0; i < 1000; i += 100) {
		do_test("select", test_select, i, 1);
		do_test("usleep", test_usleep, i, 1);
	}

	printf("Testing multi-second select and sleep\n");
	for (i = 0; i < max_secs; i++) {
		do_test("select", test_select, i * 1000, 1);
		do_test("sleep", test_sleep, i * 1000, 1);
	}

	return 0;
}
