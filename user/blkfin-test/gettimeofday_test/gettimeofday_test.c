/*
 *  Author: Aidan Williams <aidan@nicta.com.au>
 *  Copyright 2005 National ICT Australia (NICTA)
 *  Copyright (C) 2008, Analog Devices. All Rights Reserved
 *  Licensed under the GPL-2 or later
 */

#include <stdio.h>
#include <sys/time.h>


/*
 *  Return the difference between two struct timevals in microseconds
 */
long tvdelta(struct timeval *t1, struct timeval *t2)
{
	long delta, usec;

	delta = 1000000 * (t1->tv_sec - t2->tv_sec);
	usec = t1->tv_usec;
	if (t1->tv_usec < t2->tv_usec) {
		usec  += 1000000;
		delta -= 1000000;
	}
	delta += (usec - t2->tv_usec);

	return delta;
}


int main(int argc, char *argv[])
{
	struct timeval t, o;
	long delta, min = 100000, max = 0, avg = 0;
	long cnt = 0, fw = 0, bw = 0;

	gettimeofday(&o, NULL);

	while(++cnt < 500000)
	{
		gettimeofday(&t, NULL);

		delta = tvdelta(&t, &o);
		if (delta < 0) {
			printf("%lu.%06lu %lu.%06lu %ld\n",
				t.tv_sec, t.tv_usec,
				o.tv_sec, o.tv_usec,
				delta);
			++bw;
		} else {
			if(delta < min)
				min = delta;
			if(delta > max)
				max = delta;
					
			avg += delta;

			++fw;
		}

		o.tv_sec = t.tv_sec;
		o.tv_usec = t.tv_usec;

	}

	printf("%ld forward, %ld backward\n", fw, bw);
	printf("delta min/avg/max %ld/%ld/%ld\n", min, (avg / fw), max);

	return 0;
}
