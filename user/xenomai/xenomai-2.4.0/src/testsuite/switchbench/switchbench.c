/*
   Task switch latency test.
   Max Krasnyansky <maxk@qualcomm.com

   Based on latency.c by Philippe Gerum <rpm@xenomai.org>
 */

#include <sys/mman.h>
#include <unistd.h>
#include <stdlib.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <native/task.h>
#include <native/timer.h>
#include <native/sem.h>

RT_TASK event_task, worker_task;

RT_SEM switch_sem;
RTIME  switch_tsc;
unsigned long long switch_count;

long long minjitter = 10000000;
long long maxjitter = -10000000;
long long avgjitter = 0;
long long lost = 0;
long long nsamples = 100000;
long long sampling_period = 100000;

#define HISTOGRAM_CELLS 100

unsigned long histogram[HISTOGRAM_CELLS];

int do_histogram = 0;
int ignore = 5;

static inline void add_histogram(long addval)
{
	/* usec steps */
	long inabs = rt_timer_tsc2ns(addval >= 0 ? addval : -addval) / 1000;
	histogram[inabs < HISTOGRAM_CELLS ? inabs : HISTOGRAM_CELLS - 1]++;
}

void dump_stats(double sum, int total_hits)
{
	int n;
	double avg, variance = 0;

	avg = sum / total_hits;
	for (n = 0; n < HISTOGRAM_CELLS; n++) {
		long hits = histogram[n];
		if (hits)
			variance += hits * (n-avg) * (n-avg);
	}

	/* compute std-deviation (unbiased form) */
	variance /= total_hits - 1;
	variance = sqrt(variance);
	
	printf("HSS| %9d| %10.3f| %10.3f\n", total_hits, avg, variance);
}

void dump_histogram(void)
{
	int n, total_hits = 0;
	double sum = 0;
	fprintf(stderr, "---|---range-|---samples\n");
	for (n = 0; n < HISTOGRAM_CELLS; n++) {
		long hits = histogram[n];
		if (hits) {
			total_hits += hits;
			sum += n * hits;
			fprintf(stderr, "HSD| %d - %d | %10ld\n",
				n, n + 1, hits);
		}
	}
	dump_stats(sum, total_hits);
}

void event(void *cookie)
{
       int err;

       err = rt_task_set_periodic(NULL,
                                  TM_NOW,
                                  rt_timer_ns2ticks(sampling_period));
       if (err) {
               fprintf(stderr,"switch: failed to set periodic, code %d\n", err);
               return;
       }

       for (;;) {
               err = rt_task_wait_period(NULL);
               if (err) {
                       if (err != -ETIMEDOUT) {
                               /* Timer stopped. */
                               rt_task_delete(NULL);
                       }
               }

               switch_count++;
               switch_tsc = rt_timer_tsc();

               rt_sem_broadcast(&switch_sem);
       }
}

void worker(void *cookie)
{
       long long minj = 10000000, maxj = -10000000, dt, sumj = 0;
       unsigned long long count = 0;
       int err, n;

       err = rt_sem_create(&switch_sem, "dispsem", 0, S_FIFO);
       if (err) {
               fprintf(stderr,"switch: cannot create semaphore: %s\n",
                      strerror(-err));
               return;
       }

       for (n=0; n<nsamples; n++) {
               err = rt_sem_p(&switch_sem, TM_INFINITE);
               if (err) {
                       if (err != -EIDRM)
                               fprintf(stderr,"switch: failed to pend on semaphore, code %d\n", err);

                       rt_task_delete(NULL);
               }

               if (++count != switch_count) {
                       count = switch_count;
                       lost++;
                       continue;
               }

               // First few switches are slow.
               // Probably due to the Linux <-> RT context migration at task startup.
               if (count < ignore)
                       continue;

               dt = (long) (rt_timer_tsc() - switch_tsc);
               if (dt > maxj)
                       maxj = dt;
               if (dt < minj)
                       minj = dt;
               sumj += dt;

               if (do_histogram)
                       add_histogram(dt);
       }

       rt_sem_delete(&switch_sem);

       minjitter = minj;
       maxjitter = maxj;
       avgjitter = sumj / n;

       printf("RTH|%12s|%12s|%12s|%12s\n",
                      "lat min", "lat avg", "lat max", "lost");

       printf("RTD|%12.3f|%12.3f|%12.3f|%12lld\n",
                      rt_timer_tsc2ns(minjitter) / 1000.0,
                      rt_timer_tsc2ns(avgjitter) / 1000.0,
                      rt_timer_tsc2ns(maxjitter) / 1000.0, lost);

       if (do_histogram)
               dump_histogram();

       exit(0);
}

int main(int argc, char **argv)
{
       int err, c;

       while ((c = getopt(argc, argv, "hp:n:i:")) != EOF)
               switch (c) {
               case 'h':
                       /* ./switch --h[istogram] */
                       do_histogram = 1;
                       break;

               case 'p':
                       sampling_period = atoi(optarg) * 1000;
                       break;

               case 'n':
                       nsamples = atoi(optarg);
                       break;

               case 'i':
                       ignore = atoi(optarg);
                       break;

               default:

                       fprintf(stderr, "usage: switch [options]\n"
                               "\t-h             - enable histogram\n" 
                               "\t-p <period_us> - timer period\n"
                               "\t-n <samples>   - number of samples to collect\n"
                               "\t-i <samples>   - number of _first_ samples to ignore\n");
                       exit(2);
               }

       if (sampling_period == 0)
               sampling_period = 100000;	/* ns */

       if (nsamples <= 0) {
	       fprintf(stderr, "disregarding -n <%lld>, using -n <100000> "
		       "samples\n", nsamples);
               nsamples = 100000;
       }

       signal(SIGINT, SIG_IGN);
       signal(SIGTERM, SIG_IGN);

       setlinebuf(stdout);

       mlockall(MCL_CURRENT|MCL_FUTURE);
       
       printf("== Sampling period: %llu us\n", sampling_period / 1000);
       printf("== Do not interrupt this program\n");

       rt_timer_set_mode(TM_ONESHOT); /* Force aperiodic timing. */

       err = rt_task_create(&worker_task, "worker", 0, 98, T_FPU);
       if (err) {
               fprintf(stderr,"switch: failed to create worker task, code %d\n", err);
               return 1;
       }

       err = rt_task_start(&worker_task, &worker, NULL);
       if (err) {
               fprintf(stderr,"switch: failed to start worker task, code %d\n", err);
               return 1;
       }

       err = rt_task_create(&event_task, "event", 0, 99, 0);
       if (err) {
               fprintf(stderr,"switch: failed to create event task, code %d\n", err);
               return 1;
       }

       err = rt_task_start(&event_task, &event, NULL);
       if (err) {
               fprintf(stderr,"switch: failed to start event task, code %d\n", err);
               return 1;
       }

       pause();

       return 0;
}
