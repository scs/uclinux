
/*
 * latency.c: Copied from Xenomai test case - changed for normal Linux 
 */

#include <sys/mman.h>
#include <sys/time.h>
#include <unistd.h>
#include <stdlib.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <time.h>
#include <semaphore.h>
#include <pthread.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include "timerbench.h"

pthread_t latency_task, display_task;
sem_t display_sem;

#define ONE_BILLION  1000000000
#define TEN_MILLION    10000000
#define MAX_DEVNAME_LEN 30

long minjitter, maxjitter, avgjitter;
long gminjitter = TEN_MILLION, gmaxjitter = -TEN_MILLION, goverrun = 0;
long long gavgjitter = 0;

long long period_ns = 0;
int test_duration = 0;		/* sec of testing, via -T <sec>, 0 is inf */
int data_lines = 21;		/* data lines per header line, -l <lines> to change */
int quiet = 0;			/* suppress printing of RTH, RTD lines when -T given */
int benchdev_no = 0;
int benchdev = -1;
int freeze_max = 0;
int priority = 99;

#define USER_TASK       0
#define KERNEL_TASK     1
#define TIMER_HANDLER   2

int test_mode = USER_TASK;
const char *test_mode_names[] = {
	"periodic user-mode task",
	"in-kernel periodic task",
	"in-kernel timer handler"
};

time_t test_start, test_end;	/* report test duration */
int test_loops = 0;		/* outer loop count */
unsigned long cclk = 0;

#define MEASURE_PERIOD ONE_BILLION
#define SAMPLE_COUNT (MEASURE_PERIOD / period_ns)

/* Warmup time : in order to avoid spurious cache effects on low-end machines. */
#define WARMUP_TIME 1
#define HISTOGRAM_CELLS 100
int histogram_size = HISTOGRAM_CELLS;
long *histogram_avg = NULL, *histogram_max = NULL, *histogram_min = NULL;

int do_histogram = 0, do_stats = 0, finished = 0;
int bucketsize = 1000;		/* default = 1000ns, -B <size> to override */

#define read_tsc(t)					\
	({							\
	unsigned long __cy2;					\
	__asm__ __volatile__ (	"1: %0 = CYCLES2\n"		\
				"%1 = CYCLES\n"			\
				"%2 = CYCLES2\n"		\
				"CC = %2 == %0\n"		\
				"if ! CC jump 1b\n"		\
				:"=r" (((unsigned long *)&t)[1]),	\
				"=r" (((unsigned long *)&t)[0]),	\
				"=r" (__cy2)				\
				: /*no input*/ : "CC");			\
	t;								\
	})

static inline long tb_ns2tsc(long ns)
{
	return ( (ns / 1000) * (cclk / 1000000));
}

static inline long tb_tsc2ns(long tsc)
{
	return ((tsc) / (cclk / 1000000) * 1000);
}

static int tb_timer_start(long long start_tsc, long long period_tsc)
{
	struct timer_info timer_info;

	timer_info.start_tsc = start_tsc;
	timer_info.period_tsc = period_tsc;
	ioctl(benchdev, RTTST_TMR_START, &timer_info);
	return 0;
}

static int tb_timer_wait(void)
{
	int err;
	err = ioctl(benchdev, RTTST_TMR_WAIT, NULL);
	return err; 
}

static int tb_timer_stop(void)
{
	ioctl(benchdev, RTTST_TMR_STOP, NULL);
	return 0;
}

static inline void add_histogram(long *histogram, long addval)
{
	/* bucketsize steps */
	long inabs =
	    tb_tsc2ns(addval >= 0 ? addval : -addval) / bucketsize;
	histogram[inabs < histogram_size ? inabs : histogram_size - 1]++;
}

void* latency(void *cookie)
{
	int err, count, nsamples, warmup = 1;
	long long tsc, expected_tsc, period_tsc;
	
	nsamples = ONE_BILLION / period_ns;
	period_tsc = tb_ns2tsc(period_ns);
	/* start time: one millisecond from now. */
	read_tsc(tsc);
	expected_tsc = tsc + tb_ns2tsc(1000000);

	err =
	    tb_timer_start(expected_tsc, tb_ns2tsc(period_ns));

	for (;;) {
		long minj = TEN_MILLION, maxj = -TEN_MILLION, dt;
		long overrun = 0;
		long long sumj;
		test_loops++;

		for (count = sumj = 0; count < nsamples; count++) {
			unsigned long ov;

			expected_tsc += period_tsc;
			err = tb_timer_wait();
			read_tsc(tsc);
			dt = (long)(tsc - expected_tsc);
			if (dt > maxj)
				maxj = dt;
			if (dt < minj)
				minj = dt;
			sumj += dt;

			if (err) {
				overrun += ov;
				expected_tsc += period_tsc * ov;
			}

			if (!(finished || warmup) && (do_histogram || do_stats))
				add_histogram(histogram_avg, dt);
		}

		if (!warmup) {
			if (!finished && (do_histogram || do_stats)) {
				add_histogram(histogram_max, maxj);
				add_histogram(histogram_min, minj);
			}

			minjitter = minj;
			if (minj < gminjitter)
				gminjitter = minj;

			maxjitter = maxj;
			if (maxj > gmaxjitter)
				gmaxjitter = maxj;

			avgjitter = sumj / nsamples;
			gavgjitter += avgjitter;
			goverrun += overrun;
			sem_post(&display_sem);
		}

		if (warmup && test_loops == WARMUP_TIME) {
			test_loops = 0;
			warmup = 0;
		}
	}
	return (void *) 0;
}

void* display(void *cookie)
{
	int err, n = 0;
	time_t start;

	if (test_mode == USER_TASK) {
		err = sem_init(&display_sem, 0, 0); /* FIXME */
		if (err) {
			fprintf(stderr,
				"latency: cannot create semaphore: \n");
			return;
		}

	} else {
		struct rttst_tmbench_config config;

		if (test_mode == KERNEL_TASK) {
			fprintf(stderr, "kernel task mode not supported\n");
			return 0;
		}
		else
			config.mode = RTTST_TMBENCH_HANDLER;

		config.period = period_ns;
		config.priority = priority;
		config.warmup_loops = WARMUP_TIME;
		config.histogram_size = (do_histogram
					 || do_stats) ? histogram_size : 0;
		config.histogram_bucketsize = bucketsize;
		config.freeze_max = freeze_max;

		err =
		    ioctl(benchdev, RTTST_RTIOC_TMBENCH_START, &config);

		if (err) {
			fprintf(stderr,
				"latency: failed to start in-kernel timer benchmark\n");
			return;
		}
	}

	time(&start);

	if (WARMUP_TIME)
		printf("warming up...\n");

	if (quiet)
		fprintf(stderr, "running quietly for %d seconds\n",
			test_duration);

	for (;;) {
		long minj, gminj, maxj, gmaxj, avgj;

		if (test_mode == USER_TASK) {
			err = sem_wait(&display_sem);
			if (err) {
				fprintf(stderr,
					"latency: failed to pend on semaphore, code %d\n", err);
				return;
			}

			/* convert jitters to nanoseconds. */
			minj = tb_tsc2ns(minjitter);
			gminj = tb_tsc2ns(gminjitter);
			avgj = tb_tsc2ns(avgjitter);
			maxj = tb_tsc2ns(maxjitter);
			gmaxj = tb_tsc2ns(gmaxjitter);

		} else {
			struct rttst_interm_bench_res result;

			err =
			    ioctl(benchdev, RTTST_RTIOC_INTERM_BENCH_RES,
					 &result);

			if (err) {
		   	    fprintf(stderr,
				"latency: failed to call RTTST_RTIOC_INTERM_BENCH_RES, code %d\n", err);
				return;
			}

			minj = result.last.min;
			gminj = result.overall.min;
			avgj = result.last.avg;
			maxj = result.last.max;
			gmaxj = result.overall.max;
			goverrun = result.overall.overruns;
		}

		if (!quiet) {
			if (data_lines && (n++ % data_lines) == 0) {
				time_t now, dt;
				time(&now);
				dt = now - start - WARMUP_TIME;
				printf
				    ("RTT|  %.2ld:%.2ld:%.2ld  (%s, %Ld us period, "
				     "priority %d)\n", dt / 3600,
				     (dt / 60) % 60, dt % 60,
				     test_mode_names[test_mode],
				     period_ns / 1000, priority);
				printf("RTH|%12s|%12s|%12s|%8s|%12s|%12s\n",
				       "-----lat min", "-----lat avg",
				       "-----lat max", "-overrun",
				       "----lat best", "---lat worst");
			}

			printf("RTD|%12.3f|%12.3f|%12.3f|%8ld|%12.3f|%12.3f\n",
			       (double)minj / 1000,
			       (double)avgj / 1000,
			       (double)maxj / 1000,
			       goverrun,
			       (double)gminj / 1000, (double)gmaxj / 1000);
		}
	}
	return (void *)0;
}

double dump_histogram(long *histogram, char *kind)
{
	int n, total_hits = 0;
	double avg = 0;		/* used to sum hits 1st */

	if (do_histogram)
		printf("---|--param|----range-|--samples\n");

	for (n = 0; n < histogram_size; n++) {
		long hits = histogram[n];

		if (hits) {
			total_hits += hits;
			avg += n * hits;
			if (do_histogram)
				printf("HSD|    %s| %3d -%3d | %8ld\n",
				       kind, n, n + 1, hits);
		}
	}

	avg /= total_hits;	/* compute avg, reuse variable */

	return avg;
}

void dump_stats(long *histogram, char *kind, double avg)
{
	int n, total_hits = 0;
	double variance = 0;

	for (n = 0; n < histogram_size; n++) {
		long hits = histogram[n];

		if (hits) {
			total_hits += hits;
			variance += hits * (n - avg) * (n - avg);
		}
	}

	/* compute std-deviation (unbiased form) */
	variance /= total_hits - 1;
	variance = sqrt(variance);

	printf("HSS|    %s| %9d| %10.3f| %10.3f\n",
	       kind, total_hits, avg, variance);
}

void dump_hist_stats(void)
{
	double minavg, maxavg, avgavg;

	/* max is last, where its visible w/o scrolling */
	minavg = dump_histogram(histogram_min, "min");
	avgavg = dump_histogram(histogram_avg, "avg");
	maxavg = dump_histogram(histogram_max, "max");

	printf("HSH|--param|--samples-|--average--|---stddev--\n");

	dump_stats(histogram_min, "min", minavg);
	dump_stats(histogram_avg, "avg", avgavg);
	dump_stats(histogram_max, "max", maxavg);
}

void cleanup(void)
{
	time_t actual_duration;
	long gmaxj, gminj, gavgj;

	if (test_mode == USER_TASK) {
		tb_timer_stop();
		sem_destroy(&display_sem);

		gavgjitter /= (test_loops > 1 ? test_loops : 2) - 1;

		gminj = tb_tsc2ns(gminjitter);
		gmaxj = tb_tsc2ns(gmaxjitter);
		gavgj = tb_tsc2ns(gavgjitter);
	} else {
		struct rttst_overall_bench_res overall;

		overall.histogram_min = histogram_min;
		overall.histogram_max = histogram_max;
		overall.histogram_avg = histogram_avg;

		ioctl(benchdev, RTTST_RTIOC_TMBENCH_STOP, &overall);

		gminj = overall.result.min;
		gmaxj = overall.result.max;
		gavgj = overall.result.avg;
		goverrun = overall.result.overruns;
	}

	if (benchdev >= 0)
		close(benchdev);

	if (do_histogram || do_stats)
		dump_hist_stats();

	time(&test_end);
	actual_duration = test_end - test_start - WARMUP_TIME;
	if (!test_duration)
		test_duration = actual_duration;

	printf
	    ("---|------------|------------|------------|--------|-------------------------\n"
	     "RTS|%12.3f|%12.3f|%12.3f|%8ld|    %.2ld:%.2ld:%.2ld/%.2d:%.2d:%.2d\n",
	     (double)gminj / 1000, (double)gavgj / 1000, (double)gmaxj / 1000,
	     goverrun, actual_duration / 3600, (actual_duration / 60) % 60,
	     actual_duration % 60, test_duration / 3600,
	     (test_duration / 60) % 60, test_duration % 60);

	if (histogram_avg)
		free(histogram_avg);
	if (histogram_max)
		free(histogram_max);
	if (histogram_min)
		free(histogram_min);

	exit(0);
}

void sighand(int sig __attribute__ ((unused)))
{
	finished = 1;
}

int main(int argc, char **argv)
{
	int c, err;

	while ((c = getopt(argc, argv, "hp:l:T:qH:B:sD:t:fc:P:")) != EOF)
		switch (c) {
		case 'h':

			do_histogram = 1;
			break;

		case 's':

			do_stats = 1;
			break;

		case 'H':

			histogram_size = atoi(optarg);
			break;

		case 'B':

			bucketsize = atoi(optarg);
			break;

		case 'p':

			period_ns = atoi(optarg) * 1000LL;
			break;

		case 'l':

			data_lines = atoi(optarg);
			break;

		case 'T':

			test_duration = atoi(optarg);
			alarm(test_duration + WARMUP_TIME);
			break;

		case 'q':

			quiet = 1;
			break;

		case 'D':

			benchdev_no = atoi(optarg);
			break;

		case 't':

			test_mode = atoi(optarg);
			break;

		case 'f':

			freeze_max = 1;
			break;

		case 'P':
			priority = atoi(optarg);
			break;

		default:

			fprintf(stderr, "usage: latency [options]\n"
				"  [-h]                         # print histograms of min, avg, max latencies\n"
				"  [-s]                         # print statistics of min, avg, max latencies\n"
				"  [-H <histogram-size>]        # default = 200, increase if your last bucket is full\n"
				"  [-B <bucket-size>]           # default = 1000ns, decrease for more resolution\n"
				"  [-p <period_us>]             # sampling period\n"
				"  [-l <data-lines per header>] # default=21, 0 to supress headers\n"
				"  [-T <test_duration_seconds>] # default=0, so ^C to end\n"
				"  [-q]                         # supresses RTD, RTH lines if -T is used\n"
				"  [-D <testing_device_no>]     # number of testing device, default=0\n"
				"  [-t <test_mode>]             # 0=user task (default), 1=kernel task, 2=timer IRQ\n"
				"  [-f]                         # freeze trace for each new max latency\n"
				"  [-P <priority>]              # task priority (test mode 0 and 1 only)\n");
			exit(2);
		}

	if (!test_duration && quiet) {
		fprintf(stderr,
			"latency: -q only works if -T has been given.\n");
		quiet = 0;
	}

	if ((test_mode < USER_TASK) || (test_mode > TIMER_HANDLER)) {
		fprintf(stderr, "latency: invalid test mode.\n");
		exit(2);
	}

	if (test_mode == KERNEL_TASK) {
		fprintf(stderr, "latency: KERNEL_TASK mode not supported\n");
		exit(2);
	}

	time(&test_start);

	histogram_avg = calloc(histogram_size, sizeof(long));
	histogram_max = calloc(histogram_size, sizeof(long));
	histogram_min = calloc(histogram_size, sizeof(long));

	if (!(histogram_avg && histogram_max && histogram_min))
		cleanup();

	if (period_ns == 0)
		period_ns = 100000LL;	/* ns */

	if (priority < 1)
		priority = 0;
	else if (priority > 99)
		priority = 99;

	signal(SIGINT, sighand);
	signal(SIGTERM, sighand);
	signal(SIGHUP, sighand);
	signal(SIGALRM, sighand);

	setlinebuf(stdout);

	printf("== Sampling period: %Ld us\n"
	       "== Test mode: %s\n"
	       "== All results in microseconds\n",
	       period_ns / 1000, test_mode_names[test_mode]);

	mlockall(MCL_CURRENT | MCL_FUTURE);

	char devname[MAX_DEVNAME_LEN];

	snprintf(devname, MAX_DEVNAME_LEN, "/dev/timerbench0");
	benchdev = open(devname, O_RDWR);

	if (benchdev < 0) {
		fprintf(stderr,
			"latency: failed to open benchmark device, code %d\n",
			benchdev);
		return 0;
	}
		
	ioctl(benchdev, RTTST_GETCCLK, &cclk);

	err = pthread_create(&display_task, NULL, display, NULL);
	if (err) {
		fprintf(stderr,
			"latency: failed to start display task, code %d\n",
			err);
		return 0;
	}
	
	if (test_mode == USER_TASK) {

		pthread_attr_t attr;
		pthread_attr_init(&attr);
	
		if (priority > 0)
		{
			struct sched_param sched_param;
			sched_param.sched_priority = priority;
			pthread_attr_setschedpolicy(&attr, SCHED_FIFO);
			pthread_attr_setschedparam(&attr, &sched_param);
		}

		err = pthread_create(&latency_task, &attr, latency, NULL);

		if (err) {
			fprintf(stderr,
				"latency: failed to start latency task, code %d\n", err);
			return 0;
		}
	}

	while (!finished)
		pause();
	
	cleanup();

	return 0;
}
