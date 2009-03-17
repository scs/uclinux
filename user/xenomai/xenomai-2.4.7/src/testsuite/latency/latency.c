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
#include <native/task.h>
#include <native/timer.h>
#include <native/sem.h>
#include <rtdm/rttesting.h>

RT_TASK latency_task, display_task;

RT_SEM display_sem;

#define ONE_BILLION  1000000000
#define TEN_MILLION    10000000

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
int priority = T_HIPRIO;

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

#define MEASURE_PERIOD ONE_BILLION
#define SAMPLE_COUNT (MEASURE_PERIOD / period_ns)

/* Warmup time : in order to avoid spurious cache effects on low-end machines. */
#define WARMUP_TIME 1
#define HISTOGRAM_CELLS 100
int histogram_size = HISTOGRAM_CELLS;
long *histogram_avg = NULL, *histogram_max = NULL, *histogram_min = NULL;

int do_histogram = 0, do_stats = 0, finished = 0;
int bucketsize = 1000;		/* default = 1000ns, -B <size> to override */

static inline void add_histogram(long *histogram, long addval)
{
	/* bucketsize steps */
	long inabs =
	    rt_timer_tsc2ns(addval >= 0 ? addval : -addval) / bucketsize;
	histogram[inabs < histogram_size ? inabs : histogram_size - 1]++;
}

void latency(void *cookie)
{
	int err, count, nsamples, warmup = 1;
	RTIME expected_tsc, period_tsc, start_ticks;
	RT_TIMER_INFO timer_info;

	err = rt_timer_inquire(&timer_info);

	if (err) {
		fprintf(stderr, "latency: rt_timer_inquire, code %d\n", err);
		return;
	}

	nsamples = ONE_BILLION / period_ns;
	period_tsc = rt_timer_ns2tsc(period_ns);
	/* start time: one millisecond from now. */
	start_ticks = timer_info.date + rt_timer_ns2ticks(1000000);
	expected_tsc = timer_info.tsc + rt_timer_ns2tsc(1000000);

	err =
	    rt_task_set_periodic(NULL, start_ticks,
				 rt_timer_ns2ticks(period_ns));

	if (err) {
		fprintf(stderr, "latency: failed to set periodic, code %d\n",
			err);
		return;
	}

	for (;;) {
		long minj = TEN_MILLION, maxj = -TEN_MILLION, dt;
		long overrun = 0;
		long long sumj;
		test_loops++;

		for (count = sumj = 0; count < nsamples; count++) {
			unsigned long ov;

			expected_tsc += period_tsc;
			err = rt_task_wait_period(&ov);

			dt = (long)(rt_timer_tsc() - expected_tsc);
			if (dt > maxj)
				maxj = dt;
			if (dt < minj)
				minj = dt;
			sumj += dt;

			if (err) {
				if (err != -ETIMEDOUT) {
					fprintf(stderr,
						"latency: wait period failed, code %d\n",
						err);
					rt_task_delete(NULL);	/* Timer stopped. */
				}

				overrun += ov;
				expected_tsc += period_tsc * ov;
			}

			if (freeze_max && (dt > gmaxjitter)
			    && !(finished || warmup)) {
				xntrace_user_freeze(rt_timer_tsc2ns(dt), 0);
				gmaxjitter = dt;
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
			rt_sem_v(&display_sem);
		}

		if (warmup && test_loops == WARMUP_TIME) {
			test_loops = 0;
			warmup = 0;
		}
	}
}

void display(void *cookie)
{
	int err, n = 0;
	time_t start;
	char sem_name[16];

	if (test_mode == USER_TASK) {
		snprintf(sem_name, sizeof(sem_name), "dispsem-%d", getpid());
		err = rt_sem_create(&display_sem, sem_name, 0, S_FIFO);

		if (err) {
			fprintf(stderr,
				"latency: cannot create semaphore: %s\n",
				strerror(-err));
			return;
		}

	} else {
		struct rttst_tmbench_config config;

		if (test_mode == KERNEL_TASK)
			config.mode = RTTST_TMBENCH_TASK;
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
		    rt_dev_ioctl(benchdev, RTTST_RTIOC_TMBENCH_START, &config);

		if (err) {
			fprintf(stderr,
				"latency: failed to start in-kernel timer benchmark, code %d\n",
				err);
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
			err = rt_sem_p(&display_sem, TM_INFINITE);

			if (err) {
				if (err != -EIDRM)
					fprintf(stderr,
						"latency: failed to pend on semaphore, code %d\n",
						err);

				return;
			}

			/* convert jitters to nanoseconds. */
			minj = rt_timer_tsc2ns(minjitter);
			gminj = rt_timer_tsc2ns(gminjitter);
			avgj = rt_timer_tsc2ns(avgjitter);
			maxj = rt_timer_tsc2ns(maxjitter);
			gmaxj = rt_timer_tsc2ns(gmaxjitter);

		} else {
			struct rttst_interm_bench_res result;

			err =
			    rt_dev_ioctl(benchdev, RTTST_RTIOC_INTERM_BENCH_RES,
					 &result);

			if (err) {
				if (err != -EIDRM)
					fprintf(stderr,
						"latency: failed to call RTTST_RTIOC_INTERM_BENCH_RES, code %d\n",
						err);

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
		rt_sem_delete(&display_sem);

		gavgjitter /= (test_loops > 1 ? test_loops : 2) - 1;

		gminj = rt_timer_tsc2ns(gminjitter);
		gmaxj = rt_timer_tsc2ns(gmaxjitter);
		gavgj = rt_timer_tsc2ns(gavgjitter);
	} else {
		struct rttst_overall_bench_res overall;

		overall.histogram_min = histogram_min;
		overall.histogram_max = histogram_max;
		overall.histogram_avg = histogram_avg;

		rt_dev_ioctl(benchdev, RTTST_RTIOC_TMBENCH_STOP, &overall);

		gminj = overall.result.min;
		gmaxj = overall.result.max;
		gavgj = overall.result.avg;
		goverrun = overall.result.overruns;
	}

	if (benchdev >= 0)
		rt_dev_close(benchdev);

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

void faulthand(int sig)
{
	xntrace_user_freeze(0, 1);
	signal(sig, SIG_DFL);
	kill(getpid(), sig);
}

int main(int argc, char **argv)
{
	int c, err;
	char task_name[16];
	int cpu = 0;

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

		case 'c':
			cpu = T_CPU(atoi(optarg));
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
				"  [-c <cpu>]                   # pin measuring task down to given CPU\n"
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

	time(&test_start);

	histogram_avg = calloc(histogram_size, sizeof(long));
	histogram_max = calloc(histogram_size, sizeof(long));
	histogram_min = calloc(histogram_size, sizeof(long));

	if (!(histogram_avg && histogram_max && histogram_min))
		cleanup();

	if (period_ns == 0)
		period_ns = 100000LL;	/* ns */

	if (priority <= T_LOPRIO)
		priority = T_LOPRIO + 1;
	else if (priority > T_HIPRIO)
		priority = T_HIPRIO;

	signal(SIGINT, sighand);
	signal(SIGTERM, sighand);
	signal(SIGHUP, sighand);
	signal(SIGALRM, sighand);

	if (freeze_max) {
		/* If something goes wrong, we want to freeze the current
		   trace path to help debugging. */
		signal(SIGSEGV, faulthand);
		signal(SIGBUS, faulthand);
	}

	setlinebuf(stdout);

	printf("== Sampling period: %Ld us\n"
	       "== Test mode: %s\n"
	       "== All results in microseconds\n",
	       period_ns / 1000, test_mode_names[test_mode]);

	mlockall(MCL_CURRENT | MCL_FUTURE);

	if (test_mode != USER_TASK) {
		char devname[RTDM_MAX_DEVNAME_LEN];

		snprintf(devname, RTDM_MAX_DEVNAME_LEN, "rttest%d",
			 benchdev_no);
		benchdev = rt_dev_open(devname, O_RDWR);

		if (benchdev < 0) {
			fprintf(stderr,
				"latency: failed to open benchmark device, code %d\n"
				"(modprobe xeno_timerbench?)\n", benchdev);
			return 0;
		}
	}

	rt_timer_set_mode(TM_ONESHOT);	/* Force aperiodic timing. */

	snprintf(task_name, sizeof(task_name), "display-%d", getpid());
	err = rt_task_create(&display_task, task_name, 0, 0, T_FPU);

	if (err) {
		fprintf(stderr,
			"latency: failed to create display task, code %d\n",
			err);
		return 0;
	}

	err = rt_task_start(&display_task, &display, NULL);

	if (err) {
		fprintf(stderr,
			"latency: failed to start display task, code %d\n",
			err);
		return 0;
	}

	if (test_mode == USER_TASK) {
		snprintf(task_name, sizeof(task_name), "sampling-%d", getpid());
		err =
		    rt_task_create(&latency_task, task_name, 0, priority,
				   T_FPU | cpu);

		if (err) {
			fprintf(stderr,
				"latency: failed to create latency task, code %d\n",
				err);
			return 0;
		}

		err = rt_task_start(&latency_task, &latency, NULL);

		if (err) {
			fprintf(stderr,
				"latency: failed to start latency task, code %d\n",
				err);
			return 0;
		}
	}

	while (!finished)
		pause();

	cleanup();

	return 0;
}
