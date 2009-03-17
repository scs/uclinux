#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <time.h>
#include <errno.h>
#include <rtdm/rttesting.h>

struct pkt {
	struct rttst_tmbench_config config;
	struct rttst_interm_bench_res res;
};

long long period_ns = 0;
int test_duration = 0;		/* sec of testing, via -T <sec>, 0 is inf */
int data_lines = 21;		/* data lines per header line, -l <lines> to change */
int quiet = 0;			/* suppress printing of RTH, RTD lines when -T given */
int benchdev_no = -1;
int benchdev = -1;
int freeze_max;
int priority;

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

int finished = 0;

void display(void)
{
	int err, n = 0, got_results = 0;
	time_t start, actual_duration;
	struct pkt result;

	time(&start);

	printf("warming up...\n");

	if (quiet)
		fprintf(stderr, "running quietly for %d seconds\n",
			test_duration);

	while (!finished) {
		long minj, gminj, maxj, gmaxj, avgj, goverrun;

		err = read(benchdev, &result, sizeof(result));
		if (err <= 0) {
			fprintf(stderr, "read: %d, errno: %d\n", err, errno);
			break;
		}

		got_results = 1;
		minj = result.res.last.min;
		gminj = result.res.overall.min;
		avgj = result.res.last.avg;
		maxj = result.res.last.max;
		gmaxj = result.res.overall.max;
		goverrun = result.res.overall.overruns;

		if (!quiet) {
			if (data_lines && (n++ % data_lines) == 0) {
				time_t now, dt;
				time(&now);
				dt = now - start;
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

	time(&test_end);
	actual_duration = test_end - test_start;
	if (!test_duration)
		test_duration = actual_duration;

	if (got_results) {
		long gminj, gmaxj, gavgj, goverrun;

		gminj = result.res.overall.min;
		gmaxj = result.res.overall.max;
		goverrun = result.res.overall.overruns;
		gavgj = result.res.overall.avg
			/ ((result.res.overall.test_loops) > 1 ?
			   result.res.overall.test_loops : 2) - 1;

		printf("---|------------|------------|------------|--------|-------------------------\n"
		       "RTS|%12.3f|%12.3f|%12.3f|%8ld|    %.2ld:%.2ld:%.2ld/%.2d:%.2d:%.2d\n",
		       (double)gminj / 1000, (double)gavgj / 1000, (double)gmaxj / 1000,
		       goverrun, actual_duration / 3600, (actual_duration / 60) % 60,
		       actual_duration % 60, test_duration / 3600,
		       (test_duration / 60) % 60, test_duration % 60);

	}

	if (benchdev >= 0)
		close(benchdev);
}

void sighand(int sig __attribute__ ((unused)))
{
	finished = 1;
}

int main(int argc, char **argv)
{
	struct pkt pkt;
	int c;

	while ((c = getopt(argc, argv, "l:T:qP:")) != EOF)
		switch (c) {
		case 'l':

			data_lines = atoi(optarg);
			break;

		case 'T':

			test_duration = atoi(optarg);
			alarm(test_duration);
			break;

		case 'q':

			quiet = 1;
			break;

		case 'P':

			benchdev_no = atoi(optarg);
			break;

		default:

			fprintf(stderr, "usage: latency [options]\n"
				"  [-l <data-lines per header>] # default=21, 0 to supress headers\n"
				"  [-T <test_duration_seconds>] # default=0, so ^C to end\n"
				"  [-q]                         # supresses RTD, RTH lines if -T is used\n"
				"  [-P <rt_pipe_no>]            # number of testing pipe, default=auto\n");
			exit(2);
		}

	if (!test_duration && quiet) {
		fprintf(stderr,
			"latency: -q only works if -T has been given.\n");
		quiet = 0;
	}

	time(&test_start);

	signal(SIGINT, sighand);
	signal(SIGTERM, sighand);
	signal(SIGHUP, sighand);
	signal(SIGALRM, sighand);

	setlinebuf(stdout);

	if (benchdev_no == -1) {
		benchdev = open("/proc/xenomai/registry/native/pipes/klat_pipe",
				O_RDONLY);
		if (benchdev == -1) {
			perror("open(/proc/xenomai/registry/native/pipes/klat_pipe)");
			fprintf(stderr,
				"modprobe klat_mod or try the -P option?\n");
			exit(EXIT_FAILURE);
		}
	} else {
		char devname[64];
		snprintf(devname, sizeof(devname), "/dev/rtp%d", benchdev_no);
		benchdev = open(devname, O_RDONLY);
		if (benchdev == -1) {
			fprintf(stderr, "open(%s): %s\n",
				devname, strerror(errno));
			exit(EXIT_FAILURE);
		}
	}

	if (read(benchdev, &pkt, sizeof(pkt)) == -1) {
		perror("read");
		exit(EXIT_FAILURE);
	}

	test_mode = pkt.config.mode;
	priority = pkt.config.priority;
	period_ns = pkt.config.period;
	freeze_max = pkt.config.freeze_max;

	printf("== Sampling period: %Ld us\n"
	       "== Test mode: %s\n"
	       "== All results in microseconds\n",
	       period_ns / 1000, test_mode_names[test_mode]);

	display();

	return 0;
}
