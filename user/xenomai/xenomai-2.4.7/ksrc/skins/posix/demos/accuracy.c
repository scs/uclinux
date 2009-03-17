#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/mman.h>
#include <sys/time.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <semaphore.h>
#include <limits.h>

#define SEMB_NAME "/semB"

static int sampling_period = SPERIOD;

static sem_t semA;

suseconds_t t0, t1, t2, tschedmin = 99999999, tschedmax = -99999999,
    tsleepmin = 99999999, tsleepmax = -99999999;

time_t start_time;

pthread_t thidA, thidB;

static inline void get_time_us(suseconds_t * tp)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	*tp = ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

void cleanup_sem_close(void *sem)
{
	sem_close((sem_t *) sem);
}

void *threadA(void *arg)
{
	struct sched_param param = {.sched_priority = 98 };
	struct timespec ts;
	sem_t *semB;

	if ((semB = sem_open(SEMB_NAME, O_CREAT, 0, 0)) == SEM_FAILED) {
		perror("sem_open");
		exit(EXIT_FAILURE);
	}

	pthread_cleanup_push(cleanup_sem_close, semB);
	pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);

	for (;;) {
		int err;
		do {
			err = sem_wait(&semA);
			if (err == -1 && errno != EINTR) {
				perror("sem_wait");
				exit(EXIT_FAILURE);
			}
		}
		while (err == -1);

		ts.tv_sec = 0;
		ts.tv_nsec = sampling_period * 1000;
		get_time_us(&t0);
		clock_nanosleep(CLOCK_MONOTONIC, 0, &ts, NULL);
		get_time_us(&t1);
		sem_post(semB);
	}

	pthread_cleanup_pop(1);
}

void *threadB(void *arg)
{
	struct sched_param param = {.sched_priority = 99 };
	suseconds_t dt;
	sem_t *semB;

	if ((semB = sem_open(SEMB_NAME, O_CREAT, 0, 0)) == SEM_FAILED) {
		perror("sem_open");
		exit(EXIT_FAILURE);
	}

	pthread_cleanup_push(cleanup_sem_close, semB);
	pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);

	start_time = time(NULL);

	for (;;) {
		int err;
		sem_post(&semA);

		do {
			err = sem_wait(semB);
			if (err == -1 && errno != EINTR) {
				perror("sem_wait");
				exit(EXIT_FAILURE);
			}
		}
		while (err == -1);

		get_time_us(&t2);

		dt = t2 - t1;

		if (tschedmin > dt)
			tschedmin = dt;

		if (tschedmax < dt)
			tschedmax = dt;

		dt = t1 - t0;

		if (tsleepmin > dt)
			tsleepmin = dt;

		if (tsleepmax < dt)
			tsleepmax = dt;
	}

	pthread_cleanup_pop(1);
}

void cleanup(void)
{
	sem_unlink(SEMB_NAME);
	sem_destroy(&semA);
}

void cleanup_upon_sig(int sig)
{
	time_t end_time = time(NULL), dt;

	dt = end_time - start_time;

	printf("   test duration: %.2ld:%.2ld:%.2ld\n",
	       dt / 3600, (dt / 60) % 60, dt % 60);
	printf
	    ("   nanosleep accuracy: jitter min = %ld us, jitter max = %ld us\n",
	     tsleepmin - sampling_period, tsleepmax - sampling_period);
	printf
	    ("   semaphore wakeup: switch min = %ld us, switch max = %ld us\n",
	     tschedmin, tschedmax);

	pthread_cancel(thidA);
	pthread_cancel(thidB);
	signal(sig, SIG_DFL);
	pthread_join(thidA, NULL);
	pthread_join(thidB, NULL);
}

int main(int argc, char **argv)
{
	struct sched_param paramA = {.sched_priority = 98 };
	struct sched_param paramB = {.sched_priority = 99 };
	pthread_attr_t thattrA, thattrB;
	sigset_t mask, oldmask;
	struct timespec ts;
	time_t now;
	int err, c;

	while ((c = getopt(argc, argv, "p:")) != EOF)
		switch (c) {
		case 'p':

			sampling_period = atoi(optarg);

			if (sampling_period > 0)
				break;

		default:

			fprintf(stderr, "usage: %s [options]\n"
				"  [-p <period_us>]             # sampling period\n",
				argv[0]);
			exit(2);
		}

	time(&now);

	clock_getres(CLOCK_MONOTONIC, &ts);
	printf("Starting latency measurements at %s", ctime(&now));
	printf("Sampling period = %d us\n", sampling_period);
	printf("Clock resolution = %ld ns\n",
	       ts.tv_sec * 1000000000 + ts.tv_nsec);
	printf("Hit ^C to get the results.\n");

	mlockall(MCL_CURRENT | MCL_FUTURE);

	atexit(cleanup);

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	signal(SIGINT, cleanup_upon_sig);
	sigaddset(&mask, SIGTERM);
	signal(SIGTERM, cleanup_upon_sig);
	sigaddset(&mask, SIGHUP);
	signal(SIGHUP, cleanup_upon_sig);

	/* Block signals causing execution of the cleanup function, so that threadA
	   and threadB are created with these signal blocked. Calling sigsuspend()
	   from main will deterministically cause the signal handler to be executed
	   on the main thread. */
	pthread_sigmask(SIG_BLOCK, &mask, &oldmask);

	if (sem_init(&semA, 0, 0)) {
		perror("sem_init(semA)");
		exit(EXIT_FAILURE);
	}

	pthread_attr_init(&thattrA);
	pthread_attr_setdetachstate(&thattrA, PTHREAD_CREATE_JOINABLE);
	pthread_attr_setinheritsched(&thattrA, PTHREAD_EXPLICIT_SCHED);
	pthread_attr_setschedpolicy(&thattrA, SCHED_FIFO);
	pthread_attr_setschedparam(&thattrA, &paramA);
	pthread_attr_setstacksize(&thattrA, PTHREAD_STACK_MIN);
	err = pthread_create(&thidA, &thattrA, &threadA, NULL);

	if (err)
		goto fail;

	pthread_attr_init(&thattrB);
	pthread_attr_setdetachstate(&thattrB, PTHREAD_CREATE_JOINABLE);
	pthread_attr_setinheritsched(&thattrB, PTHREAD_EXPLICIT_SCHED);
	pthread_attr_setschedpolicy(&thattrB, SCHED_FIFO);
	pthread_attr_setschedparam(&thattrB, &paramB);
	pthread_attr_setstacksize(&thattrB, PTHREAD_STACK_MIN);
	err = pthread_create(&thidB, &thattrB, &threadB, NULL);

	if (err)
		goto fail;

	sigsuspend(&oldmask);

	return 0;

      fail:

	fprintf(stderr, "failed to create threads: %s\n", strerror(err));

	return 1;
}
