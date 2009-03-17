/*
 * Copyright (C) 2007 Jan Kiszka <jan.kiszka@web.de>.
 *
 * Xenomai is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/time.h>

#include <xeno_config.h>

#ifndef HAVE_RECENT_SETAFFINITY
#ifdef HAVE_OLD_SETAFFINITY
#define sched_setaffinity(pid, len, mask)	sched_setaffinity(pid, mask)
#else /* !HAVE_OLD_SETAFFINITY */
#ifndef __cpu_set_t_defined
typedef unsigned long cpu_set_t;
#endif
#define sched_setaffinity(pid, len, mask)	do { } while (0)
#ifndef CPU_ZERO
#define CPU_ZERO(set)				memset(set, 0, sizeof(*set))
#define CPU_SET(n, set)				do { } while (0)
#endif
#endif /* !HAVE_OLD_SETAFFINITY */
#endif /* !HAVE_RECENT_SETAFFINITY */

/* Test for true conformance (due to broken uClibc < 0.9.29) */
#if defined(_POSIX_SPIN_LOCKS) && _POSIX_SPIN_LOCKS == 200112L
pthread_spinlock_t lock;
#define init_lock(lock)				pthread_spin_init(lock, 0)
#define acquire_lock(lock)			pthread_spin_lock(lock)
#define release_lock(lock)			pthread_spin_unlock(lock)
#else
pthread_mutex_t lock;
#define init_lock(lock)				pthread_mutex_init(lock, NULL)
#define acquire_lock(lock)			pthread_mutex_lock(lock)
#define release_lock(lock)			pthread_mutex_unlock(lock)
#endif
unsigned long long last_common = 0;
clockid_t clock_id = CLOCK_REALTIME;

struct per_cpu_data {
    unsigned long long first_tod, first_clock;
    int first_round;
    long long offset;
    double drift;
    unsigned long warps;
    unsigned long long max_warp;
    pthread_t thread;
} *per_cpu_data;

static inline unsigned long long read_clock(clockid_t clock_id)
{
    struct timespec ts;

    clock_gettime(clock_id, &ts);
    return ts.tv_nsec + ts.tv_sec * 1000000000ULL;
}

static inline unsigned long long read_reference_clock(void)
{
    struct timeval tv;

    /* Make sure we do not pick the vsyscall variant. It won't
       switch us into secondary mode and can easily deadlock. */
    syscall(SYS_gettimeofday, &tv, NULL);
    return tv.tv_usec * 1000ULL + tv.tv_sec * 1000000000ULL;
}

void check_reference(struct per_cpu_data *per_cpu_data)
{
    unsigned long long clock_val[10], tod_val[10];
    long long delta, min_delta;
    int i, idx;

    for (i = 0; i < 10; i++) {
        tod_val[i] = read_reference_clock();
        clock_val[i] = read_clock(clock_id);
    }

    min_delta = tod_val[1] - tod_val[0];
    idx = 1;

    for (i = 2; i < 10; i++) {
        delta = tod_val[i] - tod_val[i-1];
        if (delta < min_delta) {
            min_delta = delta;
            idx = i;
        }
    }

    if (per_cpu_data->first_round) {
        per_cpu_data->first_round = 0;

        per_cpu_data->first_tod = tod_val[idx];
        per_cpu_data->first_clock = clock_val[idx];
    } else
        per_cpu_data->drift =
            (clock_val[idx] - per_cpu_data->first_clock) /
            (double)(tod_val[idx] - per_cpu_data->first_tod) - 1;

    per_cpu_data->offset = clock_val[idx] - tod_val[idx];
}

void check_time_warps(struct per_cpu_data *per_cpu_data)
{
    int i;
    unsigned long long last, now;
    long long incr;

    for (i = 0; i < 100; i++) {
        acquire_lock(&lock);
        now = read_clock(clock_id);
        last = last_common;
        last_common = now;
        release_lock(&lock);

        incr = now - last;
        if (incr < 0) {
            acquire_lock(&lock);
            per_cpu_data->warps++;
            if (-incr > per_cpu_data->max_warp)
                per_cpu_data->max_warp = -incr;
            release_lock(&lock);
        }
    }
}

void *cpu_thread(void *arg)
{
    int cpuid = (long)arg;
    struct sched_param param = { .sched_priority = 1 };
    struct timespec delay = { 0, 0 };
    cpu_set_t cpu_set;

    srandom(read_reference_clock());

    CPU_ZERO(&cpu_set);
    CPU_SET(cpuid, &cpu_set);
    sched_setaffinity(0, sizeof(cpu_set), &cpu_set);
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &param);

    while (1) {
        check_reference(&per_cpu_data[cpuid]);

        check_time_warps(&per_cpu_data[cpuid]);

        delay.tv_nsec = 1000000 + random() * (100000.0 / RAND_MAX);
        nanosleep(&delay, NULL);
    }
}

void sighand(int signal)
{
    exit(0);
}

int main(int argc, char *argv[])
{
    int cpus = sysconf(_SC_NPROCESSORS_ONLN);
    int i;
    int c;

    while ((c = getopt(argc,argv,"C:T:")) != EOF)
        switch (c) {
            case 'C':
                clock_id = atoi(optarg);
                break;

            case 'T':
                alarm(atoi(optarg));
                break;

            default:
                fprintf(stderr, "usage: clocktest [options]\n"
                        "  [-C <clock_id>]              # tested clock, default=%d (CLOCK_REALTIME)\n"
                        "  [-T <test_duration_seconds>] # default=0, so ^C to end\n",
                        CLOCK_REALTIME);
                exit(2);
        }

    mlockall(MCL_CURRENT | MCL_FUTURE);

    signal(SIGALRM, sighand);

    init_lock(&lock);

    per_cpu_data = malloc(sizeof(*per_cpu_data) * cpus);
    if (!per_cpu_data) {
        fprintf(stderr, "%s\n", strerror(ENOMEM));
        exit(1);
    }
    memset(per_cpu_data, 0, sizeof(*per_cpu_data) * cpus);

    for (i = 0; i < cpus; i++) {
        per_cpu_data[i].first_round = 1;
        pthread_create(&per_cpu_data[i].thread, NULL, cpu_thread,
		       (void *)(long)i);
    }

    printf("== Tested clock: %d (", clock_id);
    switch (clock_id) {
        case CLOCK_REALTIME:
            printf("CLOCK_REALTIME");
            break;

        case CLOCK_MONOTONIC:
            printf("CLOCK_MONOTONIC");
            break;

        default:
            printf("<unknown>");
            break;
    }
    printf(")\nCPU      ToD offset [us] ToD drift [us/s]      warps max delta [us]\n"
              "--- -------------------- ---------------- ---------- --------------\n");

    while (1) {
        for (i = 0; i < cpus; i++)
            printf("%3d %20.1f %16.3f %10lu %14.1f\n",
                   i,
                   per_cpu_data[i].offset/1000.0,
                   per_cpu_data[i].drift * 1000000.0,
                   per_cpu_data[i].warps,
                   per_cpu_data[i].max_warp/1000.0);
        usleep(250000);
        printf("\033[%dA", cpus);
    }
}
