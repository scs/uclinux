/*
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@laposte.net>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <posix_test.h>

static pthread_t root_thread_tcb;

struct thread_parms {
	const char *name;
	unsigned priority;
	clockid_t clock;
	int abstime;
	struct timespec initial;
	struct timespec period;
	unsigned total_delta_positive;
	unsigned total_delta_negative;
	unsigned ticks;
	unsigned overruns;
	pthread_t tid;
	timer_t tm;
};

struct thread_parms parm[] = {
	/* one shot, tick before new date. */
	{"1s_bnd_mon_rel", 99, CLOCK_MONOTONIC, 0, {1, 0}, {0, 0}, 1, 1},
	{"1s_bnd_mon_abs", 98, CLOCK_MONOTONIC, TIMER_ABSTIME, {2, 0}, {0, 0}, 1, 1},
	{"1s_bnd_rt_rel",  97, CLOCK_REALTIME,  0, {3, 0}, {0, 0}, 1, 1},
	{"1s_bnd_rt_abs",  96, CLOCK_REALTIME,  TIMER_ABSTIME, {4, 0}, {0, 0}, 1, 1},

	/* periodic, tick before new date, period lesser than delta */
	{"p_bnd_mon_rel_pltd", 95, CLOCK_MONOTONIC, 0, {5, 0},{1, 0}, 96, 195},
	{"p_bnd_mon_abs_pltd", 94, CLOCK_MONOTONIC, TIMER_ABSTIME,{6, 0},{1, 0}, 95, 194},
	{"p_bnd_rt_rel_pltd",  93, CLOCK_REALTIME, 0,{7, 0},{1, 0}, 94, 193},
	{"p_bnd_rt_abs_pltd",  92, CLOCK_REALTIME, TIMER_ABSTIME,{8, 0},{1, 0}, 192, 192},

	/* periodic, tick before new date, period greater than delta */
	{"p_bnd_mon_rel_pgtd", 91, CLOCK_MONOTONIC, 0, {9, 0}, {200, 0}, 1, 1},
	{"p_bnd_mon_abs_pgtd", 90, CLOCK_MONOTONIC, TIMER_ABSTIME, {10, 0}, {200, 0}, 1, 1},
	{"p_bnd_rt_rel_pgtd", 89, CLOCK_REALTIME, 0, {11, 0}, {200, 0}, 1, 1},
	{"p_bnd_rt_abs_pgtd", 88, CLOCK_REALTIME, TIMER_ABSTIME, {12, 0}, {200, 0}, 1, 2},

	/* one-shot, tick after new date. */
	{"1s_and_mon_rel", 87, CLOCK_MONOTONIC, 0, {101, 0}, {0, 0}, 0, 1},
	{"1s_and_mon_abs", 86, CLOCK_MONOTONIC, TIMER_ABSTIME, {102, 0}, {0, 0}, 0, 1},
	{"1s_and_rt_rel",  85, CLOCK_REALTIME,  0, {103, 0}, {0, 0}, 0, 1},
	{"1s_and_rt_abs",  84, CLOCK_REALTIME,  TIMER_ABSTIME, {104, 0}, {0, 0}, 1, 0},

	/* periodic, tick after new date, period lesser than delta */
	{"p_and_mon_rel_pltd", 83, CLOCK_MONOTONIC, 0, {105, 0}, {1, 0}, 0, 95},
	{"p_and_mon_abs_pltd", 82, CLOCK_MONOTONIC, TIMER_ABSTIME, {106, 0}, {1, 0}, 0, 94},
	{"p_and_rt_rel_pltd", 81, CLOCK_REALTIME, 0, {107, 0}, {1, 0}, 0, 93},
	{"p_and_rt_abs_pltd", 80, CLOCK_REALTIME, TIMER_ABSTIME, {108, 0}, {1, 0},92, 0},

	/* periodic, tick after new date, period greater than delta */
	{"p_and_mon_rel_pgtd", 79, CLOCK_MONOTONIC, 0, {109, 0}, {200, 0}, 0, 1 },
	{"p_and_mon_abs_pgtd", 78, CLOCK_MONOTONIC, TIMER_ABSTIME, {110, 0}, {200, 0}, 0, 1},
	{"p_and_rt_rel_pgtd", 77, CLOCK_REALTIME, 0, {111, 0}, {200, 0}, 0, 1 },
	{"p_and_rt_abs_pgtd", 76, CLOCK_REALTIME, TIMER_ABSTIME, {112, 0}, {200, 0}, 1, 0},
};

static void *timed_thread(void *cookie)
{
	struct thread_parms *parms = (struct thread_parms *) cookie;
	struct itimerspec its;
	sigset_t mask;

	TEST_ASSERT_OK(sigemptyset(&mask));
	TEST_ASSERT_OK(sigaddset(&mask, SIGALRM));
	TEST_ASSERT_OK(pthread_sigmask(SIG_BLOCK, &mask, NULL));

	if (parms->abstime) {
		TEST_ASSERT_OK(clock_gettime(parms->clock, &its.it_value));
		its.it_value.tv_sec += parms->initial.tv_sec;
	} else
		its.it_value = parms->initial;
	its.it_interval = parms->period;
	TEST_ASSERT_OK(timer_create(parms->clock, NULL, &parms->tm));
	TEST_ASSERT_OK(timer_settime(parms->tm, parms->abstime, &its, NULL));

	for (;;) {
		int sig;
		TEST_ASSERT(sigwait(&mask, &sig) == 0 && sig == SIGALRM);

		if (!parms->ticks++)
			TEST_MARK();

		sig = timer_getoverrun(parms->tm);
		TEST_ASSERT(sig >= 0);
		parms->overruns += sig;
	}
}


int timed_thread_create(struct thread_parms *parms)
{
	struct sched_param sparm;
	pthread_attr_t tattr;

	parms->ticks = parms->overruns = 0;

	pthread_attr_init(&tattr);
	pthread_attr_setschedpolicy(&tattr, SCHED_FIFO);
	sparm.sched_priority = parms->priority;
	pthread_attr_setschedparam(&tattr, &sparm);
	pthread_attr_setname_np(&tattr, parms->name);

	return pthread_create(&parms->tid, &tattr, timed_thread, parms);
}

void kill_threads(void)
{
	spl_t s;
	int i;

	xnlock_get_irqsave(&nklock, s);
	for (i = 0; i < sizeof(parm)/sizeof(parm[0]); i++) {
		struct thread_parms *parms = &parm[i];
		pthread_cancel(parms->tid);
	}

	for (i = 0; i < sizeof(parm)/sizeof(parm[0]); i++) {
		struct thread_parms *parms = &parm[i];
		pthread_join(parms->tid, NULL);
	}
	xnlock_put_irqrestore(&nklock, s);
}

void check_threads_delta_positive(void)
{
	int i;

	for (i = 0; i < sizeof(parm)/sizeof(parm[0]); i++) {
		struct thread_parms *parms = &parm[i];
		if (parms->total_delta_positive != parms->ticks + parms->overruns)
			xnprintf("%s: total: %d, ticks: %d, overruns: %d\n",
				 parms->name,
				 parms->total_delta_positive,
				 parms->ticks, parms->overruns);
		TEST_ASSERT(parms->total_delta_positive == parms->ticks + parms->overruns);
	}
}

void check_threads_delta_negative(void)
{
	int i;

	for (i = 0; i < sizeof(parm)/sizeof(parm[0]); i++) {
		struct thread_parms *parms = &parm[i];
		if (parms->total_delta_negative != parms->ticks + parms->overruns)
			xnprintf("%s: total: %d, ticks: %d, overruns: %d\n",
				 parms->name,
				 parms->total_delta_positive,
				 parms->ticks, parms->overruns);
		TEST_ASSERT(parms->total_delta_negative == parms->ticks + parms->overruns);
	}
}

void *root_thread(void *cookie)
{
	struct timespec ts;
	int i;

	TEST_START(0);

	TEST_ASSERT_OK(clock_gettime(CLOCK_REALTIME, &ts));

	for (i = 0; i < sizeof(parm)/sizeof(parm[0]); i++)
		TEST_ASSERT_OK(timed_thread_create(&parm[i]));

	ts.tv_sec += 100;
	TEST_ASSERT_OK(clock_settime(CLOCK_REALTIME, &ts));
	/* mon 0, rt 100 */

	TEST_MARK();

	ts.tv_sec += 100;
	TEST_ASSERT_OK(clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &ts, NULL));
	/* mon 100, rt 200 */

	kill_threads();
	check_threads_delta_positive();

	TEST_MARK();

	for (i = 0; i < sizeof(parm)/sizeof(parm[0]); i++)
		TEST_ASSERT_OK(timed_thread_create(&parm[i]));

	ts.tv_sec += 100;
	TEST_ASSERT_OK(clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &ts, NULL));
	/* mon 200, rt 300 */

	TEST_MARK();

	ts.tv_sec -= 100;
	TEST_ASSERT_OK(clock_settime(CLOCK_REALTIME, &ts));
	/* mon 200, rt 200 */

	TEST_MARK();

	ts.tv_sec += 100;
	TEST_ASSERT_OK(clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &ts, NULL));
	/* mon 300, rt 300 */

	kill_threads();
	check_threads_delta_negative();
	TEST_MARK();

	TEST_CHECK_SEQUENCE(SEQ("1s_bnd_rt_abs", 1),
			    SEQ("p_bnd_rt_abs_pltd", 1),
			    SEQ("p_bnd_rt_abs_pgtd", 1),

			    SEQ("root", 1), /* Right after timer_settime */

			    SEQ("1s_bnd_mon_rel", 1),
			    SEQ("1s_bnd_mon_abs", 1),
			    SEQ("1s_bnd_rt_rel", 1),

			    SEQ("1s_and_rt_abs", 1),

			    SEQ("p_bnd_mon_rel_pltd", 1),
			    SEQ("p_bnd_mon_abs_pltd", 1),
			    SEQ("p_bnd_rt_rel_pltd", 1),

			    SEQ("p_and_rt_abs_pltd", 1),

			    SEQ("p_bnd_mon_rel_pgtd", 1),
			    SEQ("p_bnd_mon_abs_pgtd", 1),
			    SEQ("p_bnd_rt_rel_pgtd", 1),

			    SEQ("p_and_rt_abs_pgtd", 1),

			    SEQ("root", 1), /* before nanosleep */
			    SEQ("1s_bnd_mon_rel", 1),
			    SEQ("1s_bnd_mon_abs", 1),
			    SEQ("1s_bnd_rt_rel", 1),
			    SEQ("1s_bnd_rt_abs", 1),
			    SEQ("p_bnd_mon_rel_pltd", 1),
			    SEQ("p_bnd_mon_abs_pltd", 1),
			    SEQ("p_bnd_rt_rel_pltd", 1),
			    SEQ("p_bnd_rt_abs_pltd", 1),
			    SEQ("p_bnd_mon_rel_pgtd", 1),
			    SEQ("p_bnd_mon_abs_pgtd", 1),
			    SEQ("p_bnd_rt_rel_pgtd", 1),
			    SEQ("p_bnd_rt_abs_pgtd", 1),
			    SEQ("root", 2), /* before and after clock_settime */
			    SEQ("1s_and_mon_rel", 1),
			    SEQ("1s_and_mon_abs", 1),
			    SEQ("1s_and_rt_rel", 1),
			    SEQ("p_and_mon_rel_pltd", 1),
			    SEQ("p_and_mon_abs_pltd", 1),
			    SEQ("p_and_rt_rel_pltd", 1),
			    SEQ("p_and_mon_rel_pgtd", 1),
			    SEQ("p_and_mon_abs_pgtd", 1),
			    SEQ("p_and_rt_rel_pgtd", 1),
			    SEQ("root", 1), /* final */
			    END_SEQ);
	TEST_FINISH();

	return cookie;
}

int __xeno_user_init (void)
{
	int rc;
	pthread_attr_t attr;
    

	pthread_attr_init(&attr);
	pthread_attr_setname_np(&attr, "root");
    
	rc=pthread_create(&root_thread_tcb, &attr, root_thread, NULL);

	pthread_attr_destroy(&attr);

	return rc;
}

void __xeno_user_exit (void)
{
	pthread_kill(root_thread_tcb, 30);
	pthread_join(root_thread_tcb, NULL);
}
