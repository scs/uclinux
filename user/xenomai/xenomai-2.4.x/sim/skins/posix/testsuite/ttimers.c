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

void *root_thread(void *cookie)
{
    struct itimerspec ts;
    struct sigevent evt;
    struct siginfo si;
    sigset_t set;
    timer_t tm;

    TEST_START(0);

    /* Creation. */
    TEST_ASSERT(timer_create(CLOCK_MONOTONIC + CLOCK_REALTIME + 2, NULL, &tm)
                == -1 && errno == EINVAL);

    evt.sigev_notify = SIGEV_SIGNAL;
    evt.sigev_value.sival_ptr = pthread_self();
    evt.sigev_signo = SIGALRM;
    TEST_ASSERT_OK(timer_create(CLOCK_MONOTONIC, &evt, &tm));

    ts.it_value.tv_sec = 0;
    ts.it_value.tv_nsec = 1500000000;
    TEST_ASSERT(timer_settime(tm, 0, &ts, NULL) == -1 && errno == EINVAL);
    /* We do not test the case SIGEV_THREAD and a thread with a fixed stack
       address: SIGEV_THREAD is not supported, nor the ability to create thread
       wit a fixed stack address. */

    ts.it_value.tv_sec = 0;
    ts.it_value.tv_nsec = 1000000;
    ts.it_interval.tv_sec = 0;
    ts.it_interval.tv_nsec = 0;
    TEST_ASSERT_OK(timer_settime(tm, 0, &ts, NULL));

    sigemptyset(&set);
    sigaddset(&set, SIGALRM);
    TEST_ASSERT_OK(pthread_sigmask(SIG_BLOCK, &set, NULL));
    TEST_ASSERT(0 == sigwaitinfo(&set, &si)
                && si.si_signo == SIGALRM
                && si.si_code == SI_TIMER
                && si.si_value.sival_ptr == pthread_self());
    TEST_ASSERT(timer_gettime(tm, &ts) == 0 &&
                ts.it_value.tv_sec == 0 &&
                ts.it_value.tv_nsec == 0 &&
                ts.it_interval.tv_sec == 0 &&
                ts.it_interval.tv_nsec == 0);
    TEST_ASSERT(timer_getoverrun(tm) >= 0);

    TEST_ASSERT_OK(timer_delete(tm));

    TEST_ASSERT(timer_gettime(tm, &ts) == -1 && errno == EINVAL);
    
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
