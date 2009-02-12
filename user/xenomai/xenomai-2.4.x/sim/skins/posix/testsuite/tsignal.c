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

void test_sigsets(void)
{
    int i;
    
    sigset_t sigmask;

    TEST_ASSERT_OK(sigemptyset(&sigmask));

    for(i=1; i<=SIGRTMAX; i++)
        TEST_ASSERT(!sigismember(&sigmask, i));

    TEST_ASSERT(sigaddset(&sigmask, 0)==-1 && errno==EINVAL);
    TEST_ASSERT_OK(sigaddset(&sigmask, 1));
    TEST_ASSERT_OK(sigaddset(&sigmask, 15));
    TEST_ASSERT_OK(sigaddset(&sigmask, SIGRTMAX));
    TEST_ASSERT(sigaddset(&sigmask, SIGRTMAX+1)==-1 && errno==EINVAL);

    TEST_ASSERT(sigismember(&sigmask, 0)==-1 && errno==EINVAL);
    TEST_ASSERT(sigismember(&sigmask, 1)==1);
    TEST_ASSERT(sigismember(&sigmask, 2)==0);
    TEST_ASSERT(sigismember(&sigmask, 14)==0);
    TEST_ASSERT(sigismember(&sigmask, 15)==1);
    TEST_ASSERT(sigismember(&sigmask, 16)==0);
    TEST_ASSERT(sigismember(&sigmask, SIGRTMAX-1)==0);
    TEST_ASSERT(sigismember(&sigmask, SIGRTMAX)==1);
    TEST_ASSERT(sigismember(&sigmask, SIGRTMAX+1)==-1 && errno==EINVAL);

    TEST_ASSERT_OK(sigfillset(&sigmask));

    for(i=1; i<=SIGRTMAX; i++)
        TEST_ASSERT(sigismember(&sigmask, i));
}

void test_sigpending(void)
{
    sigset_t sigmask, saved, pending;

    TEST_ASSERT_OK(sigemptyset(&sigmask));
    TEST_ASSERT_OK(sigaddset(&sigmask, 4));
    TEST_ASSERT_OK(pthread_sigmask(SIG_BLOCK, &sigmask, &saved));
    TEST_ASSERT_OK(pthread_kill(pthread_self(), 4));
    TEST_ASSERT_OK(sigpending(&pending));
    TEST_ASSERT(sigismember(&pending, 4));
}

void *wait_sig(void *cookie)
{
    sigset_t *parent = (sigset_t *) cookie;
    sigset_t sigmask, saved;
    struct timespec timeout;
    siginfo_t info;
    int sig;

    TEST_ASSERT_OK(sigemptyset(&sigmask));
    TEST_ASSERT_OK(sigaddset(&sigmask, SIGRTMIN));
    TEST_ASSERT_OK(sigaddset(&sigmask, SIGRTMIN+1));
    TEST_ASSERT_OK(pthread_sigmask(SIG_BLOCK, &sigmask, &saved));

    for(sig=1; sig<=SIGRTMAX; sig++)
        TEST_ASSERT(sigismember(&saved, sig) == sigismember(parent,sig));

    TEST_ASSERT(sigwait(&sigmask, &sig) == 0 && sig == SIGRTMIN);
    TEST_ASSERT(sigwaitinfo(&sigmask, &info) == 0 &&
                info.si_signo == SIGRTMIN+1 &&
                info.si_code == SI_QUEUE &&
                info.si_value.sival_int == 42);
    

    timeout.tv_nsec = 10000000;
    timeout.tv_sec = 0;
    /* either status is admitted by POSIX. */
    TEST_ASSERT(sigtimedwait(&sigmask, &info, &timeout) == -1 &&
                (errno == EINTR || errno == EAGAIN));

    TEST_MARK();

    return NULL;
}

void test_sigwait(void)
{
    sigset_t sigmask, saved;
    int policy;
    struct sched_param prio;
    pthread_t thread;
    pthread_attr_t tattr;
    void *status;

    TEST_ASSERT_OK(sigemptyset(&sigmask));
    TEST_ASSERT_OK(sigaddset(&sigmask, SIGRTMIN + 2));
    TEST_ASSERT_OK(pthread_sigmask(SIG_BLOCK, &sigmask, &saved));
    TEST_ASSERT_OK(sigaddset(&saved, SIGRTMIN + 2));
    
    TEST_ASSERT_OK(pthread_attr_init(&tattr));
    TEST_ASSERT_OK(pthread_attr_setinheritsched(&tattr, 1));
    TEST_ASSERT_OK(pthread_attr_setname_np(&tattr, "sigwait"));
    TEST_ASSERT_OK(pthread_create(&thread, &tattr, wait_sig, &saved));
    sched_yield();
    TEST_ASSERT_OK(pthread_attr_destroy(&tattr));

    TEST_ASSERT_OK(pthread_sigqueue_np(thread, SIGRTMIN+1, (union sigval) 42));
    TEST_ASSERT_OK(pthread_kill(thread, SIGRTMIN));
    TEST_ASSERT_OK(pthread_kill(thread, SIGRTMIN+2));

    TEST_ASSERT_OK(pthread_join(thread, &status));

    TEST_ASSERT_OK(pthread_sigmask(SIG_SETMASK, &saved, NULL));
}

int step;
pthread_mutex_t mutex;
pthread_cond_t cond;

void marker(int sig)
{
    TEST_MARK();
}

void *cond_wait(void *cookie)
{
    int rc;
    
    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));
    step=1;
    TEST_ASSERT_OK(pthread_cond_signal(&cond));
    do {
        TEST_ASSERT_OK(rc=pthread_cond_wait(&cond, &mutex));
    } while(!rc && step != 2);
    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));

    TEST_MARK();
    
    return cookie;
}

void test_cond_wait(void)
{
    pthread_attr_t tattr;
    pthread_t thread;
    struct sigaction action, saved;
    void *status;

    action.sa_handler = marker;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    TEST_MARK();
    
    TEST_ASSERT_OK(sigaction(5, &action, &saved));

    step=0;
    TEST_ASSERT_OK(pthread_attr_init(&tattr));
    TEST_ASSERT_OK(pthread_attr_setname_np(&tattr, "cond_wait"));
    TEST_ASSERT_OK(pthread_create(&thread, &tattr, cond_wait, NULL));
    TEST_ASSERT_OK(pthread_attr_destroy(&tattr));

    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));
    while(step != 1)
        TEST_ASSERT_OK(pthread_cond_wait(&cond, &mutex));
    TEST_ASSERT_OK(pthread_kill(thread, 5));
    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));

    TEST_ASSERT_OK(sched_yield());

    TEST_MARK();

    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));
    step=2;
    TEST_ASSERT_OK(pthread_cond_signal(&cond));
    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));

    TEST_ASSERT_OK(pthread_join(thread, &status));

    TEST_ASSERT_OK(sigaction(5, &saved, NULL));
}

void *mutex_lock(void *cookie)
{
    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));

    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));

    TEST_MARK();
    
    return NULL;
}

void test_mutex_lock(void)
{
    pthread_attr_t tattr;
    pthread_t thread;
    struct sigaction action, saved;
    void *status;

    action.sa_handler = marker;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    TEST_MARK();

    TEST_ASSERT_OK(sigaction(5, &action, &saved));

    TEST_ASSERT_OK(pthread_attr_init(&tattr));
    TEST_ASSERT_OK(pthread_attr_setname_np(&tattr, "mutex_lock"));
    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));
    TEST_ASSERT_OK(pthread_create(&thread, &tattr, mutex_lock, NULL));
    TEST_ASSERT_OK(pthread_attr_destroy(&tattr));

    TEST_ASSERT_OK(sched_yield());
    TEST_ASSERT_OK(pthread_kill(thread, 5));
    TEST_ASSERT_OK(sched_yield());

    TEST_MARK();

    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));

    TEST_ASSERT_OK(pthread_join(thread, &status));

    TEST_ASSERT_OK(sigaction(5, &saved, NULL));
}

sem_t sem;

void *sem_wait_thr(void *cookie)
{
    TEST_ASSERT(sem_wait(&sem)==-1 && errno==EINTR);

    TEST_ASSERT_OK(sem_wait(&sem));

    TEST_MARK();

    return NULL;
}

void test_sem_wait(void)
{
    pthread_attr_t tattr;
    pthread_t thread;
    struct sigaction action, saved;
    void *status;
    
    action.sa_handler = marker;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    TEST_MARK();
    
    TEST_ASSERT_OK(sigaction(5, &action, &saved));

    TEST_ASSERT_OK(pthread_attr_init(&tattr));
    TEST_ASSERT_OK(pthread_attr_setname_np(&tattr, "sem_wait"));
    TEST_ASSERT_OK(pthread_create(&thread, &tattr, sem_wait_thr, NULL));
    TEST_ASSERT_OK(pthread_attr_destroy(&tattr));

    TEST_ASSERT_OK(sched_yield());
    TEST_ASSERT_OK(pthread_kill(thread, 5));
    TEST_ASSERT_OK(sched_yield());

    TEST_MARK();

    TEST_ASSERT_OK(sem_post(&sem));
    
    TEST_ASSERT_OK(pthread_join(thread, &status));

    TEST_ASSERT_OK(sigaction(5, &saved, NULL));
}

pthread_t joinee;

void *joinee_thr(void *cookie)
{
    TEST_ASSERT_OK(sem_wait(&sem));

    return cookie;
}

void *join(void *cookie)
{
    void *status;
    
    TEST_ASSERT_OK(pthread_join(joinee, &status));

    TEST_MARK();
    
    return cookie;
}

void test_join(void)
{
    pthread_attr_t tattr;
    pthread_t thread;
    struct sigaction action, saved;
    void *status;
    
    action.sa_handler = marker;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;

    TEST_MARK();
    
    TEST_ASSERT_OK(sigaction(5, &action, &saved));

    TEST_ASSERT_OK(pthread_attr_init(&tattr));
    TEST_ASSERT_OK(pthread_attr_setname_np(&tattr, "joinee"));
    TEST_ASSERT_OK(pthread_create(&joinee, &tattr, joinee_thr, NULL));
    TEST_ASSERT_OK(sched_yield());
    TEST_ASSERT_OK(pthread_attr_setname_np(&tattr, "join"));
    TEST_ASSERT_OK(pthread_create(&thread, &tattr, join, NULL));
    TEST_ASSERT_OK(sched_yield());
    TEST_ASSERT_OK(pthread_attr_destroy(&tattr));

    TEST_ASSERT_OK(pthread_kill(thread, 5));
    TEST_ASSERT_OK(sched_yield());

    TEST_MARK();

    TEST_ASSERT_OK(sem_post(&sem));
    
    TEST_ASSERT_OK(pthread_join(thread, &status));

    TEST_ASSERT_OK(sigaction(5, &saved, NULL));
}

/* Blocking call which should cause execution of signal handlers :
   pthread_cond_wait
   pthread_mutex_lock
   sem_wait
   pthread_join
   ( and sigwait, except for the signals tested. )

   Functions to be tested :
   int sigemptyset(sigset_t *set);
   int sigfillset(sigset_t *set);
   int sigaddset(sigset_t *set, int signum);
   int sigdelset(sigset_t *set, int signum);
   int sigismember(const sigset_t *set, int signum);
   
   int pthread_kill(pthread_t thread, int sig);
   int pthread_sigmask(int how, const sigset_t *set, sigset_t *oset);
   
   int sigaction(int sig,const struct sigaction *action,struct sigaction *old);
   int sigpending(sigset_t *set);
   int sigwait(const sigset_t *set, int *sig);
   
*/

void *root_thread(void *cookie)
{
    
    TEST_START(0);

    TEST_ASSERT_OK(pthread_cond_init(&cond, NULL));
    TEST_ASSERT_OK(pthread_mutex_init(&mutex, NULL));
    TEST_ASSERT_OK(sem_init(&sem, 0, 0));
    
    test_sigsets();
    test_sigpending();
    test_sigwait();
    test_cond_wait();
    test_mutex_lock();
    test_sem_wait();
    test_join();
    
    TEST_CHECK_SEQUENCE(SEQ("sigwait", 1),
                        SEQ("root", 1),
                        SEQ("cond_wait", 1),
                        SEQ("root", 1),
                        SEQ("cond_wait", 1),
                        SEQ("root", 1),
                        SEQ("mutex_lock", 1),
                        SEQ("root", 1),
                        SEQ("mutex_lock", 1),
                        SEQ("root", 1),
                        SEQ("sem_wait", 1),
                        SEQ("root", 1),
                        SEQ("sem_wait", 1),
                        SEQ("root", 1),
                        SEQ("join", 1),
                        SEQ("root", 1),
                        SEQ("join", 1),
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
