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

pthread_mutex_t mutex;
pthread_t child_tid;
static pthread_t root_thread_tcb;

void *default_test(void *cookie)
{
    TEST_MARK();                /* 1 */

    TEST_ASSERT(pthread_mutex_trylock(&mutex) == EBUSY);
    
    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));

    TEST_MARK();                /* 3 */

    TEST_ASSERT_OK(sched_yield());

    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));

    TEST_MARK();                /* 5 */

    return cookie;
}

void root_default_test(void)
{
    void *child_result;
    pthread_attr_t attr;
    
    /* Default (normal) mutex test. */
    TEST_ASSERT_OK(pthread_mutex_init(&mutex, NULL));

    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));
    
    TEST_ASSERT_OK(pthread_attr_init(&attr));
    TEST_ASSERT_OK(pthread_attr_setname_np(&attr, "default_test"));
    TEST_ASSERT_OK(pthread_create(&child_tid, &attr, default_test, &attr));
    TEST_ASSERT_OK(pthread_attr_destroy(&attr));    

    TEST_ASSERT_OK(sched_yield());

    TEST_MARK();                /* 2 */

    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));

    TEST_ASSERT_OK(sched_yield());

    TEST_MARK();                /* 4 */

    TEST_ASSERT(pthread_mutex_trylock(&mutex) == EBUSY);

    TEST_ASSERT_OK(sched_yield());

    TEST_MARK();                /* 6 */

    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));
    
    TEST_ASSERT_OK(pthread_join(child_tid, &child_result) &&
                   child_result == (void *) &attr);

    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));
    
    TEST_ASSERT(pthread_mutex_unlock(&mutex) == EPERM);
    
    TEST_ASSERT_OK(pthread_mutex_destroy(&mutex));

    TEST_ASSERT(pthread_mutex_lock(&mutex) == EINVAL);
}

void *recursive_test(void *cookie)
{
    TEST_MARK();                /* 7 */

    TEST_ASSERT(pthread_mutex_trylock(&mutex) == EBUSY);
    
    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));
    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));
    TEST_ASSERT_OK(pthread_mutex_trylock(&mutex));

    TEST_ASSERT_OK(sched_yield());

    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));

    TEST_ASSERT_OK(sched_yield());

    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));

    TEST_ASSERT_OK(sched_yield());

    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));    

    TEST_MARK();                /* 9 */

    return cookie;
}

void root_recursive_test(void)
{
    void *child_result;
    pthread_attr_t tattr;
    pthread_mutexattr_t mattr;
    int type = 0;
    
    /* Recursive mutex test. */
    memset(&mattr, 0, sizeof(mattr));
    TEST_ASSERT(pthread_mutexattr_gettype(&mattr, &type) == EINVAL);
    
    TEST_ASSERT_OK(pthread_mutexattr_init(&mattr));
    TEST_ASSERT_OK(pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_RECURSIVE));
    TEST_ASSERT(pthread_mutexattr_gettype(&mattr, &type) == 0
                && type == PTHREAD_MUTEX_RECURSIVE);

    TEST_ASSERT_OK(pthread_mutex_init(&mutex, &mattr));
    TEST_ASSERT_OK(pthread_mutexattr_destroy(&mattr));

    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));
    
    TEST_ASSERT_OK(pthread_attr_init(&tattr));
    TEST_ASSERT_OK(pthread_attr_setname_np(&tattr, "recursive_test"));
    TEST_ASSERT_OK(pthread_create(&child_tid, &tattr, recursive_test, &tattr));
    TEST_ASSERT_OK(pthread_attr_destroy(&tattr));

    TEST_ASSERT_OK(sched_yield());

    TEST_MARK();                /* 8 */

    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));

    TEST_ASSERT_OK(sched_yield());

    TEST_ASSERT(pthread_mutex_trylock(&mutex) == EBUSY);
    
    TEST_ASSERT_OK(sched_yield());
    
    TEST_ASSERT(pthread_mutex_trylock(&mutex) == EBUSY);
    
    TEST_ASSERT_OK(sched_yield());
    
    TEST_ASSERT(pthread_mutex_trylock(&mutex) == EBUSY);
    
    TEST_ASSERT_OK(pthread_join(child_tid, &child_result) &&
                   child_result == (void *) &tattr);

    TEST_MARK();                /* 10 */

    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));

    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));

    TEST_ASSERT_OK(pthread_mutex_destroy(&mutex));

    TEST_ASSERT(pthread_mutex_lock(&mutex) == EINVAL);
}

void *errorcheck_test(void *cookie)
{
    TEST_MARK();                /* 11 */

    TEST_ASSERT(pthread_mutex_trylock(&mutex) == EBUSY);
    
    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));

    TEST_ASSERT_OK(sched_yield());

    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));

    TEST_MARK();                /* 13 */

    return cookie;
}

void root_errorcheck_test(void)
{
    void *child_result;
    pthread_attr_t tattr;
    pthread_mutexattr_t mattr;
    int type = 0;
    
    /* Error checking mutex test. */
    TEST_ASSERT_OK(pthread_mutexattr_init(&mattr));
    TEST_ASSERT_OK(pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_ERRORCHECK));
    TEST_ASSERT(pthread_mutexattr_gettype(&mattr, &type) == 0
                && type == PTHREAD_MUTEX_ERRORCHECK);

    TEST_ASSERT_OK(pthread_mutex_init(&mutex, &mattr));
    TEST_ASSERT_OK(pthread_mutexattr_destroy(&mattr));

    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));
    
    TEST_ASSERT_OK(pthread_attr_init(&tattr));
    TEST_ASSERT_OK(pthread_attr_setname_np(&tattr, "errorcheck_test"));
    TEST_ASSERT_OK(pthread_create(&child_tid, &tattr, errorcheck_test, &tattr));
    TEST_ASSERT_OK(pthread_attr_destroy(&tattr));

    TEST_ASSERT_OK(sched_yield());

    TEST_MARK();                /* 12 */

    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));

    TEST_ASSERT_OK(sched_yield());

    TEST_ASSERT(pthread_mutex_trylock(&mutex) == EBUSY);
    
    TEST_ASSERT_OK(pthread_join(child_tid, &child_result) &&
                   child_result == (void *) &tattr);

    TEST_MARK();                /* 14 */

    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));

    TEST_ASSERT(pthread_mutex_lock(&mutex) == EDEADLK);

    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));

    TEST_ASSERT_OK(pthread_mutex_destroy(&mutex));
}

/* Priority inversion test. Needs three threads. Uses semaphores for thread
   synchronization. */
static sem_t low_sem, mid_sem, high_sem;

void *prio_inv_low(void *cookie)
{
    struct sched_param param;
    param.sched_priority = sched_get_priority_min(SCHED_RR);
    
    TEST_ASSERT_OK(pthread_setschedparam(pthread_self(), SCHED_RR, &param));

    TEST_ASSERT_OK(sem_wait(&low_sem));

    TEST_MARK();

    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));

    /* Wake-up high priority task so that it can call pthread_mutex_lock. */
    TEST_ASSERT_OK(sem_post(&high_sem));

    /* Wake-up middle priority task, priority inversion may take place here. */
    TEST_ASSERT_OK(sem_post(&mid_sem));

    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));

    return cookie;
}

void *prio_inv_mid(void *cookie)
{
    struct sched_param param;
    param.sched_priority = (sched_get_priority_min(SCHED_RR)+
        sched_get_priority_max(SCHED_RR))/2;
    
    TEST_ASSERT_OK(pthread_setschedparam(pthread_self(), SCHED_RR, &param));

    TEST_ASSERT_OK(sem_wait(&mid_sem));

    TEST_MARK();

    return cookie;
}

void *prio_inv_high(void *cookie)
{
    struct sched_param param;
    param.sched_priority = sched_get_priority_max(SCHED_RR);

    TEST_ASSERT_OK(pthread_setschedparam(pthread_self(), SCHED_RR, &param));

    TEST_ASSERT_OK(sem_wait(&high_sem));

    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));

    TEST_MARK();

    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));

    return cookie;
}

void root_prio_inv_test(int rhs_proto)
{
    int proto;
    pthread_mutexattr_t mattr;
    pthread_attr_t tattr;
    pthread_t low,mid,high;

    TEST_ASSERT_OK(sem_init(&low_sem, 0, 0));
    TEST_ASSERT_OK(sem_init(&mid_sem, 0, 0));
    TEST_ASSERT_OK(sem_init(&high_sem, 0, 0));
    
    TEST_ASSERT_OK(pthread_mutexattr_init(&mattr));
    TEST_ASSERT_OK(pthread_mutexattr_setprotocol(&mattr,rhs_proto));
    TEST_ASSERT(pthread_mutexattr_getprotocol(&mattr, &proto) == 0
                && proto == rhs_proto);

    TEST_ASSERT_OK(pthread_mutex_init(&mutex, &mattr));
    TEST_ASSERT_OK(pthread_mutexattr_destroy(&mattr));

    TEST_ASSERT_OK(pthread_attr_init(&tattr));
    TEST_ASSERT_OK(pthread_attr_setname_np(&tattr, "low"));
    TEST_ASSERT_OK(pthread_create(&low, &tattr, prio_inv_low, NULL));
    TEST_ASSERT_OK(pthread_attr_setname_np(&tattr, "middle"));
    TEST_ASSERT_OK(pthread_create(&mid, &tattr, prio_inv_mid, NULL));
    TEST_ASSERT_OK(pthread_attr_setname_np(&tattr, "high"));
    TEST_ASSERT_OK(pthread_create(&high, &tattr, prio_inv_high, NULL));
    TEST_ASSERT_OK(pthread_attr_destroy(&tattr));
    
    TEST_ASSERT_OK(sem_post(&low_sem));
    TEST_ASSERT_OK(pthread_join(high, NULL));
    TEST_ASSERT_OK(pthread_join(mid, NULL));
    TEST_ASSERT_OK(pthread_join(low, NULL));

    TEST_ASSERT_OK(pthread_mutex_destroy(&mutex));
    TEST_ASSERT_OK(sem_destroy(&low_sem));
    TEST_ASSERT_OK(sem_destroy(&mid_sem));
    TEST_ASSERT_OK(sem_destroy(&high_sem));
}

void *root_thread(void *cookie)
{
    TEST_START(0);

    memset(&mutex, 0, sizeof(mutex));

    TEST_ASSERT(pthread_mutex_lock(&mutex) == EINVAL);

    root_default_test();

    root_recursive_test();

    root_errorcheck_test();

    root_prio_inv_test(PTHREAD_PRIO_NONE);
    
    root_prio_inv_test(PTHREAD_PRIO_INHERIT);
    
    TEST_CHECK_SEQUENCE(SEQ("default_test", 1),
                        SEQ("root", 1),
                        SEQ("default_test", 1),
                        SEQ("root", 1),
                        SEQ("default_test", 1),
                        SEQ("root", 1),
                        SEQ("recursive_test", 1),
                        SEQ("root", 1),
                        SEQ("recursive_test", 1),
                        SEQ("root", 1),
                        SEQ("errorcheck_test", 1),
                        SEQ("root", 1),
                        SEQ("errorcheck_test", 1),
                        SEQ("root", 1),
                        /* Priority inversion with protocol == PRIO_NONE */
                        SEQ("low", 1),
                        SEQ("middle", 1),
                        SEQ("high", 1),
                        /* No priority inversion with protocol == PRIO_INHERIT */
                        SEQ("low", 1),
                        SEQ("high", 1),                        
                        SEQ("middle", 1),
                        END_SEQ);

    TEST_FINISH();

    return NULL;
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
