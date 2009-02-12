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

static pthread_cond_t cond;
static pthread_mutex_t mutex;
static int flag = 0;
static sem_t sem;
static pthread_t root_thread_tcb;

void *cond_waiter(void *cookie)
{
    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));

    TEST_MARK();
    
    TEST_ASSERT_OK(sem_post(&sem));

    while(!flag) {
        TEST_ASSERT_OK(pthread_cond_wait(&cond, &mutex));

        TEST_MARK();
    }

    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));

    return cookie;
}



void *root_thread(void *cookie)
{
    pthread_attr_t tattr;
    pthread_t child1, child2;
    pthread_condattr_t cattr;
    clockid_t ck;
    void *child_status;

    TEST_START(0);

    TEST_ASSERT(pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC) == EINVAL);

    TEST_ASSERT(pthread_cond_signal(&cond) == EINVAL);

    TEST_ASSERT_OK(sem_init(&sem, 0, 0));

    TEST_ASSERT_OK(pthread_condattr_init(&cattr));

    TEST_ASSERT_OK(pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC));

    TEST_ASSERT(pthread_condattr_getclock(&cattr, &ck) == 0 &&
                ck == CLOCK_MONOTONIC);


    TEST_ASSERT_OK(pthread_cond_init(&cond, &cattr));

    TEST_ASSERT_OK(pthread_cond_destroy(&cond));

    TEST_ASSERT(pthread_cond_destroy(&cond) == EINVAL);

    TEST_ASSERT_OK(pthread_mutex_init(&mutex, NULL));
    TEST_ASSERT_OK(pthread_cond_init(&cond, NULL));

    TEST_MARK();
    
    TEST_ASSERT_OK(pthread_attr_init(&tattr));
    TEST_ASSERT_OK(pthread_attr_setname_np(&tattr, "condwait1"));
    TEST_ASSERT_OK(pthread_create(&child1, &tattr, cond_waiter, NULL));

    TEST_ASSERT_OK(pthread_attr_setname_np(&tattr, "condwait2"));
    TEST_ASSERT_OK(pthread_create(&child2, &tattr, cond_waiter, NULL));

    TEST_ASSERT_OK(sem_wait(&sem));
    TEST_ASSERT_OK(sem_wait(&sem));

    /* Useless signal. */
    TEST_ASSERT_OK(pthread_cond_signal(&cond));
    TEST_ASSERT_OK(sched_yield());
    
    /* Wake up first thread. */
    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));
    flag = 1;
    TEST_MARK();
    TEST_ASSERT_OK(pthread_cond_signal(&cond));
    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));

    /* Wake up second thread. */
    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));
    flag = 1;
    TEST_MARK();
    TEST_ASSERT_OK(pthread_cond_signal(&cond));
    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));

    TEST_ASSERT_OK(pthread_join(child1, &child_status));
    TEST_ASSERT_OK(pthread_join(child2, &child_status));

    flag = 0;
    
    TEST_ASSERT_OK(pthread_attr_setname_np(&tattr, "broadcast1"));
    TEST_ASSERT_OK(pthread_create(&child1, &tattr, cond_waiter, NULL));

    TEST_ASSERT_OK(pthread_attr_setname_np(&tattr, "broadcast2"));
    TEST_ASSERT_OK(pthread_create(&child2, &tattr, cond_waiter, NULL));

    TEST_ASSERT_OK(sem_wait(&sem));
    TEST_ASSERT_OK(sem_wait(&sem));

    /* Useless broadcast. */
    TEST_ASSERT_OK(pthread_cond_broadcast(&cond));
    TEST_ASSERT_OK(sched_yield());

    /* Wake up both threads at once. */
    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));
    flag = 1;
    TEST_MARK();
    TEST_ASSERT_OK(pthread_cond_broadcast(&cond));
    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));

    TEST_ASSERT_OK(pthread_join(child1, &child_status));
    TEST_ASSERT_OK(pthread_join(child2, &child_status));

    TEST_ASSERT_OK(pthread_attr_destroy(&tattr));
    
    TEST_CHECK_SEQUENCE(SEQ("root", 1),
                        SEQ("condwait1", 1),
                        SEQ("condwait2", 1),
                        /* Useless signal. */
                        SEQ("condwait1", 1),
                        /* Signals. */
                        SEQ("root", 2),
                        SEQ("condwait2", 1),
                        SEQ("condwait1", 1),
                        SEQ("broadcast1", 1),
                        SEQ("broadcast2", 1),
                        /* Useless broadcast. */
                        SEQ("broadcast1", 1),
                        SEQ("broadcast2", 1),
                        /* Broadcast. */
                        SEQ("root", 1),
                        SEQ("broadcast1", 1),
                        SEQ("broadcast2", 1),                        
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
