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
int step;
pthread_cond_t cond;
static pthread_t root_thread_tcb;

typedef struct cancel_mask {
    int type;
    int state;
} cancel_mask_t;

cancel_mask_t mask;

void mutex_unlock(void *mutex)
{
    TEST_ASSERT_OK(pthread_mutex_unlock((pthread_mutex_t *) mutex));
}

void *cond_wait_thread(void *cookie)
{
    pthread_setcanceltype(mask.type, &mask.type);
    pthread_setcancelstate(mask.state, &mask.state);
    
    TEST_MARK();

    pthread_cleanup_push(mutex_unlock,&mutex);
    
    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));

    step = 1;
    TEST_ASSERT_OK(pthread_cond_signal(&cond));
    while(step != 2)
        pthread_cond_wait(&cond, &mutex);

    /* Not reached if thread is canceled. */
    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));

    pthread_cleanup_pop(0);

    TEST_MARK();

    pthread_setcancelstate(mask.state, &mask.state);
    
    TEST_MARK();

    pthread_testcancel();

    return NULL;
}

void *joinee(void *cookie)
{
    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));

    step = 1;
    TEST_ASSERT_OK(pthread_cond_signal(&cond));
    while(step != 2)
        TEST_ASSERT_OK(pthread_cond_wait(&cond, &mutex));

    /* Not reached if thread is canceled. */
    
    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));

    return cookie;
}

void *joiner(void *cookie)
{
    pthread_t *joinee = (pthread_t *) cookie;
    void *status;

    pthread_setcanceltype(mask.type, &mask.type);
    pthread_setcancelstate(mask.state, &mask.state);
    
    TEST_MARK();

    pthread_join(*joinee, &status);

    TEST_MARK();

    pthread_setcancelstate(mask.state, &mask.state);
    
    TEST_MARK();

    pthread_testcancel();

    return NULL;
}

void launch_and_try_cancel(int type, int state)
{
    pthread_attr_t tattr;
    pthread_t thread1, thread2;
    void *status;

    mask.type = type;
    mask.state = state;
    step = 0;
    TEST_ASSERT_OK(pthread_attr_init(&tattr));
    TEST_ASSERT_OK(pthread_attr_setname_np(&tattr, "cond_wait"));
    TEST_ASSERT_OK(pthread_create(&thread1, &tattr, cond_wait_thread, NULL));

    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));
    while(step != 1)
        TEST_ASSERT_OK(pthread_cond_wait(&cond, &mutex));
    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));
    
    TEST_ASSERT_OK(pthread_cancel(thread1));

    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));
    step=2;
    TEST_ASSERT_OK(pthread_cond_signal(&cond));
    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));

    TEST_ASSERT(pthread_join(thread1, &status)==0 && status==PTHREAD_CANCELED);

    mask.type = type;
    mask.state = state;
    step = 0;
    TEST_ASSERT_OK(pthread_attr_setname_np(&tattr, "joinee"));
    TEST_ASSERT_OK(pthread_create(&thread1, &tattr, joinee, NULL));

    TEST_ASSERT_OK(pthread_attr_setname_np(&tattr, "joiner"));
    TEST_ASSERT_OK(pthread_create(&thread2, &tattr, joiner, &thread1));

    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));
    while(step != 1)
        TEST_ASSERT_OK(pthread_cond_wait(&cond, &mutex));
    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));

    TEST_ASSERT_OK(pthread_cancel(thread2));

    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));
    step=2;
    TEST_ASSERT_OK(pthread_cond_signal(&cond));
    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));

    TEST_ASSERT(pthread_join(thread1, &status)==0 && status==NULL);
    TEST_ASSERT(pthread_join(thread2, &status)==0 && status==PTHREAD_CANCELED);

    TEST_ASSERT_OK(pthread_attr_destroy(&tattr));
}

/* sigwait is tested in signals.c */

void *root_thread(void *cookie)
{
    pthread_mutexattr_t mattr;

    TEST_START(0);

    TEST_ASSERT_OK(pthread_mutexattr_init(&mattr));
    TEST_ASSERT_OK(pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_ERRORCHECK));
    TEST_ASSERT_OK(pthread_mutex_init(&mutex, &mattr));
    TEST_ASSERT_OK(pthread_mutexattr_destroy(&mattr));

    TEST_ASSERT_OK(pthread_cond_init(&cond, NULL));

    TEST_ASSERT(pthread_cancel(NULL) == ESRCH);

    launch_and_try_cancel(PTHREAD_CANCEL_DEFERRED, PTHREAD_CANCEL_ENABLE);
    launch_and_try_cancel(PTHREAD_CANCEL_ASYNCHRONOUS, PTHREAD_CANCEL_DISABLE);
    launch_and_try_cancel(PTHREAD_CANCEL_DEFERRED, PTHREAD_CANCEL_DISABLE);
    
    TEST_CHECK_SEQUENCE(/* DEFERRED, ENABLE */
                        SEQ("cond_wait", 1),
                        SEQ("joiner", 1),
                        /* ASYNCHRONOUS, DISABLE */
                        SEQ("cond_wait", 2),
                        SEQ("joiner", 2),
                        /* DEFERRED, DISABLE */
                        SEQ("cond_wait", 3),
                        SEQ("joiner", 3),
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
