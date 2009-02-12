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

#define SEM_NAME "/shared-sem"
static sem_t sem, *named_sem;
static pthread_t child_tid;
static pthread_t root_thread_tcb;

void *child(void *cookie)
{
    int value;
    
    TEST_MARK();

    TEST_ASSERT(sem_getvalue(&sem, &value) == 0 && value == 0);

    TEST_ASSERT(sem_trywait(&sem) == -1 && errno == EAGAIN);
    
    TEST_ASSERT_OK(sem_wait(&sem));

    TEST_MARK();
    
    return cookie;
}

void *child_named(void *cookie)
{
    sem_t *loc_named_sem = sem_open(SEM_NAME, O_CREAT | O_EXCL, 0, 0);

    TEST_ASSERT(loc_named_sem == SEM_FAILED && errno == EEXIST);

    loc_named_sem = sem_open(SEM_NAME, 0);

    TEST_ASSERT(loc_named_sem == named_sem);
    
    TEST_MARK();

    TEST_ASSERT_OK(sem_wait(named_sem));

    TEST_MARK();

    TEST_ASSERT_OK(sem_unlink(SEM_NAME));

    /* named semaphore is still valid after a call to sem_unlink. */
    TEST_ASSERT(sem_trywait(named_sem) == -1 && errno == EAGAIN);

    loc_named_sem = sem_open(SEM_NAME, O_CREAT | O_EXCL, 0, 0);

    TEST_ASSERT(loc_named_sem != SEM_FAILED && loc_named_sem != named_sem);
    
    TEST_ASSERT_OK(sem_close(named_sem));
    TEST_ASSERT_OK(sem_close(named_sem)); /* named_sem is also opened by root
                                             thread */

    TEST_ASSERT(sem_trywait(named_sem) == -1 && errno == EINVAL);

    TEST_ASSERT(sem_close(named_sem) == -1);

    TEST_ASSERT(sem_trywait(loc_named_sem) == -1 && errno == EAGAIN);

    TEST_ASSERT_OK(sem_close(loc_named_sem));

    TEST_ASSERT(sem_close(loc_named_sem) == -1);

    TEST_ASSERT(sem_trywait(loc_named_sem) == -1 && errno == EINVAL);

    TEST_ASSERT_OK(sem_unlink(SEM_NAME));

    TEST_ASSERT(sem_open(SEM_NAME, 0) == SEM_FAILED && errno == ENOENT);
}

void *root_thread(void *cookie)
{
    pthread_attr_t attr;
    void *child_result;
    int value;
    
    TEST_START(0);

    TEST_ASSERT(sem_wait(&sem) == -1 && errno == EINVAL);

    TEST_ASSERT(sem_init(&sem, 0, -1) == -1 && errno == EINVAL);

    TEST_ASSERT_OK(sem_init(&sem, 0, 0));

    TEST_ASSERT_OK(pthread_attr_init(&attr));
    TEST_ASSERT_OK(pthread_attr_setname_np(&attr, "child"));
    TEST_ASSERT_OK(pthread_create(&child_tid, &attr, child, &attr));
    TEST_ASSERT_OK(pthread_attr_destroy(&attr));

    TEST_ASSERT_OK(sched_yield());

    TEST_MARK();

    TEST_ASSERT(sem_getvalue(&sem, &value) == 0 && (value == 0 || value == -1));
    
    TEST_ASSERT_OK(sem_post(&sem));

    TEST_ASSERT_OK(pthread_join(child_tid, &child_result) &&
                   child_result == (void *) &attr);

    TEST_ASSERT(sem_getvalue(&sem, &value) == 0 && value == 0);
    
    TEST_MARK();

    TEST_ASSERT_OK(sem_destroy(&sem));

    TEST_ASSERT(sem_wait(&sem) == -1 && errno == EINVAL);

    TEST_ASSERT_OK(sem_init(&sem, 0, SEM_VALUE_MAX-1));

    TEST_ASSERT_OK(sem_post(&sem));

    TEST_ASSERT(sem_getvalue(&sem, &value) == 0 && value == SEM_VALUE_MAX);

    TEST_ASSERT(sem_post(&sem) == -1 && errno == EAGAIN);
    
    TEST_ASSERT(sem_getvalue(&sem, &value) == 0 && value == SEM_VALUE_MAX);

    named_sem = sem_open(SEM_NAME, 0);

    TEST_ASSERT(named_sem == SEM_FAILED && errno == ENOENT);

    named_sem = sem_open(SEM_NAME, O_CREAT, 0, 0);

    TEST_ASSERT(named_sem != SEM_FAILED && named_sem != &sem);
    
    TEST_ASSERT_OK(pthread_attr_init(&attr));
    TEST_ASSERT_OK(pthread_attr_setname_np(&attr, "child_named"));
    TEST_ASSERT_OK(pthread_create(&child_tid, &attr, child_named, &attr));
    TEST_ASSERT_OK(pthread_attr_destroy(&attr));
    
    TEST_ASSERT_OK(sched_yield());

    TEST_MARK();

    TEST_ASSERT_OK(sem_post(named_sem));

    TEST_ASSERT_OK(sched_yield());

    TEST_ASSERT_OK(pthread_join(child_tid, &child_result) &&
                   child_result == (void *) &attr);

    TEST_CHECK_SEQUENCE(SEQ("child", 1),
                        SEQ("root", 1),
                        SEQ("child", 1),
                        SEQ("root", 1),
                        SEQ("child_named", 1),
                        SEQ("root", 1),
                        SEQ("child_named", 1),
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
