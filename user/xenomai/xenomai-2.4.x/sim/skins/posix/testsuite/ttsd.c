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

pthread_once_t once_test_key_create = PTHREAD_ONCE_INIT;
pthread_key_t test_key;
pthread_mutex_t mutex;
static pthread_t root_thread_tcb;

void init_test_key(void)
{
    static int how_many_times = 0;
    
    TEST_MARK();
    
    TEST_ASSERT_OK(pthread_key_create(&test_key, NULL));

    TEST_ASSERT_OK(pthread_mutex_lock(&mutex));
    TEST_ASSERT(++how_many_times == 1);
    TEST_ASSERT_OK(pthread_mutex_unlock(&mutex));
}

pthread_t get_specific(void)
{
    pthread_t result;
    
    TEST_ASSERT_OK(pthread_once(&once_test_key_create, init_test_key));

    if(!(result=pthread_getspecific(test_key))) {
        result=pthread_self();

        pthread_setspecific(test_key, result);
    }

    return result;
}

void thread_spawn(pthread_t *tid, int n, void *(*routine)(void *))
{
    pthread_attr_t tattr;
    char buffer[20];

    TEST_ASSERT_OK(pthread_attr_init(&tattr));
    snprintf(buffer, 20, "%d", n);
    TEST_ASSERT_OK(pthread_attr_setname_np(&tattr, buffer));

    TEST_ASSERT_OK(pthread_create(tid, &tattr, routine, NULL));

    TEST_ASSERT_OK(pthread_attr_destroy(&tattr));
}

void *test_get_specific(void *cookie)
{
    TEST_ASSERT(pthread_equal(pthread_self(), get_specific()));

    TEST_ASSERT(pthread_equal(pthread_self(), get_specific()));

    return cookie;
}

#define THREADS 5

void *root_thread(void *cookie)
{
    pthread_t test_thread[THREADS];
    int i;
    void *status;
    
    TEST_START(0);

    TEST_ASSERT_OK(pthread_mutex_init(&mutex, NULL));

    for(i=0; i<THREADS; i++)
        thread_spawn(&test_thread[i], i+1, test_get_specific);

    for(i=0; i<THREADS; i++)
        TEST_ASSERT_OK(pthread_join(test_thread[i], &status));
    
    TEST_CHECK_SEQUENCE(SEQ("1", 1),
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
