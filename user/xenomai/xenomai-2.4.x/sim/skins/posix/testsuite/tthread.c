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

/* Checks sched_yield. */
static void *test_routine(void *cookie)
{
    TEST_MARK();                /* 3 in child1, 4 in child2 */

    sched_yield();

    TEST_MARK();                /* 5 in child1, 6 in child2 */
    
    return cookie;
}

static void *slicer(void *cookie)
{
    int i;
    
    for(i=0; i<4; i++) {
        int j;

        TEST_MARK();

        for(j=0; j<300000; j++)
            ;
    }

    pthread_exit(cookie);
}


void *root_thread(void *cookie)
{
    pthread_t child1, child2;
    pthread_attr_t attr;
    struct sched_param p;
    struct timespec ts;
    size_t s;
    int i;
    void *tmp;
    const char *str;

    TEST_START(0);

    p.sched_priority=sched_get_priority_max(SCHED_FIFO);
    TEST_ASSERT_OK(pthread_setschedparam(pthread_self(), SCHED_FIFO, &p));
    
    TEST_ASSERT_OK(pthread_attr_init(&attr));

    /* Verify some known thread attribtute default values. */
    TEST_ASSERT(pthread_attr_getdetachstate(&attr, &i)==0 &&
                i==PTHREAD_CREATE_JOINABLE);

    /* Set and get attributes values. */
    TEST_ASSERT_OK(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED));
    TEST_ASSERT(pthread_attr_getdetachstate(&attr, &i) == 0 &&
                i == PTHREAD_CREATE_DETACHED);
    TEST_ASSERT(pthread_attr_setstacksize(&attr, PTHREAD_STACK_MIN-1)==EINVAL);
    TEST_ASSERT_OK(pthread_attr_setstacksize(&attr, 4*PTHREAD_STACK_MIN));
    TEST_ASSERT(pthread_attr_getstacksize(&attr, &s) == 0 &&
                s == 4*PTHREAD_STACK_MIN);

    TEST_ASSERT_OK(pthread_attr_setname_np(&attr, "detached"));
    TEST_ASSERT(pthread_attr_getname_np(&attr, &str) == 0 &&
                !strcmp(str, "detached"));

    TEST_ASSERT_OK(pthread_attr_setinheritsched(&attr, PTHREAD_INHERIT_SCHED));
    TEST_ASSERT(pthread_attr_getinheritsched(&attr, &i) == 0 &&
                i == PTHREAD_INHERIT_SCHED);
    
    /* Check elementary scheduling determinism. */
    TEST_MARK();                /* 1 */
    
    TEST_ASSERT_OK(pthread_create(&child1, &attr, test_routine, &child1));
    TEST_ASSERT(pthread_join(child1, &tmp) == EINVAL);

    TEST_ASSERT_OK(pthread_attr_setname_np(&attr, "joinable"));
    TEST_ASSERT(pthread_attr_getname_np(&attr, &str) == 0 &&
                !strcmp(str, "joinable"));

    TEST_ASSERT_OK(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE));
    TEST_ASSERT(pthread_attr_getdetachstate(&attr, &i) == 0 &&
                i == PTHREAD_CREATE_JOINABLE);

    TEST_ASSERT_OK(pthread_create(&child2, &attr, test_routine, &child2));

    TEST_MARK();                /* 2 */

    TEST_ASSERT(pthread_join(child2, &tmp) == 0 && tmp == &child2);

    TEST_MARK();                /* 7 */

    TEST_ASSERT_OK(clock_getres(CLOCK_REALTIME, &ts));

    /* Check if running over aperiodic timer by reading the clock resolution. */
    if (!ts.tv_sec && ts.tv_nsec == 1)
        TEST_CHECK_SEQUENCE(SEQ("root", 2),
                            SEQ("detached", 1),
                            SEQ("joinable", 1),
                            SEQ("detached", 1),
                            SEQ("joinable", 1),
                            END_SEQ);
    else {
        /* Check round-robin scheduling. Only works over periodic timer, with
         * period of 10 ms. */
        TEST_ASSERT_OK(pthread_attr_setinheritsched(&attr,
                                                    PTHREAD_EXPLICIT_SCHED));
        TEST_ASSERT_OK(pthread_getschedparam(pthread_self(), &i, &p));
        TEST_ASSERT_OK(pthread_attr_setschedpolicy(&attr, SCHED_RR));
        TEST_ASSERT_OK(pthread_attr_setschedparam(&attr, &p));
        TEST_ASSERT_OK(pthread_attr_setname_np(&attr, "slicer1"));
        TEST_ASSERT_OK(pthread_create(&child1, &attr, slicer, &child1));
        
        TEST_ASSERT_OK(pthread_attr_setname_np(&attr, "slicer2"));
        TEST_ASSERT_OK(pthread_create(&child2, &attr, slicer, &child2));
        
        TEST_MARK();

        TEST_ASSERT(pthread_join(child1, &tmp) == 0 && tmp == &child1);
        TEST_ASSERT(pthread_join(child2, &tmp) == 0 && tmp == &child2);
        
        TEST_MARK();
    
        TEST_CHECK_SEQUENCE(SEQ("root", 2),
                            SEQ("detached", 1),
                            SEQ("joinable", 1),
                            SEQ("detached", 1),
                            SEQ("joinable", 1),
                            SEQ("root", 2),
                            SEQ("slicer1", 1),
                            SEQ("slicer2", 1),
                            SEQ("slicer1", 1),
                            SEQ("slicer2", 1),
                            SEQ("slicer1", 1),
                            SEQ("slicer2", 1),
                            SEQ("slicer1", 1),
                            SEQ("slicer2", 1),
                            SEQ("root", 1),
                            END_SEQ);
    }

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
