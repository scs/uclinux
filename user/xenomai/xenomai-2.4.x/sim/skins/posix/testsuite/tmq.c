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
struct mq_attr attr;
mqd_t qd, qdr, qdw;
pthread_t tid_writer, tid_reader;

static const char *tunes[] = {
    "Surfing With The Alien",
    "Lords of Karma",
    "Banana Mango",
    "Psycho Monkey",
    "Luminous Flesh Giants",
    "Moroccan Sunset",
    "Satch Boogie",
    "Flying In A Blue Dream",
    "Ride",
    "Summer Song",
    "Speed Of Light",
    "Crystal Planet",
    "Raspberry Jam Delta-V",
    "Champagne?",
    "Clouds Race Across The Sky",
    "Engines Of Creation"
};

void qdflags_setbits(mqd_t qd, unsigned flags)
{
    struct mq_attr attr;

    TEST_ASSERT_OK(mq_getattr(qd, &attr));

    attr.mq_flags |= flags;

    TEST_ASSERT_OK(mq_setattr(qd, &attr, NULL));
}

void qdflags_clrbits(mqd_t qd, unsigned flags)
{
    struct mq_attr attr;

    TEST_ASSERT_OK(mq_getattr(qd, &attr));

    attr.mq_flags &= ~flags;

    TEST_ASSERT_OK(mq_setattr(qd, &attr, NULL));
}

void *writer(void *cookie)
{
    struct sched_param par;
    unsigned i;
    mqd_t qdf;

    TEST_ASSERT(-1 == mq_send(qdr, tunes[0], strlen(tunes[0])+1, 0) && errno == EBADF);

    for(i = 0; i < sizeof(tunes)/sizeof(char *); i++)
        TEST_ASSERT_OK(mq_send(qd, tunes[i], strlen(tunes[i])+1, i));

    qdflags_setbits(qd, O_NONBLOCK);

    TEST_ASSERT(-1 == mq_send(qd, tunes[0], strlen(tunes[0])+1, 0) && errno == EAGAIN);

    TEST_MARK();                /* 1 */

    par.sched_priority = sched_get_priority_max(SCHED_FIFO);
 /* reader should preempt here (mark 2). */
    pthread_setschedparam(tid_reader, SCHED_FIFO, &par);

    TEST_MARK();                /* 3 */

    /* From that point, the reader should have switched to blocking mode and be
      blocked. Every message sent will cause a reader wakeup.*/
    for(i = 0; i < sizeof(tunes)/sizeof(char *); i++)
        TEST_ASSERT_OK(mq_send(qd, tunes[i], strlen(tunes[i])+1, i));

    /* From this point, the reader switched to lowest priority. */
    TEST_MARK();                /* 4 */

    TEST_ASSERT(0 == mq_getattr(qd, &attr) && attr.mq_curmsgs == 0);

    /* We fill the queue here. */
    for(i = 0; i < sizeof(tunes)/sizeof(char *); i++)
        TEST_ASSERT_OK(mq_send(qd, tunes[i], strlen(tunes[i])+1, i));

    /* This one should suspend the writer (and switch to mark 5) */
    i = sizeof(tunes)/sizeof(char *) - 1;
    TEST_ASSERT_OK(mq_send(qd, tunes[i], strlen(tunes[i])+1, i));

    TEST_MARK();                /* 6 */

    return cookie;
}

void *reader(void *cookie)
{
    struct sched_param par;
    struct mq_attr attr;
    unsigned i, prev;
    char buffer [42];
    ssize_t len;

    TEST_ASSERT(-1 == mq_receive(qdw, buffer, sizeof(buffer), 0) && errno == EBADF);
    prev = sizeof(tunes)/sizeof(char *);

    do {

        TEST_ASSERT(0 < (len = mq_receive(qd, buffer, sizeof(buffer), &i)));

        TEST_ASSERT(i == prev - 1 && len == strlen(buffer)+1 && !strcmp(buffer, tunes[i]));

        prev = i;
    } while(i);

    qdflags_setbits(qd, O_NONBLOCK);

    TEST_ASSERT(-1 == mq_receive(qd, buffer, sizeof(buffer), &i) && errno == EAGAIN);

    TEST_MARK();                /* 2. */

    qdflags_clrbits(qd, O_NONBLOCK);

    TEST_ASSERT(0 == mq_getattr(qd, &attr) && attr.mq_curmsgs == 0);

    for(i = 0; i < sizeof(tunes)/sizeof(char *); i++)
        {
        unsigned prio;
        len = mq_receive(qd, buffer, sizeof(buffer), &prio);

        TEST_ASSERT(prio == i && len == strlen(tunes[i])+1 && !strcmp(buffer, tunes[i]));
        }

    par.sched_priority = sched_get_priority_min(SCHED_FIFO);
/* writer should preempt here (mark 3).*/
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &par);

    /* Writer has filled the queue and is suspended, make it high priority to
       cause immediate switch. */
    TEST_MARK();                /* 5 */
    par.sched_priority = sched_get_priority_max(SCHED_FIFO);
    pthread_setschedparam(tid_writer, SCHED_FIFO, &par); /* no switch here */

    prev = sizeof(tunes)/sizeof(char *);

    /* We should receive twice the highest priority message. */
    TEST_ASSERT(0 < (len = mq_receive(qd, buffer, sizeof(buffer), &i)));
    /* Switch to writer here (mark 6). */
    TEST_ASSERT(i == prev - 1 && len == strlen(buffer)+1 && !strcmp(buffer, tunes[i]));

    do {

        TEST_ASSERT(0 < (len = mq_receive(qd, buffer, sizeof(buffer), &i)));

        TEST_ASSERT(i == prev - 1 && len == strlen(buffer)+1 && !strcmp(buffer, tunes[i]));

        if(i == sizeof(tunes)/sizeof(char *) - 1)
            TEST_MARK();        /* 7 */
        
        prev = i;
    } while(i);
    
    return cookie;
}

void *root_thread(void *cookie)
{
    pthread_attr_t tattr;

    pthread_attr_init(&tattr);
    pthread_attr_setname_np(&tattr, "writer");
    pthread_create(&tid_writer, &tattr, &writer, NULL);
    pthread_attr_setname_np(&tattr, "reader");
    pthread_create(&tid_reader, &tattr, &reader, NULL);

    pthread_join(tid_reader, NULL);

    pthread_join(tid_writer, NULL);
    
    return NULL;
}

int __xeno_user_init (void)
{
    struct mq_attr qattr, gattr;
    pthread_attr_t tattr;
    int rc;
    
    TEST_START(0);

    TEST_ASSERT((mqd_t) -1 == mq_open("/mq-test", O_RDWR) && errno == ENOENT);

    TEST_ASSERT(-1 == mq_unlink("/mq-test") && errno == ENOENT);

    qattr.mq_maxmsg = 16;
    qattr.mq_msgsize = 42;

    TEST_ASSERT((mqd_t) -1 != (qd = mq_open("/mq-test", O_RDWR | O_CREAT, 0, &qattr)));

    TEST_ASSERT(mq_getattr(qd, &gattr) == 0 &&
                gattr.mq_msgsize == qattr.mq_msgsize &&
                gattr.mq_maxmsg == qattr.mq_maxmsg &&
                gattr.mq_curmsgs == 0);

    qdr = mq_open("/mq-test", O_RDONLY);

    TEST_ASSERT(qdr != (mqd_t) -1);

    qdw = mq_open("/mq-test", O_WRONLY);

    TEST_ASSERT(qdw != (mqd_t) -1);

    pthread_attr_init(&tattr);
    pthread_attr_setname_np(&tattr, "root");
    
    rc=pthread_create(&root_thread_tcb, &tattr, root_thread, NULL);

    pthread_attr_destroy(&tattr);

    return rc;
}

void __xeno_user_exit (void)
{
    TEST_ASSERT_OK(mq_close(qd));

    TEST_ASSERT(0 == mq_close(qdr));

    TEST_ASSERT(0 == mq_close(qdw));

    TEST_ASSERT_OK(mq_unlink("/mq-test"));

    TEST_ASSERT((mqd_t) -1 == mq_open("/mq-test", O_RDWR) && errno == ENOENT);

    TEST_CHECK_SEQUENCE(SEQ("writer", 1),
                        SEQ("reader", 1),
                        SEQ("writer", 2),
                        SEQ("reader", 1),
                        SEQ("writer", 1),
                        SEQ("reader", 1),
                        END_SEQ);
    TEST_FINISH();
}
