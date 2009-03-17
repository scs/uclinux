/*
 * Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
 *
 * VxWorks is a registered trademark of Wind River Systems, Inc.
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

#include <vxworks/vxworks.h>

#define ROOT_TASK_PRI        100
#define ROOT_STACK_SIZE      16*1024

#define CONSUMER_TASK_PRI    115
#define CONSUMER_STACK_SIZE  24*1024

#define PRODUCER_TASK_PRI    110
#define PRODUCER_STACK_SIZE  24*1024

#define CONSUMER_WAIT 150
#define PRODUCER_TRIG 40

int root_thread_init(void);
void root_thread_exit(void);

#if !defined(__KERNEL__) && !defined(__XENO_SIM__)

#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define MODULE_LICENSE(x)

#define xnarch_printf printf

int main (int argc, char *argv[])
{
    int tid;

    mlockall(MCL_CURRENT|MCL_FUTURE);

    atexit(&root_thread_exit);

    tid = taskSpawn("RootTask",
		    ROOT_TASK_PRI,
		    0,
		    ROOT_STACK_SIZE,
		    (FUNCPTR)&root_thread_init,
		    0,0,0,0,0,0,0,0,0,0);
    if (tid)
	pause();

    return 1;
}

#endif /* Native, user-space execution */

MODULE_LICENSE("GPL");

static const char *satch_s_tunes[] = {
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

static int producer_tid,
           consumer_tid,
           message_qid;

void consumer_task (int a0, int a1, int a2, int a3, int a4,
		    int a5, int a6, int a7, int a8, int a9)
{
    char *msg;
    int sz;

    for (;;)
	{
	taskDelay(CONSUMER_WAIT);

	while ((sz = msgQReceive(message_qid,(char *)&msg,sizeof(msg),NO_WAIT)) != ERROR)
	    xnprintf("Now playing %s...\n",msg);
	}
}

void producer_task (int a0, int a1, int a2, int a3, int a4,
		    int a5, int a6, int a7, int a8, int a9)
{
    int next_msg = 0;
    const char *s;

    for (;;)
	{
	taskDelay(PRODUCER_TRIG);

	s = satch_s_tunes[next_msg++];
	next_msg %= (sizeof(satch_s_tunes) / sizeof(satch_s_tunes[0]));

	msgQSend(message_qid,(char *)&s,sizeof(s),WAIT_FOREVER,MSG_PRI_NORMAL);
	}
}

int root_thread_init (void)

{
    message_qid = msgQCreate(16,sizeof(char *),MSG_Q_FIFO);

    consumer_tid = taskSpawn("ConsumerTask",
			     CONSUMER_TASK_PRI,
			     0,
			     CONSUMER_STACK_SIZE,
			     (FUNCPTR)&consumer_task,
			     0,0,0,0,0,0,0,0,0,0);

    producer_tid = taskSpawn("ProducerTask",
			     PRODUCER_TASK_PRI,
			     0,
			     PRODUCER_STACK_SIZE,
			     (FUNCPTR)&producer_task,
			     0,0,0,0,0,0,0,0,0,0);
    return 0;
}

void root_thread_exit (void)

{
    taskDelete(producer_tid);
    taskDelete(consumer_tid);
    msgQDelete(message_qid);
}
