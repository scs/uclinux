/*
 * Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
 *
 * pSOS and pSOS+ are registered trademarks of Wind River Systems, Inc.
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

#include <psos+/psos.h>

MODULE_LICENSE("GPL");

#define CONSUMER_TASK_PRI    115
#define CONSUMER_USTACK_SIZE 4096
#define CONSUMER_SSTACK_SIZE 4096

#define PRODUCER_TASK_PRI    110
#define PRODUCER_USTACK_SIZE 4096
#define PRODUCER_SSTACK_SIZE 4096

#define PERIODIC_EVENT 0x1

#define CONSUMER_WAIT 150
#define PRODUCER_TRIG 40

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

static u_long producer_tid,
              consumer_tid,
              message_qid;

void consumer_task (u_long a0, u_long a1, u_long a2, u_long a3)

{
    u_long err, qid = a0, msg[4];

    for (;;)
	{
	tm_wkafter(CONSUMER_WAIT);

	while ((err = q_receive(qid,Q_NOWAIT,0,msg)) == SUCCESS)
	    xnprintf("Now playing %s...\n",(const char *)msg[0]);

	if (err != ERR_NOMSG)
	    xnpod_fatal("q_receive() failed, errno %lu",err);
	}
}

void producer_task (u_long a0, u_long a1, u_long a2, u_long a3)

{
    u_long err, tmid, events, msg[4];
    int next_msg = 0;
    u_long qid = a0;
    const char *s;

    err = tm_evevery(PRODUCER_TRIG,PERIODIC_EVENT,&tmid);

    if (err != SUCCESS)
	xnpod_fatal("tm_evevery() failed, errno %lu",err);

    for (;;)
	{
	err = ev_receive(PERIODIC_EVENT,EV_ANY,0,&events);

	if (err != SUCCESS)
	    xnpod_fatal("ev_receive() failed, errno %lu",err);

	s = satch_s_tunes[next_msg++];
	next_msg %= (sizeof(satch_s_tunes) / sizeof(satch_s_tunes[0]));

	msg[0] = (u_long)s;
	msg[1] = 0x0;
	msg[2] = 0x0;
	msg[3] = 0x0;

	err = q_send(qid,msg);

	if (err != SUCCESS)
	    xnpod_fatal("q_send() failed, errno %lu",err);
	}
}

int root_thread_init (void)

{
    u_long err, args[4];

    err = q_create("CNSQ",16,Q_LIMIT|Q_FIFO,&message_qid);
    args[0] = message_qid;

    if (err != SUCCESS)
	{
	xnprintf("q_create() failed, errno %lu",err);
	return err;
	}

    err = t_create("CONS",
		   CONSUMER_TASK_PRI,
		   CONSUMER_SSTACK_SIZE,
		   CONSUMER_USTACK_SIZE,
		   0,
		   &consumer_tid);

    if (err != SUCCESS)
	{
	xnprintf("t_create() failed, errno %lu",err);
	return err;
	}

    err = t_start(consumer_tid,0,consumer_task,args);

    if (err != SUCCESS)
	{
	xnprintf("t_start() failed, errno %lu",err);
	return err;
	}

    err = t_create("PROD",
		   PRODUCER_TASK_PRI,
		   PRODUCER_SSTACK_SIZE,
		   PRODUCER_USTACK_SIZE,
		   0,
		   &producer_tid);

    if (err != SUCCESS)
	{
	xnprintf("t_create() failed, errno %lu",err);
	return err;
	}

    err = t_start(producer_tid,0,producer_task,args);

    if (err != SUCCESS)
	{
	xnprintf("t_start() failed, errno %lu",err);
	return err;
	}

    return 0;
}

void root_thread_exit (void)

{
    t_delete(producer_tid);
    t_delete(consumer_tid);
    q_delete(message_qid);
}
