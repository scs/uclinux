/*
 * Copyright (C) 2001,2002 IDEALX (http://www.idealx.com/).
 * Adapted from CarbonKernel
 * Copyright (C) 2001  Philippe Gerum.<rpm@xenomai.org>
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
 *
 * Description: Testing VxWorks services (task to task and int to task):
 * - msgQCreate
 * - msgQDelete
 * - msgQNumMsgs
 * - msgQReceive
 * - msgQSend
 *
  */

#include <vxworks_test.h>

static TASK_ID peerTid;

/* Expecting 10 message slots per message box */

static unsigned message_list[] = {
    0xfafafafa,
    0xbebebebe,
    0xcdcdcdcd,
    0xabcdefff,
    0x12121212,
    0x34343434,
    0x56565656,
    0x78787878,
    0xdededede,
    0xbcbcbcbc
};

#define NMESSAGES (sizeof(message_list) / sizeof(message_list[0]))

static WDOG_ID wid;

static int int2taskQid ;

void msgDuringInt (long arg)

{
    int qid = 0, rc = 0, msg = 0;
    TEST_ASSERT(intContext());
    TEST_MARK();

    qid = msgQCreate(NMESSAGES,sizeof(int),MSG_Q_FIFO);
    TEST_ASSERT(qid == 0 && errno == S_intLib_NOT_ISR_CALLABLE);

    rc = msgQNumMsgs(int2taskQid);
    TEST_ASSERT(rc == 0);

    rc = msgQReceive(int2taskQid,(char *)&msg,sizeof(msg), 0);
    TEST_ASSERT(rc == ERROR && errno == S_intLib_NOT_ISR_CALLABLE);
    msg = 0x5555affe;

    rc = msgQSend(int2taskQid,(char *)&msg,sizeof(int),0, MSG_PRI_NORMAL);
    TEST_ASSERT_OK(rc);

    rc = msgQSend(int2taskQid,(char *)&msg,sizeof(int),WAIT_FOREVER, MSG_PRI_NORMAL);
    TEST_ASSERT(rc == ERROR && errno == S_msgQLib_NON_ZERO_TIMEOUT_AT_INT_LEVEL);
    TEST_MARK();
}

void testMsqInterrupt()
{
   int nmsg = 0, qid, rc, msg = 0;
   int2taskQid = msgQCreate(NMESSAGES,sizeof(int),MSG_Q_FIFO);
   TEST_ASSERT(int2taskQid != 0);

   wid = wdCreate();

   TEST_ASSERT(wid != 0);

   TEST_ASSERT_OK(wdStart(wid,1,msgDuringInt,0x25262728));

   TEST_MARK();

   TEST_ASSERT_OK(taskDelay(2));
   TEST_ASSERT_OK(wdCancel(wid));
   TEST_ASSERT_OK(wdDelete(wid));

   TEST_MARK();

   rc = msgQReceive(int2taskQid,(char *)&msg,sizeof(msg), 0);
   TEST_ASSERT(rc == sizeof(msg) && msg == 0x5555affe);

   TEST_MARK();

}

void peerTask (long a0, long a1, long a2, long a3, long a4,
               long a5, long a6, long a7, long a8, long a9)
{
    int msg = 0, nmsg, qid = a0, rootTid = a1, rc;

    TEST_MARK();

    for (nmsg = 0; nmsg < NMESSAGES; nmsg++)
        {
        rc = msgQSend(qid,(char *)&message_list[nmsg],sizeof(int),WAIT_FOREVER,MSG_PRI_NORMAL);
        TEST_ASSERT_OK(rc);
        }

    TEST_MARK();

    TEST_ASSERT_OK(taskDelay(0));

    TEST_MARK();

    TEST_ASSERT_OK(taskDelay(0));

    TEST_MARK();

    TEST_ASSERT_OK(taskSuspend(taskIdSelf()));

    TEST_MARK();

    for (nmsg = 0; nmsg < NMESSAGES; nmsg++)
        {
        TEST_MARK();
        rc = msgQReceive(qid,(char *)&msg,sizeof(msg),WAIT_FOREVER);
        TEST_ASSERT(rc == sizeof(msg));
        TEST_ASSERT(msg == message_list[nmsg]);
        }

    TEST_MARK();

    rc = msgQReceive(qid,(char *)&msg,sizeof(msg),NO_WAIT);
    TEST_ASSERT(rc == ERROR && errno == S_objLib_OBJ_UNAVAILABLE);

    TEST_MARK();

    rc = taskResume(rootTid);
    TEST_ASSERT_OK(rc);

    TEST_MARK();

    /* Do not exit since we need this task name remaining
       available to the testlib code.*/

    TEST_ASSERT_OK(taskSuspend(taskIdSelf()));
}

void rootTask (long a0, long a1, long a2, long a3, long a4,
               long a5, long a6, long a7, long a8, long a9)
{
    int nmsg = 0, qid, rc, msg = 0;
    WIND_TCB *pTcb;
    char *buffer;

    TEST_START(0);

    pTcb = taskTcb(taskIdSelf());
    TEST_ASSERT(pTcb != NULL);

    TEST_MARK();

    qid = msgQCreate(NMESSAGES,sizeof(int),0xffff);
    TEST_ASSERT(qid == 0 && errno == S_msgQLib_INVALID_QUEUE_TYPE);

#ifndef VXWORKS
    /* This is undesirable behaviour in vxWorks (at least tested under version 5.5.1. 
       Some might even call it a bug.
       Passing a negative argument to maxMsgs for msgQCreate returns a  non null MSG_Q_ID.
       Freeing it leads to a  a memPartFree: invalid block.
       For maxMsgs bigger than the available memory, vxWorks returns 0, 
       but does not set errno to a consistent value.
    */
    qid = msgQCreate(-1,sizeof(int),MSG_Q_FIFO);
    TEST_ASSERT(qid == 0 && errno == S_msgQLib_INVALID_QUEUE_TYPE);
#endif

    /* Test mailbox with 0 length messages */
    qid = msgQCreate(NMESSAGES,0,MSG_Q_FIFO);
    TEST_ASSERT(qid != 0);
    rc = msgQNumMsgs(qid);
    TEST_ASSERT(rc == 0);
    rc = msgQSend(qid,(char *)&message_list[0],0, NO_WAIT, MSG_PRI_NORMAL);
    TEST_ASSERT(rc == OK);
    rc = msgQNumMsgs(qid);
    TEST_ASSERT(rc == 1);
    rc = msgQSend(qid,(char *)&message_list[0],0, NO_WAIT, MSG_PRI_NORMAL);
    TEST_ASSERT(rc == OK);
    rc = msgQNumMsgs(qid);
    TEST_ASSERT(rc == 2);
    rc = msgQReceive(qid,(char *)&msg,0,NO_WAIT);
    TEST_ASSERT_OK(rc);
    rc = msgQNumMsgs(qid);
    TEST_ASSERT(rc == 1);
    rc = msgQReceive(qid,(char *)&msg,0,NO_WAIT);
    TEST_ASSERT_OK(rc);
    rc = msgQNumMsgs(qid);
    TEST_ASSERT(rc == 0);

    rc = msgQSend(qid,(char *)&message_list[0],0, NO_WAIT, MSG_PRI_NORMAL);
    rc = msgQSend(qid,(char *)&message_list[0],0, NO_WAIT, MSG_PRI_NORMAL);
    rc = msgQNumMsgs(qid);
    TEST_ASSERT(rc == 2);
    rc = msgQReceive(qid,(char *)&msg,2,NO_WAIT);
    TEST_ASSERT_OK(rc);
    rc = msgQNumMsgs(qid);
    TEST_ASSERT(rc == 1);

    rc = msgQDelete(qid);
    TEST_ASSERT(rc == OK);

    qid = msgQCreate(NMESSAGES,sizeof(int),MSG_Q_FIFO);
    TEST_ASSERT(qid != 0);

    peerTid = taskSpawn("Peer",
                        1,
                        0,
                        32768,
                        peerTask,
                        qid,taskIdSelf(),0,0,0,0,0,0,0,0);

    while (msgQReceive(qid,(char *)&msg,sizeof(msg),10) == sizeof(msg))
        {
        TEST_MARK();
        TEST_ASSERT(nmsg < NMESSAGES && msg == message_list[nmsg]);
        nmsg++;
        }

    TEST_ASSERT(errno == S_objLib_OBJ_TIMEOUT && nmsg == NMESSAGES);

    TEST_MARK();

    rc = msgQReceive(qid,(char *)&msg,sizeof(msg),NO_WAIT);
    TEST_ASSERT(rc == ERROR && errno == S_objLib_OBJ_UNAVAILABLE);

    TEST_MARK();

    rc = msgQSend(qid,(char *)&message_list[0],2*message_list[0], WAIT_FOREVER,MSG_PRI_NORMAL);
    TEST_ASSERT(rc == ERROR && errno == S_msgQLib_INVALID_MSG_LENGTH);

    rc = msgQSend(qid,(char *)&message_list[0],sizeof(int),WAIT_FOREVER,MSG_PRI_NORMAL);
    TEST_ASSERT_OK(rc);

    rc = msgQSend(qid,(char *)&message_list[0], 2*sizeof(int),WAIT_FOREVER,MSG_PRI_NORMAL);
    TEST_ASSERT(rc == ERROR && errno == S_msgQLib_INVALID_MSG_LENGTH);

    TEST_MARK();

    rc = msgQReceive(0,(char *)&msg,sizeof(msg),NO_WAIT);
    TEST_ASSERT(rc == ERROR && errno == S_objLib_OBJ_ID_ERROR);

    rc = msgQReceive(qid,(char *)&msg,sizeof(msg),NO_WAIT);
    TEST_ASSERT(rc == sizeof(msg));

    rc = msgQSend(qid,(char *)&message_list[0],sizeof(int),WAIT_FOREVER,MSG_PRI_NORMAL);
    TEST_ASSERT_OK(rc);
    rc = msgQReceive(qid,(char *)&msg,0,NO_WAIT);
    TEST_ASSERT_OK(rc);

    buffer = malloc(2*sizeof(message_list));
    rc = msgQReceive(qid,buffer,2*sizeof(message_list),NO_WAIT);
    TEST_ASSERT(rc == ERROR && errno == S_objLib_OBJ_UNAVAILABLE);
    free(buffer);

    TEST_MARK();

    for (nmsg = 0; nmsg < NMESSAGES; nmsg++)
        {
        rc = msgQSend(qid,(char *)&message_list[nmsg],sizeof(int),WAIT_FOREVER,MSG_PRI_NORMAL);
        TEST_ASSERT_OK(rc);
        }

    TEST_MARK();

    /* Msg queue should be full */
    rc = msgQSend(qid,(char *)&message_list[0],sizeof(int),NO_WAIT,MSG_PRI_NORMAL);
    TEST_ASSERT(rc == ERROR && errno == S_objLib_OBJ_UNAVAILABLE);

    rc = msgQNumMsgs(0);
    TEST_ASSERT(rc == ERROR && errno == S_objLib_OBJ_ID_ERROR);

    rc = msgQNumMsgs(qid);
    TEST_ASSERT(rc == NMESSAGES);

    TEST_MARK();

    /* Timeout should elapse */
    rc = msgQSend(qid,(char *)&message_list[0],sizeof(int),10,MSG_PRI_NORMAL);
    TEST_ASSERT(rc == ERROR && errno == S_objLib_OBJ_TIMEOUT);

    TEST_MARK();

    rc = taskResume(peerTid);
    TEST_ASSERT_OK(rc);

    TEST_MARK();

    rc = taskDelay(0);
    TEST_ASSERT_OK(rc);

    TEST_MARK();

    rc = msgQDelete(0);
    TEST_ASSERT(rc == ERROR && errno == S_objLib_OBJ_ID_ERROR);

    rc = msgQDelete(qid);
    TEST_ASSERT_OK(rc);

    testMsqInterrupt();

    /*
    TEST_ASSERT(!ckObjectExists(qid));
    */
    
    TEST_CHECK_SEQUENCE(SEQ("root",1),
                        SEQ("Peer",2),
                        SEQ("root",10),
                        SEQ("Peer",2),
                        SEQ("root",8),
                        SEQ("Peer",14),
                        SEQ("root",2),
                        END_SEQ);

   if (peerTid) TEST_ASSERT_OK(taskDelete(peerTid));
    
    TEST_FINISH();
}

int __xeno_user_init (void)
{
    return !taskSpawn("root",
                      1,
                      0,
                      32768,
                      rootTask,
                      0,0,0,0,0,0,0,0,0,0);
}

void __xeno_user_exit (void)
{
}

