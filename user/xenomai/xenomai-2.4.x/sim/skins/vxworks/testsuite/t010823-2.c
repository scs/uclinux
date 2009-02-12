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
 * Description: Testing VxWorks services:
 * - semMCreate
 * - semBCreate
 * - semGive
 * - semTake
 * - semFlush
 * - taskIsReady
 * - taskIsSuspended
 * - taskNameToId
 */

#include <vxworks_test.h>

static SEM_ID bsemid, mutexid;

void sem1Task  (long a0, long a1, long a2, long a3, long a4,
		long a5, long a6, long a7, long a8, long a9)
{
    WIND_TCB *pTcb = taskTcb(taskIdSelf());

    TEST_ASSERT(pTcb != NULL);

    TEST_ASSERT(semFlush(mutexid) == ERROR &&
		errno == S_semLib_INVALID_OPERATION);

    TEST_ASSERT_OK(semFlush(bsemid));

    TEST_MARK();

    TEST_ASSERT_OK(semTake(mutexid,WAIT_FOREVER));

    TEST_MARK();

    TEST_ASSERT_OK(semGive(bsemid));

    TEST_MARK();

    TEST_ASSERT_OK(semGive(mutexid));

    TEST_MARK(); /* Should not pass this mark */
}

void sem2Task  (long a0, long a1, long a2, long a3, long a4,
		long a5, long a6, long a7, long a8, long a9)
{
    WIND_TCB *pTcb = taskTcb(taskIdSelf());
    ULONG date;
    int n;

    TEST_ASSERT(pTcb != NULL);

    TEST_ASSERT(taskNameToId("Test2") == (TASK_ID)pTcb);

    TEST_MARK();

    TEST_ASSERT_OK(semTake(bsemid,WAIT_FOREVER));

    TEST_MARK();

    TEST_ASSERT_OK(semTake(bsemid,WAIT_FOREVER));

    TEST_MARK();

    TEST_ASSERT_OK(taskResume(a0));

    TEST_MARK();
    date = tickGet();
    for (n = 0; n < 1000000; n++) {
	    ULONG old_date = date;
	    date = tickGet();
	    if (date != old_date)
		    TEST_MARK();
    }

    TEST_MARK(); /* Should not pass this mark */
}

void rootTask (long a0, long a1, long a2, long a3, long a4,
	       long a5, long a6, long a7, long a8, long a9)
{
    WIND_TCB *pTcb;

    TEST_START(0);

    pTcb = taskTcb(taskIdSelf());
    TEST_ASSERT(pTcb != NULL);

    bsemid = semBCreate(0xffffffff,0);
    TEST_ASSERT(bsemid == 0 && errno == S_semLib_INVALID_QUEUE_TYPE);

    bsemid = semBCreate(SEM_Q_PRIORITY,0);
    TEST_ASSERT(bsemid != 0);

    mutexid = semMCreate(0xffffffff);
    TEST_ASSERT(mutexid == 0 && errno == S_semLib_INVALID_QUEUE_TYPE);

    mutexid = semMCreate(SEM_Q_PRIORITY|SEM_DELETE_SAFE|SEM_INVERSION_SAFE);
    TEST_ASSERT(mutexid != 0);

    taskSpawn("Test1",
	      20,		/* low-pri */
	      0,
	      32768,
	      sem1Task,
	      taskIdSelf(),0,0,0,0,0,0,0,0,0);

    taskSpawn("Test2",
	      10,		/* intermediate-pri */
	      0,
	      32768,
	      sem2Task,
	      taskIdSelf(),0,0,0,0,0,0,0,0,0);

    /* This runs at high-pri */

    TEST_MARK();

    TEST_ASSERT_OK(semTake(bsemid,WAIT_FOREVER));

    TEST_MARK();

    TEST_ASSERT_OK(taskSuspend(0));

    TEST_MARK();

    TEST_ASSERT_OK(semTake(mutexid,WAIT_FOREVER));

    TEST_MARK();

    TEST_ASSERT_OK(semGive(mutexid));

    TEST_MARK();

    TEST_ASSERT(taskIsReady(taskNameToId("Test2")));

    TEST_ASSERT(!taskIsSuspended(taskNameToId("Test2")));

    TEST_ASSERT_OK(taskDelay(1));

    TEST_MARK();

    TEST_CHECK_SEQUENCE(SEQ("root",1),
			SEQ("Test2",1),
			SEQ("root",1),
			SEQ("Test2",1),
			SEQ("Test1",2),
			SEQ("Test2",1),
			SEQ("root",1),
			SEQ("Test1",1),
			SEQ("root",2),
			SEQ("Test2",1),
			SEQ("root",1),
			END_SEQ);
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
