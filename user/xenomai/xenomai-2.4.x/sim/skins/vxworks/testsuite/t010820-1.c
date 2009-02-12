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
 * - semCCreate
 * - semDelete
 * - semGive
 * - semTake
 * - taskLock
 * - taskUnlock
 * - taskNameToId
 * - taskSuspend
 * - taskResume
 *
 */

#include <vxworks_test.h>


/*
  static ckhandle_t task1handle, task2handle;
*/

static SEM_ID semid;
static TASK_ID tTest2, tRoot;

void sem1Task  (long a0, long a1, long a2, long a3, long a4,
		long a5, long a6, long a7, long a8, long a9)
{
    WIND_TCB *pTcb = taskTcb(taskIdSelf());
    
    TEST_ASSERT(pTcb != NULL);

    semid = semCCreate(0xffffffff,0);
    TEST_ASSERT(semid == 0 && errno == S_semLib_INVALID_QUEUE_TYPE);

    semid = semCCreate(SEM_Q_FIFO,0);
    TEST_ASSERT(semid != 0);

    TEST_MARK();

    TEST_ASSERT_OK(semTake(semid,WAIT_FOREVER)); /* wait for semGive() */
    
    TEST_MARK();

    TEST_ASSERT_OK(semGive(semid));

    TEST_MARK();

    TEST_ASSERT_OK(taskSuspend(0));

    TEST_MARK();

    TEST_ASSERT_OK(semTake(semid,10));

    TEST_MARK();

    TEST_ASSERT_OK(semTake(semid,NO_WAIT));

    TEST_MARK();

    TEST_ASSERT(semTake(semid,10) == ERROR && errno == S_objLib_OBJ_TIMEOUT);

    TEST_CHECK_SEQUENCE(SEQ("Test1",1),
			SEQ("Test2",1),
			SEQ("Test1",2),
			SEQ("Test2",3),
			SEQ("Test1",3),
			END_SEQ);
    
    TEST_ASSERT_OK(semDelete(semid));

    taskDelete(tTest2);
    taskDelete(tRoot);

    TEST_FINISH();
}

void sem2Task  (long a0, long a1, long a2, long a3, long a4,
		long a5, long a6, long a7, long a8, long a9)
{
    WIND_TCB *pTcb = taskTcb(taskIdSelf());

    TEST_ASSERT(pTcb != NULL);

    TEST_MARK();

    TEST_ASSERT_OK(semGive(semid));

    TEST_MARK();

    TEST_ASSERT_OK(semTake(semid,WAIT_FOREVER)); /* wait for semGive() */

    TEST_ASSERT_OK(taskLock());

    TEST_ASSERT_OK(taskResume(taskNameToId("Test1")));

    TEST_ASSERT_OK(semGive(semid));

    TEST_MARK();

    TEST_ASSERT_OK(semGive(semid));

    TEST_MARK();

    TEST_ASSERT_OK(taskUnlock());

    TEST_ASSERT_OK(taskSuspend(0));

    TEST_MARK();		/* Should not pass this mark */
}

void rootTask (long a0, long a1, long a2, long a3, long a4,
	       long a5, long a6, long a7, long a8, long a9)
{
    TEST_START(0);

    taskSpawn("Test1",
	      19,
	      0,
	      32768,
	      sem1Task,
	      0,0,0,0,0,0,0,0,0,0);

    tTest2 = taskSpawn("Test2",
                       20,
                       0,
                       32768,
                       sem2Task,
                       0,0,0,0,0,0,0,0,0,0);

    TEST_ASSERT_OK(taskSuspend(0));

    TEST_MARK(); /* Should not pass this mark */
}

int __xeno_user_init (void)
{
    return !(tRoot = taskSpawn("root",
                               1,
                               0,
                               32768,
                               rootTask,
                               0,0,0,0,0,0,0,0,0,0));
}

void __xeno_user_exit (void)
{
}
