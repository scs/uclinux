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
 * - taskActivate
 * - taskDelete
 * - taskDeleteForce
 * - taskIdVerify
 * - taskInit
 * - taskPriorityGet
 * - taskPrioritySet
 * - taskTcb
 * - taskSafe
 * - taskUnsafe
 * - taskName
 *
 */

#include <vxworks_test.h>

static WIND_TCB peerTcb;
static WIND_TCB peerTcbPrio18;
static WIND_TCB peerTcbPrio21;

void peerTask  (long a0, long a1, long a2, long a3, long a4,
		long a5, long a6, long a7, long a8, long a9)
{
	int rc; 
	WIND_TCB *pTcb = taskTcb(taskIdSelf());
	TEST_ASSERT(pTcb == &peerTcb);

	TEST_MARK();

	TEST_ASSERT_OK(taskSafe());

	TEST_MARK();

	TEST_ASSERT_OK(taskPrioritySet(taskIdSelf(),21));

	TEST_MARK();

	TEST_ASSERT_OK(taskUnsafe());

	rc = strcmp(taskName(taskIdSelf()),"peerTask");
	TEST_ASSERT(rc == 0);
	rc = strcmp(taskName(0),"peerTask");
	TEST_ASSERT(rc == 0);

	TEST_MARK();
}

void peerTaskPrio18  (long a0, long a1, long a2, long a3, long a4,
		      long a5, long a6, long a7, long a8, long a9)
{
	int rc; 
	int prio;
	TEST_MARK();
	taskPriorityGet(taskIdSelf(),&prio);
	TEST_ASSERT(prio == 18);
	TEST_MARK();
	rc = strcmp(taskName(taskIdSelf()),"peerPrio18");
	TEST_ASSERT(rc == 0);
	rc = strcmp(taskName(0),"peerPrio18");
	TEST_ASSERT(rc == 0);
	TEST_MARK();
}


void peerTaskPrio20  (long a0, long a1, long a2, long a3, long a4,
		      long a5, long a6, long a7, long a8, long a9)
{
	int rc; 
	int prio;
	TEST_MARK();
	taskPriorityGet(taskIdSelf(),&prio);
	TEST_ASSERT(prio == 20);
	TEST_MARK();
	rc = strcmp(taskName(taskIdSelf()),"peerPrio20");
	TEST_ASSERT(rc == 0);
	rc = strcmp(taskName(0),"peerPrio20");
	TEST_ASSERT(rc == 0);
	TEST_MARK();
}

void peerTaskPrio21  (long a0, long a1, long a2, long a3, long a4,
		      long a5, long a6, long a7, long a8, long a9)
{
	int rc; 
	int prio;
	TEST_MARK();
	taskPriorityGet(taskIdSelf(),&prio);
	TEST_ASSERT(prio == 21);
	TEST_MARK();
	rc = strcmp(taskName(taskIdSelf()),"peerPrio21");
	TEST_ASSERT(rc == 0);
	rc = strcmp(taskName(0),"peerPrio21");
	TEST_ASSERT(rc == 0);
	TEST_MARK();
	taskDelay(2);
	TEST_MARK();
}

void rootTask (long a0, long a1, long a2, long a3, long a4,
	       long a5, long a6, long a7, long a8, long a9)
{
	int tid18 = 0, tid20 = 0, tid21 = 0;
	const size_t stackSize = 32768;
	char *pstackBase = NULL;
	WIND_TCB *pTcb;
	int prio = 0;
	int rc = 0;
	void *id;

	TEST_START(0);

	pTcb = taskTcb(taskIdSelf());
	TEST_ASSERT(pTcb != NULL);

#ifdef VXWORKS
	pstackBase = (char *) malloc(stackSize) + stackSize;
#endif
  
	TEST_ASSERT(taskInit(&peerTcb,
			     "peerTask",
			     -1,
			     0,
			     pstackBase,
			     stackSize,
			     peerTask,
			     0,0,0,0,0,0,0,0,0,0) == ERROR
		    && errno == S_taskLib_ILLEGAL_PRIORITY);

	TEST_ASSERT_OK(taskInit(&peerTcb,
				"peerTask",
				19,
				0,
				pstackBase,
				stackSize,
				peerTask,
				0,0,0,0,0,0,0,0,0,0));

	TEST_ASSERT_OK(taskPrioritySet(taskIdSelf(),20));

	TEST_MARK();

	TEST_ASSERT(taskPriorityGet(taskIdSelf(),&prio) == OK && prio == 20);

	TEST_MARK();

	TEST_ASSERT(taskIdVerify(0) == ERROR);
	id = malloc(20);
	memset(id, '\0', 20);
	TEST_ASSERT(taskIdVerify((TASK_ID)id) == ERROR
		    && errno == S_objLib_OBJ_ID_ERROR);
	free(id);

	TEST_ASSERT_OK(taskIdVerify((TASK_ID)&peerTcb));

	TEST_ASSERT_OK(taskActivate((TASK_ID)&peerTcb));

	TEST_MARK();

	TEST_ASSERT_OK(taskDelete((TASK_ID)&peerTcb));

	TEST_ASSERT(taskIdVerify((TASK_ID)&peerTcb)==ERROR);

	TEST_ASSERT_OK(taskPrioritySet(taskIdSelf(),20));

	TEST_ASSERT_OK(taskInit(&peerTcbPrio18,
				"peerPrio18",
				18,
				0,
				pstackBase,
				stackSize,
				peerTaskPrio18,
				0,0,0,0,0,0,0,0,0,0));
	TEST_MARK();
	TEST_ASSERT_OK(taskActivate((TASK_ID)&peerTcbPrio18));

	TEST_MARK();

	rc = taskDelete((TASK_ID)&peerTcbPrio18);
	TEST_ASSERT(rc == ERROR);
	TEST_MARK();

	TEST_ASSERT_OK(taskInit(&peerTcbPrio21,
				"peerPrio21",
				21,
				0,
				pstackBase,
				stackSize,
				peerTaskPrio21,
				0,0,0,0,0,0,0,0,0,0));
	TEST_MARK();
	TEST_ASSERT_OK(taskActivate((TASK_ID)&peerTcbPrio21));

	TEST_MARK();

	taskDelay(1);
	TEST_MARK();

	TEST_ASSERT_OK(taskDelete((TASK_ID)&peerTcbPrio21));
	TEST_MARK();

	tid18 = taskSpawn("peerPrio18",                                     
			  18,                                               
			  0,  
			  32768,
			  peerTaskPrio18,
			  0,0,0,0,0,0,0,0,0,0);
	TEST_ASSERT(tid18 != 0);
	TEST_MARK();

	tid20 = taskSpawn("peerPrio20",                                     
			  20,                                               
			  0,                                                
			  32768,
			  peerTaskPrio20,
			  0,0,0,0,0,0,0,0,0,0);
	TEST_ASSERT(tid20 != 0);

	TEST_MARK();

	tid21 = taskSpawn("peerPrio21",                                     
			  21,                                               
			  0,                                                
			  32768,
			  peerTaskPrio21,
			  0,0,0,0,0,0,0,0,0,0);
	TEST_ASSERT(tid21 != 0);

	TEST_MARK();
	taskDelay(1);
	TEST_MARK();
	TEST_ASSERT_OK(taskDelete(tid21));
	errno = 0;
	TEST_ASSERT(taskDelete(tid18) == ERROR
		    && errno == S_objLib_OBJ_ID_ERROR);
	errno = 0;
	TEST_ASSERT(taskDelete(tid20) == ERROR
		    && errno == S_objLib_OBJ_ID_ERROR);
	TEST_MARK();

	TEST_CHECK_SEQUENCE(SEQ("root",2),
			    SEQ("peerTask",2),
			    SEQ("root",1),
			    SEQ("peerTask",1),
			    SEQ("root",1),
			    SEQ("peerPrio18",3),
			    SEQ("root",4),
			    SEQ("peerPrio21",3),
			    SEQ("root",2),
			    SEQ("peerPrio18",3),
			    SEQ("root",3),
			    SEQ("peerPrio20",3),
			    SEQ("peerPrio21",3),
			    SEQ("root",2),
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
