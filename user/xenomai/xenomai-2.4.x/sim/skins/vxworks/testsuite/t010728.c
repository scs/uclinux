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
 * - intContext()
 * - intCount()
 * - intLevelSet()
 * - intLock()
 * - intUnlock()
 */

/* #include <ck/testlib.h> */
#include <vxworks_test.h>
/* #include <vxworks/vxWorks.h> */

/* static ckhandle_t intHandle; */

/* static ckhandle_t taskHandle; */

#define INTR_VECTOR 1
#define INTR_LEVEL  2

void intSvc (int parameter)

{
/*     TEST_ASSERT(ckGetIntrLevel() == INTR_LEVEL); */
    TEST_ASSERT(intCount() == 1);
    TEST_ASSERT(!!intContext());
    TEST_MARK();
}

void rootTask (long a0, long a1, long a2, long a3, long a4,
	       long a5, long a6, long a7, long a8, long a9)
{
    WIND_TCB *pTcb;
    int lockKey, rc;
/*     ckcfval_t u; */

    TEST_START(0);

    pTcb = taskTcb(taskIdSelf());
    TEST_ASSERT(pTcb != NULL);

/*     ckCreateIntr("testIntr", */
/* 		 INTR_VECTOR, */
/* 		 INTR_LEVEL, */
/* 		 (ckisr_t *)intSvc, */
/* 		 NULL, */
/* 		 NULL, */
/* 		 &intHandle); */

/*     TEST_MARK(); */

/*     rc = ckControlIntr(intHandle,CK_INTR_RAISE); */
/*     TEST_ASSERT_OK(rc); */

    TEST_MARK();

    rc = intLevelSet(INTR_LEVEL);
    TEST_ASSERT(rc == 0);

/*     rc = ckControlIntr(intHandle,CK_INTR_RAISE); */
/*     TEST_ASSERT_OK(rc); */

    TEST_MARK();

    rc = intLevelSet(0);
    TEST_ASSERT(rc == INTR_LEVEL);

    TEST_MARK();

    lockKey = intLock();
/*     rc = ckGetConf(CK_NODE_MAX_ILVL,&u); */
/*     TEST_ASSERT_OK(rc); */
    TEST_ASSERT(lockKey == 0);
/*     TEST_ASSERT(ckGetIntrLevel() == u.ival); */

/*     rc = ckControlIntr(intHandle,CK_INTR_RAISE); */
/*     TEST_ASSERT_OK(rc); */

    TEST_MARK();

    intUnlock(lockKey);
/*     TEST_ASSERT(ckGetIntrLevel() == 0); */

    TEST_MARK();

/*     rc = ckControlIntr(intHandle,CK_INTR_RAISE); */
/*     TEST_ASSERT_OK(rc); */

    TEST_MARK();

/*     TEST_CHECK_SEQUENCE(SEQ("taskHandle",1), */
/* 			SEQ("intHandle",1), */
/* 			SEQ("taskHandle",2), */
/* 			SEQ("intHandle",1), */
/* 			SEQ("taskHandle",2), */
/* 			SEQ("intHandle",1), */
/* 			SEQ("taskHandle",1), */
/* 			SEQ("intHandle",1), */
/* 			SEQ("taskHandle",1), */
/* 			END_SEQ); */
    TEST_FINISH();
}

int __xeno_user_init (void)
{
    return taskSpawn("root",
                     1,
                     0,
                     32768,
                     rootTask,
                     0,0,0,0,0,0,0,0,0,0);
}

void __xeno_user_exit (void)
{
}

