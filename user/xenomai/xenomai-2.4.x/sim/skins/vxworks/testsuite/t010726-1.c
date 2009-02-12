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
 * - kernelTimeSlice
 * - taskSpawn
 * - tickGet
 * - tickSet
 *
 */

#include <vxworks_test.h>

static TASK_ID tSlicer1, tSlicer2, tSlicer3;

void sliceTask (long a0, long a1, long a2, long a3, long a4,
                long a5, long a6, long a7, long a8, long a9)
{
    WIND_TCB *pTcb = taskTcb(taskIdSelf());
    TEST_ASSERT(pTcb != NULL);

    for (;;)
        {
        int n;

        TEST_MARK();

        for (n = 0; n < 10000; n++)
            ;
        }
}

void rootTask (long a0, long a1, long a2, long a3, long a4,
               long a5, long a6, long a7, long a8, long a9)
{
    WIND_TCB *pTcb;
    
    TEST_START(0);

    pTcb = taskTcb(taskIdSelf());
    TEST_ASSERT(pTcb != NULL);

    kernelTimeSlice(2);

    /* The root task starts with a priority of 0 */

    TEST_ASSERT((tSlicer1 = taskSpawn("Slicer1",
                                      20,
                                      0,
                                      32768,
                                      sliceTask,
                                      0,0,0,0,0,0,0,0,0,0)) != ERROR);
    
    TEST_ASSERT((tSlicer2 = taskSpawn("Slicer2",
                                      20,
                                      0,
                                      32768,
                                      sliceTask,
                                      1,0,0,0,0,0,0,0,0,0)) != ERROR);

    TEST_ASSERT((tSlicer3 = taskSpawn("Slicer3",
                                      20,
                                      0,
                                      32768,
                                      sliceTask,
                                      2,0,0,0,0,0,0,0,0,0)) != ERROR);

    taskDelay(6);

    tickSet(50);

    TEST_ASSERT(tickGet() == 50);

    TEST_MARK();

    kernelTimeSlice(0);

    TEST_MARK();

    TEST_ASSERT_OK(taskDelay(6));

    TEST_MARK();

    TEST_CHECK_SEQUENCE(SEQ("Slicer1",4),
                        SEQ("Slicer2",4),
                        SEQ("Slicer3",4),
                        SEQ("root",2),
                        SEQ("Slicer1",12),
                        SEQ("root",1),
                        END_SEQ);

    taskDelete(tSlicer1);
    taskDelete(tSlicer2);
    taskDelete(tSlicer3);    

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
