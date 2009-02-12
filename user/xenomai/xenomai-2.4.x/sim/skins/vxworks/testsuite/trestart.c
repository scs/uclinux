/*
 * Copyright (C) 2001,2002 IDEALX (http://www.idealx.com/).
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
 * - taskRestart.
 */

#include <vxworks_test.h>

SEM_ID restart_test_end;

void nopTask(long a0, long a1, long a2, long a3, long a4,
             long a5, long a6, long a7, long a8, long a9)
{
    TEST_MARK();
}

void restartTask(long a0, long a1, long a2, long a3, long a4,
                 long a5, long a6, long a7, long a8, long a9)
{
    TEST_MARK();

    TEST_ASSERT_OK(taskRestart(a0));
}

void createTask (long a0, long a1, long a2, long a3, long a4,
                long a5, long a6, long a7, long a8, long a9)
{
    static int threads=0;

    TEST_ASSERT(taskSpawn("nop", 19, 0, 32768, nopTask,
                          0,0,0,0,0,0,0,0,0,0) != ERROR);

    ++threads;
    if(threads==1)
        TEST_ASSERT(taskRestart(0) != ERROR);

    if(threads==2) {   
        TEST_ASSERT(taskSpawn("restart", 20, 0, 32768, restartTask,
                              taskIdSelf(),0,0,0,0,0,0,0,0,0) != ERROR);

        TEST_ASSERT_OK(taskDelay(0));
    }
    
    if(threads==3) {   
        TEST_ASSERT(taskSpawn("restart", 19, 0, 32768, restartTask,
                              taskIdSelf(),0,0,0,0,0,0,0,0,0) != ERROR);

        TEST_ASSERT_OK(taskSuspend(0));
    }

    TEST_MARK();

    TEST_ASSERT_OK(semGive(restart_test_end));
}

void rootTask (long a0, long a1, long a2, long a3, long a4,
               long a5, long a6, long a7, long a8, long a9)
{
    sysClkDisable();
    
    restart_test_end=semCCreate(SEM_Q_FIFO, 0);
    
    TEST_START(0);

    TEST_ASSERT(taskSpawn("create",
                          20,
                          0,
                          32768,
                          createTask,
                          0,0,0,0,0,0,0,0,0,0) != ERROR);

    TEST_ASSERT_OK(semTake(restart_test_end, WAIT_FOREVER));
    
    TEST_CHECK_SEQUENCE(SEQ("nop",2),
                        SEQ("restart",1),
                        SEQ("nop",1),
                        SEQ("restart",1),
                        SEQ("nop",1),
                        SEQ("create",1),
                        END_SEQ);

    TEST_FINISH();
}

int __xeno_user_init (void)
{
    return !taskSpawn("root",
                      0,
                      0,
                      32768,
                      rootTask,
                      0,0,0,0,0,0,0,0,0,0);
}

void __xeno_user_exit (void)
{
}
