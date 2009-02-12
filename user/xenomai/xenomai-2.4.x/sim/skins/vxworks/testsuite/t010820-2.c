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
 * - wdCreate
 * - wdDelete
 * - wdCancel
 * - wdStart
 *
 */

#include <vxworks_test.h>

static WDOG_ID wid;

void watchdogHandler (long arg)

{
    TEST_ASSERT(arg == 0x25262728);
    TEST_ASSERT(intContext());
    TEST_MARK();
}

void rootTask (long a0, long a1, long a2, long a3, long a4,
	       long a5, long a6, long a7, long a8, long a9)
{
    WIND_TCB *pTcb;

    TEST_START(0);

    pTcb = taskTcb(taskIdSelf());
    TEST_ASSERT(pTcb != NULL);

    TEST_MARK();

    wid = wdCreate();

    TEST_ASSERT(wid != 0);

    TEST_ASSERT(wdStart(0,10,watchdogHandler,0) == ERROR &&
		errno == S_objLib_OBJ_ID_ERROR);

    TEST_MARK();

    TEST_ASSERT_OK(wdStart(wid,10,watchdogHandler,0x25262728));

    TEST_MARK();

    TEST_ASSERT_OK(taskDelay(20));

    TEST_MARK();

    TEST_ASSERT(wdDelete(0) == ERROR && errno == S_objLib_OBJ_ID_ERROR);

    TEST_MARK();

    TEST_ASSERT_OK(wdDelete(wid));

    TEST_MARK();

    TEST_CHECK_SEQUENCE(SEQ("root",3),
			SEQ("ROOT",1),
			SEQ("root",3),
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
