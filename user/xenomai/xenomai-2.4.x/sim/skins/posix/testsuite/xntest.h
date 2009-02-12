/*
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@laposte.net>.
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
 */

#ifndef xntest_h
#define xntest_h

#include <nucleus/pod.h>

#define TEST_START(num) (xntest_start())

#define TEST_ASSERT(assertion)                                          \
do {                                                                    \
    if (xntest_verbose)                                                 \
        xnarch_printf(__FILE__ ":%d, " #assertion "\n", __LINE__);      \
    xntest_assert((assertion), #assertion, __FILE__, __LINE__ );        \
} while (0)

#define TEST_FINISH() (xntest_finish(__FILE__, __LINE__))

#define TEST_MARK() (xntest_mark(xnpod_current_thread()))

#define TEST_CHECK_SEQUENCE xntest_check_seq

#define SEQ(name, count) 1, __FILE__, __LINE__, name, count

#define END_SEQ (0)

extern int xntest_verbose;

#ifdef __cplusplus
extern "C" {
#endif

void xntest_start(void);

int xntest_assert(int status, char * assertion, char * file, int line);

void xntest_mark(xnthread_t * thread);

void xntest_check_seq(int next, ...);

void xntest_finish(char * file, int line);

#ifdef __cplusplus
}
#endif

#endif /* !xntest_h */
