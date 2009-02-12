/*
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@laposte.net>.
 * Copyright (C) 2003 Philippe Gerum <rpm@xenomai.org>.
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

#ifndef pse51_test_h
#define pse51_test_h

#include <string.h>             /* For strerror */
#include <xntest.h>
#include <posix/posix.h>

#define TEST_ASSERT_OK(expr)                                            \
do {                                                                    \
    int err;                                                            \
    if (xntest_verbose)                                                 \
        xnarch_printf(__FILE__ ":%d " #expr " == 0\n", __LINE__);       \
    if(!xntest_assert(((err=(expr))==0), #expr "== 0\n" ,               \
                      __FILE__, __LINE__ ))                             \
        xnarch_printf(__FILE__":%d: %s\n",                              \
                      __LINE__,                                         \
                      strerror(err == -1 ? errno : err));               \
} while (0)                                                             \

#endif /* !pse51_test_h */
