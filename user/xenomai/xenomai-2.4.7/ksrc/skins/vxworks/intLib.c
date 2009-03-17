/*
 * Copyright (C) 2001,2002 IDEALX (http://www.idealx.com/).
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>.
 * Copyright (C) 2003 Philippe Gerum <rpm@xenomai.org>.
 *
 * Xenomai is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <vxworks/defs.h>

BOOL intContext(void)
{
	return (BOOL)xnpod_interrupt_p();
}

int intCount(void)
{
	return xnpod_current_sched()->inesting;
}

int intLevelSet(int mask)
{
	return xnarch_setimask(mask);

}

int intLock(void)
{
	spl_t s;

	splhigh(s);

	return (int)s;
}

void intUnlock(int flags)
{
	spl_t s = (spl_t)flags;
	splexit(s);
}
