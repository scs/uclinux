/*
 * File:        arch/blackfin/mach-bf533/pm.c
 * Based on:    arm/mach-omap/pm.c
 * Author:      Cliff Brake <cbrake@accelent.com>
 *              Copyright (c) 2001
 * Created:     2001
 * Description: Power management for the bf533
 *
 * Rev:         $Id$
 *
 * Modified:    Nicolas Pitre - PXA250 support
 *                Copyright (c) 2002 Monta Vista Software, Inc.
 *              David Singleton - OMAP1510
 *                Copyright (c) 2002 Monta Vista Software, Inc.
 *              Dirk Behme <dirk.behme@de.bosch.com> - OMAP1510/1610
 *                Copyright 2004
 *              Michael.Kang@analog.com - Blackfin support
 * Maintained:  Michael.Kang@analog.com
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.
 * If not, write to the Free Software Foundation,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <linux/pm.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/pm.h>

#include <asm/io.h>

/*
 * Let's power down on idle, but only if we are really
 * idle, because once we start down the path of
 * going idle we continue to do idle even if we get
 * a clock tick interrupt . .
 */
void bf533_pm_idle(void)
{
}

void bf533_pm_suspend(void)
{
}

/*
 *	bf533_pm_prepare - Do preliminary suspend work.
 *	@state:		suspend state we're entering.
 *
 */

static int bf533_pm_prepare(suspend_state_t state)
{
	int error = 0;

	switch (state) {
	case PM_SUSPEND_STANDBY:
		break;
	case PM_SUSPEND_MEM:
		return -ENOTSUPP;

	case PM_SUSPEND_DISK:
		return -ENOTSUPP;

	default:
		return -EINVAL;
	}

	return error;
}

/*
 *	bf533_pm_enter - Actually enter a sleep state.
 *	@state:		State we're entering.
 *
 */

static int bf533_pm_enter(suspend_state_t state)
{
	switch (state) {
	case PM_SUSPEND_STANDBY:
		return -ENOTSUPP;

	case PM_SUSPEND_MEM:
		bf533_pm_suspend();
		break;

	case PM_SUSPEND_DISK:
		return -ENOTSUPP;

	default:
		return -EINVAL;
	}

	return 0;
}

/**
 *	bf533_pm_finish - Finish up suspend sequence.
 *	@state:		State we're coming out of.
 *
 *	This is called after we wake back up (or if entering the sleep state
 *	failed).
 */

static int bf533_pm_finish(suspend_state_t state)
{
	return 0;
}

struct pm_ops bf533_pm_ops = {
	.pm_disk_mode = PM_DISK_FIRMWARE,
	.prepare = bf533_pm_prepare,
	.enter = bf533_pm_enter,
	.finish = bf533_pm_finish,
};

static int __init bf533_pm_init(void)
{

	pm_set_ops(&bf533_pm_ops);
	return 0;
}

__initcall(bf533_pm_init);
