/*
 * File:        arch/blackfin/mach-bf537/pm.c
 * Based on:    arm/mach-omap/pm.c
 * Author:      Cliff Brake <cbrake@accelent.com>
 *              Copyright (c) 2001
 * Created:     2001
 * Description: Power management for the bf537
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

#include <asm/io.h>

/*
 * Let's power down on idle, but only if we are really
 * idle, because once we start down the path of
 * going idle we continue to do idle even if we get
 * a clock tick interrupt . .
 */
void bf537_pm_idle(void)
{
}

/*
 * when we call pm_suspend, that code  enters into idle state and sdram enter self-refresh mode
 *  to save more energy.When there is any interrupt,the core will resume
 */
void bf537_pm_suspend(void)
{
	/*sdram enter self-refresh mode*/
	 bfin_read_EBIU_SDGCTL() = (bfin_read_EBIU_SDGCTL() |SRFS);
        __builtin_bfin_ssync();
	/*any interrupt can cause CPU exit idle state*/
        bfin_write_SIC_IWR(0x00ffffff);
        __builtin_bfin_ssync();
        __asm__ (
        "CLI R2;\n\t"
        "SSYNC;\n\t"
        "IDLE;\n\t"
        "STI R2;\n\t"
        );
        /*sdram exit self-refresh mode*/
        bfin_read_EBIU_SDGCTL() = (bfin_read_EBIU_SDGCTL() |SRFS);
        __builtin_bfin_ssync();

}

/*
 *	bf537_pm_prepare - Do preliminary suspend work.
 *	@state:		suspend state we're entering.
 *
 */

static int bf537_pm_prepare(suspend_state_t state)
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
 *	bf537_pm_enter - Actually enter a sleep state.
 *	@state:		State we're entering.
 *
 */

static int bf537_pm_enter(suspend_state_t state)
{
	switch (state) {
	case PM_SUSPEND_STANDBY:
		return -ENOTSUPP;

	case PM_SUSPEND_MEM:
		bf537_pm_suspend();
		break;

	case PM_SUSPEND_DISK:
		return -ENOTSUPP;

	default:
		return -EINVAL;
	}

	return 0;
}

/**
 *	bf537_pm_finish - Finish up suspend sequence.
 *	@state:		State we're coming out of.
 *
 *	This is called after we wake back up (or if entering the sleep state
 *	failed).
 */

static int bf537_pm_finish(suspend_state_t state)
{
	return 0;
}

struct pm_ops bf537_pm_ops = {
	.pm_disk_mode = PM_DISK_FIRMWARE,
	.prepare = bf537_pm_prepare,
	.enter = bf537_pm_enter,
	.finish = bf537_pm_finish,
};

static int __init bf537_pm_init(void)
{

	pm_set_ops(&bf537_pm_ops);
	return 0;
}

__initcall(bf537_pm_init);
