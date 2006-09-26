/*
 * File:         arch/blackfin/mach-bfin/pm.c
 * Based on:     arm/mach-omap/pm.c
 * Author:       Cliff Brake <cbrake@accelent.com> Copyright (c) 2001
 *
 * Created:      2001
 * Description:  Power management for the bfin
 *
 * Rev:          $Id$
 *
 * Modified:     Nicolas Pitre - PXA250 support
 *                Copyright (c) 2002 Monta Vista Software, Inc.
 *               David Singleton - OMAP1510
 *                Copyright (c) 2002 Monta Vista Software, Inc.
 *               Dirk Behme <dirk.behme@de.bosch.com> - OMAP1510/1610
 *                Copyright 2004
 *               Copyright 2004-2006 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see the file COPYING, or write
 * to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <linux/pm.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>

#include <asm/io.h>
#include <asm/dpmc.h>
#include <asm/irq.h>

#define SIC_IWR_VAL 1 << (IRQ_PROG_INTA - (IRQ_CORETMR + 1))

void bf533_pm_suspend_standby_enter(void)
{

#if defined(CONFIG_PM_WAKEUP_BY_GPIO)
	u16 inen, polar, dir, mask;
	u16 pattern = 1 << CONFIG_PM_WAKEUP_GPIO_NUMBER;
	u32 flags;

	local_irq_save(flags);
  
  /* save state */
	inen = bfin_read_FIO_INEN();
	polar = bfin_read_FIO_POLAR();
	dir = bfin_read_FIO_DIR();
	mask = bfin_read_FIO_MASKA_D();

	bfin_write_FIO_MASKA_C(pattern);

#if CONFIG_PM_WAKEUP_GPIO_POLAR_H
	bfin_write_FIO_POLAR(polar & ~pattern);
#else
	bfin_write_FIO_POLAR(polar | pattern);
#endif

	bfin_write_FIO_DIR(dir & ~pattern);
	bfin_write_FIO_INEN(inen | pattern);
	bfin_write_FIO_MASKA_S(pattern);

  	sleep_deeper(SIC_IWR_VAL);
	  bfin_write_SIC_IWR(IWR_ENABLE_ALL);

  /* Restore original state */

	bfin_write_FIO_INEN(inen);
	bfin_write_FIO_POLAR(polar);
	bfin_write_FIO_DIR(dir);
	bfin_write_FIO_MASKA_D(mask);

	local_irq_restore(flags);
#endif				/* CONFIG_PM_WAKEUP_BY_GPIO */

#if defined(CONFIG_PM_WAKEUP_GPIO_BY_SIC_IWR) 
  sleep_deeper(CONFIG_PM_WAKEUP_SIC_IWR); 
  bfin_write_SIC_IWR(IWR_ENABLE_ALL); 
#endif				/* CONFIG_PM_WAKEUP_GPIO_BY_SIC_IWR */ 
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
		bf533_pm_suspend_standby_enter();
		break;
	case PM_SUSPEND_MEM:
		return -ENOTSUPP;

	case PM_SUSPEND_DISK:
		return -ENOTSUPP;

	default:
		return -EINVAL;
	}

	return 0;
}

/*
 *	bf533_pm_finish - Finish up suspend sequence.
 *	@state:		State we're coming out of.
 *
 *	This is called after we wake back up (or if entering the sleep state
 *	failed).
 */
static int bf533_pm_finish(suspend_state_t state)
{
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

	return 0;
}

struct pm_ops bfin_pm_ops = {
	.pm_disk_mode = PM_DISK_FIRMWARE,
	.prepare = bf533_pm_prepare,
	.enter = bf533_pm_enter,
	.finish = bf533_pm_finish,
};

static int __init bfin_pm_init(void)
{

	pm_set_ops(&bfin_pm_ops);
	return 0;
}

__initcall(bfin_pm_init);
