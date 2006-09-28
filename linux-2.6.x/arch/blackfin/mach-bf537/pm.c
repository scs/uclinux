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

/* FIO USE PORT F*/
#ifdef CONFIG_PM_WAKEUP_GPIO_PORT_F
#define pm_read_PORT_FER() bfin_read_PORTF_FER()
#define pm_write_PORT_FER(val) bfin_write_PORTF_FER(val)
#define pm_read_FIO_MASKA_D() bfin_read_PORTFIO_MASKA()
#define pm_write_FIO_MASKA_D(val) bfin_write_PORTFIO_MASKA(val)
#define pm_read_FIO_MASKA_C() bfin_read_PORTFIO_MASKA_CLEAR()
#define pm_write_FIO_MASKA_C(val) bfin_write_PORTFIO_MASKA_CLEAR(val)
#define pm_read_FIO_MASKA_S() bfin_read_PORTFIO_MASKA_SET()
#define pm_write_FIO_MASKA_S(val) bfin_write_PORTFIO_MASKA_SET(val)
#define pm_read_FIO_DIR() bfin_read_PORTFIO_DIR()
#define pm_write_FIO_DIR(val) bfin_write_PORTFIO_DIR(val)
#define pm_read_FIO_POLAR() bfin_read_PORTFIO_POLAR()
#define pm_write_FIO_POLAR(val) bfin_write_PORTFIO_POLAR(val)
#define pm_read_FIO_INEN() bfin_read_PORTFIO_INEN()
#define pm_write_FIO_INEN(val) bfin_write_PORTFIO_INEN(val)
#define SIC_IWR_VAL 1 << (IRQ_PROG_INTA - (IRQ_CORETMR + 1))
#endif

/* FIO USE PORT H*/
#ifdef CONFIG_PM_WAKEUP_GPIO_PORT_H
#define pm_read_PORT_FER() bfin_read_PORTH_FER()
#define pm_write_PORT_FER(val) bfin_write_PORTH_FER(val)
#define pm_read_FIO_MASKA_D() bfin_read_PORTHIO_MASKA()
#define pm_write_FIO_MASKA_D(val) bfin_write_PORTHIO_MASKA(val)
#define pm_read_FIO_MASKA_C() bfin_read_PORTHIO_MASKA_CLEAR()
#define pm_write_FIO_MASKA_C(val) bfin_write_PORTHIO_MASKA_CLEAR(val)
#define pm_read_FIO_MASKA_S() bfin_read_PORTHIO_MASKA_SET()
#define pm_write_FIO_MASKA_S(val) bfin_write_PORTHIO_MASKA_SET(val)
#define pm_read_FIO_DIR() bfin_read_PORTHIO_DIR()
#define pm_write_FIO_DIR(val) bfin_write_PORTHIO_DIR(val)
#define pm_read_FIO_POLAR() bfin_read_PORTHIO_POLAR()
#define pm_write_FIO_POLAR(val) bfin_write_PORTHIO_POLAR(val)
#define pm_read_FIO_INEN() bfin_read_PORTHIO_INEN()
#define pm_write_FIO_INEN(val) bfin_write_PORTHIO_INEN(val)
#define SIC_IWR_VAL 1 << (IRQ_MAC_RX - (IRQ_CORETMR + 1))
#endif

/* FIO USE PORT G*/
#ifdef CONFIG_PM_WAKEUP_GPIO_PORT_G
#define pm_read_PORT_FER() bfin_read_PORTG_FER()
#define pm_write_PORT_FER(val) bfin_write_PORTG_FER(val)
#define pm_read_FIO_MASKA_D() bfin_read_PORTGIO_MASKA()
#define pm_write_FIO_MASKA_D(val) bfin_write_PORTGIO_MASKA(val)
#define pm_read_FIO_MASKA_C() bfin_read_PORTGIO_MASKA_CLEAR()
#define pm_write_FIO_MASKA_C(val) bfin_write_PORTGIO_MASKA_CLEAR(val)
#define pm_read_FIO_MASKA_S() bfin_read_PORTGIO_MASKA_SET()
#define pm_write_FIO_MASKA_S(val) bfin_write_PORTGIO_MASKA_SET(val)
#define pm_read_FIO_DIR() bfin_read_PORTGIO_DIR()
#define pm_write_FIO_DIR(val) bfin_write_PORTGIO_DIR(val)
#define pm_read_FIO_POLAR() bfin_read_PORTGIO_POLAR()
#define pm_write_FIO_POLAR(val) bfin_write_PORTGIO_POLAR(val)
#define pm_read_FIO_INEN() bfin_read_PORTGIO_INEN()
#define pm_write_FIO_INEN(val) bfin_write_PORTGIO_INEN(val)
#define SIC_IWR_VAL 1 << (IRQ_PROG_INTA - (IRQ_CORETMR + 1))
#endif


void bf537_pm_suspend_standby_enter(void)
{

#if defined(CONFIG_PM_WAKEUP_BY_GPIO)
	u16 inen, polar, dir, mask, fer;
	u16 pattern = 1 << CONFIG_PM_WAKEUP_GPIO_NUMBER;
	u32 flags;

	local_irq_save(flags);
  
  /* save state */
	inen = pm_read_FIO_INEN();
	polar = pm_read_FIO_POLAR();
	dir = pm_read_FIO_DIR();
	mask = pm_read_FIO_MASKA_D();
	fer = pm_read_PORT_FER();

	pm_write_PORT_FER(fer & ~pattern);

	pm_write_FIO_MASKA_C(pattern);

#if defined(CONFIG_PM_WAKEUP_GPIO_POLAR_H)
	pm_write_FIO_POLAR(polar & ~pattern);
#else
	pm_write_FIO_POLAR(polar | pattern);
#endif

	pm_write_FIO_DIR(dir & ~pattern);
	pm_write_FIO_INEN(inen | pattern);
	pm_write_FIO_MASKA_S(pattern);

  	sleep_deeper(SIC_IWR_VAL);
	  bfin_write_SIC_IWR(IWR_ENABLE_ALL);

  /* Restore original state */
	pm_write_PORT_FER(fer);
	pm_write_FIO_INEN(inen);
	pm_write_FIO_POLAR(polar);
	pm_write_FIO_DIR(dir);
	pm_write_FIO_MASKA_D(mask);

	local_irq_restore(flags);
#endif				/* CONFIG_PM_WAKEUP_BY_GPIO */

#if defined(CONFIG_PM_WAKEUP_GPIO_BY_SIC_IWR)
	sleep_deeper(CONFIG_PM_WAKEUP_SIC_IWR);
	bfin_write_SIC_IWR(IWR_ENABLE_ALL);
#endif				/* CONFIG_PM_WAKEUP_GPIO_BY_SIC_IWR */

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
		bf537_pm_suspend_standby_enter();
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
 *	bf537_pm_finish - Finish up suspend sequence.
 *	@state:		State we're coming out of.
 *
 *	This is called after we wake back up (or if entering the sleep state
 *	failed).
 */
static int bf537_pm_finish(suspend_state_t state)
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
	.prepare = bf537_pm_prepare,
	.enter = bf537_pm_enter,
	.finish = bf537_pm_finish,
};

static int __init bfin_pm_init(void)
{

	pm_set_ops(&bfin_pm_ops);
	return 0;
}

__initcall(bfin_pm_init);
