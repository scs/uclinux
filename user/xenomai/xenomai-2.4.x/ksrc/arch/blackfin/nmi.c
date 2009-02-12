/**
 *   @ingroup hal
 *   @file
 *
 *   NMI watchdog support.
 *
 *   Copyright (C) 2005 Philippe Gerum.
 *
 *   Xenomai is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License as
 *   published by the Free Software Foundation, Inc., 675 Mass Ave,
 *   Cambridge MA 02139, USA; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   Xenomai is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 *   02111-1307, USA.
 */

#include <linux/version.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <asm/system.h>
#include <asm/atomic.h>
#include <asm/irqchip.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/xenomai/hal.h>

static void (*rthal_nmi_emergency) (struct pt_regs *);

static volatile void *rthal_old_nmi_handler;

asmlinkage void rthal_nmi_handler(struct pt_regs *regs);

asmlinkage void rthal_nmi_tick(struct pt_regs *regs)
{
	rthal_nmi_emergency(regs);
}

int rthal_nmi_request(void (*emergency) (struct pt_regs *))
{
	if (rthal_nmi_emergency)
		return -EBUSY;

	rthal_nmi_disarm();
	CSYNC();
	rthal_nmi_emergency = emergency;
	rthal_old_nmi_handler = (void *)bfin_read_EVT2();
	bfin_write_EVT2(&rthal_nmi_handler);
	CSYNC();

	return 0;
}

void rthal_nmi_release(void)
{
	if (rthal_nmi_emergency == NULL)
		return;

	rthal_nmi_disarm();
	CSYNC();
	bfin_write_EVT2(rthal_old_nmi_handler);
	CSYNC();
	rthal_nmi_emergency = NULL;
}

void rthal_nmi_arm(unsigned long delay)
{
	bfin_write_WDOG_CTL(0xad0);	/* Disable */
	CSYNC();
	bfin_write_WDOG_CNT(delay);
	bfin_write_WDOG_CTL(0x2);	/* Enable, generate NMIs */
	CSYNC();
}

void rthal_nmi_disarm(void)
{
	bfin_write_WDOG_CTL(0xad0);	/* Disable */
	CSYNC();
}

EXPORT_SYMBOL(rthal_nmi_request);
EXPORT_SYMBOL(rthal_nmi_release);
EXPORT_SYMBOL(rthal_nmi_arm);
EXPORT_SYMBOL(rthal_nmi_disarm);
