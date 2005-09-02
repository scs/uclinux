/*
 * linux/arch/arm/mach-bf533/pm.c
 *
 * OMAP Power Management Routines
 *
 * Original code for the SA11x0:
 * Copyright (c) 2001 Cliff Brake <cbrake@accelent.com>
 *
 * Modified for the PXA250 by Nicolas Pitre:
 * Copyright (c) 2002 Monta Vista Software, Inc.
 *
 * Modified for the OMAP1510 by David Singleton:
 * Copyright (c) 2002 Monta Vista Software, Inc.
 *
 * Cleanup 2004 for OMAP1510/1610 by Dirk Behme <dirk.behme@de.bosch.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN
 * NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <linux/pm.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/pm.h>

#include <asm/io.h>
#include <asm/mach/cpu.h>
#include <asm/mach/cdefbf533.h>
#include <asm/mach-types.h>



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
	dpmc_fops.ioctl(NULL,NULL,IOCTL_DEEP_SLEEP_MODE,0);	
}



/*
 *	bf533_pm_prepare - Do preliminary suspend work.
 *	@state:		suspend state we're entering.
 *
 */

static int bf533_pm_prepare(suspend_state_t state)
{
	int error = 0;

	switch (state)
	{
	case PM_SUSPEND_STANDBY:
		break;
	case PM_SUSPEND_MEM:
		return -ENOTSUPP

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
	switch (state)
	{
	case PM_SUSPEND_STANDBY:
		bf533_pm_suspend();
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


struct pm_ops bf533_pm_ops ={
	.pm_disk_mode = PM_DISK_FIRMWARE,
        .prepare        = bf533_pm_prepare,
        .enter          = bf533_pm_enter,
        .finish         = bf533_pm_finish,
};

static int __init bf533_pm_init(void)
{

	pm_set_ops(&bf533_pm_ops);
	return 0;
}
__initcall(bf533_pm_init);
