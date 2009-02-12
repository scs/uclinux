/**
 * @ingroup hal
 * @file
 *
 * Copyright (C) 2007 Philippe Gerum <rpm@xenomai.org>.
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
 * along with Xenomai; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _XENO_ASM_X86_HAL_H
#define _XENO_ASM_X86_HAL_H

#include <linux/ipipe.h>

#ifdef CONFIG_X86_LOCAL_APIC
#ifdef __IPIPE_FEATURE_APIC_TIMER_FREQ
#define RTHAL_COMPAT_TIMERFREQ		__ipipe_apic_timer_freq
#else
/* Fallback value: may be inaccurate. */
#define RTHAL_COMPAT_TIMERFREQ		(apic_read(APIC_TMICT) * HZ)
#endif
#else
#define RTHAL_COMPAT_TIMERFREQ		CLOCK_TICK_RATE
#endif

#if defined(CONFIG_GENERIC_CLOCKEVENTS) && !defined(__IPIPE_FEATURE_REQUEST_TICKDEV)

#include <linux/ipipe_tickdev.h>

/*
 * We handle the case of the I-pipe/x86 patch series which do provide
 * the early ipipe_request_tickdev() interface on top of the generic
 * clock event support, but prior to its refactoring. The most
 * significant changes involve an additional parameter to retrieve the
 * grabbed timer frequency passed to ipipe_request_tickdev(), and a
 * different prototype for mode and tick emulation callouts.
 *
 * This early support can be detected by testing
 * CONFIG_GENERIC_CLOCKEVENTS first, since all I-pipe patches
 * compatible with the generic clock event layer do define the
 * ipipe_request_tickdev() service, then by testing
 * __IPIPE_FEATURE_REQUEST_TICKDEV, which is only defined by I-pipe
 * patches exhibiting the refactored API.
 *
 * THIS COMPATIBILITY SUPPORT WILL BE DEPRECATED STARTING WITH Linux
 * 2.6.24. If you happen to run 2.6.22 or 2.6.23 kernels, you may want
 * to upgrade your I-pipe patch to the most recent I-pipe/2.6.23
 * release to date, which exhibits the refactored API.
 */

typedef void (*compat_emumode_t)(enum clock_event_mode,
				 struct ipipe_tick_device *tdev);
typedef int (*compat_emutick_t)(unsigned long evt,
				struct ipipe_tick_device *tdev);
#endif

extern enum rthal_ktimer_mode rthal_ktimer_saved_mode;

#ifdef __i386__
#include "hal_32.h"
#else
#include "hal_64.h"
#endif

#endif /* !_XENO_ASM_X86_HAL_H */
