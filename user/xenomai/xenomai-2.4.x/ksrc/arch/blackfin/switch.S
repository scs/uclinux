/*
 * Copyright (C) 2005 Philippe Gerum.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 * USA; either version 2 of the License, or (at your option) any later
 * version.
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

#include <linux/linkage.h>
#include <asm/blackfin.h>
#include <asm/entry.h>
#include <asm/asm-offsets.h>

/*
 * Switch context routine for Xenomai threads.
 * Kernel-based threads are basically seen as co-routines.
 * The context is saved/restored to/from regular thread_structs,
 * so that hybrid scheduling between kernel and user-space Xenomai
 * threads is possible.
 *
 * We protect all caller-saved registers across switches.
 * 
 * void rthal_thread_switch(struct thread_struct *prev, struct thread_struct *next)
 */
ENTRY(_rthal_thread_switch)

	[--sp] = rets;
	[--sp] = fp;
	[--sp] = ( R7:4, P5:3 );

	p0 = r0;
	p1 = r1;

	/* Save context. */
	p2 = usp;
	[p0+THREAD_USP] = p2;
	[p0+THREAD_KSP] = sp;
	r1.l = switch_point;
	r1.h = switch_point;
	[p0+THREAD_PC] = r1;

	/* Restore context. */
	sp = [p1+THREAD_KSP];
	p0 = [p1+THREAD_USP];
	usp = p0;
	p0 = [p1+THREAD_PC];
	jump (p0);

switch_point:

	( R7:4, P5:3 ) = [sp++];
	fp = [sp++];
	rets = [sp++];
	rts;

ENTRY(_rthal_thread_trampoline)
	r0 = [sp++]; 
	jump switch_point
	
/*
 * Check for a pending syscall event. On this arch, syscalls start as
 * exceptions, which are deferred to low priority interrupts for
 * processing them. Returns true if the syscall has been deferred.
 * 
 * int rthal_defer_switch_p(void)
 */

ENTRY(_rthal_defer_switch_p)

#ifdef CONFIG_XENO_OPT_PERVASIVE
	p2.l = lo(ILAT);
        p2.h = hi(ILAT);
        r0 = [p2];
	r1 = EVT_IVG15 (z);
        r0 = r0 & r1;
	cc = r0 == 0;
	if !cc jump 1f; 
#endif /* CONFIG_XENO_OPT_PERVASIVE */
	p2.l = lo(IPEND);
        p2.h = hi(IPEND);
	csync;
        r2 = [p2];
        r1 = 1;
        r1 = r2 - r1;
        r0 = r2 & r1;
1:
	rts

#ifdef CONFIG_XENO_HW_NMI_DEBUG_LATENCY

ENTRY(_rthal_nmi_handler)
	SAVE_ALL_SYS
	r0 = sp;
	SP += -12;	
	call _rthal_nmi_tick
	SP += 12;	
	RESTORE_ALL_SYS
	rtn; 
		
#endif /* CONFIG_XENO_HW_NMI_DEBUG_LATENCY_MAX */
