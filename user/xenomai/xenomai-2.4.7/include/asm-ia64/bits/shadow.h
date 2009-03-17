/*
 * Copyright &copy; 2001,2002,2003,2004 Philippe Gerum <rpm@xenomai.org>.
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

#ifndef _XENO_ASM_IA64_BITS_SHADOW_H
#define _XENO_ASM_IA64_BITS_SHADOW_H

#ifndef __KERNEL__
#error "Pure kernel header included from user-space!"
#endif

static inline void xnarch_init_shadow_tcb(xnarchtcb_t * tcb,
					  struct xnthread *thread,
					  const char *name)
{
	struct task_struct *task = current;

	tcb->user_task = task;
	tcb->active_task = NULL;
	tcb->fpup = task->thread.fph;
	tcb->kspp = &task->thread.ksp;
	tcb->name = name;
}

static inline void xnarch_grab_xirqs(rthal_irq_handler_t handler)
{
	unsigned irq;

	for (irq = 0; irq < IPIPE_NR_XIRQS; irq++)
		rthal_virtualize_irq(rthal_current_domain,
				     irq,
				     handler, NULL, NULL, IPIPE_HANDLE_MASK);
}

static inline void xnarch_lock_xirqs(rthal_pipeline_stage_t * ipd, int cpuid)
{
	unsigned irq;

	for (irq = 0; irq < IPIPE_NR_XIRQS; irq++) {
		unsigned vector = __ia64_local_vector_to_irq(irq);

		switch (vector) {
#ifdef CONFIG_SMP
		case IPIPE_CRITICAL_VECTOR:
		case IA64_IPI_RESCHEDULE:
		case IA64_IPI_VECTOR:

			/* Never lock out these ones. */
			continue;
#endif /* CONFIG_SMP */

		default:

			rthal_lock_irq(ipd, cpuid, irq);
		}
	}
}

static inline void xnarch_unlock_xirqs(rthal_pipeline_stage_t * ipd, int cpuid)
{
	unsigned irq;

	for (irq = 0; irq < IPIPE_NR_XIRQS; irq++) {
		unsigned vector = local_vector_to_irq(irq);

		switch (vector) {
#ifdef CONFIG_SMP
		case IPIPE_CRITICAL_VECTOR:
		case IA64_IPI_RESCHEDULE:
		case IA64_IPI_VECTOR:

			continue;
#endif /* CONFIG_SMP */

		default:

			rthal_unlock_irq(ipd, irq);
		}
	}
}

static inline int xnarch_local_syscall(struct pt_regs *regs)
{
	return -ENOSYS;
}

#define xnarch_schedule_tail(prev) do { } while(0)

#endif /* !_XENO_ASM_IA64_BITS_SHADOW_H */
