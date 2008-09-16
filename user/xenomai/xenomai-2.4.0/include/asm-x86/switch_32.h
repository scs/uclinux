/*
 * Copyright (C) 2001-2007 Philippe Gerum <rpm@xenomai.org>.
 * Copyright (C) 2004,2005 Gilles Chanteperdrix <gilles.chanteperdrix@laposte.net>.
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

#ifndef _XENO_ASM_X86_SWITCH_32_H
#define _XENO_ASM_X86_SWITCH_32_H
#define _XENO_ASM_X86_SWITCH_H

#ifndef __KERNEL__
#error "Pure kernel header included from user-space!"
#endif

static inline void xnarch_switch_threads(xnarchtcb_t *out_tcb,
					 xnarchtcb_t *in_tcb,
					 struct task_struct *outproc,
					 struct task_struct *inproc)
{
#if __GNUC__ < 3 || __GNUC__ == 3 && __GNUC_MINOR__ < 2

	__asm__ __volatile__("pushfl\n\t"
			     "pushl %%ecx\n\t"
			     "pushl %%edi\n\t"
			     "pushl %%ebp\n\t"
			     "movl %0,%%ecx\n\t"
			     "movl %%esp,(%%ecx)\n\t"
			     "movl %1,%%ecx\n\t"
			     "movl $2f,(%%ecx)\n\t"
			     "movl %2,%%ecx\n\t"
			     "movl %3,%%edi\n\t"
			     "movl (%%ecx),%%esp\n\t"
			     "pushl (%%edi)\n\t"
			     "testl %%edx,%%edx\n\t"
			     "je 1f\n\t"
			     "cmp %%edx,%%eax\n\t"
			     "jne  __switch_to\n\t"
			     "1: ret\n\t"
			     "2: popl %%ebp\n\t"
			     "popl %%edi\n\t"
			     "popl %%ecx\n\t"
			     "popfl\n\t":	/* no output */
			     :"m"(out_tcb->espp),
			      "m"(out_tcb->eipp),
			      "m"(in_tcb->espp),
			      "m"(in_tcb->eipp),
			      "b"(out_tcb),
			      "S"(in_tcb), "a"(outproc), "d"(inproc));

#else /* GCC version >= 3.2 */

	long ebx_out, ecx_out, edi_out, esi_out;

	__asm__ __volatile__("pushfl\n\t"
			     "pushl %%ebp\n\t"
			     "movl %6,%%ecx\n\t"
			     "movl %%esp,(%%ecx)\n\t"
			     "movl %7,%%ecx\n\t"
			     "movl $2f,(%%ecx)\n\t"
			     "movl %8,%%ecx\n\t"
			     "movl %9,%%edi\n\t"
			     "movl (%%ecx),%%esp\n\t"
			     "pushl (%%edi)\n\t"
			     "testl %%edx,%%edx\n\t"
			     "je 1f\n\t"
			     "cmp %%edx,%%eax\n\t"
			     "jne  __switch_to\n\t"
			     "1: ret\n\t"
			     "2: popl %%ebp\n\t"
			     "popfl\n\t":"=b"(ebx_out),
			     "=&c"(ecx_out),
			     "=S"(esi_out),
			     "=D"(edi_out), "+a"(outproc), "+d"(inproc)
			     :"m"(out_tcb->espp),
			      "m"(out_tcb->eipp),
			      "m"(in_tcb->espp), "m"(in_tcb->eipp));

#endif /* GCC version < 3.2 */
}

#endif /* !_XENO_ASM_X86_SWITCH_32_H */
