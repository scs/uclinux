 /*
  * File:        arch/blackfin/mach-common/ints-priority.c
  * Based on:
  * Author:      unknown
  *              COPYRIGHT 2005 Analog Devices
  * Created:     ?
  * Description: Set up the interupt priorities
  *
  * Rev:          $Id$
  *
  * Modified:
  *              1996 Roman Zippel
  *              1999 D. Jeff Dionne <jeff@uclinux.org>
  *              2000-2001 Lineo, Inc. D. Jefff Dionne <jeff@lineo.ca>
  *              2002 Arcturus Networks Inc. MaTed <mated@sympatico.ca>
  *              2003 Metrowerks/Motorola
  *              2003 Bas Vermeulen <bas@buyways.nl>,
  *                   BuyWays B.V. (www.buyways.nl)
  *              2004 LG Soft India
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

#include <linux/module.h>
#include <linux/kernel_stat.h>
#include <linux/seq_file.h>
#include <asm/irqchip.h>
#include <asm/traps.h>
#include <asm/blackfin.h>

/*
 * NOTES:
 * - we have separated the physical Hardware interrupt from the
 * levels that the LINUX kernel sees (see the description in irq.h)
 * -
 */

volatile unsigned long irq_flags = 0;

/* The number of spurious interrupts */
volatile unsigned int num_spurious;

struct ivgx {
	/* irq number for request_irq, available in mach-bf561/irq.h */
	int irqno;
	/* corresponding bit in the SICA_ISR0 register */
	int isrflag0;
	/* corresponding bit in the SICA_ISR1 register */
	int isrflag1;
} ivg_table[NR_PERI_INTS];

struct ivg_slice {
	/* position of first irq in ivg_table for given ivg */
	struct ivgx *ifirst;
	struct ivgx *istop;
} ivg7_13[IVG13 - IVG7 + 1];

/* BASE LEVEL interrupt handler routines */
asmlinkage void evt_nmi(void);
asmlinkage void evt_exception(void);
asmlinkage void trap(void);
asmlinkage void evt_ivhw(void);
asmlinkage void evt_timer(void);
asmlinkage void evt_evt2(void);
asmlinkage void evt_evt7(void);
asmlinkage void evt_evt8(void);
asmlinkage void evt_evt9(void);
asmlinkage void evt_evt10(void);
asmlinkage void evt_evt11(void);
asmlinkage void evt_evt12(void);
asmlinkage void evt_evt13(void);
asmlinkage void evt_soft_int1(void);
asmlinkage void evt_system_call(void);

extern void program_IAR(void);
static void search_IAR(void);

/*
 * Search SIC_IAR and fill tables with the irqvalues
 * and their positions in the SIC_ISR register.
 */
static void __init search_IAR(void)
{
	unsigned ivg, irq_pos = 0;
	for (ivg = 0; ivg <= IVG13 - IVG7; ivg++) {
		int irqn;

		ivg7_13[ivg].istop = ivg7_13[ivg].ifirst = &ivg_table[irq_pos];

		for (irqn = 0; irqn < NR_PERI_INTS; irqn++) {
			int iar_shift = (irqn & 7) * 4;
			if (ivg == (0xf & pSICA_IAR0[irqn >> 3] >> iar_shift)) {
				ivg_table[irq_pos].irqno = IVG7 + irqn;
				ivg_table[irq_pos].isrflag0 = 
					(irqn < 32 ? (1 << irqn) : 0);
				ivg_table[irq_pos].isrflag1 = 
					(irqn < 32 ? 0 : (1 << (irqn - 32)));
				ivg7_13[ivg].istop++;
				irq_pos++;
			}
		}
	}
}

/*
 * This is for BF561 internal IRQs
 */

static void ack_noop(unsigned int irq)
{
	/* Dummy function.  */
}

static void bf561_core_mask_irq(unsigned int irq)
{
	irq_flags &= ~(1 << irq);
	if (!irqs_disabled())
		local_irq_enable();
}

static void bf561_core_unmask_irq(unsigned int irq)
{
	irq_flags |= 1 << irq;
	/*
	 * If interrupts are enabled, IMASK must contain the same value
	 * as irq_flags.  Make sure that invariant holds.  If interrupts
	 * are currently disabled we need not do anything; one of the
	 * callers will take care of setting IMASK to the proper value
	 * when reenabling interrupts.
	 * local_irq_enable just does "STI irq_flags", so it's exactly
	 * what we need.
	 */
	if (!irqs_disabled())
		local_irq_enable();
	return;
}

static void bf561_internal_mask_irq(unsigned int irq)
{
	/* Dummy function.  */
}

static void bf561_internal_unmask_irq(unsigned int irq)
{
	unsigned long irq_mask;
	
	if ((irq - (IRQ_CORETMR +1)) < 32)
	{
		irq_mask = (1 << (irq - (IRQ_CORETMR + 1)));
		*pSICA_IMASK0 |= irq_mask;
	} else {
		irq_mask = (1 << (irq - (IRQ_CORETMR + 1) - 32));
		*pSICA_IMASK1 |= irq_mask;
	}
	__builtin_bfin_ssync();
}

static struct irqchip bf561_core_irqchip = {
	.ack = ack_noop,
	.mask = bf561_core_mask_irq,
	.unmask = bf561_core_unmask_irq,
};

static struct irqchip bf561_internal_irqchip = {
	.ack = ack_noop,
	.mask = bf561_internal_mask_irq,
	.unmask = bf561_internal_unmask_irq,
};

#ifdef CONFIG_IRQCHIP_DEMUX_GPIO
static int gpio_enabled[3];
static int gpio_edge_triggered[3];

static void bf561_gpio_ack_irq(unsigned int irq)
{
	int gpionr = irq - IRQ_PF0;
	int mask;
	if (gpionr < 16) {
		mask = (1L << gpionr);
		*pFIO0_FLAG_C = mask;
	} else if (gpionr < 32) {
		mask = (1L << (gpionr - 16));
		*pFIO1_FLAG_C = mask;
	} else {
		mask = (1L << (gpionr - 32));
		*pFIO2_FLAG_C = mask;
	}
/*	if (gpio_edge_triggered & mask) {
		* ack *
	} else {
		* ack and mask *
	}
*/
	__builtin_bfin_ssync();
}

static void bf561_gpio_mask_irq(unsigned int irq)
{
	int gpionr = irq - IRQ_PF0;
	int mask;
	if (gpionr < 16) {
		mask = (1L << gpionr);
		*pFIO0_FLAG_C = mask;
		__builtin_bfin_ssync();
		*pFIO0_MASKB_C = mask;
		__builtin_bfin_ssync();
	} else if (gpionr < 32) {
		mask = (1L << (gpionr - 16));
		*pFIO1_FLAG_C = mask;
		__builtin_bfin_ssync();
		*pFIO1_MASKB_C = mask;
		__builtin_bfin_ssync();
	} else {
		mask = (1L << (gpionr - 32));
		*pFIO2_FLAG_C = mask;
		__builtin_bfin_ssync();
		*pFIO2_MASKB_C = mask;
		__builtin_bfin_ssync();
	}
}

static void bf561_gpio_unmask_irq(unsigned int irq)
{
	int gpionr = irq - IRQ_PF0;
	int mask;
	if (gpionr < 16) {
		mask = (1L << gpionr);
		*pFIO0_MASKB_S = mask;
	} else if (gpionr < 32) {
		mask = (1L << (gpionr - 16));
		*pFIO1_MASKB_S = mask;
	} else {
		mask = (1L << (gpionr - 32));
		*pFIO2_MASKB_S = mask;
	}
}

static int bf561_gpio_irq_type(unsigned int irq, unsigned int type)
{
	int gpionr = irq - IRQ_PF0;
	int gpioidx = 0;
	int mask = (1L << gpionr);

	if (gpionr < 16) {
		mask = (1L << gpionr);
		*pFIO0_DIR &= ~mask;
		__builtin_bfin_ssync();
		*pFIO0_INEN |= mask;
		__builtin_bfin_ssync();
		gpioidx = 0;
	} else if (gpionr < 32) {
		mask = (1L << (gpionr - 16));
		*pFIO1_DIR &= ~mask;
		__builtin_bfin_ssync();
		*pFIO1_INEN |= mask;
		__builtin_bfin_ssync();
		gpioidx = 1;
	} else {
		mask = (1L << (gpionr - 32));
		*pFIO2_DIR &= ~mask;
		__builtin_bfin_ssync();
		*pFIO2_INEN |= mask;
		__builtin_bfin_ssync();
		gpioidx = 2;
	}

	if (type == IRQT_PROBE) {
		/* only probe unenabled GPIO interrupt lines */
		if (gpio_enabled[gpioidx] & mask)
			return 0;
		type = __IRQT_RISEDGE | __IRQT_FALEDGE;
	}
	if (type & (__IRQT_RISEDGE | __IRQT_FALEDGE |
		    __IRQT_HIGHLVL | __IRQT_LOWLVL))
		gpio_enabled[gpioidx] |= mask;
	else
		gpio_enabled[gpioidx] &= ~mask;

	if (type & (__IRQT_RISEDGE | __IRQT_FALEDGE)) {
		gpio_edge_triggered[gpioidx] |= mask;
		if (gpionr < 16)
			*pFIO0_EDGE |= mask;
		else if (gpionr < 32)
			*pFIO1_EDGE |= mask;
		else
			*pFIO2_EDGE |= mask;
	} else {
		if (gpionr < 16)
			*pFIO0_EDGE &= ~mask;
		else if (gpionr < 32)
			*pFIO1_EDGE &= ~mask;
		else
			*pFIO2_EDGE &= ~mask;
		gpio_edge_triggered[gpioidx] &= ~mask;
	}
	__builtin_bfin_ssync();

	if ((type & (__IRQT_RISEDGE | __IRQT_FALEDGE))
	    == (__IRQT_RISEDGE | __IRQT_FALEDGE))
	{
		if (gpionr < 16)
			*pFIO0_BOTH |= mask;
		else if (gpionr < 32)
			*pFIO1_BOTH |= mask;
		else
			*pFIO2_BOTH |= mask;
	} else {
		if (gpionr < 16)
			*pFIO0_BOTH &= ~mask;
		else if (gpionr < 32)
			*pFIO1_BOTH &= ~mask;
		else
			*pFIO2_BOTH &= ~mask;
	}
	__builtin_bfin_ssync();

	if ((type & (__IRQT_FALEDGE | __IRQT_LOWLVL))
	    && ((type & (__IRQT_RISEDGE | __IRQT_FALEDGE))
		!= (__IRQT_RISEDGE | __IRQT_FALEDGE)))
	{
		/* low or falling edge denoted by one */
		if (gpionr < 16)
			*pFIO0_POLAR |= mask;
		else if (gpionr < 32)
			*pFIO1_POLAR |= mask;
		else
			*pFIO2_POLAR |= mask;
	} else {
		/* high or rising edge denoted by zero */
		if (gpionr < 16)
			*pFIO0_POLAR &= ~mask;
		else if (gpionr < 32)
			*pFIO1_POLAR &= ~mask;
		else
			*pFIO2_POLAR &= ~mask;
	}
	__builtin_bfin_ssync();

	if (type & (__IRQT_RISEDGE | __IRQT_FALEDGE))
		set_irq_handler(irq, do_edge_IRQ);
	else
		set_irq_handler(irq, do_level_IRQ);

	return 0;
}
static struct irqchip bf561_gpio_irqchip = {
	.ack = bf561_gpio_ack_irq,
	.mask = bf561_gpio_mask_irq,
	.unmask = bf561_gpio_unmask_irq,
	.type = bf561_gpio_irq_type
};

static void bf561_demux_gpio_irq(unsigned int intb_irq,
				 struct irqdesc *intb_desc,
				 struct pt_regs *regs)
{
	int loop = 0;

	if (intb_irq == IRQ_PROG0_INTB) {
		do {
			int irq = IRQ_PF0;
			int flag_d = *pFIO0_FLAG_D;
			int mask = flag_d & (gpio_enabled[0] & *pFIO0_MASKB_C);
			loop = mask;
			do {
				if (mask & 1) {
					struct irqdesc *desc = irq_desc + irq;
					desc->handle(irq, desc, regs);
				}
				irq++;
				mask >>= 1;
			} while (mask);
		} while (loop);
	} else if (intb_irq == IRQ_PROG1_INTB) {
		do {
			int irq = IRQ_PF16;
			int flag_d = *pFIO1_FLAG_D;
			int mask = flag_d & (gpio_enabled[1] & *pFIO1_MASKB_C);
			loop = mask;
			do {
				if (mask & 1) {
					struct irqdesc *desc = irq_desc + irq;
					desc->handle(irq, desc, regs);
				}
				irq++;
				mask >>= 1;
			} while (mask);
		} while (loop);
	} else {
		do {
			int irq = IRQ_PF32;
			int flag_d = *pFIO2_FLAG_D;
			int mask = flag_d & (gpio_enabled[2] & *pFIO2_MASKB_C);
			loop = mask;
			do {
				if (mask & 1) {
					struct irqdesc *desc = irq_desc + irq;
					desc->handle(irq, desc, regs);
				}
				irq++;
				mask >>= 1;
			} while (mask);
		} while (loop);
	}
}
#endif				/* CONFIG_IRQCHIP_DEMUX_GPIO */

/*
 * This function should be called during kernel startup to initialize
 * the BFin IRQ handling routines.
 */

extern void evt14_softirq(void);

int __init init_arch_irq(void)
{
	int irq;
	unsigned long ilat = 0;
	/*  Disable all the peripheral intrs  - page 4-29 HW Ref manual */
	*pSICA_IMASK0 = SIC_UNMASK_ALL;
	*pSICA_IMASK1 = SIC_UNMASK_ALL;
	__builtin_bfin_ssync();

	local_irq_disable();

#ifndef CONFIG_KGDB
	*pEVT0 = evt_nmi;
#endif
	*pEVT2 = evt_evt2;
	*pEVT3 = trap;
	*pEVT5 = evt_ivhw;
	*pEVT6 = evt_timer;
	*pEVT7 = evt_evt7;
	*pEVT8 = evt_evt8;
	*pEVT9 = evt_evt9;
	*pEVT10 = evt_evt10;
	*pEVT11 = evt_evt11;
	*pEVT12 = evt_evt12;
	*pEVT13 = evt_evt13;
	*pEVT14 = evt14_softirq;
	*pEVT15 = evt_system_call;
	__builtin_bfin_csync();

	for (irq = 0; irq < SYS_IRQS; irq++) {
		if (irq <= IRQ_CORETMR)
			set_irq_chip(irq, &bf561_core_irqchip);
		else
			set_irq_chip(irq, &bf561_internal_irqchip);
#ifdef CONFIG_IRQCHIP_DEMUX_GPIO
		if ((irq != IRQ_PROG0_INTB) &&
		    (irq != IRQ_PROG1_INTB) &&
		    (irq != IRQ_PROG2_INTB)) {
#endif
			set_irq_handler(irq, do_simple_IRQ);
			set_irq_flags(irq, IRQF_VALID);
#ifdef CONFIG_IRQCHIP_DEMUX_GPIO
		} else {
			set_irq_chained_handler(irq,
						bf561_demux_gpio_irq);
		}
#endif

	}

#ifdef CONFIG_IRQCHIP_DEMUX_GPIO
	for (irq = IRQ_PF0; irq <= IRQ_PF47; irq++) {
		set_irq_chip(irq, &bf561_gpio_irqchip);
		/* if configured as edge, then will be changed to do_edge_IRQ */
		set_irq_handler(irq, do_level_IRQ);
		set_irq_flags(irq, IRQF_VALID | IRQF_PROBE);
	}
#endif
	*pIMASK = 0;
	__builtin_bfin_csync();
	ilat = *pILAT;
	__builtin_bfin_csync();
	*pILAT = ilat;
	__builtin_bfin_csync();

	printk(KERN_INFO "Configuring Blackfin Priority Driven Interrupts\n");
	/* IMASK=xxx is equivalent to STI xx or irq_flags=xx,
	 * local_irq_enable()
	 */
	program_IAR();
	/* Therefore it's better to setup IARs before interrupts enabled */
	search_IAR();

	/* Enable interrupts IVG7-15 */
	*pIMASK = irq_flags = irq_flags | IMASK_IVG15 |
	    IMASK_IVG14 | IMASK_IVG13 | IMASK_IVG12 | IMASK_IVG11 |
	    IMASK_IVG10 | IMASK_IVG9 | IMASK_IVG8 | IMASK_IVG7 | IMASK_IVGHW;
	__builtin_bfin_csync();

	local_irq_enable();
	return 0;
}

extern asmlinkage void asm_do_IRQ(unsigned int irq, struct pt_regs *regs);
void do_irq(int vec, struct pt_regs *fp)
{
	if (vec == EVT_IVTMR_P) {
		vec = IRQ_CORETMR;
	} else {
		struct ivgx *ivg = ivg7_13[vec - IVG7].ifirst;
		struct ivgx *ivg_stop = ivg7_13[vec - IVG7].istop;
		unsigned long sic_status0, sic_status1;

		__builtin_bfin_ssync();
		sic_status0 = *pSICA_IMASK0 & *pSICA_ISR0;
		sic_status1 = *pSICA_IMASK1 & *pSICA_ISR1;

		for (;; ivg++) {
			if (ivg >= ivg_stop) {
				num_spurious++;
				return;
			} else if ((sic_status0 & ivg->isrflag0) ||
				   (sic_status1 & ivg->isrflag1))
				break;
		}
		vec = ivg->irqno;
	}
	asm_do_IRQ(vec, fp);
}
