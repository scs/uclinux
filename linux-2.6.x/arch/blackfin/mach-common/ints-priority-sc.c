/*
 * File:         arch/blackfin/mach-common/ints-priority-sc.c
 * Based on:
 * Author:
 *
 * Created:      ?
 * Description:  Set up the interupt priorities
 *
 * Rev:          $Id$
 *
 * Modified:
 *               1996 Roman Zippel
 *               1999 D. Jeff Dionne <jeff@uclinux.org>
 *               2000-2001 Lineo, Inc. D. Jefff Dionne <jeff@lineo.ca>
 *               2002 Arcturus Networks Inc. MaTed <mated@sympatico.ca>
 *               2003 Metrowerks/Motorola
 *               2003 Bas Vermeulen <bas@buyways.nl>
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

#include <linux/module.h>
#include <linux/kernel_stat.h>
#include <linux/seq_file.h>
#include <asm/irqchip.h>
#include <asm/traps.h>
#include <asm/blackfin.h>

#if (defined(CONFIG_BF537) || defined(CONFIG_BF536) || defined(CONFIG_BF534))
# define BF537_GENERIC_ERROR_INT_DEMUX
#else
# undef BF537_GENERIC_ERROR_INT_DEMUX
#endif

/*
 * NOTES:
 * - we have separated the physical Hardware interrupt from the
 * levels that the LINUX kernel sees (see the description in irq.h)
 * -
 */

unsigned long irq_flags = 0;

/* The number of spurious interrupts */
unsigned int num_spurious;

struct ivgx {
	/* irq number for request_irq, available in mach-bf533/irq.h */
	int irqno;
	/* corresponding bit in the SIC_ISR register */
	int isrflag;
} ivg_table[NR_PERI_INTS];

struct ivg_slice {
	/* position of first irq in ivg_table for given ivg */
	struct ivgx *ifirst;
	struct ivgx *istop;
} ivg7_13[IVG13 - IVG7 + 1];

/* BASE LEVEL interrupt handler routines */
asmlinkage void evt_emulation(void);
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

		ivg7_13[ivg].istop = ivg7_13[ivg].ifirst =
		    &ivg_table[irq_pos];

		for (irqn = 0; irqn < NR_PERI_INTS; irqn++) {
			int iar_shift = (irqn & 7) * 4;
			if (ivg ==
			    (0xf &
			     bfin_read32((unsigned long *) SIC_IAR0 +
					 (irqn >> 3)) >> iar_shift)) {
				ivg_table[irq_pos].irqno = IVG7 + irqn;
				ivg_table[irq_pos].isrflag = 1 << irqn;
				ivg7_13[ivg].istop++;
				irq_pos++;
			}
		}
	}
}

/*
 * This is for BF533 internal IRQs
 */

static void ack_noop(unsigned int irq)
{
	/* Dummy function.  */
}

static void bf533_core_mask_irq(unsigned int irq)
{
	irq_flags &= ~(1 << irq);
	if (!irqs_disabled())
		local_irq_enable();
}

static void bf533_core_unmask_irq(unsigned int irq)
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

static void bf533_internal_mask_irq(unsigned int irq)
{
	bfin_write_SIC_IMASK(bfin_read_SIC_IMASK() &
			     ~(1 << (irq - (IRQ_CORETMR + 1))));
	__builtin_bfin_ssync();
}

static void bf533_internal_unmask_irq(unsigned int irq)
{
	bfin_write_SIC_IMASK(bfin_read_SIC_IMASK() |
			     (1 << (irq - (IRQ_CORETMR + 1))));
	__builtin_bfin_ssync();
}

static struct irqchip bf533_core_irqchip = {
	.ack = ack_noop,
	.mask = bf533_core_mask_irq,
	.unmask = bf533_core_unmask_irq,
};

static struct irqchip bf533_internal_irqchip = {
	.ack = ack_noop,
	.mask = bf533_internal_mask_irq,
	.unmask = bf533_internal_unmask_irq,
};

#ifdef BF537_GENERIC_ERROR_INT_DEMUX
static int error_int_mask;

static void bf537_generic_error_ack_irq(unsigned int irq)
{

}

static void bf537_generic_error_mask_irq(unsigned int irq)
{
	error_int_mask &= ~(1L << (irq - IRQ_PPI_ERROR));

	if (!error_int_mask) {
		local_irq_disable();
		bfin_write_SIC_IMASK(bfin_read_SIC_IMASK() &
				     ~(1 <<
				       (IRQ_GENERIC_ERROR -
					(IRQ_CORETMR + 1))));
		__builtin_bfin_ssync();
		local_irq_enable();
	}
}

static void bf537_generic_error_unmask_irq(unsigned int irq)
{
	local_irq_disable();
	bfin_write_SIC_IMASK(bfin_read_SIC_IMASK() | 1 <<
			     (IRQ_GENERIC_ERROR - (IRQ_CORETMR + 1)));
	__builtin_bfin_ssync();
	local_irq_enable();

	error_int_mask |= 1L << (irq - IRQ_PPI_ERROR);
}

static struct irqchip bf537_generic_error_irqchip = {
	.ack = bf537_generic_error_ack_irq,
	.mask = bf537_generic_error_mask_irq,
	.unmask = bf537_generic_error_unmask_irq,
};

static void bf537_demux_error_irq(unsigned int int_err_irq,
				  struct irqdesc *intb_desc,
				  struct pt_regs *regs)
{
	int irq = 0;

	__builtin_bfin_ssync();

#if (defined(CONFIG_BF537) || defined(CONFIG_BF536))
	if (bfin_read_EMAC_SYSTAT() & EMAC_ERR_MASK)
		irq = IRQ_MAC_ERROR;
	else
#endif
	if (bfin_read_SPORT0_STAT() & SPORT_ERR_MASK)
		irq = IRQ_SPORT0_ERROR;
	else if (bfin_read_SPORT1_STAT() & SPORT_ERR_MASK)
		irq = IRQ_SPORT1_ERROR;
	else if (bfin_read_PPI_STATUS() & PPI_ERR_MASK)
		irq = IRQ_PPI_ERROR;
	else if (bfin_read_CAN_GIF() & CAN_ERR_MASK)
		irq = IRQ_CAN_ERROR;
	else if (bfin_read_SPI_STAT() & SPI_ERR_MASK)
		irq = IRQ_SPI_ERROR;
	else if ((bfin_read_UART0_IIR() & UART_ERR_MASK_STAT1) &&
		 (bfin_read_UART0_IIR() & UART_ERR_MASK_STAT0))
		irq = IRQ_UART0_ERROR;
	else if ((bfin_read_UART1_IIR() & UART_ERR_MASK_STAT1) &&
		 (bfin_read_UART1_IIR() & UART_ERR_MASK_STAT0))
		irq = IRQ_UART1_ERROR;

	if (irq) {
		if (error_int_mask & (1L << (irq - IRQ_PPI_ERROR))) {
			struct irqdesc *desc = irq_desc + irq;
			desc->handle(irq, desc, regs);
		} else {

			switch (irq) {
			case IRQ_PPI_ERROR:
				bfin_write_PPI_STATUS(PPI_ERR_MASK);
				break;
#if (defined(CONFIG_BF537) || defined(CONFIG_BF536))
			case IRQ_MAC_ERROR:
				bfin_write_EMAC_SYSTAT(EMAC_ERR_MASK);
				break;
#endif
			case IRQ_SPORT0_ERROR:
				bfin_write_SPORT0_STAT(SPORT_ERR_MASK);
				break;

			case IRQ_SPORT1_ERROR:
				bfin_write_SPORT1_STAT(SPORT_ERR_MASK);
				break;

			case IRQ_CAN_ERROR:
				bfin_write_CAN_GIS(CAN_ERR_MASK);
				break;

			case IRQ_SPI_ERROR:
				bfin_write_SPI_STAT(SPI_ERR_MASK);
				break;

			default:
				break;
			}

			pr_debug("IRQ %d:"
				" MASKED PERIPHERAL ERROR INTERRUPT ASSERTED\n",
				irq);
		}
	} else
		printk(KERN_ERR
		       "%s : %s : LINE %d :\nIRQ ?: PERIPHERAL ERROR"
		       " INTERRUPT ASSERTED BUT NO SOURCE FOUND\n",
		       __FUNCTION__, __FILE__, __LINE__);


}
#endif				/* BF537_GENERIC_ERROR_INT_DEMUX */

#ifdef CONFIG_IRQCHIP_DEMUX_GPIO

# if defined(CONFIG_BF534)||defined(CONFIG_BF536)||defined(CONFIG_BF537)
static int gpiof_enabled;
static int gpiof_edge_triggered;
static int gpiog_enabled;
static int gpiog_edge_triggered;
static int gpioh_enabled;
static int gpioh_edge_triggered;

static void bf534_gpio_ack_irq(unsigned int irq)
{
	int gpionr, mask;
	if (irq < IRQ_PG0) {
		gpionr = irq - IRQ_PF0;
		mask = (1L << gpionr);
		bfin_write_PORTFIO_CLEAR(mask);
	} else if (irq < IRQ_PH0) {
		gpionr = irq - IRQ_PG0;
		mask = (1L << gpionr);
		bfin_write_PORTGIO_CLEAR(mask);
	} else {
		gpionr = irq - IRQ_PH0;
		mask = (1L << gpionr);
		bfin_write_PORTHIO_CLEAR(mask);
	}
	__builtin_bfin_ssync();
}

static void bf534_gpio_mask_irq(unsigned int irq)
{
	int gpionr, mask;
	/* NOTE: At preset for PORTF we will use MASKA
	 **      for PORTG we will use MASKB and for PORTH ??
	 */
	if (irq < IRQ_PG0) {
		gpionr = irq - IRQ_PF0;
		mask = (1L << gpionr);
		bfin_write_PORTFIO_CLEAR(mask);
		__builtin_bfin_ssync();
		bfin_write_PORTFIO_MASKA_CLEAR(mask);
	} else if (irq < IRQ_PH0) {
		gpionr = irq - IRQ_PG0;
		mask = (1L << gpionr);
		bfin_write_PORTGIO_CLEAR(mask);
		__builtin_bfin_ssync();
		bfin_write_PORTGIO_MASKB_CLEAR(mask);
	} else {
		gpionr = irq - IRQ_PH0;
		mask = (1L << gpionr);
		bfin_write_PORTHIO_CLEAR(mask);
		__builtin_bfin_ssync();
		/*bfin_write_PORTHIO_MASKA_CLEAR(mask);*/
		/*bfin_write_PORTHIO_MASKB_CLEAR(mask);*/
	}
	__builtin_bfin_ssync();
}

static void bf534_gpio_unmask_irq(unsigned int irq)
{
	int gpionr, mask;
	/* NOTE: At preset for PORTF we will use MASKA
	 **      for PORTG we will use MASKB and for PORTH ??
	 */
	if (irq < IRQ_PG0) {
		gpionr = irq - IRQ_PF0;
		mask = (1L << gpionr);
		bfin_write_PORTFIO_MASKA_SET(mask);
	} else if (irq < IRQ_PH0) {
		gpionr = irq - IRQ_PG0;
		mask = (1L << gpionr);
		bfin_write_PORTGIO_MASKB_SET(mask);
	} else {
		gpionr = irq - IRQ_PH0;
		mask = (1L << gpionr);
		/*bfin_write_PORTHIO_MASKA_SET(mask);*/
		/*bfin_write_PORTHIO_MASKB_SET(mask);*/
	}
	__builtin_bfin_ssync();
}

static int bf534_gpio_irq_type(unsigned int irq, unsigned int type)
{
	int gpionr, mask;
	/* NOTE: At preset for PORTF we will use MASKA
	 **      for PORTG we will use MASKB and for PORTH ??
	 */
	if (irq < IRQ_PG0) {
		gpionr = irq - IRQ_PF0;
		mask = (1L << gpionr);
		bfin_write_PORTFIO_DIR(bfin_read_PORTFIO_DIR() & ~mask);
		__builtin_bfin_ssync();
		bfin_write_PORTFIO_INEN(bfin_read_PORTFIO_INEN() | mask);
		__builtin_bfin_ssync();

		if (type == IRQT_PROBE) {
			/* only probe unenabled GPIO interrupt lines */
			if (gpiof_enabled & mask)
				return 0;
			type = __IRQT_RISEDGE | __IRQT_FALEDGE;
		}
		if (type & (__IRQT_RISEDGE | __IRQT_FALEDGE |
			    __IRQT_HIGHLVL | __IRQT_LOWLVL))
			gpiof_enabled |= mask;
		else
			gpiof_enabled &= ~mask;

		if (type & (__IRQT_RISEDGE | __IRQT_FALEDGE)) {
			gpiof_edge_triggered |= mask;
			bfin_write_PORTFIO_EDGE(bfin_read_PORTFIO_EDGE() |
						mask);
		} else {
			bfin_write_PORTFIO_EDGE(bfin_read_PORTFIO_EDGE() &
						~mask);
			gpiof_edge_triggered &= ~mask;
		}
		__builtin_bfin_ssync();

		if ((type & (__IRQT_RISEDGE | __IRQT_FALEDGE))
		    == (__IRQT_RISEDGE | __IRQT_FALEDGE))
			bfin_write_PORTFIO_BOTH(bfin_read_PORTFIO_BOTH() |
						mask);
		else
			bfin_write_PORTFIO_BOTH(bfin_read_PORTFIO_BOTH() &
						~mask);
		__builtin_bfin_ssync();

		if ((type & (__IRQT_FALEDGE | __IRQT_LOWLVL))
		    && ((type & (__IRQT_RISEDGE | __IRQT_FALEDGE))
			!= (__IRQT_RISEDGE | __IRQT_FALEDGE)))
			bfin_write_PORTFIO_POLAR(bfin_read_PORTFIO_POLAR() | mask);	/* low or falling edge denoted by one */
		else
			bfin_write_PORTFIO_POLAR(bfin_read_PORTFIO_POLAR() & ~mask);	/* high or rising edge denoted by zero */
	} else if (irq < IRQ_PH0) {
		gpionr = irq - IRQ_PG0;
		mask = (1L << gpionr);
		bfin_write_PORTGIO_DIR(bfin_read_PORTGIO_DIR() & ~mask);
		__builtin_bfin_ssync();
		bfin_write_PORTGIO_INEN(bfin_read_PORTGIO_INEN() | mask);
		__builtin_bfin_ssync();

		if (type == IRQT_PROBE) {
			/* only probe unenabled GPIO interrupt lines */
			if (gpiog_enabled & mask)
				return 0;
			type = __IRQT_RISEDGE | __IRQT_FALEDGE;
		}
		if (type & (__IRQT_RISEDGE | __IRQT_FALEDGE |
			    __IRQT_HIGHLVL | __IRQT_LOWLVL))
			gpiog_enabled |= mask;
		else
			gpiog_enabled &= ~mask;

		if (type & (__IRQT_RISEDGE | __IRQT_FALEDGE)) {
			gpiog_edge_triggered |= mask;
			bfin_write_PORTGIO_EDGE(bfin_read_PORTGIO_EDGE() |
						mask);
		} else {
			bfin_write_PORTGIO_EDGE(bfin_read_PORTGIO_EDGE() &
						~mask);
			gpiog_edge_triggered &= ~mask;
		}
		__builtin_bfin_ssync();

		if ((type & (__IRQT_RISEDGE | __IRQT_FALEDGE))
		    == (__IRQT_RISEDGE | __IRQT_FALEDGE))
			bfin_write_PORTGIO_BOTH(bfin_read_PORTGIO_BOTH() |
						mask);
		else
			bfin_write_PORTGIO_BOTH(bfin_read_PORTGIO_BOTH() &
						~mask);
		__builtin_bfin_ssync();

		if ((type & (__IRQT_FALEDGE | __IRQT_LOWLVL))
		    && ((type & (__IRQT_RISEDGE | __IRQT_FALEDGE))
			!= (__IRQT_RISEDGE | __IRQT_FALEDGE)))
			bfin_write_PORTGIO_POLAR(bfin_read_PORTGIO_POLAR() | mask);	/* low or falling edge denoted by one */
		else
			bfin_write_PORTGIO_POLAR(bfin_read_PORTGIO_POLAR() & ~mask);	/* high or rising edge denoted by zero */
	} else {
		gpionr = irq - IRQ_PH0;
		mask = (1L << gpionr);
		bfin_write_PORTHIO_DIR(bfin_read_PORTHIO_DIR() & ~mask);
		__builtin_bfin_ssync();
		bfin_write_PORTHIO_INEN(bfin_read_PORTHIO_INEN() | mask);
		__builtin_bfin_ssync();

		if (type == IRQT_PROBE) {
			/* only probe unenabled GPIO interrupt lines */
			if (gpioh_enabled & mask)
				return 0;
			type = __IRQT_RISEDGE | __IRQT_FALEDGE;
		}
		if (type & (__IRQT_RISEDGE | __IRQT_FALEDGE |
			    __IRQT_HIGHLVL | __IRQT_LOWLVL))
			gpioh_enabled |= mask;
		else
			gpioh_enabled &= ~mask;

		if (type & (__IRQT_RISEDGE | __IRQT_FALEDGE)) {
			gpioh_edge_triggered |= mask;
			bfin_write_PORTHIO_EDGE(bfin_read_PORTHIO_EDGE() |
						mask);
		} else {
			bfin_write_PORTHIO_EDGE(bfin_read_PORTHIO_EDGE() &
						~mask);
			gpioh_edge_triggered &= ~mask;
		}
		__builtin_bfin_ssync();

		if ((type & (__IRQT_RISEDGE | __IRQT_FALEDGE))
		    == (__IRQT_RISEDGE | __IRQT_FALEDGE))
			bfin_write_PORTHIO_BOTH(bfin_read_PORTHIO_BOTH() |
						mask);
		else
			bfin_write_PORTHIO_BOTH(bfin_read_PORTHIO_BOTH() &
						~mask);
		__builtin_bfin_ssync();

		if ((type & (__IRQT_FALEDGE | __IRQT_LOWLVL))
		    && ((type & (__IRQT_RISEDGE | __IRQT_FALEDGE))
			!= (__IRQT_RISEDGE | __IRQT_FALEDGE)))
			bfin_write_PORTHIO_POLAR(bfin_read_PORTHIO_POLAR() | mask);	/* low or falling edge denoted by one */
		else
			bfin_write_PORTHIO_POLAR(bfin_read_PORTHIO_POLAR() & ~mask);	/* high or rising edge denoted by zero */
	}
	__builtin_bfin_ssync();

	if (type & (__IRQT_RISEDGE | __IRQT_FALEDGE))
		set_irq_handler(irq, do_edge_IRQ);
	else
		set_irq_handler(irq, do_level_IRQ);

	return 0;
}
static struct irqchip bf534_gpio_irqchip = {
	.ack = bf534_gpio_ack_irq,
	.mask = bf534_gpio_mask_irq,
	.unmask = bf534_gpio_unmask_irq,
	.type = bf534_gpio_irq_type
};

static void bf534_demux_gpio_irq(unsigned int intb_irq,
				 struct irqdesc *intb_desc,
				 struct pt_regs *regs)
{
	int loop;

	/* For PORT F */
	loop = 0;
	do {
		int irq = IRQ_PF0;
		int flag_d = bfin_read_PORTFIO();
		int mask =
		    flag_d & (gpiof_enabled &
			      bfin_read_PORTFIO_MASKA_CLEAR());
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

	/* For PORT G */
	loop = 0;
	do {
		int irq = IRQ_PG0;
		int flag_d = bfin_read_PORTGIO();
		int mask =
		    flag_d & (gpiog_enabled &
			      bfin_read_PORTGIO_MASKB_CLEAR());
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

	/* For PORT H */
	loop = 0;
	do {
		int irq = IRQ_PH0;
		int flag_d = bfin_read_PORTHIO();
		/*int mask = flag_d & (gpioh_enabled & bfin_read_PORTHIO_MASKA_CLEAR());*/
		int mask =
		    flag_d & (gpioh_enabled &
			      bfin_read_PORTHIO_MASKB_CLEAR());
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
#else
static int gpio_enabled;
static int gpio_edge_triggered;

static void bf533_gpio_ack_irq(unsigned int irq)
{
	int gpionr = irq - IRQ_PF0;
	int mask = (1L << gpionr);
	bfin_write_FIO_FLAG_C(mask);
/*	if (gpio_edge_triggered & mask) {
		* ack *
	} else {
		* ack and mask *
	}
*/
	__builtin_bfin_ssync();
}

static void bf533_gpio_mask_irq(unsigned int irq)
{
	int gpionr = irq - IRQ_PF0;
	int mask = (1L << gpionr);
	bfin_write_FIO_FLAG_C(mask);
	__builtin_bfin_ssync();
	bfin_write_FIO_MASKB_C(mask);
	__builtin_bfin_ssync();
}

static void bf533_gpio_unmask_irq(unsigned int irq)
{
	int gpionr = irq - IRQ_PF0;
	int mask = (1L << gpionr);
	bfin_write_FIO_MASKB_S(mask);
}

static int bf533_gpio_irq_type(unsigned int irq, unsigned int type)
{
	int gpionr = irq - IRQ_PF0;
	int mask = (1L << gpionr);

	bfin_write_FIO_DIR(bfin_read_FIO_DIR() & ~mask);
	__builtin_bfin_ssync();
	bfin_write_FIO_INEN(bfin_read_FIO_INEN() | mask);
	__builtin_bfin_ssync();

	if (type == IRQT_PROBE) {
		/* only probe unenabled GPIO interrupt lines */
		if (gpio_enabled & mask)
			return 0;
		type = __IRQT_RISEDGE | __IRQT_FALEDGE;
	}
	if (type & (__IRQT_RISEDGE | __IRQT_FALEDGE |
		    __IRQT_HIGHLVL | __IRQT_LOWLVL))
		gpio_enabled |= mask;
	else
		gpio_enabled &= ~mask;

	if (type & (__IRQT_RISEDGE | __IRQT_FALEDGE)) {
		gpio_edge_triggered |= mask;
		bfin_write_FIO_EDGE(bfin_read_FIO_EDGE() | mask);
	} else {
		bfin_write_FIO_EDGE(bfin_read_FIO_EDGE() & ~mask);
		gpio_edge_triggered &= ~mask;
	}
	__builtin_bfin_ssync();

	if ((type & (__IRQT_RISEDGE | __IRQT_FALEDGE))
	    == (__IRQT_RISEDGE | __IRQT_FALEDGE))
		bfin_write_FIO_BOTH(bfin_read_FIO_BOTH() | mask);
	else
		bfin_write_FIO_BOTH(bfin_read_FIO_BOTH() & ~mask);
	__builtin_bfin_ssync();

	if ((type & (__IRQT_FALEDGE | __IRQT_LOWLVL))
	    && ((type & (__IRQT_RISEDGE | __IRQT_FALEDGE))
		!= (__IRQT_RISEDGE | __IRQT_FALEDGE)))
		bfin_write_FIO_POLAR(bfin_read_FIO_POLAR() | mask);	/* low or falling edge denoted by one */
	else
		bfin_write_FIO_POLAR(bfin_read_FIO_POLAR() & ~mask);	/* high or rising edge denoted by zero */
	__builtin_bfin_ssync();

	if (type & (__IRQT_RISEDGE | __IRQT_FALEDGE))
		set_irq_handler(irq, do_edge_IRQ);
	else
		set_irq_handler(irq, do_level_IRQ);

	return 0;
}
static struct irqchip bf533_gpio_irqchip = {
	.ack = bf533_gpio_ack_irq,
	.mask = bf533_gpio_mask_irq,
	.unmask = bf533_gpio_unmask_irq,
	.type = bf533_gpio_irq_type
};

static void bf533_demux_gpio_irq(unsigned int intb_irq,
				 struct irqdesc *intb_desc,
				 struct pt_regs *regs)
{
	int loop = 0;

	do {
		int irq = IRQ_PF0;
		int flag_d = bfin_read_FIO_FLAG_D();
		int mask =
		    flag_d & (gpio_enabled & bfin_read_FIO_MASKB_C());
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
#endif
#endif				/* CONFIG_IRQCHIP_DEMUX_GPIO */

/*
 * This function should be called during kernel startup to initialize
 * the BFin IRQ handling routines.
 */
int __init init_arch_irq(void)
{
	int irq;
	unsigned long ilat = 0;
	/*  Disable all the peripheral intrs  - page 4-29 HW Ref manual */
	bfin_write_SIC_IMASK(SIC_UNMASK_ALL);
	__builtin_bfin_ssync();

	local_irq_disable();

#ifndef CONFIG_KGDB
	bfin_write_EVT0(evt_emulation);
#endif
	bfin_write_EVT2(evt_evt2);
	bfin_write_EVT3(trap);
	bfin_write_EVT5(evt_ivhw);
	bfin_write_EVT6(evt_timer);
	bfin_write_EVT7(evt_evt7);
	bfin_write_EVT8(evt_evt8);
	bfin_write_EVT9(evt_evt9);
	bfin_write_EVT10(evt_evt10);
	bfin_write_EVT11(evt_evt11);
	bfin_write_EVT12(evt_evt12);
	bfin_write_EVT13(evt_evt13);
	bfin_write_EVT14(evt14_softirq);
	bfin_write_EVT15(evt_system_call);
	__builtin_bfin_csync();

	for (irq = 0; irq < SYS_IRQS; irq++) {
		if (irq <= IRQ_CORETMR)
			set_irq_chip(irq, &bf533_core_irqchip);
		else
			set_irq_chip(irq, &bf533_internal_irqchip);
#ifdef BF537_GENERIC_ERROR_INT_DEMUX
		if (irq != IRQ_GENERIC_ERROR) {
#endif

#ifdef CONFIG_IRQCHIP_DEMUX_GPIO
# if defined(CONFIG_BF534)||defined(CONFIG_BF536)||defined(CONFIG_BF537)
			if ((irq != IRQ_PROG_INTA) &&
			    (irq != IRQ_PORTG_INTB) &&
			    (irq != IRQ_PROG_INTB)) {
#else
			if (irq != IRQ_PROG_INTB) {
#endif
#endif
				set_irq_handler(irq, do_simple_IRQ);
				set_irq_flags(irq, IRQF_VALID);
#ifdef CONFIG_IRQCHIP_DEMUX_GPIO
			} else {
# if defined(CONFIG_BF534)||defined(CONFIG_BF536)||defined(CONFIG_BF537)
				set_irq_chained_handler(irq,
							bf534_demux_gpio_irq);
#else
				set_irq_chained_handler(irq,
							bf533_demux_gpio_irq);
#endif
			}
#endif

#ifdef BF537_GENERIC_ERROR_INT_DEMUX
		} else {
			set_irq_handler(irq, bf537_demux_error_irq);
		}
#endif
	}
#ifdef BF537_GENERIC_ERROR_INT_DEMUX
	for (irq = IRQ_PPI_ERROR; irq <= IRQ_UART1_ERROR; irq++) {
		set_irq_chip(irq, &bf537_generic_error_irqchip);
		set_irq_handler(irq, do_level_IRQ);
		set_irq_flags(irq, IRQF_VALID);
	}
#endif

#ifdef CONFIG_IRQCHIP_DEMUX_GPIO
	for (irq = IRQ_PF0; irq < NR_IRQS; irq++) {
# if defined(CONFIG_BF534)||defined(CONFIG_BF536)||defined(CONFIG_BF537)
		set_irq_chip(irq, &bf534_gpio_irqchip);
#else
		set_irq_chip(irq, &bf533_gpio_irqchip);
#endif
		/* if configured as edge, then will be changed to do_edge_IRQ */
		set_irq_handler(irq, do_level_IRQ);
		set_irq_flags(irq, IRQF_VALID | IRQF_PROBE);
	}
#endif
	bfin_write_IMASK(0);
	__builtin_bfin_csync();
	ilat = bfin_read_ILAT();
	__builtin_bfin_csync();
	bfin_write_ILAT(ilat);
	__builtin_bfin_csync();

	printk(KERN_INFO
	       "Configuring Blackfin Priority Driven Interrupts\n");
	/* IMASK=xxx is equivalent to STI xx or irq_flags=xx,
	 * local_irq_enable()
	 */
	program_IAR();
	/* Therefore it's better to setup IARs before interrupts enabled */
	search_IAR();

	/* Enable interrupts IVG7-15 */
	irq_flags = irq_flags | IMASK_IVG15 |
	    IMASK_IVG14 | IMASK_IVG13 | IMASK_IVG12 | IMASK_IVG11 |
	    IMASK_IVG10 | IMASK_IVG9 | IMASK_IVG8 | IMASK_IVG7 |
	    IMASK_IVGHW;
	bfin_write_IMASK(irq_flags);
	__builtin_bfin_csync();

	local_irq_enable();
	return 0;
}

void do_irq(int vec, struct pt_regs *fp)
{
	if (vec == EVT_IVTMR_P) {
		vec = IRQ_CORETMR;
	} else {
		struct ivgx *ivg = ivg7_13[vec - IVG7].ifirst;
		struct ivgx *ivg_stop = ivg7_13[vec - IVG7].istop;
		unsigned long sic_status;

		__builtin_bfin_ssync();
		sic_status = bfin_read_SIC_IMASK() & bfin_read_SIC_ISR();

		for (;; ivg++) {
			if (ivg >= ivg_stop) {
				num_spurious++;
				return;
			} else if (sic_status & ivg->isrflag)
				break;
		}
		vec = ivg->irqno;
	}
	asm_do_IRQ(vec, fp);
}

void bfin_gpio_interrupt_setup(int irq, int irq_pfx, int type)
{

#ifdef CONFIG_IRQCHIP_DEMUX_GPIO
	printk(KERN_INFO
	       "Blackfin GPIO interrupt setup: DEMUX_GPIO irq %d\n", irq);
	set_irq_type(irq_pfx, type);
#else
# if defined(CONFIG_BF534)||defined(CONFIG_BF536)||defined(CONFIG_BF537)
	unsigned short portx_fer;
# endif
	unsigned short flag;
	unsigned short FIO_PATTERN;

	if (irq_pfx < IRQ_PF0 || irq_pfx > (NR_IRQS - 1)) {
		printk(KERN_ERR "irq_pfx out of range: %d\n", irq_pfx);
		return;
	}

	flag = irq_pfx - IRQ_PF0;
	FIO_PATTERN = (1 << flag);

#if defined(CONFIG_BF534)||defined(CONFIG_BF536)||defined(CONFIG_BF537)
	portx_fer = bfin_read_PORT_FER();
	bfin_write_PORT_FER(portx_fer & ~FIO_PATTERN);
	__builtin_bfin_ssync();
#endif

	printk(KERN_INFO
	       "Blackfin GPIO interrupt setup: flag PF%d, irq %d\n", flag,
	       irq);

	if (irq == IRQ_PROG_INTA || irq == IRQ_PROG_INTB) {
		int ixab =
		    (irq -
		     IRQ_PROG_INTA) * ((unsigned short *) FIO_MASKB_D -
				       (unsigned short *) FIO_MASKA_D);

		__builtin_bfin_ssync();
		bfin_write16((unsigned short *) FIO_MASKA_C + ixab, FIO_PATTERN);	/* disable int */
		__builtin_bfin_ssync();

		if (type == IRQT_HIGH || type == IRQT_RISING)
			bfin_write_FIO_POLAR(bfin_read_FIO_POLAR() & ~FIO_PATTERN);	/* active high */
		else
			bfin_write_FIO_POLAR(bfin_read_FIO_POLAR() | FIO_PATTERN);	/* active low  */

		if (type == IRQT_HIGH || type == IRQT_LOW)
			bfin_write_FIO_EDGE(bfin_read_FIO_EDGE() & ~FIO_PATTERN);	/* by level (input) */
		else
			bfin_write_FIO_EDGE(bfin_read_FIO_EDGE() | FIO_PATTERN);	/* by edge */

		if (type == IRQT_BOTHEDGE)
			bfin_write_FIO_BOTH(bfin_read_FIO_BOTH() |
					    FIO_PATTERN);
		else
			bfin_write_FIO_BOTH(bfin_read_FIO_BOTH() &
					    ~FIO_PATTERN);

		bfin_write_FIO_DIR(bfin_read_FIO_DIR() & ~FIO_PATTERN);	/* input */
		bfin_write_FIO_FLAG_C(FIO_PATTERN);	/* clear output */
		bfin_write_FIO_INEN(bfin_read_FIO_INEN() | FIO_PATTERN);	/* enable pin */

		__builtin_bfin_ssync();
		bfin_write16((unsigned short *) FIO_MASKA_S + ixab, FIO_PATTERN);	/* enable int */
	}
#endif				/*CONFIG_IRQCHIP_DEMUX_GPIO */

}

EXPORT_SYMBOL(bfin_gpio_interrupt_setup);
