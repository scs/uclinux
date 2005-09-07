/*
 * $Id$ 
 *
 *arch/bfinnommu/mach-common/ints-priority.c
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file COPYING in the main directory of this archive
 * for more details.
 *
 * Sep 2003, Changed to support BlackFin BF533.
 *
 * June 2004, Support for Priority based Interrupt handling for Blackfin 
 *		by LG Soft India.
 *
 * Copyright 1996 Roman Zippel
 * Copyright 1999 D. Jeff Dionne <jeff@uclinux.org>
 * Copyright 2000-2001 Lineo, Inc. D. Jefff Dionne <jeff@lineo.ca>
 * Copyright 2002 Arcturus Networks Inc. MaTed <mated@sympatico.ca>
 * Copyright 2003 Metrowerks/Motorola
 * Copyright 2003 Bas Vermeulen <bas@buyways.nl>,
 *                BuyWays B.V. (www.buyways.nl)
 * Copyright 2004 LG Soft India 
 */

#include <linux/module.h>
#include <linux/kernel_stat.h>
#include <linux/seq_file.h>
#include <asm/irqchip.h>
#include <asm/traps.h>
#include <asm/blackfin.h>

#if (defined(CONFIG_BF537) || defined(CONFIG_BF536) || defined(CONFIG_BF534))
  #define BF537_GENERIC_ERROR_INT_DEMUX
#else
  #undef BF537_GENERIC_ERROR_INT_DEMUX
#endif

/********************************************************************
 * NOTES:
 * - we have separated the physical Hardware interrupt from the
 * levels that the LINUX kernel sees (see the description in irq.h)
 * - 
 ********************************************************************/

volatile unsigned long irq_flags = 0;

/* The number of spurious interrupts */
volatile unsigned int num_spurious;

struct ivgx	{
	int irqno;	/*irq number for request_irq, available in mach-bf533/irq.h*/
	int isrflag;	/*corresponding bit in the SIC_ISR register*/
}ivg_table[NR_PERI_INTS];

struct ivg_slice {
	struct ivgx *ifirst; /* position of first irq in ivg_table for given ivg */
	struct ivgx *istop;  
} ivg7_13[IVG13-IVG7+1];


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

/* Search SIC_IAR and fill tables with the irqvalues 
and their positions in the SIC_ISR register */

static void __init search_IAR(void)	
{
    unsigned ivg, irq_pos = 0;
    for (ivg = 0; ivg <= IVG13-IVG7; ivg++)
    {
        int irqn;

        ivg7_13[ivg].istop = 
        ivg7_13[ivg].ifirst = &ivg_table[irq_pos];        
          
        for(irqn = 0; irqn < NR_PERI_INTS; irqn++)
          if (ivg == (0x0f & pSIC_IAR0[irqn >> 3] >> (irqn & 7) * 4))
          {
             ivg_table[irq_pos].irqno = IVG7 + irqn;
			 ivg_table[irq_pos].isrflag = 1 << irqn;
             ivg7_13[ivg].istop++;
             irq_pos++;
          }
    }
}
			
/*
 * This is for BF533 internal IRQs
 */

static void bf533_core_mask_irq(unsigned int irq)
{
	local_irq_disable();
	irq_flags &= ~(1<<irq);
	local_irq_enable();
}

static void bf533_core_unmask_irq(unsigned int irq)
{
	/* enable the interrupt */
	local_irq_disable();
	irq_flags |= 1<<irq;
	local_irq_enable();
	return;
}

static void bf533_internal_mask_irq(unsigned int irq)
{
  //dummy function
}

static void bf533_internal_unmask_irq(unsigned int irq)
{
	unsigned long irq_mask;
	local_irq_disable();
	irq_mask = (1<<(irq - (IRQ_CORETMR+1)));
   	*pSIC_IMASK |= irq_mask;
	__builtin_bfin_ssync();
	local_irq_enable();
}

static struct irqchip bf533_core_irqchip = {
	.ack		= bf533_core_mask_irq,
	.mask		= bf533_core_mask_irq,
	.unmask		= bf533_core_unmask_irq,
};

static struct irqchip bf533_internal_irqchip = {
	.ack		= bf533_internal_mask_irq,
	.mask		= bf533_internal_mask_irq,
	.unmask		= bf533_internal_unmask_irq,
};

#ifdef BF537_GENERIC_ERROR_INT_DEMUX
static int error_int_mask;

static void bf537_generic_error_ack_irq(unsigned int irq)
{

}

static void bf537_generic_error_mask_irq(unsigned int irq)
{
	error_int_mask &= ~(1L << (irq - IRQ_PPI_ERROR));

	if(!error_int_mask) 
		{
			local_irq_disable();
		   	*pSIC_IMASK |= (1<<(IRQ_GENERIC_ERROR - (IRQ_CORETMR+1)));
			__builtin_bfin_ssync();
			local_irq_enable();		
		}
}

static void bf537_generic_error_unmask_irq(unsigned int irq)
{
	local_irq_disable();
	*pSIC_IMASK |= (1<<(IRQ_GENERIC_ERROR - (IRQ_CORETMR+1)));
	__builtin_bfin_ssync();
	local_irq_enable();

	error_int_mask |= (1L << (irq - IRQ_PPI_ERROR));
}


static struct irqchip bf537_generic_error_irqchip = {
	.ack		= bf537_generic_error_ack_irq,
	.mask		= bf537_generic_error_mask_irq,
	.unmask		= bf537_generic_error_unmask_irq,
};

static void bf537_demux_error_irq(unsigned int int_err_irq, struct irqdesc *intb_desc,
				 struct pt_regs *regs)
{
	int irq = 0;

	 __builtin_bfin_ssync();
	
#if (defined(CONFIG_BF537) || defined(CONFIG_BF536))
		if (*pEMAC_SYSTAT & EMAC_ERR_MASK) irq = IRQ_MAC_ERROR; else
#endif
		if (*pSPORT0_STAT & SPORT_ERR_MASK) irq = IRQ_SPORT0_ERROR; else
		if (*pSPORT1_STAT & SPORT_ERR_MASK) irq = IRQ_SPORT1_ERROR; else
		if (*pPPI_STATUS & PPI_ERR_MASK) irq = IRQ_PPI_ERROR; else
		if (*pCAN_GIF & CAN_ERR_MASK) irq = IRQ_CAN_ERROR; else	
		if (*pSPI_STAT & SPI_ERR_MASK) irq = IRQ_SPI_ERROR; else
		if ((*pUART0_IIR & UART_ERR_MASK_STAT1)  && (*pUART0_IIR & UART_ERR_MASK_STAT0)) irq = IRQ_UART0_ERROR; else	
		if ((*pUART1_IIR & UART_ERR_MASK_STAT1)  && (*pUART1_IIR & UART_ERR_MASK_STAT0)) irq = IRQ_UART1_ERROR;	

		if(irq)
		  {	
			  if(error_int_mask & (1L << (irq - IRQ_PPI_ERROR)))
				{
					struct irqdesc *desc = irq_desc + irq;
					desc->handle(irq, desc, regs);
				}
				  else 
				  	printk(KERN_ERR "%s : %s : LINE %d  : \nIRQ %d: MASKED PERIPHERAL ERROR INTERRUPT ASSERTED\n",
				  	  __FUNCTION__,__FILE__,__LINE__,irq);
		  }
			else
			  printk(KERN_ERR "%s : %s : LINE %d :\nIRQ ?: PERIPHERAL ERROR INTERRUPT ASSERTED BUT NO SOURCE FOUND\n",
			    __FUNCTION__,__FILE__,__LINE__);

}
#endif /* BF537_GENERIC_ERROR_INT_DEMUX */

#ifdef CONFIG_IRQCHIP_DEMUX_GPIO
static int gpio_enabled;
static int gpio_edge_triggered;

static void bf533_gpio_ack_irq(unsigned int irq)
{
	int gpionr = irq - IRQ_PF0;
	int mask = (1L << gpionr);
	*pFIO_FLAG_C = mask;
//	if (gpio_edge_triggered & mask) {
//		/* ack */
//	} else {
//		/* ack and mask */
//	}
	__builtin_bfin_ssync();
}

static void bf533_gpio_mask_irq(unsigned int irq)
{
	int gpionr = irq - IRQ_PF0;
	int mask = (1L << gpionr);
	*pFIO_FLAG_C = mask;
	__builtin_bfin_ssync();
	*pFIO_MASKB_C = mask;
	__builtin_bfin_ssync();
}

static void bf533_gpio_unmask_irq(unsigned int irq)
{
	int gpionr = irq - IRQ_PF0;
	int mask = (1L << gpionr);
	*pFIO_MASKB_S = mask;
}

static int bf533_gpio_irq_type(unsigned int irq, unsigned int type)
{
	int gpionr = irq - IRQ_PF0;
	int mask = (1L << gpionr);

	*pFIO_DIR &= ~mask;  __builtin_bfin_ssync();
	*pFIO_INEN |= mask;  __builtin_bfin_ssync();

	if (type == IRQT_PROBE) {
		/* only probe unenabled GPIO interrupt lines */
		if ( gpio_enabled & mask)
			return 0;
		type = __IRQT_RISEDGE | __IRQT_FALEDGE;
	}
	if (type & (__IRQT_RISEDGE|__IRQT_FALEDGE|__IRQT_HIGHLVL|__IRQT_LOWLVL))
		gpio_enabled |= mask;
	else
		gpio_enabled &= ~mask;

	if (type & (__IRQT_RISEDGE|__IRQT_FALEDGE)) {
		gpio_edge_triggered |= mask;
		*pFIO_EDGE |= mask;
	} else {
		*pFIO_EDGE &= ~mask;
		gpio_edge_triggered &= ~mask;
	}
	__builtin_bfin_ssync();

	if ((type & (__IRQT_RISEDGE|__IRQT_FALEDGE)) == (__IRQT_RISEDGE|__IRQT_FALEDGE))
		*pFIO_BOTH |= mask;
	else
		*pFIO_BOTH &= ~mask;
	__builtin_bfin_ssync();

	if ((type & (__IRQT_FALEDGE|__IRQT_LOWLVL)) && ((type & (__IRQT_RISEDGE|__IRQT_FALEDGE)) != (__IRQT_RISEDGE|__IRQT_FALEDGE)))
		*pFIO_POLAR |= mask;  /* low or falling edge denoted by one */
	else
		*pFIO_POLAR &= ~mask; /* high or rising edge denoted by zero */
	__builtin_bfin_ssync();

	if (type & (__IRQT_RISEDGE|__IRQT_FALEDGE))
		set_irq_handler(irq, do_edge_IRQ);
	else
		set_irq_handler(irq, do_level_IRQ);

	return 0;
}
static struct irqchip bf533_gpio_irqchip = {
	.ack		= bf533_gpio_ack_irq,
	.mask		= bf533_gpio_mask_irq,
	.unmask		= bf533_gpio_unmask_irq,
	.type           = bf533_gpio_irq_type
};

static void bf533_demux_gpio_irq(unsigned int intb_irq, struct irqdesc *intb_desc,
				 struct pt_regs *regs)
{
	int loop = 0;
	
	do {
		int irq = IRQ_PF0;
		int flag_d = *pFIO_FLAG_D;
		int mask = flag_d & (gpio_enabled & *pFIO_MASKB_C);
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
#endif /* CONFIG_IRQCHIP_DEMUX_GPIO */

/*
 * This function should be called during kernel startup to initialize
 * the BFin IRQ handling routines.
 */

extern void _deferred_ret_from_exception(void);

int __init  init_arch_irq(void)
{
	int irq;	
	unsigned long ilat = 0;
	/*  Disable all the peripheral intrs  - page 4-29 HW Ref manual */
	*pSIC_IMASK = SIC_UNMASK_ALL;
	__builtin_bfin_ssync();	
   
	local_irq_disable();
	
#ifndef CONFIG_KGDB	
	*pEVT0 = evt_nmi;
#endif
	*pEVT2  = evt_evt2;
	*pEVT3	= trap;
	*pEVT5 	= evt_ivhw;
	*pEVT6 	= evt_timer;
	*pEVT7 	= evt_evt7;
	*pEVT8	= evt_evt8;
	*pEVT9	= evt_evt9;
	*pEVT10	= evt_evt10;
	*pEVT11	= evt_evt11;
	*pEVT12	= evt_evt12;
	*pEVT13	= evt_evt13;
	*pEVT14 = _deferred_ret_from_exception;
	*pEVT15 = evt_system_call;
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
		if (irq != IRQ_PROG_INTB) {
#endif
			set_irq_handler(irq, do_level_IRQ);
			set_irq_flags(irq, IRQF_VALID);
#ifdef CONFIG_IRQCHIP_DEMUX_GPIO
		} else {
			set_irq_chained_handler(irq, bf533_demux_gpio_irq);
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



#ifdef BF537_GENERIC_ERROR_INT_DEMUX
  	for (irq = IRQ_PPI_ERROR; irq <= IRQ_UART1_ERROR; irq++) {
		set_irq_chip(irq, &bf537_generic_error_irqchip);
		set_irq_handler(irq, do_level_IRQ); 
		set_irq_flags(irq, IRQF_VALID);
	}
#endif


#ifdef CONFIG_IRQCHIP_DEMUX_GPIO
  	for (irq = IRQ_PF0; irq <= IRQ_PF15; irq++) {
		set_irq_chip(irq, &bf533_gpio_irqchip);
		set_irq_handler(irq, do_level_IRQ); /* if configured as edge, then will be changed to do_edge_IRQ */
		set_irq_flags(irq, IRQF_VALID|IRQF_PROBE);
	}
#endif
   	*pIMASK = 0;
	__builtin_bfin_csync();
	ilat  = *pILAT;
	__builtin_bfin_csync();
	*pILAT = ilat;
	__builtin_bfin_csync();

	printk(KERN_INFO "Configuring Blackfin Priority Driven Interrupts\n");
	program_IAR();   /* IMASK=xxx is equivalent to STI xx or irq_flags=xx, local_irq_enable() */
	search_IAR();    /* Therefore it's better to setup IARs before interrupts enabled */

   	/* Enable interrupts IVG7-15 */
	*pIMASK = irq_flags = irq_flags | IMASK_IVG15 | IMASK_IVG14 |IMASK_IVG13 |IMASK_IVG12 |IMASK_IVG11 |
		IMASK_IVG10 |IMASK_IVG9 |IMASK_IVG8 |IMASK_IVG7 |IMASK_IVGHW;	
	__builtin_bfin_csync();

	local_irq_enable();
	return 0;
}

extern asmlinkage void asm_do_IRQ(unsigned int irq, struct pt_regs *regs);
void do_irq(int vec, struct pt_regs *fp)
{

          struct ivgx *ivg = ivg7_13[vec-IVG7].ifirst;
          struct ivgx *ivg_stop = ivg7_13[vec-IVG7].istop;
	  unsigned long sic_status;	

	  __builtin_bfin_ssync();
 	  sic_status = *pSIC_IMASK & *pSIC_ISR;

	  for(;; ivg++) {
              if (ivg >= ivg_stop)  {
		num_spurious++;
                return;
              }
              else if (sic_status & ivg->isrflag)
                break;
         }
	  vec = ivg->irqno;

	asm_do_IRQ(vec, fp);
}
