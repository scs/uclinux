/*
 * arch/bfinnommu/mach-bf533/ints-priority.c
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

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/kernel_stat.h>
#include <linux/seq_file.h>
#include <asm/system.h>
#include <asm/irq.h>
#include <asm/traps.h>
#include <asm/io.h>
#include <asm/machdep.h>
#include <asm/setup.h>

#include <asm/errno.h>	/*ENXIO etc*/
#include <asm/blackfin.h>
/********************************************************************
 * NOTES:
 * - we have separated the physical Hardware interrupt from the
 * levels that the LINUX kernel sees (see the description in irq.h)
 * - 
 ********************************************************************/

#define INTERNAL_IRQS (32)

int irq_flags = 0;

struct ivgx	{

	int irqno;	/*irq number for request_irq, available in bf533_irq.h*/
	int isrpos;	/*corresponding position in the SIC_ISR register*/
}ivg7[7],ivg8[7],ivg9[7],ivg10[7],ivg11[7],ivg12[7],ivg13[7];

/*counters for the table*/
unsigned char ivg7_cnt=0,ivg8_cnt=0,ivg9_cnt=0,ivg10_cnt=0,ivg11_cnt=0,ivg12_cnt=0,ivg13_cnt=0;

/*********************
 * Prototypes
 ********************/
asmlinkage void bfin_irq_panic( int reason, struct pt_regs * reg);
extern void dump(struct pt_regs * regs);

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


void program_IAR(void);
void search_IAR(unsigned int sic_iarx);	
int getirq_number(struct ivgx *ivg);

/* irq node variables for the 32 (potential) on chip sources */
static irq_node_t int_irq_list[INTERNAL_IRQS];

/*********
 * bfin_irq_panic
 * - calls panic with string setup
 *********/
asmlinkage void bfin_irq_panic( int reason, struct pt_regs * regs)
{
	
  	printk("\n\nException: IRQ 0x%x entered\n", reason);
	printk(" code=[0x%08x],  ", (unsigned int)regs->seqstat & 0x3f);
	printk(" stack frame=0x%04x,  ",(unsigned int)(unsigned long) regs);
	printk(" bad PC=0x%04x\n", (unsigned int)regs->pc);
	dump(regs);
	panic("Unhandled IRQ or exceptions!\n");
}

/*Program the IAR registers*/
void program_IAR()
{
		unsigned long val=0;
		/* Program the IAR0 Register with the configured priority */

		if (CONFIG_DEF_UART_ERROR != CONFIG_UART_ERROR)	{
			val = ((CONFIG_UART_ERROR-7) << UART_ERROR_POS);
			*pSIC_IAR0 &= UART_ERROR_BIT;
			asm("ssync;");	
			*pSIC_IAR0 |= val;
			asm("ssync;");	
			}
		
		if (CONFIG_DEF_SPORT0_ERROR != CONFIG_SPORT0_ERROR)	{	
			val = ((CONFIG_SPORT0_ERROR-7) << SPORT0_ERROR_POS);
			*pSIC_IAR0 &= SPORT0_ERROR_BIT;
			asm("ssync;");	
			*pSIC_IAR0 |= val;
			asm("ssync;");	
			}
		
		if (CONFIG_DEF_SPI_ERROR != CONFIG_SPI_ERROR)	{	
			val = ((CONFIG_SPI_ERROR-7) << SPI_ERROR_POS);
			*pSIC_IAR0 &= SPI_ERROR_BIT;
			asm("ssync;");	
			*pSIC_IAR0 |= val;
			asm("ssync;");	
			}

		if (CONFIG_DEF_SPORT1_ERROR != CONFIG_SPORT1_ERROR)	{	
			val = ((CONFIG_SPORT1_ERROR-7) << SPORT1_ERROR_POS);
			*pSIC_IAR0 &= SPORT1_ERROR_BIT;
			asm("ssync;");	
			*pSIC_IAR0 |= val;
			asm("ssync;");	
			}

		if (CONFIG_DEF_PPI_ERROR != CONFIG_PPI_ERROR)	{	
			val = ((CONFIG_PPI_ERROR-7) << PPI_ERROR_POS);
			*pSIC_IAR0 &= PPI_ERROR_BIT;
			asm("ssync;");	
			*pSIC_IAR0 |= val;
			asm("ssync;");	
			}

		if (CONFIG_DEF_DMA_ERROR != CONFIG_DMA_ERROR)	{	
			val = ((CONFIG_DMA_ERROR-7) << DMA_ERROR_POS);
			*pSIC_IAR0 &= DMA_ERROR_BIT;
			asm("ssync;");	
			*pSIC_IAR0 |= val;
			asm("ssync;");	
			}

		if (CONFIG_DEF_PLLWAKE_ERROR != CONFIG_PLLWAKE_ERROR)	{	
			val = ((CONFIG_PLLWAKE_ERROR-7) << PLLWAKE_ERROR_POS);
			*pSIC_IAR0 &= PLLWAKE_ERROR_BIT;
			asm("ssync;");	
			*pSIC_IAR0 |= val;
			asm("ssync;");	
			}

		if (CONFIG_DEF_RTC_ERROR != CONFIG_RTC_ERROR)	{	
			val = ((CONFIG_RTC_ERROR-7) << RTC_ERROR_POS);
			*pSIC_IAR0 &= RTC_ERROR_BIT;
			asm("ssync;");	
			*pSIC_IAR0 |= val;
			asm("ssync;");	
			}
				
		/* Program the IAR1 Register with the configured priority */
		
		if (CONFIG_DEF_DMA0_PPI != CONFIG_DMA0_PPI)	{	
			val = ((CONFIG_DMA0_PPI-7) << DMA0_PPI_POS);
			*pSIC_IAR1 &= DMA0_PPI_BIT;
			asm("ssync;");	
			*pSIC_IAR1 |= val;
			asm("ssync;");	
			}

		if (CONFIG_DEF_DMA1_SPORT0RX != CONFIG_DMA1_SPORT0RX)	{	
			val = ((CONFIG_DMA1_SPORT0RX-7) << DMA1_SPORT0RX_POS);
			*pSIC_IAR1 &= DMA1_SPORT0RX_BIT;
			asm("ssync;");	
			*pSIC_IAR1 |= val;
			asm("ssync;");	
			}
		
		if (CONFIG_DEF_DMA2_SPORT0TX != CONFIG_DMA2_SPORT0TX)	{	
			val = ((CONFIG_DMA2_SPORT0TX-7) << DMA2_SPORT0TX_POS);
			*pSIC_IAR1 &= DMA2_SPORT0TX_BIT;
			asm("ssync;");	
			*pSIC_IAR1 |= val;
			asm("ssync;");	
			}

		if (CONFIG_DEF_DMA3_SPORT1RX != CONFIG_DMA3_SPORT1RX)	{	
			val = ((CONFIG_DMA3_SPORT1RX-7) << DMA3_SPORT1RX_POS);
			*pSIC_IAR1 &= DMA3_SPORT1RX_BIT;
			asm("ssync;");	
			*pSIC_IAR1 |= val;
			asm("ssync;");	
			}

		if (CONFIG_DEF_DMA4_SPORT1TX != CONFIG_DMA4_SPORT1TX)	{	
			val = ((CONFIG_DMA4_SPORT1TX-7) << DMA4_SPORT1TX_POS);
			*pSIC_IAR1 &= DMA4_SPORT1TX_BIT;
			asm("ssync;");	
			*pSIC_IAR1 |= val;
			asm("ssync;");	
			}

		if (CONFIG_DEF_DMA5_SPI != CONFIG_DMA5_SPI)	{	
			val = ((CONFIG_DMA5_SPI-7) << DMA5_SPI_POS);
			*pSIC_IAR1 &= DMA5_SPI_BIT;
			asm("ssync;");	
			*pSIC_IAR1 |= val;
			asm("ssync;");	
			}

		if (CONFIG_DEF_DMA6_UARTRX != CONFIG_DMA6_UARTRX)	{
			val = ((CONFIG_DMA6_UARTRX-7) << DMA6_UARTRX_POS);
			*pSIC_IAR1 &= DMA6_UARTRX_BIT;
			asm("ssync;");	
			*pSIC_IAR1 |= val;
			asm("ssync;");	
			}

		if (CONFIG_DEF_DMA7_UARTTX != CONFIG_DMA7_UARTTX)	{	
			val = ((CONFIG_DMA7_UARTTX-7) << DMA7_UARTTX_POS);
			*pSIC_IAR1 &= DMA7_UARTTX_BIT;
			asm("ssync;");	
			*pSIC_IAR1 |= val;
			asm("ssync;");	
			}

		/* Program the IAR2 Register with the configured priority */

		if (CONFIG_DEF_TIMER0 != CONFIG_TIMER0)	{	
			val = ((CONFIG_TIMER0-7) << TIMER0_POS);
			*pSIC_IAR2 &= TIMER0_BIT;
			asm("ssync;");	
			*pSIC_IAR2 |= val;
			asm("ssync;");	
			}

		if (CONFIG_DEF_TIMER1 != CONFIG_TIMER1)	{	
			val = ((CONFIG_TIMER1-7) << TIMER1_POS);
			*pSIC_IAR2 &= TIMER1_BIT;
			asm("ssync;");	
			*pSIC_IAR2 |= val;
			asm("ssync;");	
			}

		if (CONFIG_DEF_TIMER2 != CONFIG_TIMER2)	{	
			val = ((CONFIG_TIMER2-7) << TIMER2_POS);
			*pSIC_IAR2 &= TIMER2_BIT;
			asm("ssync;");	
			*pSIC_IAR2 |= val;
			asm("ssync;");	
			}

		if (CONFIG_DEF_PFA != CONFIG_PFA)	{	
			val = ((CONFIG_PFA-7) << PFA_POS);
			*pSIC_IAR2 &= PFA_BIT;
			asm("ssync;");	
			*pSIC_IAR2 |= val;
			asm("ssync;");	
			}

		if (CONFIG_DEF_PFB != CONFIG_PFB)	{	
			val = ((CONFIG_PFB-7) << PFB_POS);
			*pSIC_IAR2 &= PFB_BIT;
			asm("ssync;");	
			*pSIC_IAR2 |= val;
			asm("ssync;");	
			}

		if (CONFIG_DEF_MEMDMA0 != CONFIG_MEMDMA0)	{	
			val = ((CONFIG_MEMDMA0-7) << MEMDMA0_POS);
			*pSIC_IAR2 &= MEMDMA0_BIT;
			asm("ssync;");	
			*pSIC_IAR2 |= val;
			asm("ssync;");	
			}

		if (CONFIG_DEF_MEMDMA1 != CONFIG_MEMDMA1)	{	
			val = ((CONFIG_MEMDMA1-7) << MEMDMA1_POS);
			*pSIC_IAR2 &= MEMDMA1_BIT;
			asm("ssync;");	
			*pSIC_IAR2 |= val;
			asm("ssync;");	
			}
		
		if (CONFIG_DEF_WDTIMER != CONFIG_WDTIMER)	{	
			val = ((CONFIG_WDTIMER-7) << WDTIMER_POS);
			*pSIC_IAR2 &= WDTIMER_BIT;
			asm("ssync;");	
			*pSIC_IAR2 |= val;
			asm("ssync;");	
			}

}	/*End of program_IAR*/

/* Search SIC_IAR and fill tables with the irqvalues 
and their positions in the SIC_ISR register -Nidhi */

void search_IAR(unsigned int sic_iarx)	
{
	unsigned int irqval = 0,val = 0;
	int i;

	if (sic_iarx==0)	{
		val= *pSIC_IAR0 & 0xf;
		asm("ssync;");	
		irqval = 7;
	}	
	else if (sic_iarx==1)	{
		val= *pSIC_IAR1 & 0xf;
		asm("ssync;");	
		irqval = 15;
	}
	else if (sic_iarx==2)	{
		val= *pSIC_IAR2 & 0xf;
		asm("ssync;");	
		irqval = 23;
	}

	for(i=0;i<8;i++)	{	/*8 nibbles in the SIC_ISR register*/
		if(i!=0)	{
			if (sic_iarx==0)	val = ((*pSIC_IAR0) >> (i*4)) & 0xf;
			if (sic_iarx==1)	val = ((*pSIC_IAR1) >> (i*4)) & 0xf;
			if (sic_iarx==2)	val = ((*pSIC_IAR2) >> (i*4)) & 0xf;
		}

		/* check value in nibble and find which priority it is */
		switch(val)	{
			case 0:		/* interrupt will be routed to Ivg7 table */
				ivg7[ivg7_cnt].irqno=irqval;	/* irqval for request_irq */		
				ivg7[ivg7_cnt].isrpos=irqval-7;	/* pos in SIC_ISR to check if 
									interrupt occurred*/ 
				ivg7_cnt++;	
				break;		
					
			case 1:
				ivg8[ivg8_cnt].irqno=irqval;		
				ivg8[ivg8_cnt].isrpos=irqval-7;
				ivg8_cnt++;	
				break;		
	
			case 2:
				ivg9[ivg9_cnt].irqno=irqval;		
				ivg9[ivg9_cnt].isrpos=irqval-7;

				ivg9_cnt++;	
				break;		
			case 3:
				ivg10[ivg10_cnt].irqno=irqval;		
				ivg10[ivg10_cnt].isrpos=irqval-7;
				
				ivg10_cnt++;	
				break;		
			case 4:
				ivg11[ivg11_cnt].irqno=irqval;		
				ivg11[ivg11_cnt].isrpos=irqval-7;

				ivg11_cnt++;	
				break;		
			case 5:
				ivg12[ivg12_cnt].irqno=irqval;		
				ivg12[ivg12_cnt].isrpos=irqval-7;
				ivg12_cnt++;	
				break;		
			case 6:
				ivg13[ivg13_cnt].irqno=irqval;		
				ivg13[ivg13_cnt].isrpos=irqval-7;
				ivg13_cnt++;	
				break;
			}	/*All nibles in SIC_IAR0 searched and all tables configured with
				  respective interrupts*/		
		irqval++;
		}		/*End of for*/
}		
			
/*
 * This function should be called during kernel startup to initialize
 * the BFin IRQ handling routines.
 */

int  bfin_init_IRQ(void)
{

	int i;	
	unsigned long ilat = 0;
	/*  Disable all the peripheral intrs  - page 4-29 HW Ref manual */
	*pSIC_IMASK = SIC_UNMASK_ALL;
	asm("ssync;");	
   
	local_irq_disable();
	
#ifndef CONFIG_KGDB	
	*pEVT0 = evt_nmi;
	asm("csync;");	
#endif
	*pEVT2  = evt_evt2;
	asm("csync;");	
	*pEVT3	= trap;
	asm("csync;");	
	*pEVT5 	= evt_ivhw;
	asm("csync;");	
	*pEVT6 	= evt_timer;	 
	asm("csync;");	
	*pEVT7 	= evt_evt7;
	asm("csync;");	
	*pEVT8	= evt_evt8;	
	asm("csync;");	
	*pEVT9	= evt_evt9;	
	asm("csync;");	
	*pEVT10	= evt_evt10;	
	asm("csync;");	
	*pEVT11	= evt_evt11;	
	asm("csync;");	
	*pEVT12	= evt_evt12;	
	asm("csync;");	
	*pEVT13	= evt_evt13;	
	asm("csync;");	

	*pEVT14 = evt_system_call;	
	asm("csync;");	
	*pEVT15 = evt_soft_int1;	
	asm("csync;");	

  	for (i = 0; i < INTERNAL_IRQS; i++) {
		int_irq_list[i].handler = NULL;
		int_irq_list[i].flags   = IRQ_FLG_STD;
		int_irq_list[i].dev_id  = NULL;
		int_irq_list[i].devname = NULL;
	}
   	*pIMASK = 0;
	asm("csync;");
	ilat  = *pILAT;
	asm("csync;");
	*pILAT = ilat;
	asm("csync;");
   	/* Enable interrupts IVG7-15 */
	*pIMASK = irq_flags = irq_flags | IMASK_IVG15 | IMASK_IVG14 |IMASK_IVG13 |IMASK_IVG12 |IMASK_IVG11 |
	IMASK_IVG10 |IMASK_IVG9 |IMASK_IVG8 |IMASK_IVG7 |IMASK_IVGHW;	
	asm("csync;");

	printk(KERN_INFO "Configuring Blackfin Priority Driven Interrupts\n");
	program_IAR();
	search_IAR(0);
	search_IAR(1);
	search_IAR(2);
	
	local_irq_enable();
	return 0;
}

void bfin_enable_irq(unsigned int irq);
void bfin_disable_irq(unsigned int irq);

int bfin_request_irq(unsigned int irq, int (*handler)(int, void *, struct pt_regs *), unsigned long flags, const char *devname, void *dev_id)
{
	if (irq >= INTERNAL_IRQS) {
		printk("%s: Unknown IRQ %d from %s\n", 
			      __FUNCTION__, irq, devname);
		return -ENXIO;
	}

	if (!(int_irq_list[irq].flags & IRQ_FLG_STD)) {
		if (int_irq_list[irq].flags & IRQ_FLG_LOCK)	{
		printk(KERN_ERR "%s: IRQ %d from %s is not replaceable\n",
			       __FUNCTION__, irq, int_irq_list[irq].devname);
			return -EBUSY;
	}
		if (flags & IRQ_FLG_REPLACE) {
			printk(KERN_ERR "%s: %s can't replace IRQ %d from %s\n",
			       __FUNCTION__, devname, irq, int_irq_list[irq].devname);
			return -EBUSY;
		}
	}
	int_irq_list[irq].handler = handler;
	int_irq_list[irq].flags   = flags;
	int_irq_list[irq].dev_id  = dev_id;
	int_irq_list[irq].devname = devname;

	return 0;
}

void bfin_free_irq(unsigned int irq, void *dev_id)
{
	if (irq >= INTERNAL_IRQS) {
		printk ("%s: Unknown IRQ %d\n", __FUNCTION__, irq);
		return;
	}

	if (int_irq_list[irq].dev_id != dev_id)
		printk(KERN_INFO "%s: removing probably wrong IRQ %d from %s\n",
		       __FUNCTION__, irq, int_irq_list[irq].devname);
	int_irq_list[irq].handler = NULL; 
	int_irq_list[irq].flags   = IRQ_FLG_STD;
	int_irq_list[irq].dev_id  = NULL;
	int_irq_list[irq].devname = NULL;

	bfin_disable_irq(irq);
}

/*
 * Enable/disable a particular machine specific interrupt source.
 * Note that this may affect other interrupts in case of a shared interrupt.
 * This function should only be called for a _very_ short time to change some
 * internal data, that may not be changed by the interrupt at the same time.
 * int_(enable|disable)_irq calls may also be nested.
 */

void bfin_enable_irq(unsigned int irq)
{
	unsigned long irq_val;

	local_irq_disable();
	if (irq >= INTERNAL_IRQS) {
		printk("%s: Unknown IRQ %d\n", __FUNCTION__, irq);
		return;
	}

	if (irq <= IRQ_CORETMR)
	{
		/* enable the interrupt */
		irq_flags |= 1<<irq;
		local_irq_enable();
		return;
	}

	if (irq == IRQ_SPORT0)
		irq_val = 0x600;
	else if (irq == IRQ_SPORT1)
		irq_val = 0x1800;
	else if (irq == IRQ_UART)
		irq_val = 0xC000;
	else
		irq_val = (1<<(irq - (IRQ_CORETMR+1)));		

   	*pSIC_IMASK |= irq_val;
	asm("ssync;");

	local_irq_enable();
}

void bfin_disable_irq(unsigned int irq)
{
	unsigned long irq_val;

	if (irq >= INTERNAL_IRQS) {
		printk("%s: Unknown IRQ %d\n", __FUNCTION__, irq);
		return;
	}

	if (irq < IRQ_CORETMR)
	{
		local_irq_disable();
		irq_flags &= ~(1<<irq);
		local_irq_enable();
		return;
	}

	/*
 	 * If it is the interrupt for peripheral,
	 * we only disable it in SIC_IMASK register.
	 * No need to change IMASK register of CORE,
	 * since all of the IVG for peripherals was 
 	 * enabled in bfin_init_IRQ()
	 *
	 */

	if (irq == IRQ_SPORT0)
		irq_val = 0x600;
	else if (irq == IRQ_SPORT1)
		irq_val = 0x1800;
	else if (irq == IRQ_UART)
		irq_val = 0xC000;
	else
		irq_val = (1<<(irq - (IRQ_CORETMR + 1)));

	local_irq_disable();

   	*pSIC_IMASK &= ~(irq_val); 
	asm("ssync;");
	
	local_irq_enable();

}

void  call_isr(int irq, struct pt_regs * fp)
{
	if(int_irq_list[irq].handler)
	{
	    int_irq_list[irq].handler(irq,int_irq_list[irq].dev_id, fp);
	    kstat_cpu(0).irqs[irq]++;
	}
/*	else
		printk("unregistered interrupt %d\n",irq);*/
}

void bfin_do_irq(int vec, struct pt_regs *fp)
{
    	if (vec <= IRQ_CORETMR)
	{	
		 call_isr(vec, fp);
		 return;
	}

	switch(vec)	{

		case IVG7:
			call_isr(getirq_number(ivg7),fp);
			break;
		case IVG8:
			call_isr(getirq_number(ivg8),fp);
			break;
		case IVG9:
			call_isr(getirq_number(ivg9),fp);
			break;
		case IVG10:
			call_isr(getirq_number(ivg10),fp);
			break;
		case IVG11:
			call_isr(getirq_number(ivg11),fp);
			break;
		case IVG12:
			call_isr(getirq_number(ivg12),fp);
			break;
		case IVG13:
			call_isr(getirq_number(ivg13),fp);
			break;
	}

}

/* This function checks which interrupt occurred under the 
   table and returns the irq number
   Dont try to alter this.	 
*/

int getirq_number(struct ivgx *ivg)
{
	int i=0;
	unsigned long sic_isr, sic_imask, posval;
	
	sic_imask = *pSIC_IMASK;
	asm("ssync;");
	
	sic_isr = *pSIC_ISR;
	asm("ssync;");

	for (;i<7;i++)	{
		posval = (1 << ivg[i].isrpos);
		if((sic_isr & posval) != 0)	{
			if((sic_imask & posval) != 0)	{
				return ivg[i].irqno;
			}
		}
	}
	return -1;
}

int bfin_get_irq_list(struct seq_file* p, void* v)
{
	return 0;
}

void config_bfin_irq(void)
{
	mach_default_handler = NULL;
	mach_init_IRQ        = bfin_init_IRQ;
	mach_request_irq     = bfin_request_irq;
	mach_free_irq        = bfin_free_irq;
	mach_enable_irq      = bfin_enable_irq;
	mach_disable_irq     = bfin_disable_irq;
	mach_get_irq_list    = bfin_get_irq_list;
	mach_process_int     = bfin_do_irq;
}

int show_interrupts(struct seq_file *p, void *v)
{
	int i = *(loff_t *) v;
	
	if (i < NR_IRQS) {
		if (int_irq_list[i].devname) {
			seq_printf(p, "%3d: %10u ", i, kstat_cpu(0).irqs[i]);
			if (int_irq_list[i].flags & IRQ_FLG_LOCK)
				seq_printf(p, "L ");
			else
				seq_printf(p, "  ");
			seq_printf(p, "%s\n", int_irq_list[i].devname);
		}
	}
	if (i == NR_IRQS)
		seq_printf(p, "   : %10u   spurious\n", num_spurious);
	return 0;
}

void init_irq_proc(void)
{
	/* Insert /proc/irq driver here */
}
