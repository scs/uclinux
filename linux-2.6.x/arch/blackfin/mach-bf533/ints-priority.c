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

#include <linux/module.h>
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
	int isrflag;	/*corresponding bit in the SIC_ISR register*/
}ivg_table[23];

struct ivg_slice {
	struct ivgx *ifirst; /* position of first irq in ivg_table for given ivg */
	struct ivgx *istop;  
} ivg7_13[16];

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

static void program_IAR(void);
static void search_IAR(void);	

/* irq node variables for the 32 (potential) on chip sources */
static irq_node_t int_irq_list[INTERNAL_IRQS];

/*********
 * bfin_irq_panic
 * - calls panic with string setup
 *********/
asmlinkage void bfin_irq_panic( int reason, struct pt_regs * regs)
{
	extern char _etext;
	int sig = 0;
	siginfo_t info;

  	printk("\n\nException: IRQ 0x%x entered\n", reason);
	printk(" code=[0x%08x],  ", (unsigned int)regs->seqstat);
	printk(" stack frame=0x%04x,  ",(unsigned int)(unsigned long) regs);
	printk(" bad PC=0x%04x\n", (unsigned int)regs->pc);
	if(reason == 0x5) {
 
 	printk("\n----------- HARDWARE ERROR -----------\n\n");
		
	/* There is only need to check for Hardware Errors, since other EXCEPTIONS are handled in TRAPS.c (MH)  */
		switch(((unsigned int)regs->seqstat) >> 14)	  {
				case (0x2):			//System MMR Error
					info.si_code = BUS_ADRALN;
		                        sig = SIGBUS;
					printk(HWC_x2);
					break;
				case (0x3):			//External Memory Addressing Error
				        info.si_code = BUS_ADRERR;
					sig = SIGBUS;
					printk(HWC_x3);
					break;
				case (0x12):			//Performance Monitor Overflow
					printk(HWC_x12);
					break;
				case (0x18):			//RAISE 5 instruction
					printk(HWC_x18);
					break;
				default:			//Reserved
					printk(HWC_default);
					break;
			}
	}
	dump(regs);
	if (0 == (info.si_signo = sig) || 
	    regs->orig_pc < (unsigned)&_etext) /* in kernelspace */
	    panic("Unhandled IRQ or exceptions!\n");
	else { /* in userspace */
	    info.si_errno = 0;
	    info.si_addr = (void *) regs->pc;
	    force_sig_info (sig, &info, current);
        }
}

/*Program the IAR registers*/
static void __init program_IAR()
{
		/* Program the IAR0 Register with the configured priority */
	        *pSIC_IAR0 =  ((CONFIG_PLLWAKE_ERROR-7) << PLLWAKE_ERROR_POS) |
                ((CONFIG_DMA_ERROR   -7) <<    DMA_ERROR_POS) |
                ((CONFIG_PPI_ERROR   -7) <<    PPI_ERROR_POS) |
                ((CONFIG_SPORT0_ERROR-7) << SPORT0_ERROR_POS) |
                ((CONFIG_SPI_ERROR   -7) <<    SPI_ERROR_POS) |
                ((CONFIG_SPORT1_ERROR-7) << SPORT1_ERROR_POS) |
                ((CONFIG_UART_ERROR  -7) <<   UART_ERROR_POS) |
                ((CONFIG_RTC_ERROR   -7) <<    RTC_ERROR_POS);
	        asm("ssync;");	

		*pSIC_IAR1 =	((CONFIG_DMA0_PPI-7)    << DMA0_PPI_POS) |
                ((CONFIG_DMA1_SPORT0RX-7) << DMA1_SPORT0RX_POS) |
                ((CONFIG_DMA2_SPORT0TX-7) << DMA2_SPORT0TX_POS) |
                ((CONFIG_DMA3_SPORT1RX-7) << DMA3_SPORT1RX_POS) |
                ((CONFIG_DMA4_SPORT1TX-7) << DMA4_SPORT1TX_POS) |
                ((CONFIG_DMA5_SPI-7)    << DMA5_SPI_POS)    |
                ((CONFIG_DMA6_UARTRX-7) << DMA6_UARTRX_POS) |
                ((CONFIG_DMA7_UARTTX-7) << DMA7_UARTTX_POS);
	        asm("ssync;");	
 
		*pSIC_IAR2 =	((CONFIG_TIMER0-7) << TIMER0_POS) |
		((CONFIG_TIMER1-7) << TIMER1_POS) |
		((CONFIG_TIMER2-7) << TIMER2_POS) |
		((CONFIG_PFA-7) << PFA_POS) |
		((CONFIG_PFB-7) << PFB_POS) |
		((CONFIG_MEMDMA0-7) << MEMDMA0_POS) |
		((CONFIG_MEMDMA1-7) << MEMDMA1_POS) |
		((CONFIG_WDTIMER-7) << WDTIMER_POS);
	        asm("ssync;");	
}	/*End of program_IAR*/

/* Search SIC_IAR and fill tables with the irqvalues 
and their positions in the SIC_ISR register -Nidhi */

static void __init search_IAR()	
{
    unsigned ivg, irq_pos = 0;
    for(ivg = IVG7; ivg <= IVG13; ivg++)
    {
        int irqn;

        ivg7_13[ivg].istop = 
        ivg7_13[ivg].ifirst = &ivg_table[irq_pos];        
          
        for(irqn = 0; irqn < 24; irqn++)
          if (ivg == IVG7 + (0x0f & pSIC_IAR0[irqn >> 3] >> (irqn & 7) * 4))
          {
             ivg_table[irq_pos].irqno = IVG7 + irqn;
             ivg_table[irq_pos].isrflag = 1 << irqn;
              ivg7_13[ivg].istop++;
              irq_pos++;
          }
    }
}		
			
/*
 * This function should be called during kernel startup to initialize
 * the BFin IRQ handling routines.
 */

int __init  bfin_init_IRQ(void)
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

	printk(KERN_INFO "Configuring Blackfin Priority Driven Interrupts\n");
	program_IAR();   /* IMASK=xxx is equivalent to STI xx or irq_flags=xx, local_irq_enable() */
	search_IAR();    /* Therefore it's better to setup IARs before interrupts enabled */

   	/* Enable interrupts IVG7-15 */
	*pIMASK = irq_flags = irq_flags | IMASK_IVG15 | IMASK_IVG14 |IMASK_IVG13 |IMASK_IVG12 |IMASK_IVG11 |
	IMASK_IVG10 |IMASK_IVG9 |IMASK_IVG8 |IMASK_IVG7 |IMASK_IVGHW;	
	asm("csync;");

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
		printk (KERN_ERR "%s: Unknown IRQ %d\n", __FUNCTION__, irq);
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

void bfin_do_irq(int vec, struct pt_regs *fp)
{
   	if (vec > IRQ_CORETMR)
        {
          struct ivgx *ivg = ivg7_13[vec].ifirst;
          struct ivgx *ivg_stop = ivg7_13[vec].istop;
	  unsigned long sic_status;	

	  asm("ssync;");	
 	  sic_status = *pSIC_IMASK & *pSIC_ISR;

	  for(;; ivg++) {
              if (ivg >= ivg_stop)  {
		num_spurious++;
                return;
              }
              else if ((sic_status & ivg->isrflag) != 0)
                break;
         }
	  vec = ivg->irqno;
        }
	if(int_irq_list[vec].handler)
	{
	    int_irq_list[vec].handler(vec,int_irq_list[vec].dev_id, fp);
	    kstat_cpu(0).irqs[vec]++;
	}
	else
	{
		printk("unregistered interrupt irq=%d\n",vec);
		num_spurious++;
	}
}

int bfin_get_irq_list(struct seq_file* p, void* v)
{
	return 0;
}

void __init config_bfin_irq(void)
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
	
	if (i < INTERNAL_IRQS) {
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
