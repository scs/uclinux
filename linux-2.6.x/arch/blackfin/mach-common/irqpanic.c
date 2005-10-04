/*
 * File: $Id$
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file COPYING in the main directory of this archive
 * for more details. 
*/

#include <linux/module.h>
#include <linux/kernel_stat.h>
#include <asm/traps.h>
#include <asm/blackfin.h>

extern void dump(struct pt_regs * regs, void *);

/*********
 * irq_panic
 * - calls panic with string setup
 *********/
asmlinkage void irq_panic( int reason, struct pt_regs * regs)
{
	int sig = 0;
	siginfo_t info;

  	printk("\n\nException: IRQ 0x%x entered\n", reason);
	printk(" code=[0x%08x],  ", (unsigned int)regs->seqstat);
	printk(" stack frame=0x%04x,  ",(unsigned int)(unsigned long) regs);
	printk(" bad PC=0x%04x\n", (unsigned int)regs->pc);
	if(reason == 0x5) {
 
 	printk("\n----------- HARDWARE ERROR -----------\n\n");
		
	/* There is only need to check for Hardware Errors, since other EXCEPTIONS are handled in TRAPS.c (MH)  */
	switch(((unsigned int)regs->seqstat) >> 14) {
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

	regs->ipend = *pIPEND;
	dump(regs, regs->pc);
	if (0 == (info.si_signo = sig) || 
	    0 == user_mode(regs)) /* in kernelspace */
	    panic("Unhandled IRQ or exceptions!\n");
	else { /* in userspace */
	    info.si_errno = 0;
	    info.si_addr = (void *) regs->pc;
	    force_sig_info (sig, &info, current);
        }
}
