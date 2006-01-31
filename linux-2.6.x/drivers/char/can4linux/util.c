/*
 * can4linux -- LINUX CAN device driver source
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * 
 * derived from the the LDDK can4linux version
 *     (c) 1996,1997 Claus Schroeter (clausi@chemie.fu-berlin.de)
 *
 *------------------------------------------------------------------
 * $Header$
 *
 *--------------------------------------------------------------------------
 *
 *
 * modification history
 * --------------------
 * $Log$
 * Revision 1.1  2006/01/31 09:11:45  hennerich
 * Initial checkin can4linux driver Blackfin BF537/6/4 Task[T128]
 *
 * Revision 1.1  2003/07/18 00:11:46  gerg
 * I followed as much rules as possible (I hope) and generated a patch for the
 * uClinux distribution. It contains an additional driver, the CAN driver, first
 * for an SJA1000 CAN controller:
 *   uClinux-dist/linux-2.4.x/drivers/char/can4linux
 * In the "user" section two entries
 *   uClinux-dist/user/can4linux     some very simple test examples
 *   uClinux-dist/user/horch         more sophisticated CAN analyzer example
 *
 * Patch submitted by Heinz-Juergen Oertel <oe@port.de>.
 *
 *
 *
 */


#include "defs.h"
#include <linux/sched.h> 
#include <linux/proc_fs.h>
#include <linux/pci.h>

/*
 * Refuse to compile under versions older than 1.99.4
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,0)
#  error "This module needs Linux 2.4 or newer"
#endif

/* each CAN channel has one wait_queue for read and one for write */
wait_queue_head_t CanWait[MAX_CHANNELS];
wait_queue_head_t CanOutWait[MAX_CHANNELS];

/* for each CAN channel allocate a TX and RX FIFO */
msg_fifo_t   Tx_Buf[MAX_CHANNELS];
msg_fifo_t   Rx_Buf[MAX_CHANNELS];

#ifdef CAN_USE_FILTER
    msg_filter_t Rx_Filter[MAX_CHANNELS]; 
#endif
/* used to store always the last frame sent on this channel */
canmsg_t     last_Tx_object[MAX_CHANNELS];

unsigned char *can_base[MAX_CHANNELS];	/* ioremapped adresses */
unsigned int can_range[MAX_CHANNELS];	/* ioremapped adresses */
int selfreception[MAX_CHANNELS] = {0};	/* flag indicating that selfreception
                                           of frames is allowed */

#if defined(MCF5282)
	/* Motorola ColdFire Board FlexCAN */
#include <asm/coldfire.h>
#include <asm/mcfsim.h>

/* enabel the interrupts at the interrupt controller
 used:
  - receivebuffer 1

*/
void mcf_irqsetup(void)
{
volatile unsigned char *icrp;	/* interrupt control register pointer */
volatile unsigned long *imrp;	/* interrupt mask register pointer    */

    /* Initialize FlexCAN interrupt handler
      - Initialize the interrupt configurataion register (CANICR with
        a specific request level and vector base address
      - Initialize IARB[3:0] to a non zero value in CANMCR
        ( This is done in CAN-ChipReset() )
      - Set the required mask bits in the IMASK register (for all message
        buffer interrupts) in CANCTRL0 for bus off and error interrupts,
        and in CANMCR for WAKE interrupt.
        (happens in CAN-ChipReset() too)

	MCF5282 has two interrupt controllers, FlexCAN interrupts are
	scheduled to INTC1 (the second one, with lower priority)
	Int source nr  -- Source --                    vector
	 8             -- message buffer 0             136
	 9             -- message buffer 1             137
	   ...
	23             -- message buffer 15            151
	24             -- Error Int                    152
	25             -- Bus-Off Int                  153
	26             -- Wake-Up Int                  154


       Interrupt Vector number is vector_number = 128 + interrupt source number
       (for INTC1)                    
       vector_number = 137 (std receive object == MB 1) 

     */
    icrp = (volatile unsigned char *) (MCF_MBAR + MCFICM_INTC1 + 
	    MCFINTC_ICR0 + MCFINT_CAN_BUF00 );
    *icrp = 0x33; /* CANx with level 6, priority 3 */
    /* printk("icrp %p = 0x%08x\n", icrp, *icrp); */

    icrp = (volatile unsigned char *) (MCF_MBAR + MCFICM_INTC1 + 
	    MCFINTC_ICR0 + MCFINT_CAN_BUF01 );
    *icrp = 0x33; /* CANx with level 6, priority 3 */
    /* printk("icrp %p = 0x%08x\n", icrp, *icrp); */

    icrp = (volatile unsigned char *) (MCF_MBAR + MCFICM_INTC1 + 
	    MCFINTC_ICR0 + MCFINT_CAN_BUF02 );
    *icrp = 0x33; /* CANx with level 6, priority 3 */
    /* printk("icrp %p = 0x%08x\n", icrp, *icrp); */
    
    icrp = (volatile unsigned char *) (MCF_MBAR + MCFICM_INTC1 + 
	    MCFINTC_ICR0 + MCFINT_CAN_WARN );
    *icrp = 0x33; /* CANx with level 6, priority 3 */
    /* printk("icrp %p = 0x%08x\n", icrp, *icrp); */

    icrp = (volatile unsigned char *) (MCF_MBAR + MCFICM_INTC1 + 
	    MCFINTC_ICR0 + MCFINT_CAN_BUSOFF );
    *icrp = 0x33; /* CANx with level 6, priority 3 */
    /* printk("icrp %p = 0x%08x\n", icrp, *icrp); */

    /* set Mask register too
    The IMRHn and IMRLn registers are each 32 bits in size and provide a
    bit map for each interrupt to allow the request to be disabled (1 =
    disable the request, 0 = enable the request).  The IMRn is set to all
    ones by reset, disabling all interrupt requests. The IMRn can be read
    and written. A write that sets bit 0 of the IMR forces the other 63
    bits to be set, disabling all interrupt sources, and providing a global
    mask-all capability.
    */
    imrp = (volatile unsigned long *) (MCF_MBAR + MCFICM_INTC1 +
		MCFINTC_IMRL);
    *imrp &= ~(   (1 << (MCFINT_CAN_BUF00 ))
    	        | (1 << (MCFINT_CAN_BUF01 ))
    	        | (1 << (MCFINT_CAN_BUF02 ))
    	        | (1 << (MCFINT_CAN_WARN ))
    	        | 1);
    /*            ^ unmask all */

    /* printk("imrp %p = 0x%08x\n", imrp, *imrp); */
}

void mcf_irqreset(void)
{
volatile unsigned long *imrp;	/* interrupt mask register pointer    */

    /* Mask register auch rücksetzen
    The IMRHn and IMRLn registers are each 32 bits in size and provide a
    bit map for each interrupt to allow the request to be disabled (1 =
    disable the request, 0 = enable the request).  The IMRn is set to all
    ones by reset, disabling all interrupt requests. The IMRn can be read
    and written. A write that sets bit 0 of the IMR forces the other 63
    bits to be set, disabling all interrupt sources, and providing a global
    mask-all capability.
    */
    imrp = (volatile unsigned long *) (MCF_MBAR + MCFICM_INTC1 +
		MCFINTC_IMRL);
    *imrp |= ((1 << (MCFINT_CAN_BUF00 ))
    	    | (1 << (MCFINT_CAN_BUF01 )) 
    	    | (1 << (MCFINT_CAN_BUF02 )) 
    	    | (1 << (MCFINT_CAN_WARN ))
            | 1);

}
#endif

#if defined(CCPC104)
	/* Motorola ColdFire Board CTRLink */
#include <asm/coldfire.h>
#include <asm/mcfsim.h>

void pc104_irqsetup(void)
{
volatile unsigned long	*icrp;

    /* The PC104 device uses external IRQ3 */

    /* reset all PI (pending Interrupts) to 0, mask IPL priority level 
     * and add 0d to INT3
     * each ext int 4 bits 
     *    _  _  _  _
     *    PI,..IPL..   0d -->  1 1 0 1 --> PI = 1
     *                                     PL = 5
     *        
     */
    icrp = (volatile unsigned long *) (MCF_MBAR + MCFSIM_ICR1);
    *icrp = (*icrp & 0x77077777) | 0x00d00000;
}

void pc104_irqack(int irq)
{
	volatile unsigned long	*icrp;
	/*
	Writing a 1 to PI enables the value for the corresponding IPL field to be set.
	Note: for external interrupts only,
	writing a one to this bit clears the corresponding interrupt latch.
	The external interrupt must be toggled before another interrupt is latched.
	*/
	/* The PC104 device uses external IRQ3 */
	icrp = (volatile unsigned long *) (MCF_MBAR + MCFSIM_ICR1);
	*icrp = (*icrp & 0x77777777) | 0x00800000;
}

#endif


#if 0
/* code sould be in hardware specific c-file */


int Can_RequestIrq(int minor, int irq, irq_handler_t handler)
{
int err=0;

    DBGin("Can_RequestIrq");
    /*

    int request_irq(unsigned int irq,			// interrupt number  
              void (*handler)(int, void *, struct pt_regs *), // pointer to ISR
		              irq, dev_id, registers on stack
              unsigned long irqflags, const char *devname,
              void *dev_id);

       dev_id - The device ID of this handler (see below).       
       This parameter is usually set to NULL,
       but should be non-null if you wish to do  IRQ  sharing.
       This  doesn't  matter when hooking the
       interrupt, but is required so  that,  when  free_irq()  is
       called,  the  correct driver is unhooked.  Since this is a
       void *, it can point to anything (such  as  a  device-spe­
       cific  structure,  or even empty space), but make sure you
       pass the same pointer to free_irq().

    */

#if defined(CONFIG_PPC)
    /* LINUX_PPC */
    err = request_8xxirq( irq, handler, 0, "Can", NULL );
#elif defined(MCF5282)
    {
    int i;
    	/* 19 Int vectors are used on Interrupt Controller 1 */
	for( i = 136; i < 155; i++) {
	    err = request_irq( i, handler, SA_SHIRQ, "Can", &Can_minors[minor]);
	    if(err) {
    		DBGout();return err;
	    }
	}
    }
#elif defined(AD_BLACKFIN)
    {
    err = request_irq(irq, handler, SA_INTERRUPT|SA_SHIRQ, \
    					"Can-RX", &Can_minors[minor]);
    err = request_irq(irq +1 , handler, SA_INTERRUPT|SA_SHIRQ, \
    					"Can-TX", &Can_minors[minor]);
    }
#else 
    err = request_irq(irq, handler, SA_SHIRQ, "Can", &Can_minors[minor]);
#endif
    if( !err ) {
	/* printk("Requested IRQ[%d]: %d @ 0x%x", minor, irq, handler); */

/* Now the kernel has assigned a service to the Interruptvector,
   time to enable the hardware to generate an ISR.

   here should be used a generic function e.g. can_irqsetup(minor)
   and do whatever needed for the app. hardware
   to reduce ifdef clutter
   */
#if defined(CCPC104)
	pc104_irqsetup();
#endif
#if defined(MCF5282)
	mcf_irqsetup();
#endif

	irq2minormap[irq] = minor;

	irq2pidmap[irq] = current->pid;
	DBGprint(DBG_BRANCH,("Requested IRQ: %d @ 0x%lx",
				irq, (unsigned long)handler));
	IRQ_requested[minor] = 1;
    }
    DBGout();
    return err;
}

int Can_FreeIrq(int minor, int irq )
{
    DBGin("Can_FreeIrq");
    IRQ_requested[minor] = 0;

#if defined(MCF5282)
    /* reset interrupt masks */
    mcf_irqreset();
#endif
#if defined(MCF5282)
    {
    int i;
    	/* 19 Int vectors are used on Interrupt Controller 1 */
	for(i = 136; i < 155; i++) {
	    free_irq(i, &Can_minors[minor]);
	}
    }
#endif

#if defined(AD_BLACKFIN)
    free_irq(irq, &Can_minors[minor]);
    free_irq(irq + 1, &Can_minors[minor]);
#else 
    /* release the vector from the kernel */
    free_irq(irq, &Can_minors[minor]);
#endif

    DBGout();
    return 0;
}
#endif

int Can_WaitInit(int minor)
{
    DBGin("Can_WaitInit");
	/* reset the wait_queue pointer */
	init_waitqueue_head(&CanWait[minor]);
	init_waitqueue_head(&CanOutWait[minor]);
    DBGout();
    return 0;
}

/*
initialize RX and TX Fifo's
*/
int Can_FifoInit(int minor)
{
int i;

    DBGin("Can_FifoInit");
       Tx_Buf[minor].head   = Rx_Buf[minor].head = 0;
       Tx_Buf[minor].tail   = Rx_Buf[minor].tail = 0;
       Tx_Buf[minor].status = Rx_Buf[minor].status = 0;
       Tx_Buf[minor].active = Rx_Buf[minor].active = 0;
       for(i = 0; i < MAX_BUFSIZE; i++) {
	   Tx_Buf[minor].free[i]  = BUF_EMPTY;
       }
    DBGout();
    return 0;
}

#ifdef CAN_USE_FILTER
int Can_FilterInit(int minor)
{
int i;

    DBGin("Can_FilterInit");
       Rx_Filter[minor].use      = 0;
       Rx_Filter[minor].signo[0] = 0;
       Rx_Filter[minor].signo[1] = 0;
       Rx_Filter[minor].signo[2] = 0;

       for(i=0;i<MAX_ID_NUMBER;i++)	
	  Rx_Filter[minor].filter[i].rtr_response = NULL;

    DBGout();
    return 0;
}

int Can_FilterCleanup(int minor)
{
int i;

    DBGin("Can_FilterCleanup");
    for(i=0;i<MAX_ID_NUMBER;i++) {
	    if( Rx_Filter[minor].filter[i].rtr_response != NULL )	
	       kfree( Rx_Filter[minor].filter[i].rtr_response);
	    Rx_Filter[minor].filter[i].rtr_response = NULL;
    }
    DBGout();
    return 0;
}


int Can_FilterOnOff(int minor, unsigned on) {
    DBGin("Can_FilterOnOff");
       Rx_Filter[minor].use = (on!=0);
    DBGout();
    return 0;
}

int Can_FilterMessage(int minor, unsigned message, unsigned enable) {
    DBGin("Can_FilterMessage");
       Rx_Filter[minor].filter[message].enable = (enable!=0);
    DBGout();
    return 0;
}

int Can_FilterTimestamp(int minor, unsigned message, unsigned stamp) {
    DBGin("Can_FilterTimestamp");
       Rx_Filter[minor].filter[message].timestamp = (stamp!=0);
    DBGout();
    return 0;
}

int Can_FilterSignal(int minor, unsigned id, unsigned signal) {
    DBGin("Can_FilterSignal");
       if( signal <= 3 )
       Rx_Filter[minor].filter[id].signal = signal;
    DBGout();
    return 0;
}

int Can_FilterSigNo(int minor, unsigned signo, unsigned signal ) {
    DBGin("Can_FilterSigNo");
       if( signal < 3 )
       Rx_Filter[minor].signo[signal] = signo;
    DBGout();
    return 0;
}
#endif

#ifdef CAN_RTR_CONFIG
int Can_ConfigRTR( int minor, unsigned message, canmsg_t *Tx )
{
canmsg_t *tmp;

    DBGin("Can_ConfigRTR");
    if( (tmp = kmalloc ( sizeof(canmsg_t), GFP_ATOMIC )) == NULL ){
	    DBGprint(DBG_BRANCH,("memory problem"));
	    DBGout(); return -1;
    }
    Rx_Filter[minor].filter[message].rtr_response = tmp;
    memcpy( Rx_Filter[minor].filter[message].rtr_response , Tx, sizeof(canmsg_t));	
    DBGout(); return 1;
    return 0;
}

int Can_UnConfigRTR( int minor, unsigned message )
{
canmsg_t *tmp;

    DBGin("Can_UnConfigRTR");
    if( Rx_Filter[minor].filter[message].rtr_response != NULL ) {
	    kfree(Rx_Filter[minor].filter[message].rtr_response);
	    Rx_Filter[minor].filter[message].rtr_response = NULL;
    }	
    DBGout(); return 1;
    return 0;
}
#endif


#ifdef DEBUG

/* dump_CAN or CAN_dump() which is better ?? */
#if CAN4LINUX_PCI
#else
#endif
#include <asm/io.h>

#if 0
/* simply dump a memory area bytewise for 2*16 addresses */
void dump_CAN(unsigned long adress, int offset)
{
int i, j;
unsigned long ptr = (unsigned long)ioremap(adress, 256);
    printk("     CAN at Adress 0x%x\n", adress);
    for(i = 0; i < 2; i++) {
	printk("     ");
	for(j = 0; j < 16; j++) {
	    /* printk("%02x ", *ptr++); */
	    printk("%02x ", readb(ptr));
	    ptr += offset;
	}
	printk("\n");
    }
}

/*
 * adress - start address 
 * n      - number of 16 byte rows, 
 * offset - print every n-th byte
 */
void dump_CAN(unsigned long adress, int n, int offset)
{
int i, j;
    printk("     CAN at Adress 0x%x\n", adress);
    for(i = 0; i < n; i++) {
	printk("     ");
	for(j = 0; j < 16; j++) {
	    /* printk("%02x ", *ptr++); */
	    printk("%02x ", readb(adress));
	    adress += offset;
	}
	printk("\n");
    }
}
#endif

#if CAN4LINUX_PCI
# define REG_OFFSET 4
#else
# define REG_OFFSET 1
#endif
/**
*   Dump the CAN controllers register contents,
*   identified by the device minr number to stdout
*
*   Base[minor] should contain the virtual adress
*/
void Can_dump(int minor)
{
int i, j;
int index = 0;

	for(i = 0; i < 2; i++) {
	    for(j = 0; j < 16; j++) {
		printk("%02x ",
#ifdef  CAN_PORT_IO
		inb((int) (Base[minor] + index)) );
#else
		readb((u32) (can_base[minor] + index)) );
#endif
		index += REG_OFFSET;
	    }
	    printk("\n");
	}
}
#endif

#ifdef CAN4LINUX_PCI
/* reset both can controllers on the EMS-Wünsche CPC-PCI Board */
/* writing to the control range at BAR1 of the PCI board */
void reset_CPC_PCI(unsigned long address)
{
unsigned long ptr = (unsigned long)ioremap(address, 32);
    DBGin("reset_CPC_PCI");
    /* printk("reset_CPC_PCI\n"); */
    writeb(0x01, ptr);
    writeb(0x00, ptr);
}

/* check memory region if there is a CAN controller
*  assume the controller was resetted before testing 
*/
int controller_available(unsigned long address, int offset)
{
unsigned long ptr = (unsigned long)ioremap(address, 32 * offset);

    DBGin("controller_available");
    /* printk("controller_available %ld\n", address); */


    /* printk("0x%0x, ", readb(ptr + (2 * offset)) ); */
    /* printk("0x%0x\n", readb(ptr + (3 * offset)) ); */

    if(   0x0c == readb(ptr + (2 * offset))
       && 0xe0 == readb(ptr + (3 * offset)) ) {
	return 1;
    } else {
	return 0;
    }
}
#endif



#ifdef CAN4LINUX_PCI
static u32 addresses[] = {
    PCI_BASE_ADDRESS_0,
    PCI_BASE_ADDRESS_1,
    PCI_BASE_ADDRESS_2,
    PCI_BASE_ADDRESS_3,
    PCI_BASE_ADDRESS_4,
    PCI_BASE_ADDRESS_5,
    0
};

/* used for storing the global pci register address */
u32 Can_pitapci_control[4];


/*
scan the pci bus
 look for vendor/device Id == Siemens PITA
 if found
    look for  subvendor id
    if found
      write to pita register 1c in the first address range the value 0x04000000
*/
int pcimod_scan(void)
{
    int i, pos = 0;
    int bus, fun;
    unsigned char headertype = 0;
    u32 id;
    u32 vdid;				/* vendor/device id */
    int candev = 0;				/* number of found devices */

    if (!pcibios_present()) {
        printk("CAN: No PCI bios present\n");
        return ENODEV;
    }
    /* printk("CAN: PCI bios present!\n"); */

    /*
     * This code is derived from "drivers/pci/pci.c". This means that
     * the GPL applies to this source file and credit is due to the
     * original authors (Drew Eckhardt, Frederic Potter, David
     * Mosberger-Tang)
     */
    for (bus = 0; !bus; bus++) { /* only bus 0 :-) */
        for (fun=0; fun < 0x100 && pos < PAGE_SIZE; fun++) {
            if (!PCI_FUNC(fun)) /* first function */
                pcibios_read_config_byte(bus,fun,PCI_HEADER_TYPE, &headertype);
            else if (!(headertype & 0x80))
                continue;
            /* the following call gets vendor AND device ID */
            pcibios_read_config_dword(bus, fun, PCI_VENDOR_ID, &id);
            if (!id || id == ~0) {
                headertype = 0; continue;
            }
            /* v-endor and d-evice id */
            vdid = id;
#if 0
            printk(" -- found pci device, vendor id = %u/0x%x , device 0x%x\n",
            	(id & 0xffff), (id & 0xffff), (id >> 16));
#endif
            pcibios_read_config_dword(bus, fun, PCI_CLASS_REVISION, &id);
#if 0
            printk("    class 0x%x, Revision %d\n",
            	(id >> 8), (id & 0x0ff));
#endif
            if(vdid == (PCI_VENDOR + (PCI_DEVICE << 16))) {
		unsigned char irq;
		u16 cmd;
		u32 svdid;			/* subsystem vendor/device id */
		    /* found EMS CAN CPC-PCI */
		    vdid = 0;	/* reset it */
		    printk("    found Siemens PITA PCI-Chip\n");
		    pcibios_read_config_byte(bus, fun, PCI_INTERRUPT_LINE, &irq);
		    printk("        using IRQ %d\n", irq);
		    pcibios_read_config_word(bus, fun, PCI_COMMAND, &cmd);
		    /* printk("        cmd: 0x%x\n", cmd); */

                    /* PCI_COMMAND should be at least PCI_COMMAND_MEMORY */
		    pcibios_write_config_word(bus, fun,
		    		/* PCI_COMMAND, PCI_COMMAND_MEMORY); */
		    		PCI_COMMAND, PCI_COMMAND_MEMORY + PCI_COMMAND_MASTER	);
		    pcibios_read_config_word(bus, fun, PCI_COMMAND, &cmd);
		    /* printk("        cmd: 0x%x\n", cmd); */




		    pcibios_read_config_dword(bus, fun, PCI_SUBSYSTEM_VENDOR_ID, &svdid);
		    /* printk("        s_vendor 0x%x, s_device 0x%x\n", */
					/* (svdid & 0xffff), (svdid >> 16)); */

		/* How can we be sure that that is an EMS CAN card ?? */


		for (i = 0; addresses[i]; i++) {
		    u32 curr, mask;
		    char *type;

		    pcibios_read_config_dword(bus, fun, addresses[i], &curr);
		    cli();
		    pcibios_write_config_dword(bus, fun, addresses[i], ~0);
		    pcibios_read_config_dword(bus, fun, addresses[i], &mask);
		    pcibios_write_config_dword(bus, fun, addresses[i], curr);
		    sti();

		    /* printk("    region %i: mask 0x%08lx, now at 0x%08lx\n", i, */
				   /* (unsigned long)mask, */
				   /* (unsigned long)curr); */
#if 0 /* we don't need this message, so we don't need this code */
		    if (!mask) {
			printk("    region %i not existent\n", i);
			break;
		    }
#endif
		    /* extract the type, and the programmable bits */
		    if (mask & PCI_BASE_ADDRESS_SPACE) {
		    type = "I/O"; mask &= PCI_BASE_ADDRESS_IO_MASK;
		    } else {
			type = "mem"; mask &= PCI_BASE_ADDRESS_MEM_MASK;
		    }
		/* printk("    region %i: type %s, size %i\n", i, */
			      /* type, ~mask+1); */

		    if(i == 0) {
		    	/* BAR0 internal PITA registers */
			unsigned long ptr = (unsigned long)ioremap(curr, 256);
			/* enable memory access */
		    	/* printk("write to pita\n"); */
			writel(0x04000000, ptr + 0x1c);
			Can_pitapci_control[candev] = ptr;

		    }
		    if(i == 1) {
		    	/* BAR1 parallel I/O
		    	 * at address 0 are some EMS control registers
		    	 * at address 0x400 the first controller area 
		    	 * at address 0x600 the second controller area 
			 * registers are read as 32bit
			 *
			 * at adress 0 we can verify the card
			 * 0x55 0xaa 0x01 0xcb
			 */
			/* dump_CAN(curr, 4); */

			reset_CPC_PCI(curr);

			/* enable interrupts Int_0 */
			/* write to PITAs ICR register */
    			writel(0x00020000, Can_pitapci_control[candev] + 0x0);

			/* dump_CAN(curr + 0x400, 4); */
			if(controller_available(curr + 0x400, 4)) {
			    printk("CAN: at pos 1\n");
			    if(candev > 4) {
				printk("CAN: only 4 devices supported\n");
				break; /* the devices scan loop */
			    }
			    Base[candev]
			    = (unsigned long)ioremap(curr + 0x400, 32*4);
			    IOModel[candev] = 'm';
			    IRQ[candev] = irq;
			    candev++;
			} else {
			    printk("CAN: NO at pos 1\n");
			}
			/* dump_CAN(curr + 0x600, 4); */

			if(controller_available(curr + 0x600, 4)) {
			    printk("CAN: at pos 2\n");
			    if(candev > 4) {
				printk("CAN: only 4 devices supported\n");
				break; /* the devices scan loop */
			    }
			    /* share the board control register with prev ch */
    			    Can_pitapci_control[candev] = 
				Can_pitapci_control[candev - 1];
			    Base[candev]
			    = (unsigned long)ioremap(curr + 0x600, 32*4);
			    IOModel[candev] = 'm';
			    IRQ[candev] = irq;
			    candev++;
			} else {
			    printk("CAN: NO at pos 2\n");
			}
		    }

		}
            } /* EMS CPC-PCI */
        } /* for all devices */
    } /* for all busses */
    return 0;
}
#endif


