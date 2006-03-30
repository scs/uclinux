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
 *
 */


#include <linux/sched.h> 
#include <linux/proc_fs.h>
#include <linux/pci.h>
#include "defs.h"

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
msg_fifo_t   Tx_Buf[MAX_CHANNELS] = {{0}};
msg_fifo_t   Rx_Buf[MAX_CHANNELS] = {{0}};

#ifdef CAN_USE_FILTER
    msg_filter_t Rx_Filter[MAX_CHANNELS] = {{0}}; 
#endif
/* used to store always the last frame sent on this channel */
canmsg_t     last_Tx_object[MAX_CHANNELS];

unsigned char *can_base[MAX_CHANNELS] = {0};	/* ioremapped adresses */
unsigned int can_range[MAX_CHANNELS] = {0};	/* ioremapped adresses */
int selfreception[MAX_CHANNELS] = {0};	/* flag indicating that selfreception
				       of frames is allowed */
int timestamp[MAX_CHANNELS] = {1};	/* flag indicating that timestamp 
				       value should assigned to rx messages */
int wakeup[MAX_CHANNELS] = {1};		/* flag indicating that leeping
				    processes are waken up in case of events */




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

#if 1
/* simply dump a memory area bytewise for n*16 addresses */
/*
 * adress - start address 
 * n      - number of 16 byte rows, 
 * offset - print every n-th byte
 */
void dump_CAN(unsigned long adress, int n, int offset)
{
int i, j;
    printk("     CAN at Adress 0x%lx\n", adress);
    for(i = 0; i < n; i++) {
	printk("     ");
	for(j = 0; j < 16; j++) {
	    /* printk("%02x ", *ptr++); */
	    printk("%02x ", readb((void __iomem *)adress));
	    adress += offset;
	}
	printk("\n");
    }
}
#endif

#ifdef CPC_PCI 
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
void can_dump(int minor)
{
int i, j;
int index = 0;

	for(i = 0; i < 2; i++) {
	    printk("0x%04x: ", Base[minor] + (i * 16));
	    for(j = 0; j < 16; j++) {
		printk("%02x ",
#ifdef  CAN_PORT_IO
		inb((int) (Base[minor] + index)) );
#else
		readb((void __iomem *) (can_base[minor] + index)) );
#endif
		/* slow_down_io(); */
		index += REG_OFFSET;
	    }
	    printk("\n");
	}
}
#endif

#ifdef CAN4LINUX_PCI
#if 0
/* reset both can controllers on the EMS-Wünsche CPC-PCI Board */
/* writing to the control range at BAR1 of the PCI board */
void reset_CPC_PCI(unsigned long address)
{
unsigned long ptr = (unsigned long)ioremap(address, 32);
    DBGin("reset_CPC_PCI");
    writeb(0x01, (void __iomem *)ptr);
}

/* check memory region if there is a CAN controller
*  assume the controller was resetted before testing 
*
*  The check for an avaliable controller is difficult !
*  After an Hardware Reset (or power on) the Conroller 
*  is in the so-called 'BasicCAN' mode.
*     we can check for: 
*         adress  name      value
*	    0x00  mode       0x21
*           0x02  status     0xc0
*           0x03  interrupt  0xe0
* Once loaded thr driver switches into 'PeliCAN' mode and things are getting
* difficult, because we now have only a 'soft reset' with not so  unique
* values. The have to be masked before comparing.
*         adress  name       mask   value
*	    0x00  mode               
*           0x01  command    0xff    0x00
*           0x02  status     0x37    0x34
*           0x03  interrupt  0xfb    0x00
*
*/
int controller_available(unsigned long address, int offset)
{
unsigned long ptr = (unsigned long)ioremap(address, 32 * offset);

    DBGin("controller_available");
    /* printk("controller_available %ld\n", address); */


    /* printk("0x%0x, ", readb(ptr + (2 * offset)) ); */
    /* printk("0x%0x\n", readb(ptr + (3 * offset)) ); */

    if ( 0x21 == readb((void __iomem *)ptr))  {
	/* compare rest values of status and interrupt register */
	if(   0x0c == readb((void __iomem *)ptr + (2 * offset))
	   && 0xe0 == readb((void __iomem *)ptr + (3 * offset)) ) {
	    return 1;
	} else {
	    return 0;
	}
    } else {
	/* may be called after a 'soft reset' in 'PeliCAN' mode */
	/*   value     address                     mask    */
	if(   0x00 ==  readb((void __iomem *)ptr + (1 * offset))
	   && 0x34 == (readb((void __iomem *)ptr + (2 * offset))    & 0x37)
	   && 0x00 == (readb((void __iomem *)ptr + (3 * offset))    & 0xfb)
	  ) {
	return 1;
    } else {
	return 0;
    }

    }
}
#endif
#endif

/*----------------------------------------------------------------------------*/
/*----------------------------------------------------------------------------*/

/*----------------------------------------------------------------------------*/
