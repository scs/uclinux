/************************************************************
*
* Copyright (C) 2004, Analog Devices. All Rights Reserved
*
* FILE adsp-spiadc.c
* PROGRAMMER(S): Michael Hennerich (Analog Devices Inc.)
*
*
* DATE OF CREATION: Sept. 10th 2004
*
* SYNOPSIS:
*
* DESCRIPTION: It's driver of SPI in ADSP-BF533(ADI's DSP). It can
*              only be used in unix or linux.
* CAUTION:     you may need use ioctl to change it's configuration.
**************************************************************
* MODIFICATION HISTORY:
* Sept 10, 2004   adsp-spiadc.c Created.
************************************************************
*
* This program is free software; you can distribute it and/or modify it
* under the terms of the GNU General Public License (Version 2) as
* published by the Free Software Foundation.
*
* This program is distributed in the hope it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
* FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
* for more details.
*
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 59 Temple Place - Suite 330, Boston MA 02111-1307, USA.
*
************************************************************/
#include <linux/kernel.h> 
#include <linux/module.h> 
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/string.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/blackfin.h>
#include <asm/dma.h>

#include "adsp-spiadc.h"

/* definitions */

#undef	DEBUG
//#define DEBUG

#ifdef DEBUG
#define DPRINTK(x...)	printk(x)
#else
#define DPRINTK(x...)	do { } while (0)
#endif 



#define TOL 		       5

#define TIMEOUT		       50 


#define SPI_BUF_LEN        1024
#define SPI_REGSIZE        16

#define SPI_MAJOR          252   /* experiential */
#define SPI0_MINOR         0

#define SPI_DEVNAME       "spi"
#define SPI_INTNAME       "spiint"  /* Should be less than 19 chars. */

typedef struct Spi_Device_t
{
    int     opened;
    int     nonblock;
    int     master;
    int     bdrate;
    int     channel; /* only valid in master mode */
    int     polar;
    int     phase;
    int     outenable;
    int     irqnum;
    int     byteorder;  /* 0: MSB first; 1: LSB first; */
    int     length;     /* 0: 8 bits; 1: 16 bits */
    int     sendopt;    /* 0: Sending lastword if Txbuf Empty;
                           1: Sending 0 if Txbuf Empty; */
    int     recvopt;    /* 0: Discard packet if Rxbuffer is full;
                           1: Flush Rxbuffer if it is full; */



    unsigned char 	mode;
    unsigned char 	sense;
    unsigned char 	edge;
    unsigned short 	level;
    unsigned int     triggerpos;
    unsigned int     actcount;
    unsigned short   *buffer;
    unsigned short   done;
    unsigned short   timeout;
    struct fasync_struct *fasyc;
    wait_queue_head_t* rx_avail;
}spi_device_t;


/* Globals */
/* We must declare queue structure by the following macro. 
 * firstly declare 'wait_queue_head_t' and then 'init_waitqueue_head' 
 * doesn't work in 2.4.7 kernel / redhat 7.2 */
static DECLARE_WAIT_QUEUE_HEAD(spirxq0);

static spi_device_t spiinfo;

static int set_spi_reg(unsigned int addr, unsigned short sdata);
static int get_spi_reg(unsigned int addr, unsigned short *pdata);



/***********************************************************
*
* FUNCTION NAME :set_spi_reg
*
* INPUTS/OUTPUTS:
* in_addr  - register address.
* in_sdata - data which would be write into register.
*
* VALUE RETURNED:
* NONE
*
* FUNCTION(S) CALLED:
*
* GLOBAL VARIABLES REFERENCED: spiinfo
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: Using it set SPI's register.
*
* CAUTION:  SPI registers' address are in word aliened.

*************************************************************
* MODIFICATION HISTORY :
**************************************************************/
static set_spi_reg(unsigned int addr, unsigned short sdata)
{

    outw(sdata,addr);
    asm("ssync;");
    return;
}

/***********************************************************
*
* FUNCTION NAME :get_spi_reg
*
* INPUTS/OUTPUTS:
* in_addr  - register address.
* out_pdata - data which would be read from relative register.
*
* VALUE RETURNED:
* NONE
*
* FUNCTION(S) CALLED:
*
* GLOBAL VARIABLES REFERENCED: spiinfo
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: Using it set SPI's register.
*
* CAUTION:  SPI registers' address are in word aliened.

*************************************************************
* MODIFICATION HISTORY :
**************************************************************/
static get_spi_reg(unsigned int addr, unsigned short *pdata)
{
        
    *pdata = inw(addr);

    return 0;
}




/***********************************************************
*
* FUNCTION NAME :spiadc_reg_reset
*
* INPUTS/OUTPUTS:
* in_idev - device number , other unavailable.
* VALUE RETURNED:
* void
* 
* FUNCTION(S) CALLED:
*
* GLOBAL VARIABLES REFERENCED: 
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: Reset SPI to initialization state.
*
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/
void spiadc_reg_reset(spi_device_t *pdev)
{
    unsigned short sdata = 0;

    /* Ctrl register */
    sdata = BIT_CTL_OPENDRAIN | BIT_CTL_PHASE | BIT_CTL_TIMOD_DMA_RX;
    set_spi_reg(SPI_CTL, sdata); /* Disable SPI, open drain */
    set_spi_reg(SPI_FLG, 0xff00); /* Disable pin, out 3 state*/
    set_spi_reg(SPI_BAUD, SPI_DEFAULT_BARD); /* Default clock. */
    set_spi_reg(SPI_STAT, 0xffff); /* Clear all status bits.*/
}

/***********************************************************
*
* FUNCTION NAME :spiadc_irq
*
* INPUTS/OUTPUTS:
* in_irq - Interrupt vector number.
* in_dev_id  - point to device information structure base address.
* in_regs - unuse here.
*
* VALUE RETURNED:
* void
* 
* FUNCTION(S) CALLED:
*
* GLOBAL VARIABLES REFERENCED: spiinfo
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: ISR of SPI
*
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/



void spiadc_irq(int irq, void *dev_id, struct pt_regs *regs)
{
    unsigned short regdata;
    unsigned short i;
    spi_device_t *pdev = (spi_device_t*)dev_id;
    
    DPRINTK("spiadc_irq: \n");


*pDMA5_IRQ_STATUS |= 0x0001;

if(pdev->mode) {
	
	/* Search for trigger condition */
	

		if(pdev->sense) {
			
			/* Edge sensitive */
			
				if(pdev->edge){
					
					/* Falling edge */ 
			pdev->triggerpos=0;
			for(i=1;(i < pdev->actcount)&& !pdev->triggerpos;i++) {
		

				if((pdev->buffer[i-1]!=4095) && (pdev->buffer[i+1]!=4095)) 
				if ((pdev->buffer[i-1] > pdev->level)&&(pdev->buffer[i+1] < pdev->level)) {
					pdev->triggerpos=i;
					i=pdev->actcount; 
				};
			}
				
				
			    if(!pdev->triggerpos && pdev->timeout--) goto restartDMA;	
					
				} else {
					
					/* Rising edge */
					
			pdev->triggerpos=0;
			for(i=1;(i < pdev->actcount)&& !pdev->triggerpos;i++) {
		

				if((pdev->buffer[i-1]!=4095) && (pdev->buffer[i+1]!=4095)) 
				if ((pdev->buffer[i-1] < pdev->level)&&(pdev->buffer[i+1] > pdev->level)) {
					pdev->triggerpos=i;
					i=pdev->actcount; 
				};
			}
				
				
			    if(!pdev->triggerpos && pdev->timeout--) goto restartDMA;	
					
				};
			
		} else {
			
				if(pdev->edge){
					
					/* Falling edge */ 
			pdev->triggerpos=0;
			for(i=1;(i < pdev->actcount)&& !pdev->triggerpos;i++) {
		

				if((pdev->buffer[i-1]!=4095) && (pdev->buffer[i+1]!=4095)) 
				if ((pdev->buffer[i-1] > pdev->level)&&(pdev->buffer[i+1] < pdev->level)) {
					pdev->triggerpos=i;
					i=pdev->actcount; 
				};
			}
				
				
			    if(!pdev->triggerpos && pdev->timeout--) goto restartDMA;	
					
				} else {
					
					/* Rising edge */
					
			pdev->triggerpos=0;
			for(i=1;(i < pdev->actcount)&& !pdev->triggerpos;i++) {
		

				if((pdev->buffer[i-1]!=4095) && (pdev->buffer[i+1]!=4095)) 
				if ((pdev->buffer[i-1] < pdev->level)&&(pdev->buffer[i+1] > pdev->level)) {
					pdev->triggerpos=i;
					i=pdev->actcount; 
				};
			}
				
				
			    if(!pdev->triggerpos && pdev->timeout--) goto restartDMA;	
					
				};
		
		};
	
	
	};

	// disable spi
	set_spi_reg(SPI_CTL,0x0);

	*pDMA5_CONFIG = 0;//Disable DMA5

 	pdev->done = 1; // Found trigger
        

    /* Give a signal to user program. */
    if(pdev->fasyc)
        kill_fasync(&(pdev->fasyc), SIGIO, POLLIN);
        
    DPRINTK("spiadc_irq: wake_up_interruptible pdev->done=%d\n",pdev->done);
    /* wake up read/write block. */
    wake_up_interruptible(pdev->rx_avail);
    
    
    DPRINTK("spiadc_irq: return \n");
    return;



/* Restart DMA sequence */

restartDMA:

	// configure spi port
	// SPI DMA write, 16-bit data, MSB first, SPI Master

	*pSPI_CTL = BIT_CTL_TIMOD_DMA_RX | BIT_CTL_WORDSIZE | BIT_CTL_MASTER;	

	// Set up DMA5 
	// Map DMA5 to SPI
	*pDMA5_PERIPHERAL_MAP	= 0x5000;
	
	// Configure DMA5

	// Start address of data buffer
	*pDMA5_START_ADDR = pdev->buffer;
	// DMA inner loop count
	*pDMA5_X_COUNT = pdev->actcount*2;
	
	*pDMA5_X_MODIFY = 2;

	// enable DMAs
	*pDMA5_CONFIG = (*pDMA5_CONFIG | DMAEN );

	// enable spi
	get_spi_reg(SPI_CTL,&regdata);
	set_spi_reg(SPI_CTL, regdata | BIT_CTL_ENABLE);

	DPRINTK("spiadc_irq: return Enable Dma Again\n");
	
	return;

}


/***********************************************************
*
* FUNCTION NAME :spi_ioctl
*
* INPUTS/OUTPUTS:
* in_inode - Description of openned file.
* in_filp - Description of openned file.
* in_cmd - Command passed into ioctl system call.
* in/out_arg - It is parameters which is specified by last command
*
* RETURN:
* 0 OK
* -EINVAL  Invalid baudrate
*
* FUNCTION(S) CALLED:
*
* GLOBAL VARIABLES REFERENCED: spiinfo
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: 
* 
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/
static int spi_ioctl(struct inode *inode, struct file *filp, uint cmd, unsigned long arg)
{
    unsigned short regdata;
    spi_device_t *pdev = filp->private_data;

    switch (cmd) 
    {
        case CMD_SPI_OUT_ENABLE:
        {
            DPRINTK("spi_ioctl: CMD_SPI_OUT_ENABLE \n");
            get_spi_reg( SPI_CTL, &regdata);
            if(arg)
            {
                /* Normal output */
                pdev->outenable = CFG_SPI_OUTENABLE;
                set_spi_reg(SPI_CTL, regdata & ~BIT_CTL_OPENDRAIN);
            }
            else
            {
                /* Open drain */
                pdev->outenable = CFG_SPI_OUTDISABLE;
                set_spi_reg(SPI_CTL, regdata | BIT_CTL_OPENDRAIN);
            }
            break;
        }
        case CMD_SPI_SET_BAUDRATE:
        {
            DPRINTK("spi_ioctl: CMD_SPI_SET_BAUDRATE \n");
            /* BaudRate 0,1 unavail */
            if((unsigned short)arg <= 1)
                return -EINVAL;
            /* SPI's baud rate is SCLK / ( arg * 2) */
            pdev->bdrate = (unsigned short)arg;
            set_spi_reg(SPI_BAUD, (unsigned short)arg);
            break;
        }
        case CMD_SPI_SET_POLAR:
        {
            /* Can't change clock polar when queues are not empty. */
            
	    DPRINTK("spi_ioctl: CMD_SPI_SET_POLAR \n");
            get_spi_reg( SPI_CTL, &regdata);
            if(arg)
            {
                /* Clk Active Low */
                pdev->polar = CFG_SPI_ACTLOW;
                set_spi_reg(SPI_CTL, regdata | BIT_CTL_POLAR );
            }
            else
            {
                /* Clk Active High */
                pdev->polar = CFG_SPI_ACTHIGH;
                set_spi_reg(SPI_CTL, regdata & ~BIT_CTL_POLAR );
            }
            break;
        }
        case CMD_SPI_SET_PHASE:
        {
            /* Can't change clock's phase when queues are not empty. */
            
            DPRINTK("spi_ioctl: CMD_SPI_SET_PHASE \n");

            get_spi_reg( SPI_CTL, &regdata);
            if(arg)
            {
                /* Clk toggled from transferring */
                pdev->phase = CFG_SPI_PHASESTART;
                set_spi_reg(SPI_CTL, regdata | BIT_CTL_PHASE );
            }
            else
            {
                /* Clk toggled middle transferring */
                pdev->phase = CFG_SPI_PHASEMID;
                set_spi_reg(SPI_CTL, regdata & ~BIT_CTL_PHASE );
            }
            break;
        }
        case CMD_SPI_SET_MASTER:
        {
            
            DPRINTK("spi_ioctl: CMD_SPI_SET_MASTER \n");
            get_spi_reg( SPI_CTL, &regdata);
            if(arg == 0) 
            {
                pdev->master = CFG_SPI_SLAVE;
                /* Slave Mode */
                regdata &= ~BIT_CTL_MASTER;
                /* Enable SPI */
                set_spi_reg(SPI_CTL, regdata | BIT_CTL_ENABLE);
            }
            else
            {
                pdev->master = CFG_SPI_MASTER;
                /* Change Tx mode: Writing Tx Buff causes sending. */

                /* Master Mode */
                regdata |= BIT_CTL_MASTER;
                /* Disable Interrupt */
                //disable_irq(pdev->irqnum);
                /* Enable SPI */
                set_spi_reg(SPI_CTL, regdata | BIT_CTL_ENABLE);
            }
            break;
        }
        case CMD_SPI_SET_SENDOPT:
        {
            DPRINTK("spi_ioctl: CMD_SPI_SET_SENDOPT \n");
            get_spi_reg( SPI_CTL, &regdata);
            if(arg)
            {
                /* Send 0 if tx buffer is empty. */
                pdev->sendopt = CFG_SPI_SENELAST;
                set_spi_reg(SPI_CTL, regdata | BIT_CTL_SENDOPT );
            }
            else
            {
                /* Send last word if tx buffer is empty. */
                pdev->sendopt = CFG_SPI_SENDZERO;
                set_spi_reg(SPI_CTL, regdata & ~BIT_CTL_SENDOPT );
            }
            break;
        }
        case CMD_SPI_SET_RECVOPT:
        {
            DPRINTK("spi_ioctl: CMD_SPI_SET_RECVOPT \n");
            get_spi_reg( SPI_CTL, &regdata);
            if(arg)
            {
                /* Flush received data if Rx Buffer is full */
                pdev->recvopt = CFG_SPI_RCVFLUSH;
                /*set_spi_reg(SPI_CTL, regdata | 0x0008 );*/
            }
            else
            {
                /* Discard new data if Rx buffer is null */
                pdev->recvopt = CFG_SPI_RCVDISCARD;
                /*set_spi_reg(SPI_CTL, regdata & ~0x0008 );*/
            }
            break;
        }
        case CMD_SPI_SET_ORDER:
        {
           
	    DPRINTK("spi_ioctl: CMD_SPI_SET_ORDER \n");
            get_spi_reg( SPI_CTL, &regdata);
            if(arg)
            {
                /* LSB first send. */
                pdev->byteorder = CFG_SPI_LSBFIRST;
                set_spi_reg(SPI_CTL, regdata | BIT_CTL_BITORDER);
            }
            else
            {
                /* MSB first send. */
                pdev->byteorder = CFG_SPI_MSBFIRST;
                set_spi_reg(SPI_CTL, regdata & ~BIT_CTL_BITORDER);
            }
            break;
        }
        case CMD_SPI_SET_LENGTH16:
        {
            
            DPRINTK("spi_ioctl: CMD_SPI_SET_LENGTH16 \n");   
            get_spi_reg( SPI_CTL, &regdata);
            if(arg)
            {
                /* 16 bits each word, that is, 2 bytes data sent each time. */
                pdev->length = CFG_SPI_WORDSIZE16;
                set_spi_reg(SPI_CTL, regdata | BIT_CTL_WORDSIZE);
                *pDMA5_CONFIG = (*pDMA5_CONFIG | WDSIZE_16);
                
            }
            else
            {
                /* 8 bits each word, that is, 1 byte data sent each time. */
                pdev->length = CFG_SPI_WORDSIZE8;
                set_spi_reg(SPI_CTL, regdata & ~BIT_CTL_WORDSIZE);
            }
            break;
        }
        case CMD_SPI_MISO_ENABLE:
        {
            DPRINTK("spi_ioctl: CMD_SPI_MISO_ENABLE \n"); 
            get_spi_reg( SPI_CTL, &regdata);
            if(arg)
                set_spi_reg(SPI_CTL, regdata | BIT_CTL_MISOENABLE);
            else
                set_spi_reg(SPI_CTL, regdata & ~BIT_CTL_MISOENABLE);                     
            break;
        }
        case CMD_SPI_SET_CSAVAIL:
        {
            DPRINTK("spi_ioctl: CMD_SPI_SET_CSAVAIL \n"); 
            get_spi_reg( SPI_CTL, &regdata);
            /* First clear CS */
            if((unsigned short)arg == 0)
                set_spi_reg(SPI_CTL, 0xff00);
            else
                set_spi_reg(SPI_CTL, regdata | (unsigned short)arg);
            break;
        }
        case CMD_SPI_SET_CSENABLE:
        {
        	DPRINTK("spi_ioctl: CMD_SPI_SET_CSENABLE \n"); 
        	if((arg > 7) || (arg < 1))
                return -EINVAL;
            get_spi_reg( SPI_FLG, &regdata);
            set_spi_reg(SPI_FLG, regdata | (unsigned short)(1 << arg));
            break;
        }
        case CMD_SPI_SET_CSDISABLE:
        {
        	DPRINTK("spi_ioctl: CMD_SPI_SET_CSDISABLE \n");
        	if((arg > 7) || (arg < 1))
                return -EINVAL;
            get_spi_reg( SPI_FLG, &regdata);
            set_spi_reg(SPI_FLG, regdata & ~(unsigned short)(1 << arg));
            break;
        }
        case CMD_SPI_SET_CSLOW:
        {
        	DPRINTK("spi_ioctl: CMD_SPI_SET_CSLOW \n");
        	if((arg > 7) || (arg < 1))
                return -EINVAL;
            get_spi_reg( SPI_FLG, &regdata);
            set_spi_reg(SPI_FLG, regdata & ~(unsigned short)((1 << arg) << 8));
            break;
        }
        case CMD_SPI_SET_CSHIGH:
        {
        	DPRINTK("spi_ioctl: CMD_SPI_SET_CSHIGH \n");
        	if((arg > 7) || (arg < 1))
                return -EINVAL;
            get_spi_reg( SPI_FLG, &regdata);
            set_spi_reg(SPI_FLG, regdata | (unsigned short)((1 << arg) << 8));
            break;
        }
        /* The following is for debug use. */
        case CMD_SPI_GET_STAT:
        {
            DPRINTK("spi_ioctl: CMD_SPI_GET_STAT \n");
            /* Return the status register, should be for debug use only. */
            get_spi_reg( SPI_STAT, (unsigned short*)arg);
            break;
        }
        case CMD_SPI_GET_CFG:
        {
            DPRINTK("spi_ioctl: CMD_SPI_GET_CFG \n");
            /* Return the ctrl register, should be for debug use only. */
            get_spi_reg( SPI_CTL, (unsigned short*)arg);
            break;
        }
        case CMD_SPI_GET_ALLCONFIG:
        {
            unsigned short usreg;
            DPRINTK("spi_ioctl: CMD_SPI_GET_ALLCONFIG \n");
            
            printk("opened: %d.\n",spiinfo.opened);
            printk("nonblock: %d.\n",spiinfo.nonblock);
            printk("master: %d.\n",spiinfo.master);
            printk("bdrate: %d.\n",spiinfo.bdrate);
            printk("outenable: %d.\n",spiinfo.outenable);
            printk("irqnum: %d.\n",spiinfo.irqnum);
            printk("length: %d.\n",spiinfo.length);
            
            get_spi_reg( SPI_CTL, &usreg);
            printk("Ctrl reg:0x%x.\n", usreg);
            break;
        }
		case CMD_SPI_SET_TRIGGER_MODE:
        {
			DPRINTK("spi_ioctl: CMD_SPI_SET_TRIGGER_MODE \n");
			pdev->mode = (unsigned char)arg;
            break;
        }        
		case CMD_SPI_SET_TRIGGER_SENSE:
        {
			DPRINTK("spi_ioctl: CMD_SPI_SET_TRIGGER_SENSE \n");
			pdev->sense = (unsigned char)arg;
            break;
        } 
		case CMD_SPI_SET_TRIGGER_EDGE:
        {
			DPRINTK("spi_ioctl: CMD_SPI_SET_TRIGGER_EDGE \n");
			pdev->edge = (unsigned char)arg;
            break;
        } 
		case CMD_SPI_SET_TRIGGER_LEVEL:
        {
			DPRINTK("spi_ioctl: CMD_SPI_SET_TRIGGER_LEVEL \n");
			pdev->level = (unsigned short)arg;
            break;
        } 
                
        default:
            return -EINVAL;
    }
    return 0;
}




/***********************************************************
*
* FUNCTION NAME :spi_fasync
*
* INPUTS/OUTPUTS:
* in_fd - File descriptor of openned file.
* in_filp - Description of openned file.
*
* RETURN:
*
* FUNCTION(S) CALLED:
*
* GLOBAL VARIABLES REFERENCED: spiinfo
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: It is invoked when user changes status of sync
*              it resister a hook in system. When there is 
*              data coming, user program would get a signal.
*              
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/
static int spi_fasync(int fd, struct file *filp, int on)
{
    spi_device_t *pdev = filp->private_data;
    return fasync_helper(fd, filp, on, &(pdev->fasyc));
}

/***********************************************************
*
* FUNCTION NAME :spi_read
*
* INPUTS/OUTPUTS:
* in_filp - Description of openned file.
* in_count - how many bytes user wants to get.
* out_buf - data would be write to this address.
* 
* RETURN
* positive number: bytes read back 
* -EINVIL When word size is set to 16, reading odd bytes.
* -EAGAIN When reading mode is set to non block and there is no rx data.
*
* FUNCTION(S) CALLED:
*
* GLOBAL VARIABLES REFERENCED: spiinfo
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: It is invoked when user call 'read' system call
*              to read from system.
*              
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/
static ssize_t spi_read (struct file *filp, char *buf, size_t count, loff_t *pos)
{
    unsigned short regdata;
    int i , ierr;
    spi_device_t *pdev = filp->private_data;

DPRINTK("spi_read: \n");

    if(count <= 0)
        return 0;



    pdev->actcount = count;

    pdev->timeout = TIMEOUT;

	/* Allocate some memory */

	pdev->buffer = kmalloc(count*4,GFP_KERNEL);
	
	pdev->done=0;


	// configure spi port
    	// SPI DMA write, 16-bit data, MSB first, SPI Master
     
    	set_spi_reg(SPI_CTL,BIT_CTL_TIMOD_DMA_RX | BIT_CTL_WORDSIZE | BIT_CTL_MASTER);	

	// Set up DMA5
    	// Map DMA5 to SPI
    	*pDMA5_PERIPHERAL_MAP	= 0x5000;
    	
    	// Configure DMA5
    	// 16-bit transfers
    	*pDMA5_CONFIG = WDSIZE_16;
    
    	// Start address of data buffer
    	*pDMA5_START_ADDR = pdev->buffer;
    
    	// DMA inner loop count
    	*pDMA5_X_COUNT = 2*count;
    	
    	// Inner loop address increment
    	*pDMA5_X_MODIFY = 2;
	
	//Enable Interrupt 
   	enable_irq(pdev->irqnum);	
	
	// enable DMAs
	*pDMA5_CONFIG = (*pDMA5_CONFIG | WNR | DI_EN | DMAEN );
	
	// enable spi
	get_spi_reg(SPI_CTL,&regdata);
	set_spi_reg(SPI_CTL,regdata | BIT_CTL_ENABLE);

	
    /* Wait for data available */
    if(1)
    {
        if(pdev->nonblock)
            return -EAGAIN;
        else
        {
            DPRINTK("SPI wait_event_interruptible\n");
            ierr = wait_event_interruptible(*(pdev->rx_avail),pdev->done);
            if(ierr)
            {
                /* waiting is broken by a signal */
                printk("SPI wait_event_interruptible ierr\n");
                return ierr;
            }
        }
    }

    DPRINTK("SPI wait_event_interruptible done\n");

#ifdef DEBUG
    for (i=0; i<count; i++) printk("Val: %d \n",pdev->buffer[i]);
#endif    
    DPRINTK(" 1 = %d pdev->buffer = %x pdev->triggerpos = %x BOTH: %x \n",pdev->buffer[0],pdev->buffer,pdev->triggerpos, pdev->buffer + pdev->triggerpos);

 
    copy_to_user(buf, pdev->buffer + pdev->triggerpos + 1 , count*2); 
    kfree(pdev->buffer);
    

    DPRINTK("spi_read: return \n");
    
    return count;
}


/***********************************************************
*
* FUNCTION NAME :spi_open
*
* INPUTS/OUTPUTS:
* in_inode - Description of openned file.
* in_filp - Description of openned file.
* 
* RETURN
* 0: Open ok.
* -ENXIO  No such device
*
* FUNCTION(S) CALLED:
*
* GLOBAL VARIABLES REFERENCED: spiinfo
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: It is invoked when user call 'open' system call
*              to open spi device.
*              
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
*
* March 20, 2003  Chang Junxiao, Change request_irq the 'NULL'
*                  is changed into infomation pointer. This is
*                  a bug, the former infomation pointer is changed 
*                  into interrupt name. 
**************************************************************/
static int spi_open (struct inode *inode, struct file *filp)
{
    int idev = 0;
    char intname[20];
    int minor = MINOR (inode->i_rdev);

    DPRINTK("spi_open: \n");
    
    /* SPI ? */
    if(minor != SPI0_MINOR) return -ENXIO;
    

    if(spiinfo.opened)
        return -EMFILE;
    
    /* Clear configuration information */
    memset(&spiinfo, 0, sizeof(spi_device_t));

    if(filp->f_flags & O_NONBLOCK)
        spiinfo.nonblock = 1;

	
	    spiinfo.rx_avail = &spirxq0;
	    
	    spiinfo.opened = 1;
	    spiinfo.phase = 1;
	    spiinfo.bdrate = SPI_DEFAULT_BARD;
	    
	    strcpy(intname, SPI_INTNAME);
	    spiinfo.irqnum = SPI_IRQ_NUM;
	        
	
	    filp->private_data = &spiinfo;
	    	
	    spiadc_reg_reset(filp->private_data);
	    
    
    if(request_irq(spiinfo.irqnum, spiadc_irq, SA_INTERRUPT, 
                   intname, filp->private_data) < 0)
    {
        printk("ADSP-SPIADC: Can't register IRQ.\n");
        return -EFAULT;
    }

    /* Incremetn the usage count */
    MOD_INC_USE_COUNT;

    DPRINTK("spi_open: return \n");
    
    return 0;
}

/***********************************************************
*
* FUNCTION NAME :spi_release
*
* INPUTS/OUTPUTS:
* in_inode - Description of openned file.
* in_filp - Description of openned file.
* 
* RETURN
* Always 0
*
* FUNCTION(S) CALLED:
*
* GLOBAL VARIABLES REFERENCED: spiinfo
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: It is invoked when user call 'close' system call
*              to close device.
*              
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/
static int spi_release (struct inode *inode, struct file *filp)
{
    spi_device_t *pdev = filp->private_data;

    DPRINTK("spi_release: close() \n");
    
    free_irq(pdev->irqnum, pdev);
    
    spiadc_reg_reset(pdev);
    pdev->opened = 0; 
    
    spi_fasync(-1, filp, 0);
    /* Decrement the usage count */
    MOD_DEC_USE_COUNT;

    DPRINTK("spi_release: close() return \n");
    return 0;
}

static struct file_operations spi_fops = {
    owner:      THIS_MODULE,
    read:       spi_read,
    ioctl:      spi_ioctl,
    open:       spi_open,
    release:    spi_release,
    fasync:     spi_fasync,
};


/***********************************************************
*
* FUNCTION NAME :spiadc_init / init_module
*                
* INPUTS/OUTPUTS:
* 
* RETURN:
* 0 if module init ok.
* -1 init fail.
*
* FUNCTION(S) CALLED:
*
* GLOBAL VARIABLES REFERENCED: spiinfo
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: It will be invoked when using 'insmod' command.
*              or invoke it directly if spi module is needed.
*
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/
#ifdef MODULE
int init_module(void)
#else 
int __init spiadc_init(void)
#endif /* MODULE */
{
    int result;

    
    result = register_chrdev(SPI_MAJOR, SPI_DEVNAME, &spi_fops);
    if (result < 0) 
    {
        printk(KERN_WARNING "SPI: can't get minor %d\n", SPI_MAJOR);
        return result;
    }
    printk("SPI: ADSP SPI-ADC Driver INIT IRQ:%d \n",SPI_IRQ_NUM);
    return 0;
}   

__initcall(spiadc_init);

/***********************************************************
*
* FUNCTION NAME :spiadc_uninit / cleanup_module
*                
* INPUTS/OUTPUTS:
* 
* RETURN:
*
* FUNCTION(S) CALLED:
*
* GLOBAL VARIABLES REFERENCED: spiinfo
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: It will be invoked when using 'rmmod' command.
*              or, you invoke it directly when it needs remove
*              spi module.
*              
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/
#ifdef MODULE
void cleanup_module(void)
#else
void spiadc_uninit(void)
#endif /* MODULE */
{
    unregister_chrdev(SPI_MAJOR, SPI_DEVNAME);
    printk("<1>Goodbye SPI \n");
}





