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
* DESCRIPTION: SPI-ADC/DAC Driver for ADSP-BF533/2/1. It can
*              only be used in linux.
* CAUTION:     you may need use ioctl to change it's configuration.
**************************************************************
* MODIFICATION HISTORY:
* Sept 10, 2004   adsp-spiadc.c Created. (Michael Hennerich)
* May 24, 2005    Added waitqueue and interrupt for write (Michael Hennerich)
*                 Removed obsolete code fragment form ioctl
*                 Changed read / write count to always be in bytes
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
#include <asm/cacheflush.h>

#include <asm/dma.h>
#include "bfin_spi_channel.h"

/* definitions */

//#define MODULE

#undef	DEBUG
//#define DEBUG

#ifdef DEBUG
#define DPRINTK(x...)	printk(x)
#else
#define DPRINTK(x...)	do { } while (0)
#endif 

#define SKFS			   4  /* number of first samples to skip */

#define TOL 		       5

#define TIMEOUT		       50 


#define SPI_BUF_LEN        1024
#define SPI_REGSIZE        16

#define SPI_MAJOR          252   /* experiential */
#define SPI0_MINOR         0

#define SPI_DEVNAME       "SPI"
#define SPI_INTNAME       "SPIINT"  /* Should be less than 19 chars. */

typedef struct Spi_Info_t
{
	int     opened;
	int     nonblock;

	spi_device_t spi_dev;

	unsigned char 	mode;
	unsigned short  access_mode;
	unsigned char 	sense;
	unsigned char 	edge;
	unsigned char 	cont;
	unsigned short 	level;
	unsigned int     triggerpos;
	unsigned int     actcount;
	unsigned short   *buffer;
	unsigned short   done;
	int timeout;
	struct fasync_struct *fasyc;
	wait_queue_head_t* rx_avail;
}spi_info_t;


/* Globals */
/* We must declare queue structure by the following macro. 
 * firstly declare 'wait_queue_head_t' and then 'init_waitqueue_head' 
 * doesn't work in 2.4.7 kernel / redhat 7.2 */
static DECLARE_WAIT_QUEUE_HEAD(spirxq0);

static spi_info_t spiinfo;
static u_long spi_get_sclk(void);


static u_long spi_get_sclk(void)
{
	u_long sclk=0,vco;
	
	vco = (CONFIG_CLKIN_HZ) * ((*pPLL_CTL >> 9)& 0x3F);

	if (1 & *pPLL_CTL) /* DR bit */
		vco >>= 1;

	if((*pPLL_DIV & 0xf) != 0)
		sclk = vco/(*pPLL_DIV & 0xf);
	else
		printk("Invalid System Clock\n");	

	return (sclk);
}


static irqreturn_t spiadc_irq(int irq, void *dev_id, struct pt_regs *regs)
{
	unsigned short i;
	spi_info_t *pdev = (spi_info_t*)dev_id;
	
	DPRINTK("spiadc_irq: \n");
	
        /* Acknowledge DMA Interrupt*/
	spi_clear_irqstat(&(pdev->spi_dev));
	
	if (pdev->access_mode == SPI_WRITE) goto irq_done;
	
	pdev->triggerpos=0;
	
	if(pdev->mode) {
		/* Search for trigger condition */
		if(pdev->sense) {
			/* Edge sensitive */
			if(pdev->edge){
				/* Falling edge */ 
				pdev->triggerpos=0;
				for(i=1+SKFS;(i < pdev->actcount)&& !pdev->triggerpos;i++) {
					
					if ((pdev->buffer[i-1] > pdev->level)&&(pdev->buffer[i+1] < pdev->level)) {
						pdev->triggerpos=i;
						i=pdev->actcount; 
					};
				}
				if(!pdev->triggerpos && pdev->timeout--) goto restartDMA;	
				
			} else {
				/* Rising edge */
				pdev->triggerpos=0;
				for(i=1+SKFS;(i < pdev->actcount)&& !pdev->triggerpos;i++) {
					
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
				for(i=1+SKFS;(i < pdev->actcount)&& !pdev->triggerpos;i++) {
					if ((pdev->buffer[i-1] > pdev->level)&&(pdev->buffer[i+1] < pdev->level)) {
						pdev->triggerpos=i;
						i=pdev->actcount; 
					};
				}
				if(!pdev->triggerpos && pdev->timeout--) goto restartDMA;	
			} else {
				/* Rising edge */
				pdev->triggerpos=0;
				for(i=1+SKFS;(i < pdev->actcount)&& !pdev->triggerpos;i++) {
					if ((pdev->buffer[i-1] < pdev->level)&&(pdev->buffer[i+1] > pdev->level)) {
						pdev->triggerpos=i;
						i=pdev->actcount; 
					};
				}
				
				if(!pdev->triggerpos && pdev->timeout--) goto restartDMA;	
			};
		};
	};
	
	
 irq_done:

	spi_disable(&(pdev->spi_dev));
	
 	pdev->done = 1; // Found trigger
	/* Give a signal to user program. */
	if(pdev->fasyc)
		kill_fasync(&(pdev->fasyc), SIGIO, POLLIN);
	
	DPRINTK("spiadc_irq: wake_up_interruptible pdev->done=%d\n",pdev->done);
	/* wake up read/write block. */
	
	wake_up_interruptible(pdev->rx_avail);
        
	DPRINTK("spiadc_irq: return \n");
	return IRQ_HANDLED;
	
/* Restart DMA sequence */
 restartDMA:
	
	spi_disable(&(pdev->spi_dev));
	spi_enable(&(pdev->spi_dev));
	
	DPRINTK("spiadc_irq: return Enable Dma Again\n");
	return IRQ_HANDLED;
}


static int spi_ioctl(struct inode *inode, struct file *filp, uint cmd, unsigned long arg)
{
	unsigned long value;
	spi_info_t *pdev = filp->private_data;
	
	switch (cmd) 
	{
        case CMD_SPI_OUT_ENABLE:
        {
		DPRINTK("spi_ioctl: CMD_SPI_OUT_ENABLE \n");
		if(arg)
		{
			/* Normal output */
			pdev->spi_dev.out_opendrain = CFG_SPI_OUTENABLE;
		}
		else
		{
			/* Open drain */
			pdev->spi_dev.out_opendrain = CFG_SPI_OUTDISABLE;
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
		pdev->spi_dev.bdrate = (unsigned short)arg;
		break;
        }
        case CMD_SPI_SET_POLAR:
        {
		/* Can't change clock polar when queues are not empty. */
		
		DPRINTK("spi_ioctl: CMD_SPI_SET_POLAR \n");
		if(arg)
		{
			/* Clk Active Low */
			pdev->spi_dev.polar = CFG_SPI_ACTLOW;
		}
		else
		{
			/* Clk Active High */
			pdev->spi_dev.polar = CFG_SPI_ACTHIGH;
		}
		break;
        }
        case CMD_SPI_SET_PHASE:
        {
		/* Can't change clock's phase when queues are not empty. */
		
		DPRINTK("spi_ioctl: CMD_SPI_SET_PHASE \n");
		
		if(arg)
		{
			/* Clk toggled from transferring */
			pdev->spi_dev.phase = CFG_SPI_PHASESTART;
		}
		else
		{
			/* Clk toggled middle transferring */
			pdev->spi_dev.phase = CFG_SPI_PHASEMID;
		}
		break;
        }
        case CMD_SPI_SET_MASTER:
        {
		
		DPRINTK("spi_ioctl: CMD_SPI_SET_MASTER \n");
		if(arg == 0) 
		{
			pdev->spi_dev.master = CFG_SPI_SLAVE;
		}
		else
		{
			pdev->spi_dev.master = CFG_SPI_MASTER;
		}
		break;
        }
        case CMD_SPI_SET_SENDOPT:
        {
		DPRINTK("spi_ioctl: CMD_SPI_SET_SENDOPT \n");
		if(arg)
		{
			/* Send 0 if tx buffer is empty. */
			pdev->spi_dev.send_zero = CFG_SPI_SENELAST;
		}
		else
		{
			/* Send last word if tx buffer is empty. */
			pdev->spi_dev.send_zero = CFG_SPI_SENDZERO;
		}
		break;
        }
        case CMD_SPI_SET_RECVOPT:
        {
		DPRINTK("spi_ioctl: CMD_SPI_SET_RECVOPT \n");
		if(arg)
		{
			/* Flush received data if Rx Buffer is full */
			pdev->spi_dev.more_data = CFG_SPI_RCVFLUSH;
		}
		else
		{
			/* Discard new data if Rx buffer is null */
			pdev->spi_dev.more_data = CFG_SPI_RCVDISCARD;
		}
		break;
        }
        case CMD_SPI_SET_ORDER:
        {
		
		DPRINTK("spi_ioctl: CMD_SPI_SET_ORDER \n");
		if(arg)
		{
			/* LSB first send. */
			pdev->spi_dev.byteorder = CFG_SPI_LSBFIRST;
		}
		else
		{
			/* MSB first send. */
			pdev->spi_dev.byteorder = CFG_SPI_MSBFIRST;
		}
		break;
        }
        case CMD_SPI_SET_LENGTH16:
        {
		
		DPRINTK("spi_ioctl: CMD_SPI_SET_LENGTH16 \n");   
		if(arg)
		{
			/* 16 bits each word, that is, 2 bytes data sent each time. */
			pdev->spi_dev.size = CFG_SPI_WORDSIZE16;
			pdev->spi_dev.dma_config |= WDSIZE_16;
			
		}
		else
		{
			/* 8 bits each word, that is, 1 byte data sent each time. */
			pdev->spi_dev.size = CFG_SPI_WORDSIZE8;
			pdev->spi_dev.dma_config &= ~WDSIZE_16;
		}
		break;
        }
	case CMD_SPI_MISO_ENABLE:
        {
		DPRINTK("spi_ioctl: CMD_SPI_MISO_ENABLE \n"); 
		if(arg)
			pdev->spi_dev.emiso = CFG_SPI_MISOENABLE;
		else
			pdev->spi_dev.emiso = CFG_SPI_MISODISABLE;
		break;
        }
        case CMD_SPI_SET_CSENABLE:
        {
        	DPRINTK("spi_ioctl: CMD_SPI_SET_CSENABLE \n"); 
        	if((arg > 7) || (arg < 1))
			return -EINVAL;
		pdev->spi_dev.flag |= (unsigned short)(1 << arg);
		break;
        }
	case CMD_SPI_SET_CSDISABLE:
	{
		DPRINTK("spi_ioctl: CMD_SPI_SET_CSDISABLE \n");
		if((arg > 7) || (arg < 1))
			return -EINVAL;
		pdev->spi_dev.flag &= ~(unsigned short)(1 << arg);
		break;
        }
	case CMD_SPI_SET_CSLOW:
	{
		DPRINTK("spi_ioctl: CMD_SPI_SET_CSLOW \n");
		if((arg > 7) || (arg < 1))
			return -EINVAL;
		pdev->spi_dev.flag &=  ~(unsigned short)((1 << arg) << 8);
		break;
	}
	case CMD_SPI_SET_CSHIGH:
	{
		DPRINTK("spi_ioctl: CMD_SPI_SET_CSHIGH \n");
		if((arg > 7) || (arg < 1))
			return -EINVAL;
		pdev->spi_dev.flag |= (unsigned short)((1 << arg) << 8);
		break;
	}
        /* The following is for debug use. */
	case CMD_SPI_GET_STAT:
        {
		DPRINTK("spi_ioctl: CMD_SPI_GET_STAT \n");
		/* Return the status register, should be for debug use only. */
		spi_get_stat((unsigned short*)arg);
		break;
        }
        case CMD_SPI_GET_CFG:
        {
		DPRINTK("spi_ioctl: CMD_SPI_GET_CFG \n");
		/* Return the ctrl register, should be for debug use only. */
		spi_get_ctl((unsigned short*)arg);
		break;
        }
	case CMD_SPI_GET_ALLCONFIG:
	{
		unsigned short usreg;
		DPRINTK("spi_ioctl: CMD_SPI_GET_ALLCONFIG \n");
		
		printk("opened: %d.\n",pdev->opened);
		printk("nonblock: %d.\n",pdev->nonblock);
		printk("master: %d.\n",pdev->spi_dev.master);
		printk("bdrate: %d.\n",pdev->spi_dev.bdrate);
		printk("outenable: %d.\n",pdev->spi_dev.out_opendrain);
		printk("length: %d.\n",pdev->spi_dev.size);
		
		spi_get_ctl(&usreg);
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
	case CMD_SPI_GET_SYSTEMCLOCK:
	{
		value = spi_get_sclk();
#ifdef DEBUG
		printk("spi_ioctl: CMD_SPI_GET_SYSTEMCLOCK SCLK: %d \n", value);	
#endif
		copy_to_user((unsigned long *)arg, &value, sizeof(unsigned long));                
		break;
	}
	case CMD_SPI_SET_WRITECONTINUOUS:
	{
		DPRINTK("spi_ioctl: CMD_SPI_SET_WRITECONTINUOUS \n");
		pdev->cont = (unsigned char)arg;
		if(arg)
		{
			pdev->spi_dev.dma_config |=  (FLOW_AUTO << 12);	
		}
		else
		{
			pdev->spi_dev.dma_config &=  ~(FLOW_AUTO << 12);	            
		}
		break;
	} 
	default:
		return -EINVAL;
	}
	
	spi_set_ctl(&(pdev->spi_dev));
	return 0;
}



static int spi_fasync(int fd, struct file *filp, int on)
{
    spi_info_t *pdev = filp->private_data;
    return fasync_helper(fd, filp, on, &(pdev->fasyc));
}


static ssize_t spi_read (struct file *filp, char *buf, size_t count, loff_t *pos)
{
	int ierr;
	spi_info_t *pdev = filp->private_data;
	
	DPRINTK("spi_read: \n");
	
	if(count <= 0)
		return 0;

	pdev->actcount = count;
	pdev->timeout = TIMEOUT;
	pdev->done=0;

	/* Allocate some memory */
	pdev->buffer = kmalloc((count+SKFS*2)*2,GFP_KERNEL); // TODO: change GFP_KERNEL to GFP_DMA as soon as it is available


	/* Invalidate allocated memory in Data Cache */ 
	// TODO: remove this line as soon GFP_DMA memory allocation is in place 
	blackfin_dcache_invalidate_range((unsigned long)pdev->buffer,((unsigned long) pdev->buffer)+(count+SKFS*2)*2); 

	spi_dma_read(&(pdev->spi_dev), pdev->buffer, (count+SKFS));

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
	int i;
	for (i=0; i<count; i++) printk("Val: %d \n",pdev->buffer[i]);   
	printk(" 1 = %d pdev->buffer = %x pdev->triggerpos = %x BOTH: %x \n",pdev->buffer[0],pdev->buffer,pdev->triggerpos, pdev->buffer + pdev->triggerpos);
#endif 

	if(!(pdev->timeout < 0) && (!pdev->triggerpos))
		copy_to_user(buf, pdev->buffer + SKFS, count);
	else 
		copy_to_user(buf, pdev->buffer + pdev->triggerpos, count);

	kfree(pdev->buffer);
	
	DPRINTK(" timeout = %d \n",pdev->timeout);
	DPRINTK("spi_read: return \n");
	if(pdev->timeout < 0) 
		return SPI_ERR_TRIG;
	
	return count;
}

static ssize_t spi_write (struct file *filp, const char *buf, size_t count, loff_t *f_pos)
{
    int ierr;
    spi_info_t *pdev = filp->private_data;

	DPRINTK("spi_write: \n");

    if(count <= 0)
        return 0;

    pdev->actcount = count;
    pdev->timeout = TIMEOUT;
    pdev->done=0;

    blackfin_dcache_flush_range((unsigned long)buf,((unsigned long)buf+(count)));
		
    if(! pdev->cont)
	    pdev->spi_dev.dma_config |= ( DI_EN );

    
    spi_dma_write(&(pdev->spi_dev), (unsigned long *)buf, count);
	

    /* Wait for DMA finished */
    if(!pdev->cont)
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
    
    DPRINTK("spi_write: return \n");
    
    return count;
}


static int spi_open (struct inode *inode, struct file *filp)
{
    int minor = MINOR (inode->i_rdev);

    DPRINTK("spi_open: \n");
    
    /* SPI ? */
    if(minor != SPI0_MINOR) return -ENXIO;

    if(spiinfo.opened)
        return -EMFILE;
    
    /* Clear configuration information */
    memset(&spiinfo, 0, sizeof(spi_info_t));

    if(filp->f_flags & O_NONBLOCK)
        spiinfo.nonblock = 1;
	
    spiinfo.rx_avail = &spirxq0;	    
    spiinfo.opened = 1;
    spiinfo.cont = 0;

    /* prepare data for spi control registers */
    spiinfo.spi_dev.bdrate = SPI_DEFAULT_BARD;
    strcpy(spiinfo.spi_dev.dev_name, SPI_INTNAME);
    spiinfo.spi_dev.out_opendrain = CFG_SPI_OUTENABLE;
    spiinfo.spi_dev.phase = CFG_SPI_PHASESTART;
    spiinfo.spi_dev.flag = 0xff00;
    spiinfo.spi_dev.dma = 1;
    spiinfo.spi_dev.irq_handler = spiadc_irq;
   
    filp->private_data = &spiinfo;
    
    /* request spi channel and set spi control regs */
    spi_channel_request(&(spiinfo.spi_dev));
	
    DPRINTK("spi_open: return \n");
    return 0;
}

static int spi_release (struct inode *inode, struct file *filp)
{
    spi_info_t *pdev = filp->private_data;

    DPRINTK("spi_release: close() \n");

    spi_channel_release(&(pdev->spi_dev));

    pdev->opened = 0; 
    
    spi_fasync(-1, filp, 0);

    DPRINTK("spi_release: close() return \n");
    return 0;
}

static struct file_operations spi_fops = {
    owner:      THIS_MODULE,
    read:       spi_read,
    write:      spi_write,
    ioctl:      spi_ioctl,
    open:       spi_open,
    release:    spi_release,
    fasync:     spi_fasync,
};


//#ifdef MODULE
//int init_module(void)
//#else 

int __init spiadc_init(void)
//#endif /* MODULE */
{
    int result;

    
    result = register_chrdev(SPI_MAJOR, SPI_DEVNAME, &spi_fops);
    if (result < 0) 
    {
        printk(KERN_WARNING "SPI: can't get minor %d\n", SPI_MAJOR);
        return result;
    }

    printk("SPI: ADSP SPI-ADC Driver INIT IRQ:%d \n",SPI0_IRQ_NUM);
    return 0;
}   
//#ifndef MODULE
//__initcall(spiadc_init);
//#endif

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
//#ifdef MODULE
//void cleanup_module(void)
//#else
void spiadc_uninit(void)
//#endif /* MODULE */
{
    unregister_chrdev(SPI_MAJOR, SPI_DEVNAME);
    printk("<1>Goodbye SPI \n");

}

module_init(spiadc_init);
module_exit(spiadc_uninit);

MODULE_AUTHOR("Michael Hennerich");
MODULE_LICENSE("GPL");




