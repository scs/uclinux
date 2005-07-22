/************************************************************
*
* Copyright (C) 2003, Motorola. All Rights Reserved
*
* FILE spi.h
* PROGRAMMER(S): J.X.Chang (jxchang@motorola.com)
*
*
* DATE OF CREATION: March 8, 2003
*
* SYNOPSIS:
*
* DESCRIPTION: It's driver of SPI in ADSP-BF533(ADI's DSP). It can
*              only be used in unix or linux.
* CAUTION:     It start with a slave, output disable working mode,
*              you may need use ioctl to change it's configuration.
**************************************************************
* MODIFICATION HISTORY:
* May   10, 2005  Modifications for irqchip framework M.Hennerich
* April 27, 2004  Modifications for ADSP-BF533 M.Hennerich
* April 22, 2004  Bug fixes M.Hennerich
* March 8, 2003   File spi.c Created.
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
#include <asm/io.h>
#include <asm/irq.h>
#include <asm/blackfin.h>


#include "spi.h"

/* definitions */

#define SPI0_REGBASE       0xffc00500

#define SPI_BUF_LEN        128
#define SPI_REGSIZE        16

#define SPI_MAJOR          252   /* experiential */
#define SPI0_MINOR         0

#define SPI_DEVNAME        "spi"
#define SPI_INT0NAME       "spiint0"  /* Should be less than 19 chars. */

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

    unsigned int     regbase;
    unsigned int     txrpos;
    unsigned int     txwpos;
    unsigned int     rxrpos;
    unsigned int     rxwpos;
    unsigned short   txbuf[SPI_BUF_LEN];
    unsigned short   rxbuf[SPI_BUF_LEN];
    struct fasync_struct *fasyc;
    wait_queue_head_t* tx_wq;
    wait_queue_head_t* rx_wq;
}spi_device_t;

/* Globals */
/* We must declare queue structure by the following macro. 
 * firstly declare 'wait_queue_head_t' and then 'init_waitqueue_head' 
 * doesn't work in 2.4.7 kernel / redhat 7.2 */
static DECLARE_WAIT_QUEUE_HEAD(spitxq0);
static DECLARE_WAIT_QUEUE_HEAD(spitxq1);
static DECLARE_WAIT_QUEUE_HEAD(spirxq0);
static DECLARE_WAIT_QUEUE_HEAD(spirxq1);

static spi_device_t spiinfo;

static int set_spi_reg(spi_device_t *pdev, unsigned int offset, unsigned short sdata);
static int get_spi_reg(spi_device_t *pdev, unsigned int offset, unsigned short *pdata);
static int txq_isfull(spi_device_t *pdev);
static int rxq_isfull(spi_device_t *pdev);

/***********************************************************
*
* FUNCTION NAME :set_spi_reg
*
* INPUTS/OUTPUTS:
* in_pdev - point to device information structure base address.
* in_offset - register address, offset to it's base.
* in_sdata - data which would be write into register.
*
* VALUE RETURNED:
* Always 0
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
static int set_spi_reg(spi_device_t *pdev, unsigned int offset, unsigned short sdata)
{

    *(unsigned short*)(pdev->regbase + offset) = sdata;
    asm("ssync;");
    return 0;
}

/***********************************************************
*
* FUNCTION NAME :get_spi_reg
*
* INPUTS/OUTPUTS:
* in_pdev - point to device information structure base address.
* in_offset - register address, offset to it's base.
* our_pdata - data which would be read from relative register.
*
* VALUE RETURNED:
* Always 0
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
static int get_spi_reg(spi_device_t *pdev, unsigned int offset, unsigned short *pdata)
{
        
    *pdata = *(unsigned short*)(pdev->regbase + offset);
    __builtin_bfin_ssync();
    return 0;
}

/***********************************************************
*
* FUNCTION NAME :txq_isfull
*
* INPUTS/OUTPUTS:
* in_pdev - point to device information structure base address.
*
* VALUE RETURNED:
* 0 Tx queue is empty
* 1 Tx queue is full
* other: A part of queue are in use.
*
* FUNCTION(S) CALLED:
*
* GLOBAL VARIABLES REFERENCED: spiinfo
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: Check whether Tx queue is full or empty
*
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/
static int txq_isfull(spi_device_t *pdev)
{
    int idlenum;
 
    idlenum = (pdev->txrpos + SPI_BUF_LEN - pdev->txwpos) % SPI_BUF_LEN;
    /* num = 1, queue is full, 0 empty, others partly used */
    return idlenum;
}

/***********************************************************
*
* FUNCTION NAME :rxq_isfull
*
* INPUTS/OUTPUTS:
* in_pdev - point to device information structure base address.
*
* VALUE RETURNED:
* 0 Rx queue is empty
* 1 Rx queue is full
* other: A part of queue are in use.
*
* FUNCTION(S) CALLED:
*
* GLOBAL VARIABLES REFERENCED: spiinfo
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: Check whether Rx queue is full or empty
*
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/
static int rxq_isfull(spi_device_t *pdev)
{
    int idlenum;

    idlenum = (pdev->rxrpos + SPI_BUF_LEN - pdev->rxwpos) % SPI_BUF_LEN;
    /* num = 1, queue is full, 0 empty, others partly used */
    return idlenum;
}

/***********************************************************
*
* FUNCTION NAME :spi_reg_reset
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
void spi_reg_reset(spi_device_t *pdev)
{
    unsigned short sdata = 0;

    /* Ctrl register */
    sdata = BIT_CTL_OPENDRAIN | BIT_CTL_PHASE;
    set_spi_reg(pdev, SPI_CTRL, sdata); /* Disable SPI, open drain */
    set_spi_reg(pdev, SPI_FLAG, 0xff00); /* Disable pin, out 3 state*/
    set_spi_reg(pdev, SPI_BAUD, SPI_DEFAULT_BARD); /* Default clock. */
    set_spi_reg(pdev, SPI_STAU, 0xffff); /* Clear all status bits.*/
}

/***********************************************************
*
* FUNCTION NAME :spi_irq
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
static irqreturn_t spi_irq(int irq, void *dev_id, struct pt_regs *regs)
{
    unsigned short regdata;
    spi_device_t *pdev = (spi_device_t*)dev_id;
    
    

    
    /* There maybe a interrupt after enable irq before sending */
    get_spi_reg(pdev, SPI_STAU, &regdata);
    if(!(regdata & 0x0001))	return IRQ_HANDLED;
        
    /* SPI interrupt is caused sending over.*/
    /* Is there any data unsend? */
    if(txq_isfull(pdev))
    {
        set_spi_reg(pdev, SPI_TXBUFF, pdev->txbuf[pdev->txrpos]);
        pdev->txrpos++;
        if(pdev->txrpos == SPI_BUF_LEN)
            pdev->txrpos = 0;
    }
    else
    {
        /* There is no data unsend, and it's a master, stop interrupt.
        --- Interrupt is cleared by writing Tx register, if we don't 
        disable this irq, interrupt always on. */
        if(pdev->master)
            disable_irq(irq);
    }
    /* Is Rx Buffer full? */
    get_spi_reg(pdev, SPI_RXBUFF, &regdata);
    if(rxq_isfull(pdev) != 1)
    {
        /* There is free space */
        pdev->rxbuf[(pdev->rxwpos)] = regdata;
        pdev->rxwpos++;
        if(pdev->rxwpos == SPI_BUF_LEN)
            pdev->rxwpos = 0;
    }
    else if(pdev->recvopt == 1)
    {
        /* There is no space and we must flush old data */
        pdev->rxbuf[(pdev->rxwpos)] = regdata;
        pdev->rxwpos++;
        if(pdev->rxwpos == SPI_BUF_LEN)
            pdev->rxwpos = 0;
        pdev->rxrpos++;
        if(pdev->rxrpos == SPI_BUF_LEN)
            pdev->rxrpos = 0;
    }
    /* Give a signal to user program. */
    if(pdev->fasyc)
        kill_fasync(&(pdev->fasyc), SIGIO, POLLIN);
        
    /* wake up read/write block. */
    wake_up_interruptible(pdev->tx_wq);
    wake_up_interruptible(pdev->rx_wq);

	return IRQ_HANDLED;
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
            get_spi_reg(pdev, SPI_CTRL, &regdata);
            if(arg)
            {
                /* Normal output */
                pdev->outenable = CFG_SPI_OUTENABLE;
                set_spi_reg(pdev, SPI_CTRL, regdata & ~BIT_CTL_OPENDRAIN);
            }
            else
            {
                /* Open drain */
                pdev->outenable = CFG_SPI_OUTDISABLE;
                set_spi_reg(pdev, SPI_CTRL, regdata | BIT_CTL_OPENDRAIN);
            }
            break;
        }
        case CMD_SPI_SET_BAUDRATE:
        {
            /* BaudRate 0,1 unavail */
            if((unsigned short)arg <= 1)
                return -EINVAL;
            /* SPI's baud rate is SCLK / ( arg * 2) */
            pdev->bdrate = (unsigned short)arg;
            set_spi_reg(pdev, SPI_BAUD, (unsigned short)arg);
            break;
        }
        case CMD_SPI_SET_POLAR:
        {
            /* Can't change clock polar when queues are not empty. */
            if((pdev->txrpos != pdev->txwpos) ||
               (pdev->rxrpos != pdev->rxwpos))
               return -EBUSY;

            get_spi_reg(pdev, SPI_CTRL, &regdata);
            if(arg)
            {
                /* Clk Active Low */
                pdev->polar = CFG_SPI_ACTLOW;
                set_spi_reg(pdev, SPI_CTRL, regdata | BIT_CTL_POLAR );
            }
            else
            {
                /* Clk Active High */
                pdev->polar = CFG_SPI_ACTHIGH;
                set_spi_reg(pdev, SPI_CTRL, regdata & ~BIT_CTL_POLAR );
            }
            break;
        }
        case CMD_SPI_SET_PHASE:
        {
            /* Can't change clock's phase when queues are not empty. */
            if((pdev->txrpos != pdev->txwpos) ||
               (pdev->rxrpos != pdev->rxwpos))
               return -EBUSY;

            get_spi_reg(pdev, SPI_CTRL, &regdata);
            if(arg)
            {
                /* Clk toggled from transferring */
                pdev->phase = CFG_SPI_PHASESTART;
                set_spi_reg(pdev, SPI_CTRL, regdata | BIT_CTL_PHASE );
            }
            else
            {
                /* Clk toggled middle transferring */
                pdev->phase = CFG_SPI_PHASEMID;
                set_spi_reg(pdev, SPI_CTRL, regdata & ~BIT_CTL_PHASE );
            }
            break;
        }
        case CMD_SPI_SET_MASTER:
        {
            /* Can't change master mode after transfering. */
            if(pdev->txrpos || pdev->txwpos || 
               pdev->rxrpos || pdev->rxwpos)
            {
                return -EBUSY;
            }
            get_spi_reg(pdev, SPI_CTRL, &regdata);
            if(arg == 0) 
            {
                pdev->master = CFG_SPI_SLAVE;
                /* Slave Mode */
                regdata &= ~BIT_CTL_MASTER;
                /* Enable SPI */
                set_spi_reg(pdev, SPI_CTRL, regdata | BIT_CTL_ENABLE);
            }
            else
            {
                pdev->master = CFG_SPI_MASTER;
                /* Change Tx mode: Writing Tx Buff causes sending. */
                regdata |= BIT_CTL_TXMOD;
                /* Master Mode */
                regdata |= BIT_CTL_MASTER;
                /* Disable Interrupt */
                //disable_irq(pdev->irqnum);
                /* Enable SPI */
                set_spi_reg(pdev, SPI_CTRL, regdata | BIT_CTL_ENABLE);
            }
            break;
        }
        case CMD_SPI_SET_SENDOPT:
        {
            get_spi_reg(pdev, SPI_CTRL, &regdata);
            if(arg)
            {
                /* Send 0 if tx buffer is empty. */
                pdev->sendopt = CFG_SPI_SENELAST;
                set_spi_reg(pdev, SPI_CTRL, regdata | BIT_CTL_SENDOPT );
            }
            else
            {
                /* Send last word if tx buffer is empty. */
                pdev->sendopt = CFG_SPI_SENDZERO;
                set_spi_reg(pdev, SPI_CTRL, regdata & ~BIT_CTL_SENDOPT );
            }
            break;
        }
        case CMD_SPI_SET_RECVOPT:
        {
            get_spi_reg(pdev, SPI_CTRL, &regdata);
            if(arg)
            {
                /* Flush received data if Rx Buffer is full */
                pdev->recvopt = CFG_SPI_RCVFLUSH;
                /*set_spi_reg(pdev, SPI_CTRL, regdata | 0x0008 );*/
            }
            else
            {
                /* Discard new data if Rx buffer is null */
                pdev->recvopt = CFG_SPI_RCVDISCARD;
                /*set_spi_reg(pdev, SPI_CTRL, regdata & ~0x0008 );*/
            }
            break;
        }
        case CMD_SPI_SET_ORDER:
        {
            /* Can't change sending order when queues are not empty. */
            if((pdev->txrpos != pdev->txwpos) ||
               (pdev->rxrpos != pdev->rxwpos))
               return -EBUSY;

            get_spi_reg(pdev, SPI_CTRL, &regdata);
            if(arg)
            {
                /* LSB first send. */
                pdev->byteorder = CFG_SPI_LSBFIRST;
                set_spi_reg(pdev, SPI_CTRL, regdata | BIT_CTL_BITORDER);
            }
            else
            {
                /* MSB first send. */
                pdev->byteorder = CFG_SPI_MSBFIRST;
                set_spi_reg(pdev, SPI_CTRL, regdata & ~BIT_CTL_BITORDER);
            }
            break;
        }
        case CMD_SPI_SET_LENGTH16:
        {
            /* Can't change word's length when queues are not empty. */
            if((pdev->txrpos != pdev->txwpos) ||
               (pdev->rxrpos != pdev->rxwpos))
               return -EBUSY;
               
            get_spi_reg(pdev, SPI_CTRL, &regdata);
            if(arg)
            {
                /* 16 bits each word, that is, 2 bytes data sent each time. */
                pdev->length = CFG_SPI_WORDSIZE16;
                set_spi_reg(pdev, SPI_CTRL, regdata | BIT_CTL_WORDSIZE);
            }
            else
            {
                /* 8 bits each word, that is, 1 byte data sent each time. */
                pdev->length = CFG_SPI_WORDSIZE8;
                set_spi_reg(pdev, SPI_CTRL, regdata & ~BIT_CTL_WORDSIZE);
            }
            break;
        }
        case CMD_SPI_MISO_ENABLE:
        {
            get_spi_reg(pdev, SPI_CTRL, &regdata);
            if(arg)
                set_spi_reg(pdev, SPI_CTRL, regdata | BIT_CTL_MISOENABLE);
            else
                set_spi_reg(pdev, SPI_CTRL, regdata & ~BIT_CTL_MISOENABLE);                     
            break;
        }
        case CMD_SPI_SET_CSAVAIL:
        {
            get_spi_reg(pdev, SPI_CTRL, &regdata);
            /* First clear CS */
            if((unsigned short)arg == 0)
                set_spi_reg(pdev, SPI_CTRL, 0xff00);
            else
                set_spi_reg(pdev, SPI_CTRL, regdata | (unsigned short)arg);
            break;
        }
        case CMD_SPI_SET_CSENABLE:
        {
        	if((arg > 7) || (arg < 1))
                return -EINVAL;
            get_spi_reg(pdev, SPI_FLAG, &regdata);
            set_spi_reg(pdev, SPI_FLAG, regdata | (unsigned short)(1 << arg));
            break;
        }
        case CMD_SPI_SET_CSDISABLE:
        {
        	if((arg > 7) || (arg < 1))
                return -EINVAL;
            get_spi_reg(pdev, SPI_FLAG, &regdata);
            set_spi_reg(pdev, SPI_FLAG, regdata & ~(unsigned short)(1 << arg));
            break;
        }
        case CMD_SPI_SET_CSLOW:
        {
        	if((arg > 7) || (arg < 1))
                return -EINVAL;
            get_spi_reg(pdev, SPI_FLAG, &regdata);
            set_spi_reg(pdev, SPI_FLAG, regdata & ~(unsigned short)((1 << arg) << 8));
            break;
        }
        case CMD_SPI_SET_CSHIGH:
        {
        	if((arg > 7) || (arg < 1))
                return -EINVAL;
            get_spi_reg(pdev, SPI_FLAG, &regdata);
            set_spi_reg(pdev, SPI_FLAG, regdata | (unsigned short)((1 << arg) << 8));
            break;
        }
        /* The following is for debug use. */
        case CMD_SPI_GET_STAT:
        {
            /* Return the status register, should be for debug use only. */
            get_spi_reg(pdev, SPI_STAU, (unsigned short*)arg);
            break;
        }
        case CMD_SPI_GET_CFG:
        {
            /* Return the ctrl register, should be for debug use only. */
            get_spi_reg(pdev, SPI_CTRL, (unsigned short*)arg);
            break;
        }
        case CMD_SPI_GET_ALLCONFIG:
        {
            unsigned short usreg;
            /*
            printk("opened: %d.\n",spiinfo.opened);
            printk("nonblock: %d.\n",spiinfo.nonblock);
            printk("master: %d.\n",spiinfo.master);
            printk("bdrate: %d.\n",spiinfo.bdrate);
            printk("outenable: %d.\n",spiinfo.outenable);
            printk("irqnum: %d.\n",spiinfo.irqnum);
            printk("length: %d.\n",spiinfo.length);
            */
            get_spi_reg(pdev, SPI_CTRL, &usreg);
            printk("Ctrl reg:0x%x.\n", usreg);
            break;
        }
        
        
        default:
            return -EINVAL;
    }
    return 0;
}

/***********************************************************
*
* FUNCTION NAME :spi_poll
*
* INPUTS/OUTPUTS:
* in_inode - Description of openned file.
*
* RETURN:
* status of current device.
*
* FUNCTION(S) CALLED:
*
* GLOBAL VARIABLES REFERENCED: spiinfo
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: It is invoked when user use system call 'poll'
*              to poll whether there are data coming or empty
*              space to sending data.
*              
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/
unsigned int spi_poll(struct file * filp, struct poll_table_struct * polltbl)
{
    unsigned int status = 0;
    spi_device_t *pdev = filp->private_data;
        
    poll_wait(filp, pdev->tx_wq, polltbl);
    poll_wait(filp, pdev->rx_wq, polltbl);
    
    if(txq_isfull(pdev) != 1)
    {
        /* There is empty space in tx queue. */
        status = POLLOUT;
    }
    if(rxq_isfull(pdev) != 0)
    {
        /* There is data in tx queue. */
        status |= POLLIN;
    }
    return status;
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
    int rxqavail, readnum, i ,readpos, ierr;
    spi_device_t *pdev = filp->private_data;

    if(count <= 0)
        return 0;

    /* Wait for data available */
    if(rxq_isfull(pdev) == 0)
    {
        if(pdev->nonblock)
            return -EAGAIN;
        else
        {
            ierr = wait_event_interruptible(*(pdev->rx_wq),
                pdev->rxwpos != pdev->rxrpos);
            if(ierr)
            {
                /* waiting is broken by a signal */
                return ierr;
            }
        }
    }

    /* How many data available? */
    rxqavail = (pdev->rxwpos + SPI_BUF_LEN - pdev->rxrpos)
            % SPI_BUF_LEN;

    if(pdev->length)
    {
        /* Since 16 bits format is select, odd count shouldn't be specified.*/
        if((count % 2) == 1)
            return -EINVAL;
        /* Data is store in 16 bits, but reading need 8 bits */ 
        if(rxqavail * 2 > count)
            readnum = count;
        else
            readnum = rxqavail * 2;
    
        readpos = pdev->rxrpos;  /* Current available data position. */

        /* 16 bits */
        for(i = 0; i < readnum; i += 2)
        {
            buf[i] = (unsigned char)pdev->rxbuf[readpos];
            buf[i+1] = (unsigned char)(pdev->rxbuf[readpos] >> 8);
            readpos++;
            if(readpos == SPI_BUF_LEN)
                readpos = 0;
        }
        pdev->rxrpos = readpos;
    }
    else
    {
        /* Data stored in 8 bits */
        if(rxqavail > count)
            readnum = count;
        else
            readnum = rxqavail;
            
        readpos = pdev->rxrpos;  /* Current available data position. */
        for(i = 0; i < readnum; i++)
        {
            buf[i] = (unsigned char)pdev->rxbuf[readpos];
            readpos++;
            if(readpos == SPI_BUF_LEN)
                readpos = 0; /* It's a recycle buffer */
        }
        pdev->rxrpos = readpos;
    }
    
    
    return readnum;
}

/***********************************************************
*
* FUNCTION NAME :spi_write
*
* INPUTS/OUTPUTS:
* in_filp - Description of openned file.
* in_count - how many bytes user wants to send.
* out_buf - where we get those sending data.
* 
* RETURN
* positive number: bytes sending out.
* 0: There is no data send out or parameter error.
* RETURN:
* >0 The actual count sending out.
* -EINVIL When word size is set to 16, writing odd bytes.
* -EAGAIN When sending mode is set to non block and there is no tx buffer.
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
*
* March 18, 2003  Fix the txqempty calculating bug.
**************************************************************/
static ssize_t spi_write (struct file *filp, const char *buf, size_t count, loff_t *f_pos)
{
    int i,ierr;
    int sendnum, txqempty;
    unsigned short regdata;
    unsigned int currpos, lastpos;
    spi_device_t *pdev = filp->private_data;

    if(count <= 0)
        return 0;

    if(txq_isfull(pdev) == 1)
    {
        if(pdev->nonblock)
            return -EAGAIN;
        else
        {
            /* Wait for tx space. This waiting would not be raced. */
            ierr = wait_event_interruptible(*(pdev->tx_wq), txq_isfull(pdev) != 1);
            if(ierr < 0)
                return ierr;
        }
    }
    /* This bug fixed. tx queue calculating wrong. 
    txqempty = (pdev->txrpos + SPI_BUF_LEN - pdev->txwpos) % SPI_BUF_LEN;
    */
    txqempty = SPI_BUF_LEN - ((pdev->txwpos + SPI_BUF_LEN 
            - pdev->txrpos) % SPI_BUF_LEN + 1);
    if(pdev->length)
    {
        /* 16 bits each word. */
        if((count % 2) == 1)
            return -EINVAL;
        /* If not so many data, only write 'count' data. */
        /* Buffer can contain SPI_BUF_LEN - 1 data. */
        if(2 * txqempty > count)
            sendnum = count;
        else
            sendnum = txqempty * 2;

        currpos = pdev->txwpos;
        for(i = 0; i < sendnum; i += 2)
        {
			pdev->txbuf[currpos] = (unsigned short)((unsigned char)(buf[i]));
			pdev->txbuf[currpos] |= (unsigned short)((unsigned char)(buf[i+1]) << 8);
            currpos++;
            if(currpos == SPI_BUF_LEN)
                currpos = 0;
        }
        pdev->txwpos = currpos;
    }
    else
    {
        /* 8 bits each word */
        if(txqempty > count)
            sendnum = count;
        else
            sendnum = txqempty;
        currpos = pdev->txwpos;
        for(i=0;i<sendnum;i++)
        {
            pdev->txbuf[currpos] = buf[i];
            currpos++;
            if(currpos == SPI_BUF_LEN)
                currpos = 0;
        }
        pdev->txwpos = currpos;
    }
    if(txqempty == (SPI_BUF_LEN - 1))
    {
        get_spi_reg(pdev, SPI_STAU, &regdata);
        if(!(regdata & BIT_STU_SENDOVER))
        {
            /* Bad news! The last sending hasn't been over. */
            /* Clear queue. */
            pdev->txwpos = pdev->txrpos;
            return -EAGAIN;
        }
        /* This is restart sending or first sending */
        if(pdev->txrpos == (SPI_BUF_LEN - 1))
        {
            lastpos = (SPI_BUF_LEN - 1);
            pdev->txrpos = 0;
        }
        else
        {
            lastpos = pdev->txrpos;
            pdev->txrpos++;
        }
        set_spi_reg(pdev, SPI_TXBUFF, pdev->txbuf[lastpos]);
        /* Open interrupt which maybe closed by IRQ for sending over.*/
        enable_irq(pdev->irqnum);
    }
    return sendnum;
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




    /* SPI 0 ? */
    if(minor != SPI0_MINOR) return -ENXIO;
    

    if(spiinfo.opened)
        return -EMFILE;
    
    /* Clear configuration information */
    memset(&spiinfo, 0, sizeof(spi_device_t));

    if(filp->f_flags & O_NONBLOCK)
        spiinfo.nonblock = 1;
/*  This way doesn't work. 
    init_waitqueue_head(&(spiinfo.tx_wq));
    init_waitqueue_head(&(spiinfo.rx_wq));
*/


    
        spiinfo.tx_wq = &spitxq0;
        spiinfo.rx_wq = &spirxq0;
        spiinfo.regbase = SPI0_REGBASE;
    
    spiinfo.opened = 1;
    spiinfo.phase = 1;
    spiinfo.bdrate = SPI_DEFAULT_BARD;
    
    strcpy(intname, SPI_INT0NAME);
    spiinfo.irqnum = SPI0_IRQ_NUM;
        

    filp->private_data = &spiinfo;
    


    spi_reg_reset(filp->private_data);
    

    
    if(request_irq(spiinfo.irqnum, spi_irq, SA_INTERRUPT, 
                   intname, filp->private_data) < 0)
    {
        printk("SPI: Can't register IRQ.\n");
        return -EFAULT;
    }

    /* Incremetn the usage count */
    MOD_INC_USE_COUNT;

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

    free_irq(pdev->irqnum, pdev);
    
    spi_reg_reset(pdev);
    pdev->opened = 0; 
    
    spi_fasync(-1, filp, 0);
    /* Decrement the usage count */
    MOD_DEC_USE_COUNT;

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


/***********************************************************
*
* FUNCTION NAME :spi_init / init_module
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
int __init spi_init(void)
#endif /* MODULE */
{
    int result;

    printk("spi0: INIT\n");
    result = register_chrdev(SPI_MAJOR, SPI_DEVNAME, &spi_fops);
    if (result < 0) 
    {
        printk(KERN_WARNING "spi0: can't get minor %d\n", SPI_MAJOR);
        return result;
    }
    return 0;
}   

__initcall(spi_init);

/***********************************************************
*
* FUNCTION NAME :spi_uninit / cleanup_module
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
void spi_uninit(void)
#endif /* MODULE */
{
    unregister_chrdev(SPI_MAJOR, SPI_DEVNAME);
    printk("<1>Goodbye spi \n");
}

