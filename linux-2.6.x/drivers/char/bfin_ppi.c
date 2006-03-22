/************************************************************
*
* Copyright (C) 2004, Analog Devices. All Rights Reserved
* Copyright (C) 2005, Eastman Kodak Company. All Rights Reserved
*
* FILE ppi.c
* PROGRAMMER(S): John DeHority (john.dehority@NOSPAM@kodak.com
*
*
* DATE OF CREATION: May 5, 2005
*
* SYNOPSIS:
*
* DESCRIPTION: PPI Input Driver for ADSP-BF533
*              It can only be used in linux.
* CAUTION:     you need to use ioctl to change configuration.
**************************************************************
* MODIFICATION HISTORY:
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
#include <linux/delay.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/blackfin.h>
#include <asm/dma.h>
#include <asm/cacheflush.h>

#include <asm/bf533_timers.h>

#include "ppi.h"

/* definitions */

//#define MODULE

#undef	DEBUG
//#define DEBUG

#ifdef DEBUG
#define DPRINTK(x...)	printk(x)
#else
#define DPRINTK(x...)	do { } while (0)
#endif 

#define PPI_MAJOR          241   /* experiential */
#define PPI0_MINOR         0

#define PPI_DEVNAME       "ppi"
#define PPI_INTNAME       "ppiint"  /* Should be less than 19 chars. */


typedef struct Ppi_Device_t
{
    unsigned char     	opened;
	unsigned char		nonblock;
    unsigned char     	portenable;
	unsigned char		datalen;
	unsigned char		triggeredge;

    unsigned char 	cont;
	unsigned char	dimensions;		//1D or 2D
	unsigned short	delay;
	unsigned short	access_mode;
    unsigned short   *buffer;
    unsigned short   done;
    unsigned short 	 dma_config;
	unsigned short	linelen;
	unsigned short	numlines;
	unsigned short	ppi_control;
    int     irqnum;
    struct fasync_struct *fasyc;
    wait_queue_head_t* rx_avail;
}ppi_device_t;


/* Globals */
/* We must declare queue structure by the following macro. 
 * firstly declare 'wait_queue_head_t' and then 'init_waitqueue_head' 
 * doesn't work in 2.4.7 kernel / redhat 7.2 */
static DECLARE_WAIT_QUEUE_HEAD(ppi_wq0);

static ppi_device_t ppiinfo;
static int get_ppi_reg(unsigned int addr, unsigned short *pdata);

/***********************************************************
*
* FUNCTION NAME :get_ppi_reg
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
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: Using it set PPI's register.
*
* CAUTION:  PPI registers' address are in word aliened.

*************************************************************
* MODIFICATION HISTORY :
**************************************************************/
static int 
get_ppi_reg(unsigned int addr, unsigned short *pdata)
{
        
    *pdata = inw(addr);

    return 0;
}

/***********************************************************
*
* FUNCTION NAME :ppi_reg_reset
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
* DESCRIPTION: Reset PPI to initialization state.
*
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/
void 
ppi_reg_reset(ppi_device_t *pdev)
{

	*pPPI_CONTROL = 0x0000; 
    *pPPI_STATUS =  0x0000; 
    *pPPI_COUNT =  0x0000; 
    *pPPI_FRAME =  0x0000;
    *pPPI_DELAY =  0x0000;
}

/***********************************************************
*
* FUNCTION NAME :ppi_irq
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
* GLOBAL VARIABLES REFERENCED: ppiinfo
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: ISR of PPI
*
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/

static irqreturn_t 
ppi_irq(int irq, void *dev_id, struct pt_regs *regs)
{
    unsigned short regdata;
    ppi_device_t *pdev = (ppi_device_t*)dev_id;
    
    DPRINTK("ppi_irq: \n");
	get_ppi_reg(DMA0_IRQ_STATUS, &regdata);


	if ( ! (regdata & DMA_DONE) ){
		DPRINTK("DMA0_IRQ_STATUS = %X\n", regdata);
	}

	clear_dma_irqstat(CH_PPI);

	pdev->done = 1;

	if ( pdev->access_mode == PPI_WRITE )
		disable_gptimers( (TIMER1bit | TIMER2bit) );

	// disable ppi
	get_ppi_reg(PPI_CONTROL,&regdata);
	*pPPI_CONTROL =  pdev->ppi_control = regdata & ~PORT_EN;

	// disable DMA
	disable_dma(CH_PPI);

    /* Give a signal to user program. */
    if(pdev->fasyc)
        kill_fasync(&(pdev->fasyc), SIGIO, POLLIN);
    
    /* wake up read/write block. */
    wake_up_interruptible(pdev->rx_avail);
        
    DPRINTK("ppi_irq: return \n");

    return IRQ_HANDLED;
}


/***********************************************************
*
* FUNCTION NAME :ppi_ioctl
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
* GLOBAL VARIABLES REFERENCED: ppiinfo
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: 
* 
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/
static int 
ppi_ioctl(struct inode *inode, struct file *filp, uint cmd, unsigned long arg)
{
    unsigned short regdata;
    ppi_device_t *pdev = filp->private_data;

    switch (cmd) 
    {
        case CMD_PPI_PORT_ENABLE:
        {
            DPRINTK("ppi_ioctl: CMD_PPI_PORT_ENABLE \n");
            get_ppi_reg( PPI_CONTROL, &regdata);
			pdev->portenable = (unsigned short)arg;
            if(arg)
                regdata |= PORT_EN;
            else 
                regdata &= ~PORT_EN;
			*pPPI_CONTROL = pdev->ppi_control = regdata;
            break;
        }
        case CMD_PPI_PORT_DIRECTION:
        {
            DPRINTK("ppi_ioctl: CMD_PPI_PORT_DIRECTION\n");
            get_ppi_reg( PPI_CONTROL, &regdata);
            if(arg)
                regdata |= PORT_DIR;
            else 
                regdata &= ~PORT_DIR;
			*pPPI_CONTROL = pdev->ppi_control = regdata;
            break;
        }
		case CMD_PPI_XFR_TYPE:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_XFR_TYPE\n");
			if (arg < 0  || arg > 3)
				return -EINVAL;
			get_ppi_reg( PPI_CONTROL, &regdata);
			regdata &= ~XFR_TYPE;
			regdata |= ((unsigned short)arg << 2);
			*pPPI_CONTROL = pdev->ppi_control = regdata;
			break;
		}
		case CMD_PPI_PORT_CFG:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_PORT_CFG\n");
			if (arg < 0  || arg > 3)
				return -EINVAL;
			get_ppi_reg( PPI_CONTROL, &regdata);
			regdata &= ~PORT_CFG;
			regdata |= ((unsigned short)arg << 4);
			*pPPI_CONTROL = pdev->ppi_control = regdata;
			break;
		}
		case CMD_PPI_FIELD_SELECT:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_FIELD_SELECT\n");
			get_ppi_reg( PPI_CONTROL, &regdata);
            if(arg)
                regdata |= FLD_SEL;
            else 
                regdata &= ~FLD_SEL;
			*pPPI_CONTROL =  pdev->ppi_control = regdata;
			break;
		}
		case CMD_PPI_PACKING:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_PACKING\n");
			get_ppi_reg( PPI_CONTROL, &regdata);
            if(arg)
                regdata |= PACK_EN;
            else 
                regdata &= ~PACK_EN;
			*pPPI_CONTROL =  pdev->ppi_control = regdata;
			break;
		}
		case CMD_PPI_SKIPPING:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_SKIPPING\n");
			get_ppi_reg( PPI_CONTROL, &regdata);
            if(arg)
                regdata |= SKIP_EN;
            else 
                regdata &= ~SKIP_EN;
			*pPPI_CONTROL =  pdev->ppi_control = regdata;
			break;
		}
		case CMD_PPI_SKIP_ODDEVEN:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_SKIP_ODDEVEN\n");
			get_ppi_reg( PPI_CONTROL, &regdata);
            if(arg)
                regdata |= SKIP_EO;
            else 
                regdata &= ~SKIP_EO;
			*pPPI_CONTROL =  pdev->ppi_control = regdata;
			break;
		}
		case CMD_PPI_DATALEN:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_DATALEN\n");
			if (arg < 0  || arg > 7)
				return -EINVAL;
			pdev->datalen = (unsigned short)arg;
			get_ppi_reg( PPI_CONTROL, &regdata);
			regdata &= ~DLENGTH;
			regdata |= (arg << 11);
			*pPPI_CONTROL =  pdev->ppi_control = regdata;
			break;
		}
		case CMD_PPI_CLK_EDGE:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_CLK_EDGE\n");
			get_ppi_reg( PPI_CONTROL, &regdata);
            if(arg)
                regdata |= POLC;
            else 
                regdata &= ~POLC;
			*pPPI_CONTROL =  pdev->ppi_control = regdata;
			break;
		}
		case CMD_PPI_TRIG_EDGE:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_TRIG_EDGE\n");
			pdev->triggeredge = (unsigned short)arg;
			get_ppi_reg( PPI_CONTROL, &regdata);
            if(arg)
                regdata |= POLFS;
            else 
                regdata &= ~POLFS;
			*pPPI_CONTROL =  pdev->ppi_control = regdata;
			break;
		}
		case CMD_PPI_LINELEN:
		{
			DPRINTK("ppi_ioctl:  CMD_PPI_LINELEN\n");
			if (arg < 0  || arg > PPI_DMA_MAXSIZE)
				return -EINVAL;
			pdev->linelen = (unsigned short)arg;
			break;
		}
		case CMD_PPI_NUMLINES:
		{
			DPRINTK("ppi_ioctl:  CMD_PPI_NUMLINES\n");
			if (arg < 0  || arg > PPI_DMA_MAXSIZE)
				return -EINVAL;
			pdev->numlines = (unsigned short)arg;
			break;

		}
		case CMD_PPI_SET_WRITECONTINUOUS:
		{
			DPRINTK("ppi_ioctl:  CMD_PPI_SET_WRITECONTINUOUS\n");
			pdev->cont = (unsigned char)arg;
			break;

		}
		case CMD_PPI_SET_DIMS:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_SET_DIMS\n");
			pdev->dimensions = (unsigned char)arg;
			break;
		}

		case CMD_PPI_DELAY:
		{	DPRINTK("ppi_ioctl: CMD_PPI_DELAY\n");
			pdev->delay = (unsigned short)arg;
			break;
		}

#ifdef DEBUG
        case CMD_PPI_GET_ALLCONFIG:
        {
            unsigned short usreg;
            DPRINTK("ppi_ioctl: CMD_PPI_GET_ALLCONFIG \n");
            
            printk("opened: %d.\n",ppiinfo.opened);
            printk("portenable: %d.\n",ppiinfo.portenable);
			printk("nonblock: %d.\n", ppiinfo.nonblock);
            printk("irqnum: %d.\n",ppiinfo.irqnum);
            printk("pixel size: %d.\n",ppiinfo.datalen);
			printk("line length: %hd.\n", ppiinfo.linelen);
			printk("num lines: %hd.\n", ppiinfo.numlines);
            
            get_ppi_reg( PPI_CONTROL, &usreg);
            printk("Ctrl reg:     0x%04hx.\n", usreg);
			get_ppi_reg( PPI_STATUS, &usreg);
			printk("Status reg:   0x%04hx.\n", usreg);
			get_ppi_reg( PPI_COUNT, &usreg);
			printk("Status count: 0x%04hx.\n", usreg);
			get_ppi_reg( PPI_FRAME, &usreg);
			printk("Status frame: 0x%04hx.\n", usreg);
			get_ppi_reg( PPI_DELAY, &usreg);
			printk("Status delay: 0x%04hx.\n", usreg);
			get_ppi_reg( 0xFFC00640, &usreg);  //TIMER_ENABLE
			printk("Timer Enable: 0x%04hx.\n", usreg);
            break;
        }
#endif
       default:
            return -EINVAL;
    }
    return 0;
}




/***********************************************************
*
* FUNCTION NAME :ppi_fasync
*
* INPUTS/OUTPUTS:
* in_fd - File descriptor of openned file.
* in_filp - Description of openned file.
*
* RETURN:
*
* FUNCTION(S) CALLED:
*
* GLOBAL VARIABLES REFERENCED: ppiinfo
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
static int 
ppi_fasync(int fd, struct file *filp, int on)
{
    ppi_device_t *pdev = filp->private_data;
    return fasync_helper(fd, filp, on, &(pdev->fasyc));
}

/***********************************************************
*
* FUNCTION NAME :ppi_read
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
* GLOBAL VARIABLES REFERENCED: ppiinfo
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
static ssize_t 
ppi_read (struct file *filp, char *buf, size_t count, loff_t *pos)
{
    unsigned short regdata;
	unsigned short	stepSize;
    int ierr;
    ppi_device_t *pdev = filp->private_data;

	DPRINTK("ppi_read: \n");

    if(count <= 0)
        return 0;

	pdev->done=0;
	pdev->access_mode = PPI_READ;

    blackfin_dcache_invalidate_range((unsigned long)buf,((unsigned long)buf)+count); 

	/* 
	** configure ppi port for DMA TIMOD RX (receive)
	** Note:  the rest of PPI control register bits should already be set 
	** with ioctls before read operation
	*/

	stepSize = ( pdev->datalen > CFG_PPI_DATALEN_8 ) ?	// adjust transfer size
		2 : 1;

	get_ppi_reg(PPI_CONTROL,&regdata);
	*pPPI_CONTROL =  pdev->ppi_control = regdata & ~PORT_DIR;

	get_ppi_reg(PPI_STATUS, &regdata); // read status register to clear it

	/* 
	** Configure DMA Controller
	** WNR:  memory write
	** RESTART: flush DMA FIFO before beginning work unit
	** DI_EN: generate interrupt on completion of work unit
	** DMA2D: 2 dimensional buffer
	*/
	pdev->dma_config |= ( WNR | RESTART );
	if (! pdev->cont )
		pdev->dma_config |= DI_EN ;
	if ( pdev->datalen > CFG_PPI_DATALEN_8 ) 	/* adjust transfer size */
		pdev->dma_config |= WDSIZE_16;
	if (pdev->dimensions == CFG_PPI_DIMS_2D) {
		pdev->dma_config |= DMA2D;
	}

	set_dma_config(CH_PPI, pdev->dma_config);
	set_dma_start_addr(CH_PPI, (unsigned long)buf);
	set_dma_x_modify(CH_PPI, stepSize);

	/*
	** 1D or 2D DMA 
	*/
	if (pdev->dimensions == CFG_PPI_DIMS_2D) /* configure for 2D transfers */
	{ 
		DPRINTK("PPI read -- 2D data xcount = linelen = %hd,
			ycount = numlines = %hd stepsize = %hd \n", 
			pdev->linelen, pdev->numlines, stepSize );

		set_dma_x_count(CH_PPI, pdev->linelen); 
		set_dma_y_count(CH_PPI, pdev->numlines);
		set_dma_y_modify(CH_PPI, stepSize);

		/* configure PPI registers to match DMA registers */
		*pPPI_COUNT =  pdev->linelen - 1;
		*pPPI_FRAME =  pdev->numlines;
	} 
	else {
		if ( pdev->datalen > CFG_PPI_DATALEN_8 ) 	/* adjust transfer size */
			set_dma_x_count(CH_PPI, count/2);
		else
			set_dma_x_count(CH_PPI, count);
		DPRINTK("PPI read -- 1D data count = %d\n", 
			pdev->datalen ? count/2 : count);
	}
	
	DPRINTK("dma_config = 0x%04hX\n", pdev->dma_config);

	*pPPI_DELAY = (unsigned short) pdev->delay;

	asm("ssync;");
	enable_dma(CH_PPI);

	/* read ppi status to clear it before enabling*/
	get_ppi_reg(PPI_STATUS, &regdata);


	// enable ppi
	get_ppi_reg(PPI_CONTROL,&regdata);
	*pPPI_CONTROL = pdev->ppi_control = regdata | PORT_EN;
	asm("ssync;");

	/* Wait for data available */
	if(1)
	{
		if(pdev->nonblock)
			return -EAGAIN;
		else
		{
			DPRINTK("PPI wait_event_interruptible\n");
			ierr = wait_event_interruptible(*(pdev->rx_avail),pdev->done);
			if(ierr)
			{
				/* waiting is broken by a signal */
				printk("PPI wait_event_interruptible ierr\n");
				return ierr;
			}
		}
	}

    DPRINTK("PPI wait_event_interruptible done\n");

	/*
	** disable ppi and dma  -- order matters! see 9-16
	*/
	get_ppi_reg(PPI_CONTROL,&regdata);
	*pPPI_CONTROL =  pdev->ppi_control = regdata & ~PORT_EN;
	disable_dma(CH_PPI);

    DPRINTK("ppi_read: return \n");

	return count;
}

/***********************************************************
*
* FUNCTION NAME :ppi_write
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
* GLOBAL VARIABLES REFERENCED: ppiinfo
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
static ssize_t 
ppi_write (struct file *filp, const char *buf, size_t count, loff_t *f_pos)
{
    unsigned short regdata;
	int	ierr;
	short			t1_config = 0;
	short			t2_config = 0;
	unsigned short	t_mask;
	unsigned int	linePeriod;
	unsigned int	frameSize;
	unsigned short	stepSize;
    ppi_device_t *pdev = filp->private_data;

	DPRINTK("ppi_write: \n");

    if(count <= 0)
        return 0;

	pdev->done=0;
	pdev->access_mode = PPI_WRITE;

    blackfin_dcache_invalidate_range((unsigned long)buf,
						((unsigned long)buf+(count*2)));
		
	
	pdev->dma_config = set_bfin_dma_config( 
		DIR_READ, // read from memory to write to PPI
		FLOW_STOP, // no chained DMA operation
		INTR_ON_BUF, // interrupt when whole transfer complete
		(pdev->numlines)? DIMENSION_2D : DIMENSION_LINEAR, // 2D or 1D
		DATA_SIZE_16 );
	DPRINTK("dma_config = 0x%04X\n", pdev->dma_config);
	set_dma_config(CH_PPI, pdev->dma_config);
	set_dma_start_addr(CH_PPI, (unsigned long) buf);

	if ( pdev->datalen > CFG_PPI_DATALEN_8 ){ 	/* adjust transfer size */
		frameSize = count/2;
		stepSize = 2;
	}
	else {
		frameSize = count;
		stepSize = 1;
	}

	/* 
	** set timer configuration register template
	**
	** see note on page 11-29 of BF533 HW Reference Manual
	** for setting PULSE_HI according to PPI trigger edge configuration
	** of PPI_FS1 and PPI_FS2
	**
	** set TOGGLE_HI so line and frame are not asserted simultaneously
	*/
	t1_config = (TIMER_CLK_SEL | TIMER_TIN_SEL | 
			TIMER_MODE_PWM | TIMER_TOGGLE_HI );
	if ( pdev->triggeredge )
		t1_config &= ~TIMER_PULSE_HI;
	else
		t1_config |= TIMER_PULSE_HI;

	t2_config = t1_config;
	t1_config |= TIMER_PERIOD_CNT;	// set up line sync to be recurring 

	if (pdev->dimensions == CFG_PPI_DIMS_2D) /* configure for 2D transfers */
	{ 
		DPRINTK("PPI write -- 2D data linelen = %hd, numlines = %hd\n", 
			pdev->linelen, pdev->numlines );

		linePeriod = pdev->linelen + pdev->delay;
		frameSize = linePeriod * pdev->numlines * 2; // TOGGLE_HI effects

		set_dma_x_count(CH_PPI, pdev->linelen); 
		set_dma_x_modify(CH_PPI, stepSize);
		set_dma_y_count(CH_PPI, pdev->numlines);
		set_dma_y_modify(CH_PPI, stepSize);

		/* configure PPI registers to match DMA registers */
		*pPPI_COUNT =  pdev->linelen - 1;
		*pPPI_FRAME =  pdev->numlines;
		*pPPI_DELAY =  pdev->delay;
		
		/* 
		** configure 2 timers for 2D
		** Timer1 - hsync - line time  PPI_FS1
		** Timer2 - vsync - frame time PPI_FS2
		*/
		t_mask = (TIMER1bit | TIMER2bit);  //use both timers

		set_gptimer_config( TIMER2_id, t2_config );
		set_gptimer_period( TIMER2_id, frameSize );
		set_gptimer_pwidth( TIMER2_id, frameSize );
		DPRINTK("Timer 2: (frame/vsync) config = %04hX, period = %d, width = %d\n",
			get_gptimer_config(TIMER2_id),
			get_gptimer_period(TIMER2_id),
			get_gptimer_pwidth(TIMER2_id) );

		set_gptimer_config( TIMER1_id, t1_config );
		set_gptimer_period( TIMER1_id, linePeriod );
		//divide linelen by 4 due to TOGGLE_HI behavior
		set_gptimer_pwidth( TIMER1_id, (pdev->linelen >> 2) ); 
		DPRINTK("Timer 1: (line/hsync) config = %04hX, period = %d, width = %d\n",
			get_gptimer_config(TIMER1_id),
			get_gptimer_period(TIMER1_id),
			get_gptimer_pwidth(TIMER1_id) );
	}
	else {
		DPRINTK("PPI write -- 1D data count = %d\n", count);

		t_mask = TIMER1bit;

		set_dma_x_count(CH_PPI, frameSize);
		set_dma_x_modify(CH_PPI, stepSize);

		/* 
		** set timer1 for frame vsync 
		**		use t2_config,  cuz it is the non-recurring conf
		*/
		set_gptimer_config( TIMER1_id, t2_config );   
		set_gptimer_period( TIMER1_id, frameSize + 1 );
		set_gptimer_pwidth( TIMER1_id, frameSize );

		DPRINTK("Timer 1: config = %04hX, period = %d, width = %d\n",
			t2_config,
			get_gptimer_period(TIMER1_id),
			get_gptimer_pwidth(TIMER1_id) );
		
	}
	asm("ssync;");
	enable_dma(CH_PPI);

	get_ppi_reg(PPI_COUNT, &regdata);
	DPRINTK("PPI_COUNT = %d\n", regdata );
	get_ppi_reg(PPI_FRAME, &regdata);
	DPRINTK("PPI_FRAME = %d\n", regdata );
	get_ppi_reg(PPI_DELAY, &regdata);
	DPRINTK("PPI_DELAY = %d\n", regdata );
	
	// enable ppi
	get_ppi_reg(PPI_CONTROL,&regdata);
	*pPPI_CONTROL =  pdev->ppi_control = regdata | PORT_EN;
	DPRINTK("PPI_CONTROL(enabled) = %04hX\n", pdev->ppi_control);

	// rewrite timer configuration registers per BF533 anomaly #25
	set_gptimer_config( TIMER1_id, t1_config );
	set_gptimer_config( TIMER2_id, t2_config );

	enable_gptimers(t_mask);

	/* Wait for DMA to finish */

	if (!pdev->cont) {
		if(pdev->nonblock){
			return -EAGAIN;
		}
		else { 
			DPRINTK("PPI wait_event_interruptible\n");
			ierr = wait_event_interruptible(*(pdev->rx_avail), pdev->done);
			if (ierr) {
				/* waiting is broken by a signal */
				printk("PPI wait_event_interruptible ierr = %d\n", ierr );
				return ierr;
			}
		}
	}

	get_ppi_reg(PPI_STATUS, &regdata);
	DPRINTK("PPI Status reg: %x\n", regdata );

    DPRINTK("ppi_write: return \n");

	/*
	** disable ppi and dma  -- order matters! see 9-16
	*/
	get_ppi_reg(PPI_CONTROL,&regdata);
	*pPPI_CONTROL =  pdev->ppi_control = regdata & ~PORT_EN;
	disable_dma(CH_PPI);
	

	return count;

}

/***********************************************************
*
* FUNCTION NAME :ppi_open
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
* GLOBAL VARIABLES REFERENCED: ppiinfo
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: It is invoked when user call 'open' system call
*              to open ppi device.
*              
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/
static int 
ppi_open (struct inode *inode, struct file *filp)
{
    char intname[20];
    int minor = MINOR (inode->i_rdev);

    DPRINTK("ppi_open: \n");
    
    /* PPI ? */
    if(minor != PPI0_MINOR) return -ENXIO;
    

    if(ppiinfo.opened)
        return -EMFILE;
    
    /* Clear configuration information */
    memset(&ppiinfo, 0, sizeof(ppi_device_t));

    if(filp->f_flags & O_NONBLOCK)
        ppiinfo.nonblock = 1;

	ppiinfo.rx_avail = &ppi_wq0;
	
	ppiinfo.opened = 1;
	ppiinfo.cont = 0;
	
	strcpy(intname, PPI_INTNAME);
	ppiinfo.irqnum = PPI_IRQ_NUM;
		
	filp->private_data = &ppiinfo;
		
	ppi_reg_reset(filp->private_data);
	    
	/* Request DMA0 channel, and pass the interrupt handler */

	if(request_dma(CH_PPI, "BF533_PPI_DMA") < 0)
		{
		panic("Unable to attach BlackFin PPI DMA channel\n");
		return -EFAULT;
		}	
	else
	     set_dma_callback(CH_PPI, (void*)ppi_irq, filp->private_data);
	

    DPRINTK("ppi_open: return \n");
    
    return 0;
}

/***********************************************************
*
* FUNCTION NAME :ppi_release
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
* GLOBAL VARIABLES REFERENCED: ppiinfo
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
static int 
ppi_release (struct inode *inode, struct file *filp)
{
    ppi_device_t *pdev = filp->private_data;

    DPRINTK("ppi_release: close() \n");
    

    /* After finish DMA, release it. */
	free_dma(CH_PPI);
    
    ppi_reg_reset(pdev);
    pdev->opened = 0; 
    
    ppi_fasync(-1, filp, 0);

    DPRINTK("ppi_release: close() return \n");
    return 0;
}

static struct file_operations ppi_fops = {
    owner:      THIS_MODULE,
    read:       ppi_read,
    write:      ppi_write,
    ioctl:      ppi_ioctl,
    open:       ppi_open,
    release:    ppi_release,
    fasync:     ppi_fasync,
};


/***********************************************************
*
* FUNCTION NAME :ppi_init / init_module
*                
* INPUTS/OUTPUTS:
* 
* RETURN:
* 0 if module init ok.
* -1 init fail.
*
* FUNCTION(S) CALLED:
*
* GLOBAL VARIABLES REFERENCED: ppiinfo
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: It will be invoked when using 'insmod' command.
*              or invoke it directly if ppi module is needed.
*
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/
//#ifdef MODULE
//int init_module(void)
//#else 

int __init 
ppi_init(void)
//#endif /* MODULE */
{
    int result;

    
    result = register_chrdev(PPI_MAJOR, PPI_DEVNAME, &ppi_fops);
    if (result < 0) 
    {
        printk(KERN_WARNING "PPI: can't get major %d\n", PPI_MAJOR);
        return result;
    }
    printk("PPI: PPI-EKC Driver INIT IRQ:%d \n",PPI_IRQ_NUM);
    return 0;
}   
//#ifndef MODULE
//__initcall(ppi_init);
//#endif

/***********************************************************
*
* FUNCTION NAME :ppi_uninit / cleanup_module
*                
* INPUTS/OUTPUTS:
* 
* RETURN:
*
* FUNCTION(S) CALLED:
*
* GLOBAL VARIABLES REFERENCED: ppiinfo
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: It will be invoked when using 'rmmod' command.
*              or, you invoke it directly when it needs remove
*              ppi module.
*              
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/
//#ifdef MODULE
//void cleanup_module(void)
//#else
void 
ppi_uninit(void)
//#endif /* MODULE */
{
    unregister_chrdev(PPI_MAJOR, PPI_DEVNAME);
    printk("<1>Goodbye PPI \n");

}

module_init(ppi_init);
module_exit(ppi_uninit);

MODULE_AUTHOR("John DeHority");
MODULE_LICENSE("GPL");




