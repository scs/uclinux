/*
 * linux/drivers/video/bfin_ad7171.c -- Analog Devices Blackfin + AD7171 video out chip
 * 
 * Based on vga16fb.cCopyright 1999 Ben Pfaff <pfaffben@debian.org> and Petr Vandrovec <VANDROVE@vc.cvut.cz>
 * Copyright 2004 Ashutosh Kumar Singh (ashutosh.singh@rrap-software.com)
 *
 * This file is subject to the terms and conditions of the GNU General
 * Public License.  See the file COPYING in the main directory of this
 * archive for more details.  
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/tty.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/fb.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <asm/board/cdefBF533.h>
#include <asm/irq.h>
#include <linux/timer.h>
#include <asm/bf533_dma.h>

#define CONFIG_VIDEO_BLACKFIN_PPI_IRQ IRQ_PPI
#define CONFIG_VIDEO_BLACKFIN_PPI_IRQ_ERR IRQ_DMA_ERROR
#define MAX_NO_OF_FRAMES	20
#define FRAME_SIZE		188640

struct timer_list buffer_swapping_timer ;
extern char *ycrcb_buffer_out ; 	//definition and mem allocation
					//in driver file.
extern char *pre_ycrcb_buffer_out ;

short int temp_ycrcb_frame_no = 0;	//It's current value
					//shall represent frame
					//(in the group of frames)
					//currently being transmitted
char *temp_pre_ycrcb_buffer_out;//if dont understand why 
				//is this needed, look for
				//above declaration and
				//corresponding comment :-)
short int bfin_v4l2_timer_status =0;

irqreturn_t __attribute((section(".text.l1")))
ppi_handler(int irq,
            void *dev_id,
            struct pt_regs *regs)
{
  *pDMA0_IRQ_STATUS |= 1;
  return IRQ_HANDLED;
}



static void timerfunction(unsigned long ptr);
static void timer_setup(void);

static void __attribute((section(".text.l1")))
timerfunction(unsigned long ptr)
{
	if(temp_ycrcb_frame_no >= MAX_NO_OF_FRAMES) 
		bfin_v4l2_timer_status = 0;
	else {
		_NtscVideoOutBuffUpdate(ycrcb_buffer_out, pre_ycrcb_buffer_out);
		timer_setup();
		bfin_v4l2_timer_status = 1 ;
        	add_timer(&buffer_swapping_timer) ;
		pre_ycrcb_buffer_out += temp_ycrcb_frame_no++ ;
	}
}


void
timer_setup(void)
{

        /*** Initialize the timer structure***/

        init_timer(&buffer_swapping_timer) ;
        buffer_swapping_timer.function = timerfunction ;
        buffer_swapping_timer.expires = jiffies + HZ*1 ;

        /***Initialisation ends***/

}

static int id;

void
init_device_bfin_v4l2()
{

/*****************************************************************
 *
 *
 *
 * Very first of all lets try to aquire DMA channels.
 * We will need PPI dma that will output data to AD7171
 * chip.
 * Then we will need a pair of MEM DMA channels to
 * transfer data from YCRCB buffer to output buffer
 * which contain blanking information as well.
 *
 *
 *
 ****************************************************************/


/* We need to request
 * kernel for PPI DMA channel
 */
#if 0 
	if( request_dma(CH_PPI, "BFIN_V4L2_DRIVER", NULL) ){
		printk( KERN_ERR, "Unable to allocate ppi dma %d\n", CH_PPI);
		return -ENODEV;
	}
#endif


/* Request for getting PPI
 * interrupt vector location
 * to use our own PPI interrupt 
 * handler
 */
        if( request_irq(CONFIG_VIDEO_BLACKFIN_PPI_IRQ, &ppi_handler, SA_SHIRQ, "PPI Data", &id ) ){
                printk( KERN_ERR "Unable to allocate ppi IRQ %d\n", CONFIG_VIDEO_BLACKFIN_PPI_IRQ);
		freedma(CH_PPI);
                return -ENODEV;
        }


#if 0
/* If we have got PPI DMA channel
 * lets try for MEM DMA channel.
 */
if(! request_dma(CH_MEM_STREAM0_DEST, "BFIN_V4L2_DRIVER", NULL) {
                 printk( KERN_ERR, "Unable to allocate mem dma %d\n", CH_MEM_STREAM0_DEST);
		freedma(CH_PPI);
		disable_irq(CONFIG_VIDEO_BLACKFIN_PPI_IRQ);
                return -ENODEV;
        }

        if(request_dma(CH_MEM_STREAM0_SRC, "BFIN_V4L2_DRIVER", NULL) {
                 printk( KERN_ERR, "Unable to allocate mem dma %d\n", CH_MEM_STREAM0_SRC);
		freedma(CH_PPI);
		disable_irq(CONFIG_VIDEO_BLACKFIN_PPI_IRQ);
		freedma(CH_MEM_STREAM0_DEST);
                return -ENODEV;
        }


/*******************************************************************
 *
 *
 * If we have reached upto here, we have got dma channels
 * lets configure them. 
 *
 *
 ******************************************************************/
#endif


	_NtscVideoOutFrameBuffInit(ycrcb_buffer_out, pre_ycrcb_buffer_out);
	
	_Flash_Setup_ADV_Reset() ;
	_config_ppi() ;
	_config_dma(ycrcb_buffer_out) ;
	enable_irq(CONFIG_VIDEO_BLACKFIN_PPI_IRQ);
        // enable the dma
        *pDMA0_CONFIG |= 1;
        *pPPI_CONTROL |= 1;
}

void
device_bfin_close()
{
	//disable DMA
	*pPPI_CONTROL &= 0;
	*pDMA0_CONFIG &= 0;
#if 0
	freedma(CH_PPI);
#endif
	//Release the interrupt.
	free_irq(CONFIG_VIDEO_BLACKFIN_PPI_IRQ, &id);
	printk(" bfin_ad7171 Realeased\n") ;
}
void
bfin_v4l2_update_video()
{
	_NtscVideoOutBuffUpdate(ycrcb_buffer_out, pre_ycrcb_buffer_out);
}
