/********************************************************************************************
 *									    		    *
 * 	Project Name- Video For Linux 2 For Blackfin 533 supoorted Platfors 		    *
 *									    		    *
 ********************************************************************************************

(C) Copyright 2005 -	Rrap Software Private Limited 
 
File Name:		bfin_v4l2_device.c

Date Modified:		4th March 3005	

Purpose:		To perform hardware specfic operations.
			
Author:			Ashutosh K Singh <ashutosh.singh@rrap-software.com>

Based on 	 	Zoran zr36057/zr36067 PCI controller driver, for the
 	 		Pinnacle/Miro DC10/DC10+/DC30/DC30+, Iomega Buz, Linux
			Media Labs LML33/LML33R10.  by Serguei Miridonov <mirsev@cicese.mx>

			This program is free software; you can redistribute it and/or modify
			it under the terms of the GNU General Public License as published by
			the Free Software Foundation; either version 2 of the License, or
			(at your option) any later version.
			
			 This program is distributed in the hope that it will be useful,
			 but WITHOUT ANY WARRANTY; without even the implied warranty of
			 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
			 GNU General Public License for more details.
			
			 You should have received a copy of the GNU General Public License
			 along with this program; if not, write to the Free Software
			 Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *********************************************************************************************/ 
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/mm.h>
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

extern char *ycrcb_buffer_out ; 	//definition and mem allocation
					//in driver file.
extern char *pre_ycrcb_buffer_out ;
static int id;

irqreturn_t __attribute((section(".text.l1")))
ppi_handler(int irq,
            void *dev_id,
            struct pt_regs *regs)
{
  *pDMA0_IRQ_STATUS |= 1;
  return IRQ_HANDLED;
}

void
init_device_bfin_v4l2()
{
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
	//Release the interrupt.
	free_irq(CONFIG_VIDEO_BLACKFIN_PPI_IRQ, &id);
	printk(" bfin_ad7171 Realeased\n") ;
}
