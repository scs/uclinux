/********************************************************************************************
 *									    		    *
 * 	Project Name- Video For Linux 2 For Blackfin 533 supoorted Platfors 		    *
 *									    		    *
 ********************************************************************************************

(C) Copyright 2005 -	Rrap Software Private Limited 
 
File Name:		bfin_v4l2_device.c

Date Modified:		4th March 2005	

Purpose:		To perform hardware specfic operations.
			
Author:			Ashutosh K Singh <ashutosh.singh@rrap-software.com>

Based on: 	 	Zoran zr36057/zr36067 PCI controller driver, for the
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
#include <asm/irq.h>
#include <linux/timer.h>
#include <asm/bf533_dma.h>
#include <asm/blackfin.h>
 
#define CONFIG_VIDEO_BLACKFIN_PPI_IRQ IRQ_PPI
#define CONFIG_VIDEO_BLACKFIN_PPI_IRQ_ERR IRQ_DMA_ERROR
#define V4L2_YCRCB_FRAME_SIZE (1512000 * 4) 

extern char *ycrcb_buffer_out ; 	//definition and mem allocation
					//in driver file.
extern char *pre_ycrcb_buffer_out ;
char *ycrcb_buffer_out_1 ;
char *ycrcb_buffer_out_2 ;
#define YCRCB_BUFFER_1 0x5a00400
#define YCRCB_BUFFER_2 0x7800000
int id2;

/* Memory DMA status.
 * Needed as on the basis of these
 * values write() function call
 * will progress.
 */
int mem_dma1_status = 0, mem_dma0_status = 0 ;

/* As PPI will ping-pong between two buffers
 * it very important to synchronize PPI and 
 * and MEM DMA. It should be made sure that
 * MEM DMA and PPI DMA both are not accessing
 * the same buffer. For this we will use 
 * flags and macros defined below.
 */
#define YCRCB_BUFFER_BUSY 1
#define WAIT_TILL_NEXT_PPI_INTR 2
#define YCRCB_BUFFER_FREE_FOR_MDMA_WRITE 3
#define BUFFER_BEING_WRITTEN 4
#define BUFFER_WRITTEN 5
extern wait_queue_head_t bfin_v4l2_write_wait ;

//int ycrcb_buffer_1_status = YCRCB_BUFFER_BUSY, ycrcb_buffer_2_status = YCRCB_BUFFER_FREE_FOR_MDMA_WRITE ;
int ycrcb_buffer_1_status, ycrcb_buffer_2_status ;
int which_buff =0;

irqreturn_t __attribute__((l1_text))
ppi_handler(int irq,
            void *dev_id,
            struct pt_regs *regs)
{
//if this handler acts slowly we will
//need to put status variables in L1
	if(ycrcb_buffer_1_status == WAIT_TILL_NEXT_PPI_INTR) {
		ycrcb_buffer_1_status = YCRCB_BUFFER_FREE_FOR_MDMA_WRITE ;
		//wake-up sleep in write function to check for favourable conditions.
	}
	if(ycrcb_buffer_2_status == WAIT_TILL_NEXT_PPI_INTR) {
		ycrcb_buffer_2_status = YCRCB_BUFFER_FREE_FOR_MDMA_WRITE ;
		//wake-up sleep in write function to check for favourable conditions.
	}

	wake_up(&bfin_v4l2_write_wait) ;
	bfin_write_DMA0_IRQ_STATUS(bfin_read_DMA0_IRQ_STATUS() | 1);
	return IRQ_HANDLED;
}

irqreturn_t __attribute__((l1_text))
bfin_v4l2_memdma0_interrupt_handler(int irq,
            void *dev_id,
            struct pt_regs *regs)
{
	mem_dma0_status = 0 ;
	bfin_write_MDMA_D0_IRQ_STATUS(0x1);
	return IRQ_HANDLED;
}

irqreturn_t __attribute__((l1_text))
bfin_v4l2_memdma1_interrupt_handler(int irq,
            void *dev_id,
            struct pt_regs *regs)
{
	bfin_write_MDMA_D1_IRQ_STATUS(0x1);
	mem_dma1_status = 0 ;
	if(ycrcb_buffer_1_status == BUFFER_BEING_WRITTEN) {
		ycrcb_buffer_1_status = BUFFER_WRITTEN ;
		_change_descriptor_start_address( ycrcb_buffer_out_1) ;
		ycrcb_buffer_2_status = WAIT_TILL_NEXT_PPI_INTR ;
	}
	else {
		ycrcb_buffer_2_status = BUFFER_WRITTEN ;
		_change_descriptor_start_address( ycrcb_buffer_out_2) ;
		ycrcb_buffer_1_status = WAIT_TILL_NEXT_PPI_INTR ;
	}

	//wake-up sleep in write function to check for favourable conditions.
	wake_up(&bfin_v4l2_write_wait) ;
/* Since MEM DMA 1 has lower priority as compared with MEM DMA 0,
 * it is for sure that MEM DMA1 will not complete before MEM DMA0
 */

	return IRQ_HANDLED;
}

void
init_device_bfin_v4l2(void)
{

/* Very first of all lets aquire MEM DMA channels.
 * As the offset between even field and odd field
 * addresses is larger than Y_MODIFY can handle,
 * single 2D DMA is of no help. So we will use both
 * of the MEM DMA channels, each dedicated to even
 * and odd fields respectively.
 */
        if( request_irq(IRQ_MEM_DMA0, &bfin_v4l2_memdma0_interrupt_handler, SA_SHIRQ, "PPI Data", &id2) ){
                printk( KERN_ERR "Unable to allocate mem dma IRQ %d\n", IRQ_MEM_DMA0);
                return -ENODEV;
        }

        if( request_irq(IRQ_MEM_DMA1, &bfin_v4l2_memdma1_interrupt_handler, SA_SHIRQ, "PPI Data", &id2) ){
                printk( KERN_ERR "Unable to allocate mem dma IRQ %d\n", IRQ_MEM_DMA1);
                return -ENODEV;
        }


/* Request for getting PPI
 * interrupt vector location
 * to use our own PPI interrupt 
 * handler
 */
        if( request_irq(CONFIG_VIDEO_BLACKFIN_PPI_IRQ, &ppi_handler, SA_SHIRQ, "PPI Data", &id2 ) ){
                printk( KERN_ERR "Unable to allocate ppi IRQ %d\n", CONFIG_VIDEO_BLACKFIN_PPI_IRQ);
//		freedma(CH_PPI);
                return -ENODEV;
        }
#if CONFIG_MEM_SIZE <= 64
	ycrcb_buffer_out_1 = YCRCB_BUFFER_1 ;  
	ycrcb_buffer_out_2 = YCRCB_BUFFER_2 ;  
#else
	ycrcb_buffer_out_1  = (char *)kmalloc(V4L2_YCRCB_FRAME_SIZE, GFP_KERNEL) ;
	ycrcb_buffer_out_2  = (char *)kmalloc(V4L2_YCRCB_FRAME_SIZE, GFP_KERNEL) ;
	printk("\n\n\n**FOR BETTER RESULTS SET MEMORY SIZE AS 64 or less**\n\n\n") ;
#endif
	ycrcb_buffer_1_status = YCRCB_BUFFER_BUSY ;
	ycrcb_buffer_2_status = YCRCB_BUFFER_FREE_FOR_MDMA_WRITE ;
	_NtscVideoOutFrameBuffInit(ycrcb_buffer_out_1, pre_ycrcb_buffer_out);
	_NtscVideoOutFrameBuffInit(ycrcb_buffer_out_2, pre_ycrcb_buffer_out);
	_Flash_Setup_ADV_Reset() ;
	_config_ppi() ;
	_config_dma(ycrcb_buffer_out_1) ;
	enable_irq(CONFIG_VIDEO_BLACKFIN_PPI_IRQ);
        // enable the dma
        bfin_write_DMA0_CONFIG(bfin_read_DMA0_CONFIG() | 1);
        bfin_write_PPI_CONTROL(bfin_read_PPI_CONTROL() | 1);
}

void
device_bfin_close()
{
	//disable DMA
	bfin_write_PPI_CONTROL(bfin_read_PPI_CONTROL() & 0);
	bfin_write_DMA0_CONFIG(bfin_read_DMA0_CONFIG() & 0);
	//Release the interrupt.
	free_irq(CONFIG_VIDEO_BLACKFIN_PPI_IRQ, &id2);
	free_irq(IRQ_MEM_DMA0, &id2);
	free_irq(IRQ_MEM_DMA1, &id2);
	printk(" bfin_ad7171 Realeased\n") ;
}

void __attribute__((l1_text))
bfin_v4l2_memdma_setup(char *ycrcb_buffer_update, char *ycrcb_buffer_raw)
{

	ycrcb_buffer_update += 0x079BC ;//initial offset 
//	bfin_write_MDMA_D0_IRQ_STATUS(DMA_DONE | DMA_ERR);
	/* Copy sram functions from sdram to sram */
	/* Setup destination start address */
	bfin_write_MDMA_D0_START_ADDR(ycrcb_buffer_update);
	/* Setup destination xcount */
	bfin_write_MDMA_D0_X_COUNT(360 );
	/* Setup destination xmodify */
	bfin_write_MDMA_D0_X_MODIFY(4);
	/* Setup destination ycount */
	bfin_write_MDMA_D0_Y_COUNT(262 );
	/* Setup destination ymodify */
	bfin_write_MDMA_D0_Y_MODIFY(280);

	/* Setup Source start address */
	bfin_write_MDMA_S0_START_ADDR(ycrcb_buffer_raw);
	/* Setup Source xcount */
	bfin_write_MDMA_S0_X_COUNT(360 );
	/* Setup Source xmodify */
	bfin_write_MDMA_S0_X_MODIFY(4);
	/* Setup Source ycount */
	bfin_write_MDMA_S0_Y_COUNT(262 );
	/* Setup Source ymodify */
	bfin_write_MDMA_S0_Y_MODIFY(1444 );




	ycrcb_buffer_update += 0x06DC38 ;//Even Odd Field Offset
	ycrcb_buffer_raw += 1440;
//	bfin_write_MDMA_D1_IRQ_STATUS(DMA_DONE | DMA_ERR);
	/* Copy sram functions from sdram to sram */
	/* Setup destination start address */
	bfin_write_MDMA_D1_START_ADDR(ycrcb_buffer_update);
	/* Setup destination xcount */
	bfin_write_MDMA_D1_X_COUNT(360 );
	/* Setup destination xmodify */
	bfin_write_MDMA_D1_X_MODIFY(4);
	/* Setup destination ycount */
	bfin_write_MDMA_D1_Y_COUNT(262 );
	/* Setup destination ymodify */
	bfin_write_MDMA_D1_Y_MODIFY(280);

	/* Setup Source start address */
	bfin_write_MDMA_S1_START_ADDR(ycrcb_buffer_raw);
	/* Setup Source xcount */
	bfin_write_MDMA_S1_X_COUNT(360 );
	/* Setup Source xmodify */
	bfin_write_MDMA_S1_X_MODIFY(4);
	/* Setup Source ycount */
	bfin_write_MDMA_S1_Y_COUNT(262 );
	/* Setup Source ymodify */
	bfin_write_MDMA_S1_Y_MODIFY(1444 );






	/* Set word size to 32, set to read, enable interrupt for wakeup */
	/* Enable source DMA */
	bfin_write_MDMA_S0_CONFIG((DMA2D | WDSIZE_32 | DMAEN) );
	bfin_write_MDMA_S1_CONFIG((DMA2D | WDSIZE_32 | DMAEN) );
	__builtin_bfin_ssync();
	bfin_write_MDMA_D0_CONFIG(( DI_EN | WNR | DMA2D | WDSIZE_32 | DMAEN) ); 
	bfin_write_MDMA_D1_CONFIG(( DI_EN | WNR | DMA2D | WDSIZE_32 | DMAEN) ); 
}
