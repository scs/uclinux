/*
 * ########################################################################
 *
 *  This program is free software; you can distribute it and/or modify it
 *  under the terms of the GNU General Public License (Version 2) as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 *  for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place - Suite 330, Boston MA 02111-1307, USA.
 *
 * ########################################################################
*/

/*
*  arch/bfinnommu/kernel/simple_dma.c
*  This file contains the simple DMA Implementation for BF533
*
*  Copyright (C) 2004 LG Soft India
*
*/
#include <linux/config.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/param.h>

#include <asm/dma.h>

/* Remove unused code not exported by symbol or internally called */ 
#define REMOVE_DEAD_CODE


/**************************************************************************
 * Global Variables 
***************************************************************************/

static DMA_CHANNEL 	dma_ch[MAX_BLACKFIN_DMA_CHANNEL];

static DMA_register* 	base_addr[MAX_BLACKFIN_DMA_CHANNEL] =
{
	(DMA_register *) DMA0_NEXT_DESC_PTR,
	(DMA_register *) DMA1_NEXT_DESC_PTR,
	(DMA_register *) DMA2_NEXT_DESC_PTR,
	(DMA_register *) DMA3_NEXT_DESC_PTR,
	(DMA_register *) DMA4_NEXT_DESC_PTR,
	(DMA_register *) DMA5_NEXT_DESC_PTR,
	(DMA_register *) DMA6_NEXT_DESC_PTR,
	(DMA_register *) DMA7_NEXT_DESC_PTR,
	(DMA_register *) MDMA_D0_NEXT_DESC_PTR,
	(DMA_register *) MDMA_S0_NEXT_DESC_PTR,
	(DMA_register *) MDMA_D1_NEXT_DESC_PTR,
	(DMA_register *) MDMA_S1_NEXT_DESC_PTR,
};



/*------------------------------------------------------------------------------
 *       Set the Buffer Clear bit in the Configuration register of specific DMA
 *       channel. This will stop the descriptor based DMA operation.
 *-----------------------------------------------------------------------------*/
static void clear_dma_buffer(unsigned int channel)
{
     dma_ch[channel].regs->cfg |= RESTART;
     SSYNC();
     dma_ch[channel].regs->cfg &= ~RESTART;
     SSYNC();
}

int __init blackfin_dma_init(void)
{
	int 	i;
	
	printk("Blackfin DMA Controller for BF533\n");
	for (i = 0; i < MAX_BLACKFIN_DMA_CHANNEL; i++) {
		dma_ch[i].dma_channel_status = DMA_CHANNEL_FREE;
		dma_ch[i].regs = base_addr[i];
		init_MUTEX(&(dma_ch[i].dmalock));
	}

	return 0;
}

arch_initcall(blackfin_dma_init);

/*
 *	Form the channel find the irq number for that channel.
 */
static int bf533_channel2irq( unsigned int channel)
{
	int ret_irq = -1;

	switch (channel){
		case CH_PPI:
			ret_irq = IRQ_PPI;
			break;

		case CH_SPORT0_RX:	
			ret_irq = IRQ_SPORT0_RX;
			break;

		case CH_SPORT0_TX:
			ret_irq = IRQ_SPORT0_TX;
			break;

		case CH_SPORT1_RX:
			ret_irq = IRQ_SPORT1_RX;
			break;

		case CH_SPORT1_TX:
			ret_irq = IRQ_SPORT1_TX;
			break;

		case CH_SPI:
			ret_irq = IRQ_SPI;
			break;

		case CH_UART_RX:
			ret_irq	= IRQ_UART_RX;
			break;

		case CH_UART_TX:
			ret_irq	= IRQ_UART_TX;
			break;
			
		case CH_MEM_STREAM0_SRC:
		case CH_MEM_STREAM0_DEST:
			ret_irq = IRQ_MEM_DMA0;
			break;

		case CH_MEM_STREAM1_SRC:
		case CH_MEM_STREAM1_DEST:
			ret_irq = IRQ_MEM_DMA1;
			break;
	}
	return ret_irq;
}

/*------------------------------------------------------------------------------
 *	Request the specific DMA channel from the system.
 *-----------------------------------------------------------------------------*/
int request_dma(unsigned int channel, char *device_id)
{
     
     DMA_DBG("request_dma() : BEGIN \n");
     down(&(dma_ch[channel].dmalock));
     
     if ((dma_ch[channel].dma_channel_status == DMA_CHANNEL_REQUESTED )
	 ||(dma_ch[channel].dma_channel_status == DMA_CHANNEL_ENABLED)){
	  up(&(dma_ch[channel].dmalock));
	  DMA_DBG("DMA CHANNEL IN USE  \n");
	  return -EBUSY;
     }
     
     else{
	  dma_ch[channel].dma_channel_status = DMA_CHANNEL_REQUESTED ;
	  DMA_DBG("DMA CHANNEL IS ALLOCATED  \n");
     }
     
     up(&(dma_ch[channel].dmalock));

     dma_ch[channel].device_id = device_id;

     /* This is to be enabled by putting a restriction -
           you have to request DMA , before doing any operations on
           descriptor/channel
     */
     DMA_DBG("request_dma() : END  \n");
     return channel;
     
}


int set_dma_callback(unsigned int channel, dma_interrupt_t callback, void *data)
{
     int ret_irq = 0;     

     assert(dma_ch[channel].dma_channel_status != DMA_CHANNEL_FREE || channel < MAX_BLACKFIN_DMA_CHANNEL);
 
     if( callback != NULL ) {
	  int     ret_val;
	  ret_irq =bf533_channel2irq(channel);
	  
          ret_val = request_irq(ret_irq,(void *)callback,SA_INTERRUPT,dma_ch[channel].device_id,data);
          if( ret_val ) {
               printk("Request irq in DMA engine failed.\n");
               return -EPERM;
          }
     }
     return 0;
}


void free_dma(unsigned int channel)
{
	DMA_DBG("freedma() : BEGIN \n");

     assert(dma_ch[channel].dma_channel_status != DMA_CHANNEL_FREE || channel < MAX_BLACKFIN_DMA_CHANNEL);
	 
	/* Halt the DMA */
	disable_dma(channel);
	clear_dma_buffer(channel);
	
	/* Clear the DMA Variable in the Channel*/
	down(&(dma_ch[channel].dmalock));
	dma_ch[channel].dma_channel_status = DMA_CHANNEL_FREE;
	up(&(dma_ch[channel].dmalock));

	DMA_DBG("freedma() : END \n");
	return;
}

int dma_channel_active(unsigned int channel)
{
     if(dma_ch[channel].dma_channel_status == DMA_CHANNEL_FREE){
          return 0;
     } else {
          return 1;
     }
}

 
/*------------------------------------------------------------------------------
*	stop the specific DMA channel.
*-----------------------------------------------------------------------------*/
void disable_dma(unsigned int channel)
{
	DMA_DBG("stop_dma() : BEGIN \n");

	assert(dma_ch[channel].dma_channel_status != DMA_CHANNEL_FREE && channel < MAX_BLACKFIN_DMA_CHANNEL);

	dma_ch[channel].regs->cfg &= ((~DI_SEL) & (~DI_EN) & (~DMAEN));	/* Clean the enable bit and disable interrupt */
	SSYNC();
	dma_ch[channel].dma_channel_status  = DMA_CHANNEL_REQUESTED;
	/* Needs to be enabled Later */
	DMA_DBG("stop_dma() : END \n");
	return;
}

void enable_dma(unsigned int channel)
{
	DMA_DBG("enable_dma() : BEGIN \n");

	assert(dma_ch[channel].dma_channel_status != DMA_CHANNEL_FREE && channel < MAX_BLACKFIN_DMA_CHANNEL);
	
	dma_ch[channel].dma_channel_status = DMA_CHANNEL_ENABLED;
	dma_ch[channel].regs->curr_x_count=0;
	dma_ch[channel].regs->curr_y_count=0;
	
	dma_ch[channel].regs->cfg |= DMAEN;	/* Set the enable bit */
	SSYNC();
	DMA_DBG("enable_dma() : END \n");
	return;
}

/*------------------------------------------------------------------------------
*		Set the Start Address register for the specific DMA channel
* 		This function can be used for register based DMA,
*		to setup the start address
*		addr:		Starting address of the DMA Data to be transferred.
*-----------------------------------------------------------------------------*/
void set_dma_start_addr(unsigned int channel, unsigned long addr)
{
	DMA_DBG("set_dma_start_addr() : BEGIN \n");
	
	assert(dma_ch[channel].dma_channel_status != DMA_CHANNEL_FREE && channel < MAX_BLACKFIN_DMA_CHANNEL);
		 
	dma_ch[channel].regs->start_addr = addr;
	SSYNC();
	DMA_DBG("set_dma_start_addr() : END\n");
}


void set_dma_x_count(unsigned int channel, unsigned short x_count)
{
     assert(dma_ch[channel].dma_channel_status != DMA_CHANNEL_FREE && channel < MAX_BLACKFIN_DMA_CHANNEL);
	 
	dma_ch[channel].regs->x_count = x_count;
	SSYNC();
}

void set_dma_y_count(unsigned int channel, unsigned short y_count)
{
     assert(dma_ch[channel].dma_channel_status != DMA_CHANNEL_FREE && channel < MAX_BLACKFIN_DMA_CHANNEL);
	 
	dma_ch[channel].regs->y_count = y_count;
	SSYNC();
}

void set_dma_x_modify(unsigned int channel, unsigned short x_modify)
{
     assert(dma_ch[channel].dma_channel_status != DMA_CHANNEL_FREE && channel < MAX_BLACKFIN_DMA_CHANNEL);

	dma_ch[channel].regs->x_modify = x_modify;
	SSYNC();
}

void set_dma_y_modify(unsigned int channel, unsigned short y_modify)
{
     assert(dma_ch[channel].dma_channel_status != DMA_CHANNEL_FREE && channel < MAX_BLACKFIN_DMA_CHANNEL);

	dma_ch[channel].regs->y_modify = y_modify;
	SSYNC();
}

void set_dma_config(unsigned int channel,  unsigned short config)
{
     assert(dma_ch[channel].dma_channel_status != DMA_CHANNEL_FREE && channel < MAX_BLACKFIN_DMA_CHANNEL);
         
     dma_ch[channel].regs->cfg |= config;
     SSYNC();
}

unsigned short set_bfin_dma_config(char direction, char flow_mode,
                                    char intr_mode, char dma_mode, char width)
{
     unsigned short config;

     config = ((direction << 1) | (width << 2) | (dma_mode << 4) | (intr_mode << 6) | (flow_mode << 12) | RESTART);
     return config;
}



/*------------------------------------------------------------------------------
 *	Get the DMA status of a specific DMA channel from the system.
 *-----------------------------------------------------------------------------*/
unsigned short get_dma_curr_irqstat(unsigned int channel)
{
     assert(dma_ch[channel].dma_channel_status != DMA_CHANNEL_FREE && channel < MAX_BLACKFIN_DMA_CHANNEL);
	 
	return dma_ch[channel].regs->irq_status;
}

/*------------------------------------------------------------------------------
 *	Clear the DMA_DONE bit in DMA status. Stop the DMA completion interrupt.
 *-----------------------------------------------------------------------------*/
void clear_dma_irqstat(unsigned int channel)
{
	assert(dma_ch[channel].dma_channel_status != DMA_CHANNEL_FREE && channel < MAX_BLACKFIN_DMA_CHANNEL);
	dma_ch[channel].regs->irq_status |= 3;
}

/*------------------------------------------------------------------------------
 *	Get current DMA xcount of a specific DMA channel from the system.
 *-----------------------------------------------------------------------------*/
unsigned short get_dma_curr_xcount(unsigned int channel)
{
     assert(dma_ch[channel].dma_channel_status != DMA_CHANNEL_FREE && channel < MAX_BLACKFIN_DMA_CHANNEL);

	return dma_ch[channel].regs->curr_x_count;
}

/*------------------------------------------------------------------------------
 *	Get current DMA ycount of a specific DMA channel from the system.
 *-----------------------------------------------------------------------------*/
unsigned short get_dma_curr_ycount(unsigned int channel)
{
     assert(dma_ch[channel].dma_channel_status != DMA_CHANNEL_FREE && channel < MAX_BLACKFIN_DMA_CHANNEL);

	return dma_ch[channel].regs->curr_y_count;
}


EXPORT_SYMBOL(request_dma);
EXPORT_SYMBOL(set_dma_callback);
EXPORT_SYMBOL(enable_dma);
EXPORT_SYMBOL(disable_dma);
EXPORT_SYMBOL(dma_channel_active);

EXPORT_SYMBOL(get_dma_curr_irqstat);
EXPORT_SYMBOL(clear_dma_irqstat);
EXPORT_SYMBOL(get_dma_curr_xcount);
EXPORT_SYMBOL(get_dma_curr_ycount);
EXPORT_SYMBOL(set_dma_start_addr);

EXPORT_SYMBOL(set_dma_config);
EXPORT_SYMBOL(set_bfin_dma_config);
EXPORT_SYMBOL(set_dma_x_count);
EXPORT_SYMBOL(set_dma_x_modify);
EXPORT_SYMBOL(set_dma_y_count);
EXPORT_SYMBOL(set_dma_y_modify);



