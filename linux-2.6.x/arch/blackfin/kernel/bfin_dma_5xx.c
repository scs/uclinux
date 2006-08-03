/*
 * File:         arch/blackfin/kernel/bfin_dma_5xx.c
 * Based on:
 * Author:
 *
 * Created:
 * Description:  This file contains the simple DMA Implementation for Blackfin
 *
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright 2004-2006 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see the file COPYING, or write
 * to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <linux/config.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/param.h>
#include <asm/irqchip.h>

#include <asm/dma.h>

/* Remove unused code not exported by symbol or internally called */
#define REMOVE_DEAD_CODE

#define SSYNC __builtin_bfin_ssync()

/**************************************************************************
 * Global Variables
***************************************************************************/

static dma_channel_t dma_ch[MAX_BLACKFIN_DMA_CHANNEL];
#if defined (CONFIG_BF561)
static dma_register_t *base_addr[MAX_BLACKFIN_DMA_CHANNEL] = {
	(dma_register_t *) DMA1_0_NEXT_DESC_PTR,
	(dma_register_t *) DMA1_1_NEXT_DESC_PTR,
	(dma_register_t *) DMA1_2_NEXT_DESC_PTR,
	(dma_register_t *) DMA1_3_NEXT_DESC_PTR,
	(dma_register_t *) DMA1_4_NEXT_DESC_PTR,
	(dma_register_t *) DMA1_5_NEXT_DESC_PTR,
	(dma_register_t *) DMA1_6_NEXT_DESC_PTR,
	(dma_register_t *) DMA1_7_NEXT_DESC_PTR,
	(dma_register_t *) DMA1_8_NEXT_DESC_PTR,
	(dma_register_t *) DMA1_9_NEXT_DESC_PTR,
	(dma_register_t *) DMA1_10_NEXT_DESC_PTR,
	(dma_register_t *) DMA1_11_NEXT_DESC_PTR,
	(dma_register_t *) DMA2_0_NEXT_DESC_PTR,
	(dma_register_t *) DMA2_1_NEXT_DESC_PTR,
	(dma_register_t *) DMA2_2_NEXT_DESC_PTR,
	(dma_register_t *) DMA2_3_NEXT_DESC_PTR,
	(dma_register_t *) DMA2_4_NEXT_DESC_PTR,
	(dma_register_t *) DMA2_5_NEXT_DESC_PTR,
	(dma_register_t *) DMA2_6_NEXT_DESC_PTR,
	(dma_register_t *) DMA2_7_NEXT_DESC_PTR,
	(dma_register_t *) DMA2_8_NEXT_DESC_PTR,
	(dma_register_t *) DMA2_9_NEXT_DESC_PTR,
	(dma_register_t *) DMA2_10_NEXT_DESC_PTR,
	(dma_register_t *) DMA2_11_NEXT_DESC_PTR,
	(dma_register_t *) MDMA1_D0_NEXT_DESC_PTR,
	(dma_register_t *) MDMA1_S0_NEXT_DESC_PTR,
	(dma_register_t *) MDMA1_D1_NEXT_DESC_PTR,
	(dma_register_t *) MDMA1_S1_NEXT_DESC_PTR,
	(dma_register_t *) MDMA2_D0_NEXT_DESC_PTR,
	(dma_register_t *) MDMA2_S0_NEXT_DESC_PTR,
	(dma_register_t *) MDMA2_D1_NEXT_DESC_PTR,
	(dma_register_t *) MDMA2_S1_NEXT_DESC_PTR,
	(dma_register_t *) IMDMA_D0_NEXT_DESC_PTR,
	(dma_register_t *) IMDMA_S0_NEXT_DESC_PTR,
	(dma_register_t *) IMDMA_D1_NEXT_DESC_PTR,
	(dma_register_t *) IMDMA_S1_NEXT_DESC_PTR,
};
#else
static dma_register_t *base_addr[MAX_BLACKFIN_DMA_CHANNEL] = {
	(dma_register_t *) DMA0_NEXT_DESC_PTR,
	(dma_register_t *) DMA1_NEXT_DESC_PTR,
	(dma_register_t *) DMA2_NEXT_DESC_PTR,
	(dma_register_t *) DMA3_NEXT_DESC_PTR,
	(dma_register_t *) DMA4_NEXT_DESC_PTR,
	(dma_register_t *) DMA5_NEXT_DESC_PTR,
	(dma_register_t *) DMA6_NEXT_DESC_PTR,
	(dma_register_t *) DMA7_NEXT_DESC_PTR,
#if (defined(CONFIG_BF537) || defined(CONFIG_BF534) || defined(CONFIG_BF536))
	(dma_register_t *) DMA8_NEXT_DESC_PTR,
	(dma_register_t *) DMA9_NEXT_DESC_PTR,
	(dma_register_t *) DMA10_NEXT_DESC_PTR,
	(dma_register_t *) DMA11_NEXT_DESC_PTR,
#endif
	(dma_register_t *) MDMA_D0_NEXT_DESC_PTR,
	(dma_register_t *) MDMA_S0_NEXT_DESC_PTR,
	(dma_register_t *) MDMA_D1_NEXT_DESC_PTR,
	(dma_register_t *) MDMA_S1_NEXT_DESC_PTR,
};
#endif

/*------------------------------------------------------------------------------
 *       Set the Buffer Clear bit in the Configuration register of specific DMA
 *       channel. This will stop the descriptor based DMA operation.
 *-----------------------------------------------------------------------------*/
static void clear_dma_buffer(unsigned int channel)
{
	dma_ch[channel].regs->cfg |= RESTART;
	SSYNC;
	dma_ch[channel].regs->cfg &= ~RESTART;
	SSYNC;
}

int __init blackfin_dma_init(void)
{
	int i;

	printk(KERN_INFO "Blackfin DMA Controller\n");

	for (i = 0; i < MAX_BLACKFIN_DMA_CHANNEL; i++) {
		dma_ch[i].chan_status = DMA_CHANNEL_FREE;
		dma_ch[i].regs = base_addr[i];
		init_MUTEX(&(dma_ch[i].dmalock));
	}

	return 0;
}

arch_initcall(blackfin_dma_init);

/*
 *	Form the channel find the irq number for that channel.
 */
#if !defined (CONFIG_BF561)

static int bf533_channel2irq(unsigned int channel)
{
	int ret_irq = -1;

	switch (channel) {
	case CH_PPI:
		ret_irq = IRQ_PPI;
		break;

#if (defined(CONFIG_BF537) || defined(CONFIG_BF534) || defined(CONFIG_BF536))
	case CH_EMAC_RX:
		ret_irq = IRQ_MAC_RX;
		break;

	case CH_EMAC_TX:
		ret_irq = IRQ_MAC_TX;
		break;

	case CH_UART1_RX:
		ret_irq = IRQ_UART1_RX;
		break;

	case CH_UART1_TX:
		ret_irq = IRQ_UART1_TX;
		break;
#endif

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
		ret_irq = IRQ_UART_RX;
		break;

	case CH_UART_TX:
		ret_irq = IRQ_UART_TX;
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

# define channel2irq(channel) bf533_channel2irq(channel)

#else

static int bf561_channel2irq(unsigned int channel)
{
	int ret_irq = -1;

	switch (channel) {
	case CH_PPI0:
		ret_irq = IRQ_PPI0;
		break;
	case CH_PPI1:
		ret_irq = IRQ_PPI1;
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
		ret_irq = IRQ_UART_RX;
		break;
	case CH_UART_TX:
		ret_irq = IRQ_UART_TX;
		break;

	case CH_MEM_STREAM0_SRC:
	case CH_MEM_STREAM0_DEST:
		ret_irq = IRQ_MEM_DMA0;
		break;
	case CH_MEM_STREAM1_SRC:
	case CH_MEM_STREAM1_DEST:
		ret_irq = IRQ_MEM_DMA1;
		break;
	case CH_MEM_STREAM2_SRC:
	case CH_MEM_STREAM2_DEST:
		ret_irq = IRQ_MEM_DMA2;
		break;
	case CH_MEM_STREAM3_SRC:
	case CH_MEM_STREAM3_DEST:
		ret_irq = IRQ_MEM_DMA3;
		break;

	case CH_IMEM_STREAM0_SRC:
	case CH_IMEM_STREAM0_DEST:
		ret_irq = IRQ_IMEM_DMA0;
		break;
	case CH_IMEM_STREAM1_SRC:
	case CH_IMEM_STREAM1_DEST:
		ret_irq = IRQ_IMEM_DMA1;
		break;
	}
	return ret_irq;
}
# define channel2irq(channel) bf561_channel2irq(channel)

#endif

/*------------------------------------------------------------------------------
 *	Request the specific DMA channel from the system.
 *-----------------------------------------------------------------------------*/
int request_dma(unsigned int channel, char *device_id)
{

	DMA_DBG("request_dma() : BEGIN \n");
	down(&(dma_ch[channel].dmalock));

	if ((dma_ch[channel].chan_status == DMA_CHANNEL_REQUESTED)
	    || (dma_ch[channel].chan_status == DMA_CHANNEL_ENABLED)) {
		up(&(dma_ch[channel].dmalock));
		DMA_DBG("DMA CHANNEL IN USE  \n");
		return -EBUSY;
	} else {
		dma_ch[channel].chan_status = DMA_CHANNEL_REQUESTED;
		DMA_DBG("DMA CHANNEL IS ALLOCATED  \n");
	}

	up(&(dma_ch[channel].dmalock));

	dma_ch[channel].device_id = device_id;
	dma_ch[channel].irq_callback = NULL;

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

	assert(dma_ch[channel].chan_status != DMA_CHANNEL_FREE
	       && channel < MAX_BLACKFIN_DMA_CHANNEL);

	if (callback != NULL) {
		int ret_val;
		ret_irq = channel2irq(channel);

		dma_ch[channel].data = data;

		ret_val =
		    request_irq(ret_irq, (void *)callback, SA_INTERRUPT,
				dma_ch[channel].device_id, data);
		if (ret_val) {
			printk(KERN_NOTICE "Request irq in DMA engine failed.\n");
			return -EPERM;
		}
		dma_ch[channel].irq_callback = callback;
	}
	return 0;
}

void free_dma(unsigned int channel)
{
	int ret_irq;

	DMA_DBG("freedma() : BEGIN \n");
//	printk("free channel %d, chan_free is %d, status is %d, MAX is %d\n",DMA_CHANNEL_FREE, channel,dma_ch[channel].chan_status,MAX_BLACKFIN_DMA_CHANNEL);
	assert(dma_ch[channel].chan_status != DMA_CHANNEL_FREE
	       && channel < MAX_BLACKFIN_DMA_CHANNEL);

	/* Halt the DMA */
	disable_dma(channel);
	clear_dma_buffer(channel);

	if (dma_ch[channel].irq_callback != NULL) {
		ret_irq = channel2irq(channel);
		free_irq(ret_irq, dma_ch[channel].data);
	}

	/* Clear the DMA Variable in the Channel */
	down(&(dma_ch[channel].dmalock));
	dma_ch[channel].chan_status = DMA_CHANNEL_FREE;
	up(&(dma_ch[channel].dmalock));

	DMA_DBG("freedma() : END \n");
}

void dma_enable_irq(unsigned int channel)
{
	int ret_irq;

	DMA_DBG("dma_enable_irq() : BEGIN \n");
	assert(dma_ch[channel].chan_status != DMA_CHANNEL_FREE
	       && channel < MAX_BLACKFIN_DMA_CHANNEL);

	ret_irq = channel2irq(channel);
	enable_irq(ret_irq);
}

void dma_disable_irq(unsigned int channel)
{
	int ret_irq;

	DMA_DBG("dma_disable_irq() : BEGIN \n");
	assert(dma_ch[channel].chan_status != DMA_CHANNEL_FREE
	       && channel < MAX_BLACKFIN_DMA_CHANNEL);

	ret_irq = channel2irq(channel);
	disable_irq(ret_irq);
}


int dma_channel_active(unsigned int channel)
{
	if (dma_ch[channel].chan_status == DMA_CHANNEL_FREE) {
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

	assert(dma_ch[channel].chan_status != DMA_CHANNEL_FREE
	       && channel < MAX_BLACKFIN_DMA_CHANNEL);

	dma_ch[channel].regs->cfg &= ~DMAEN;	/* Clean the enable bit */
	SSYNC;
	dma_ch[channel].chan_status = DMA_CHANNEL_REQUESTED;
	/* Needs to be enabled Later */
	DMA_DBG("stop_dma() : END \n");
	return;
}

void enable_dma(unsigned int channel)
{
	DMA_DBG("enable_dma() : BEGIN \n");

	assert(dma_ch[channel].chan_status != DMA_CHANNEL_FREE
	       && channel < MAX_BLACKFIN_DMA_CHANNEL);

	dma_ch[channel].chan_status = DMA_CHANNEL_ENABLED;
	dma_ch[channel].regs->curr_x_count = 0;
	dma_ch[channel].regs->curr_y_count = 0;

	dma_ch[channel].regs->cfg |= DMAEN;	/* Set the enable bit */
	SSYNC;
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

	assert(dma_ch[channel].chan_status != DMA_CHANNEL_FREE
	       && channel < MAX_BLACKFIN_DMA_CHANNEL);

	dma_ch[channel].regs->start_addr = addr;
	SSYNC;
	DMA_DBG("set_dma_start_addr() : END\n");
}

void set_dma_next_desc_addr(unsigned int channel, unsigned long addr)
{
	DMA_DBG("set_dma_next_desc_addr() : BEGIN \n");

	assert(dma_ch[channel].chan_status != DMA_CHANNEL_FREE
	       && channel < MAX_BLACKFIN_DMA_CHANNEL);

	dma_ch[channel].regs->next_desc_ptr = addr;
	SSYNC;
	DMA_DBG("set_dma_start_addr() : END\n");
}

void set_dma_x_count(unsigned int channel, unsigned short x_count)
{
	assert(dma_ch[channel].chan_status != DMA_CHANNEL_FREE
	       && channel < MAX_BLACKFIN_DMA_CHANNEL);

	dma_ch[channel].regs->x_count = x_count;
	SSYNC;
}

void set_dma_y_count(unsigned int channel, unsigned short y_count)
{
	assert(dma_ch[channel].chan_status != DMA_CHANNEL_FREE
	       && channel < MAX_BLACKFIN_DMA_CHANNEL);

	dma_ch[channel].regs->y_count = y_count;
	SSYNC;
}

void set_dma_x_modify(unsigned int channel, short x_modify)
{
	assert(dma_ch[channel].chan_status != DMA_CHANNEL_FREE
	       && channel < MAX_BLACKFIN_DMA_CHANNEL);

	dma_ch[channel].regs->x_modify = x_modify;
	SSYNC;
}

void set_dma_y_modify(unsigned int channel, short y_modify)
{
	assert(dma_ch[channel].chan_status != DMA_CHANNEL_FREE
	       && channel < MAX_BLACKFIN_DMA_CHANNEL);

	dma_ch[channel].regs->y_modify = y_modify;
	SSYNC;
}

void set_dma_config(unsigned int channel, unsigned short config)
{
	assert(dma_ch[channel].chan_status != DMA_CHANNEL_FREE
	       && channel < MAX_BLACKFIN_DMA_CHANNEL);

	dma_ch[channel].regs->cfg = config;
	SSYNC;
}

unsigned short
set_bfin_dma_config(char direction, char flow_mode,
		    char intr_mode, char dma_mode, char width)
{
	unsigned short config;

	config =
	    ((direction << 1) | (width << 2) | (dma_mode << 4) |
	     (intr_mode << 6) | (flow_mode << 12) | RESTART);
	return config;
}

void set_dma_sg(unsigned int channel, dmasg_t * sg, int nr_sg)
{
	assert(dma_ch[channel].chan_status != DMA_CHANNEL_FREE
	       && channel < MAX_BLACKFIN_DMA_CHANNEL);

	dma_ch[channel].regs->cfg |= ((nr_sg & 0x0F) << 8);

	dma_ch[channel].regs->next_desc_ptr = (unsigned int)sg;

	SSYNC;
}

/*------------------------------------------------------------------------------
 *	Get the DMA status of a specific DMA channel from the system.
 *-----------------------------------------------------------------------------*/
unsigned short get_dma_curr_irqstat(unsigned int channel)
{
	assert(dma_ch[channel].chan_status != DMA_CHANNEL_FREE
	       && channel < MAX_BLACKFIN_DMA_CHANNEL);

	return dma_ch[channel].regs->irq_status;
}

/*------------------------------------------------------------------------------
 *	Clear the DMA_DONE bit in DMA status. Stop the DMA completion interrupt.
 *-----------------------------------------------------------------------------*/
void clear_dma_irqstat(unsigned int channel)
{
	assert(dma_ch[channel].chan_status != DMA_CHANNEL_FREE
	       && channel < MAX_BLACKFIN_DMA_CHANNEL);
	dma_ch[channel].regs->irq_status |= 3;
}

/*------------------------------------------------------------------------------
 *	Get current DMA xcount of a specific DMA channel from the system.
 *-----------------------------------------------------------------------------*/
unsigned short get_dma_curr_xcount(unsigned int channel)
{
	assert(dma_ch[channel].chan_status != DMA_CHANNEL_FREE
	       && channel < MAX_BLACKFIN_DMA_CHANNEL);

	return dma_ch[channel].regs->curr_x_count;
}

/*------------------------------------------------------------------------------
 *	Get current DMA ycount of a specific DMA channel from the system.
 *-----------------------------------------------------------------------------*/
unsigned short get_dma_curr_ycount(unsigned int channel)
{
	assert(dma_ch[channel].chan_status != DMA_CHANNEL_FREE
	       && channel < MAX_BLACKFIN_DMA_CHANNEL);

	return dma_ch[channel].regs->curr_y_count;
}

void *dma_memcpy(void * dest,const void *src,size_t count)
{
	BUG_ON(count > 0xFFFF);

	bfin_write_MDMA_D0_IRQ_STATUS(DMA_DONE | DMA_ERR);

	/* Copy sram functions from sdram to sram */
	/* Setup destination start address */
	bfin_write_MDMA_D0_START_ADDR(dest);
	/* Setup destination xcount */
	bfin_write_MDMA_D0_X_COUNT(count );
	/* Setup destination xmodify */
	bfin_write_MDMA_D0_X_MODIFY(1);

	/* Setup Source start address */
	bfin_write_MDMA_S0_START_ADDR(src);
	/* Setup Source xcount */
	bfin_write_MDMA_S0_X_COUNT(count);
	/* Setup Source xmodify */
	bfin_write_MDMA_S0_X_MODIFY(1);

	/* Enable source DMA */
	bfin_write_MDMA_S0_CONFIG((DMAEN));
	SSYNC;

	bfin_write_MDMA_D0_CONFIG(( WNR | DMAEN));

	while (bfin_read_MDMA_D0_IRQ_STATUS() & DMA_RUN)
		bfin_write_MDMA_D0_IRQ_STATUS(bfin_read_MDMA_D0_IRQ_STATUS() | (DMA_DONE | DMA_ERR));

	bfin_write_MDMA_D0_IRQ_STATUS(bfin_read_MDMA_D0_IRQ_STATUS() | (DMA_DONE | DMA_ERR));

	dest += count;
	src  += count;
	return dest;
}

EXPORT_SYMBOL(request_dma);
EXPORT_SYMBOL(set_dma_callback);
EXPORT_SYMBOL(enable_dma);
EXPORT_SYMBOL(disable_dma);
EXPORT_SYMBOL(dma_channel_active);
EXPORT_SYMBOL(free_dma);

EXPORT_SYMBOL(get_dma_curr_irqstat);
EXPORT_SYMBOL(clear_dma_irqstat);
EXPORT_SYMBOL(get_dma_curr_xcount);
EXPORT_SYMBOL(get_dma_curr_ycount);
EXPORT_SYMBOL(set_dma_start_addr);

EXPORT_SYMBOL(set_dma_config);
EXPORT_SYMBOL(set_dma_next_desc_addr);
EXPORT_SYMBOL(set_bfin_dma_config);
EXPORT_SYMBOL(set_dma_x_count);
EXPORT_SYMBOL(set_dma_x_modify);
EXPORT_SYMBOL(set_dma_y_count);
EXPORT_SYMBOL(set_dma_y_modify);
EXPORT_SYMBOL(set_dma_sg);
EXPORT_SYMBOL(dma_disable_irq);
EXPORT_SYMBOL(dma_enable_irq);
EXPORT_SYMBOL(dma_memcpy);
