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

#if !defined(REMOVE_DEAD_CODE)
static DMA_MAPPING mapping[] = {
	{ DMA_DEVICE_PPI,		0,	0,	PMAP_PPI	},
	{ DMA_DEVICE_SPORT_RX,	0,	0,	PMAP_SPORT0_RX	},
	{ DMA_DEVICE_SPORT_TX,	0,	0,	PMAP_SPORT0_TX	},
	{ DMA_DEVICE_SPORT_RX,	1,	0,	PMAP_SPORT1_RX	},
	{ DMA_DEVICE_SPORT_TX,	1,	0,	PMAP_SPORT1_TX	},
	{ DMA_DEVICE_SPI,		0,	0,	PMAP_SPI	},
	{ DMA_DEVICE_UART_RX,	0,	0,	PMAP_UART_RX	},
	{ DMA_DEVICE_UART_TX,	0,	0,	PMAP_UART_TX	},
};
#endif

//#define	MEM_DMA_TEST 0
#undef MEM_DMA_TEST

static void inline enable_dma_stopmode(unsigned int);
static void inline enable_dma_autobuffer(unsigned int);
static void inline enable_dma_descr_array(unsigned int);
static void inline enable_dma_descr_small(unsigned int);
static void inline enable_dma_descr_large(unsigned int);
static unsigned short inline get_dma_curr_x_count(unsigned int);
static unsigned short inline get_dma_curr_y_count(unsigned int); 
static void clear_dma_buffer(unsigned int channel);
static void disable_dma_buffer_clear(unsigned int channel);
static void enable_dma_data_row_intr(unsigned int channel);
static void enable_dma_data_intr(unsigned int channel);
static void enable_dma_err_intr(unsigned int channel);
static void disable_dma_intr(unsigned int channel);
static void disable_dma_buffer_clear(unsigned int);
static void clear_dma_buffer(unsigned int);
inline unsigned short get_dma_irq_stat(unsigned int channel);
int bfin_freedma(unsigned int);
int bfin_request_dma(char *,unsigned int,dma_interrupt_t,void *);
static void set_dma_type(unsigned int, char);

void src_dma_int_handler(int irq, void *dev_id,struct pt_regs *pt_regs)
{
//	unsigned short irq_stat = get_dma_irq_stat(CH_MEM_STREAM0_SRC);
	get_dma_irq_stat(CH_MEM_STREAM0_SRC);

	disable_irq(irq);
}

void dst_dma_int_handler(int irq, void *dev_id,struct pt_regs *pt_regs)
{
//	unsigned short irq_stat = get_dma_irq_stat(CH_MEM_STREAM0_DEST);
	get_dma_irq_stat(CH_MEM_STREAM0_DEST);

	disable_irq(irq);
}
/*
 *	bfin_mem_dma is a function to do memory to memory DMA, also this is
 *	a example to show how those functions in EXPORT_SYMBOL need to be used.
 */
int bfin_mem_dma(unsigned short *pages_src,unsigned short *pages_dest, 
		int len,	/* length of the requested transfer */
		int	size, /* size of each transfer */
		dma_interrupt_t sint_handler, 
		dma_interrupt_t dint_handler)
{
	DMA_RESULT 	ret0, ret1;
	struct dma_config_t cfgsrc, cfgdst;
	unsigned short irq_stat;
		
	ret0=bfin_request_dma("MRDMA",CH_MEM_STREAM0_DEST,src_dma_int_handler,NULL);
	ret1=bfin_request_dma("MWDMA",CH_MEM_STREAM0_SRC,dst_dma_int_handler,NULL);
	
	if( (ret0<0) || (ret1<0) ) {
		printk("Request DMA for memory read and write failed.\n");
		return -1;
	}
	/* - Setup the parameters for the DMA channel */
	memset(&cfgsrc, 0, sizeof(struct dma_config_t));
	memset(&cfgdst, 0, sizeof(struct dma_config_t));

	if( size == sizeof(unsigned char )) {
		cfgsrc.config.config_u = (0x1000 | DI_EN | DI_SEL | WDSIZE_8);
		cfgdst.config.config_u = (0x1000 | DI_EN | DI_SEL | WDSIZE_8 |WNR );
	} else if( size == sizeof(unsigned short))  {	
		cfgsrc.config.config_u = (0x1000 | DI_EN | DI_SEL | WDSIZE_16);
		cfgdst.config.config_u = (0x1000 | DI_EN | DI_SEL | WDSIZE_16 |WNR );
	} else  {
		cfgsrc.config.config_u = (0x1000 | DI_EN | DI_SEL | WDSIZE_32);
		cfgdst.config.config_u = (0x1000 | DI_EN | DI_SEL | WDSIZE_32 |WNR );
	}
    cfgsrc.xcount    = len; 
    cfgsrc.xmodify   = 0;
	cfgsrc.dma_2d =0;
	//	cfgsrc.int_en = 1;
	cfgsrc.int_en = 0;

    cfgdst.xcount    = len;
	printk("xcount is %d words.\n", cfgdst.xcount);
    cfgdst.xmodify   = size;
	cfgdst.dma_2d =0;
	//	cfgsrc.int_en = 1;
	cfgsrc.int_en = 0;

	ret0 = bfin_setupdma(CH_MEM_STREAM0_SRC, pages_src, len, cfgsrc);
	ret1 = bfin_setupdma(CH_MEM_STREAM0_DEST, pages_dest, len, cfgdst);
	
	/* 5- start the DMA for desired channel */
	bfin_startdma(CH_MEM_STREAM0_SRC);
	bfin_startdma(CH_MEM_STREAM0_DEST);

	/* 6- Wait DMA to finish or cause errors */
	while(1) {
		printk("Wait mem to mem DMA to finish....");
		irq_stat = get_dma_irq_stat(CH_MEM_STREAM0_DEST);
		if( irq_stat & DMA_DONE ) {
			printk("done!");
			break;
		}	
		if( irq_stat & DMA_ERR ) {
			printk("error!");
			break;
		}	
	}	
	/* 8- After finish DMA, release it. */
	bfin_freedma(CH_MEM_STREAM0_SRC);
	bfin_freedma(CH_MEM_STREAM0_DEST);
	return 0;
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

#ifdef MEM_DMA_TEST
	unsigned short *pages_src, *pages_dest;
	if (!(pages_src =  __get_free_pages(GFP_KERNEL,1)))
		return -ENOMEM;
	if (!(pages_dest =  __get_free_pages(GFP_KERNEL,1)))
		return -ENOMEM;

	 // memset to init them to different values...
	memset( pages_src, 0x0, PAGE_SIZE);
	memset( pages_dest, 0xFF, PAGE_SIZE);

	bfin_mem_dma(pages_src, pages_dest, PAGE_SIZE/2, sizeof(unsigned short), NULL, NULL);

	if( memcmp(pages_src, pages_dest, PAGE_SIZE) ) {
		/*	DMA meet problems, need to check the reason in the interrupt handler*/
		printk("Memory to memory DMA test failed.\n");
	} else
		printk("Memory to memory DMA test done.\n");
	
	free_pages((unsigned long)pages_src, 1);
	free_pages((unsigned long)pages_dest, 1);
#endif	
	return 0;
}

arch_initcall(blackfin_dma_init);

#if !defined(REMOVE_DEAD_CODE)
/*------------------------------------------------------------------------------
* Initialize the channel with the given values
*-----------------------------------------------------------------------------*/
static void init_channel(unsigned int channel,
			unsigned short cfg, unsigned short start_addr,
			unsigned short x_count, unsigned short x_modify,
			unsigned short y_count, unsigned short y_modify)
{
	dma_ch[channel].regs->cfg = cfg;
	dma_ch[channel].regs->start_addr = start_addr;
	dma_ch[channel].regs->x_count = x_count;
	dma_ch[channel].regs->x_modify = x_modify;
	dma_ch[channel].regs->y_count = y_count;
	dma_ch[channel].regs->y_modify = y_modify;
	SSYNC();
}
#endif
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
 *	Get the DMA status of a specific DMA channel from the system.
 *-----------------------------------------------------------------------------*/
int bfin_get_dma_status(unsigned int channel)
{
	return dma_ch[channel].regs->irq_status;
}

/*------------------------------------------------------------------------------
 *	Clear the DMA_DONE bit in DMA status. Stop the DMA completion interrupt.
 *-----------------------------------------------------------------------------*/
void bfin_clear_dma_done(unsigned int channel)
{
	dma_ch[channel].regs->irq_status |= 1;
}

/*------------------------------------------------------------------------------
 *	Clear the DMA_ERR bit in DMA status. Stop the DMA error interrupt.
 *-----------------------------------------------------------------------------*/
void bfin_clear_dma_err(unsigned int channel)
{
	dma_ch[channel].regs->irq_status |= 2;
}

/*------------------------------------------------------------------------------
 *	Get current DMA xcount of a specific DMA channel from the system.
 *-----------------------------------------------------------------------------*/
int bfin_get_curxcount(unsigned int channel)
{
	return dma_ch[channel].regs->curr_x_count;
}

/*------------------------------------------------------------------------------
 *	Get current DMA ycount of a specific DMA channel from the system.
 *-----------------------------------------------------------------------------*/
int bfin_get_curycount(unsigned int channel)
{
	return dma_ch[channel].regs->curr_y_count;
}

/*------------------------------------------------------------------------------
 *	Request the specific DMA channel from the system.
 *-----------------------------------------------------------------------------*/
int bfin_request_dma(char *name,unsigned int channel, 
							dma_interrupt_t callback, void *data)
{
	int		ret_irq = 0;
 
	DMA_DBG("request_dma() : BEGIN \n");
	down(&(dma_ch[channel].dmalock));

	if ((dma_ch[channel].dma_channel_status == DMA_CHANNEL_REQUESTED )
		||(dma_ch[channel].dma_channel_status == DMA_CHANNEL_ENABLED)){
		up(&(dma_ch[channel].dmalock));
		DMA_DBG("DMA CHANNEL IN USE  \n");
		return DMA_CHANNEL_IN_USE;
	}
	else{
		dma_ch[channel].dma_channel_status = DMA_CHANNEL_REQUESTED ;
		DMA_DBG("DMA CHANNEL IS ALLOCATED  \n");
	}
	up(&(dma_ch[channel].dmalock));
 	dma_ch[channel].callback = callback;
	dma_ch[channel].descr_base = BASE_VALUE;
	dma_ch[channel].LoopbackFlag = 0;
	dma_ch[channel].data= data;

	/* This is to be enabled by putting a restriction -
	   you have to request DMA , before doing any operations on
	   descriptor/channel
	*/
	DMA_DBG("InitializeChannel : Done  \n");

	if( callback != NULL ) {
		int	ret_val;
		ret_irq =bf533_channel2irq(channel);
		ret_val = request_irq(ret_irq,(void *)callback,SA_INTERRUPT,name,data);
		if( ret_val ) {
			printk("Request irq in DMA engine failed.\n");
			return DMA_FAIL;
		} 	
	}	
	DMA_DBG("request_dma() : END  \n");
	return channel;
}

int bfin_freedma(unsigned int channel)
{
	DMA_DBG("freedma() : BEGIN \n");
		
	/* Halt the DMA */
	bfin_stopdma(channel);
	clear_dma_buffer(channel);
	disable_dma_buffer_clear(channel);

	/* Make sure the DMA channel will be stopped before free it */
	disable_irq (bf533_channel2irq(channel) );
	
	/* Clear the DMA Variable in the Channel*/
	dma_ch[channel].last_descriptor = BASE_VALUE;
	dma_ch[channel].first_descriptor = BASE_VALUE;
	dma_ch[channel].wait_last_descriptor = BASE_VALUE;
	dma_ch[channel].wait_first_descriptor = BASE_VALUE;
	dma_ch[channel].next_descriptor = BASE_VALUE;

	down(&(dma_ch[channel].dmalock));
	dma_ch[channel].dma_channel_status = DMA_CHANNEL_FREE;
	up(&(dma_ch[channel].dmalock));

	DMA_DBG("freedma() : END \n");
	return 0;
}
 
/*
 *	Flag: - 1:clear DMA_DONE interrupt status bit;
 *		  - 2:clear DMA_ERR interrupt status  bit;
 *		  - 3:clear both	
 */
int bfin_ack_dma_int(unsigned int channel, int flag)
{
	dma_ch[channel].regs->irq_status |=( flag & 0x3 );
	SSYNC();
	return DMA_SUCCESS;
}
/*------------------------------------------------------------------------------
*	stop the specific DMA channel.
*-----------------------------------------------------------------------------*/
int bfin_stopdma(unsigned int channel)
{
	DMA_DBG("stop_dma() : BEGIN \n");
//#if 0
	/* Here we are not checking for enable_dma() - is it required ?*/
	disable_dma_intr(channel);
//#endif	
	dma_ch[channel].regs->cfg &= ~DMAEN;	/* Clean the enable bit */
	SSYNC();
	dma_ch[channel].dma_channel_status  = DMA_CHANNEL_REQUESTED;
	/* Needs to be enabled Later */
	DMA_DBG("stop_dma() : END \n");
	return DMA_SUCCESS;
}

int bfin_startdma(unsigned int channel)
{
	DMA_DBG("enable_dma() : BEGIN \n");

	/* here we are not returning if the channel is not requested. 
	   We have to do this - But need to be discussed */
	dma_ch[channel].flowmode = (((dma_ch[channel].regs->cfg ) &
							(0xf000)) >> 12);
	enable_dma_intr(channel);
    enable_irq(bf533_channel2irq(channel));
	dma_ch[channel].dma_channel_status = DMA_CHANNEL_ENABLED;
	dma_ch[channel].regs->cfg |= DMAEN;	/* Set the enable bit */
	SSYNC();
	DMA_DBG("enable_dma() : END \n");
	return DMA_SUCCESS;
}


/*
 *	According to the DMA, setting up the mode, address, etc and prepair
 *	the DMA transfer.
 *	Note: Provide this function for most of DMA use case but not all.
 *	If device driver want to use other modes, it must setup by itself.
 * 	- only autobuf mode enabled;
 */
int bfin_setupdma(unsigned int channel, void *buf, unsigned int len, struct dma_config_t cfg)
{
	DMA_register* dma = dma_ch[channel].regs;

	dma->start_addr = (unsigned long)buf;
	dma->cfg = cfg.config.config_u;
#if 0	
	dma->cfg = cfg.config;
#endif	
	dma->x_count    = cfg.xcount;
	dma->x_modify   = cfg.xmodify;
	dma->curr_x_count = 0;
	dma->curr_y_count = 0;

	if( cfg.dma_2d ) {
		dma->y_count    = cfg.ycount;
		dma->y_modify   = cfg.ymodify;
	}	
	if( cfg.int_en)
		enable_dma_intr(channel);

	SSYNC();
	return 0;
}	

#if !defined(REMOVE_DEAD_CODE)
/*------------------------------------------------------------------------------
*	Set the base address of the DMA descriptor block
*	base:			The address of the DMA descriptors
*-----------------------------------------------------------------------------*/
static void set_dma_descriptor_base(unsigned int channel, unsigned int base)
{
	DMA_DBG("set_dma_descriptor_base() : BEGIN \n");
 	dma_ch[channel].descr_base = base;
	DMA_DBG("set_dma_descriptor_base() : END \n");
}
/*------------------------------------------------------------------------------
*		Set the Start Address register for the specific DMA channel
* 		This function can be used for register based DMA,
*		to setup the start address
*		addr:		Starting address of the DMA Data to be transferred.
*-----------------------------------------------------------------------------*/
static void set_dma_start_addr(unsigned int channel, unsigned long addr)
{
	DMA_DBG("set_dma_start_addr() : BEGIN \n");
	dma_ch[channel].regs->start_addr = addr;
	SSYNC();
	DMA_DBG("set_dma_start_addr() : END\n");
}

/*------------------------------------------------------------------------------
*	Set the transfer direction for the specific DMA channel
*	This function can be used in the Register based DMA.
*	dir:	Transfer direction
*			0: Read from memory,
*			1: Write to memory
*-----------------------------------------------------------------------------*/
void set_dma_dir(unsigned int channel,  unsigned char dir)
{
	if( dir ) 
		dma_ch[channel].regs->cfg |= WNR;	/* Write to memory */
	else
		dma_ch[channel].regs->cfg &= ~WNR;	/* Write to memory */
	SSYNC();
}

/*------------------------------------------------------------------------------
*	Specify the transfer mode for the specific DMA channel
*	type:	Transfer mode
*			0: Stop Mode
*			1: Autobuffer based DMA
*			4: Descriptor Array based DMA
*			6: Descriptor list (small Model)
*			7: Descriptor list (large Model)
*-----------------------------------------------------------------------------*/
void set_dma_type(unsigned int channel, char type)
{
	dma_ch[channel].regs->cfg &= 0x0FFF;
	switch(type){
		case FLOW_STOP:		/* STOP mode */
			break;
		case FLOW_AUTO:	/* Autobuffer based DMA */
			dma_ch[channel].regs->cfg |= (FLOW_AUTO << 12 );
			break;
		case FLOW_ARRAY:	/* Decriptor Array based DMA mode */
			dma_ch[channel].regs->cfg |= (FLOW_ARRAY << 12);
			break;
		case FLOW_SMALL:	/* Decriptor list (small) */
			dma_ch[channel].regs->cfg |= (FLOW_SMALL << 12);
			break;
		case FLOW_LARGE:	/* Decripotr list (large)*/
			dma_ch[channel].regs->cfg |= (FLOW_LARGE << 12);
			break;
		default: 	/* Invalid TYPE */
			DMA_DBG ("Invalid TYPE \n");
			break;
	}
	SSYNC();
}

void set_dma_x_count(unsigned int channel, unsigned short x_count)
{
	dma_ch[channel].regs->x_count = x_count;
	SSYNC();
}

void set_dma_y_count(unsigned int channel, unsigned short y_count)
{
	dma_ch[channel].regs->y_count = y_count;
	SSYNC();
}

void set_dma_x_modify(unsigned int channel, unsigned short x_modify)
{
	dma_ch[channel].regs->x_modify = x_modify;
	SSYNC();
}

void set_dma_y_modify(unsigned int channel, unsigned short y_modify)
{
	dma_ch[channel].regs->y_modify = y_modify;
	SSYNC();
}

void set_dma_config(unsigned int channel, unsigned short config)
{
	dma_ch[channel].regs->cfg = config;
	SSYNC();
}

/*------------------------------------------------------------------------------
*	This function is used Mainly during the register based DMA.
*-----------------------------------------------------------------------------*/
static void set_dma_currdesc_addr(unsigned int channel, 
		unsigned long desc_addr)
{
	dma_ch[channel].regs->curr_desc_ptr = desc_addr;
	SSYNC();
}

/*------------------------------------------------------------------------------
*	This function is used Mainly during the register based DMA.
*-----------------------------------------------------------------------------*/
static void set_dma_nextdesc_addr(unsigned int channel, 
		unsigned long next_desc_addr)
{
	dma_ch[channel].regs->next_desc_ptr = next_desc_addr;
	SSYNC();
}

/*------------------------------------------------------------------------------
* set_dma_transfer_size()
* Set the data size of transfer for the specific DMA channel
* size:			Data size.
*		DATA_SIZE_8:	8-bit width
*		DATA_SIZE_16:	16-bit width
*		DATA_SIZE_32:	32-bit width
*-----------------------------------------------------------------------------*/
void set_dma_transfer_size(unsigned int channel, char size)
{
	unsigned short size_word;

	size_word = 0;
	/* Set the 2 & 3 bits as 0 for Initialization */
	dma_ch[channel].regs->cfg &= 0xFFF3;
	
	switch (size) {
		case DATA_SIZE_8:
			break;
		case DATA_SIZE_16:
			dma_ch[channel].regs->cfg |= WDSIZE_16;
			break;
		case DATA_SIZE_32:
			dma_ch[channel].regs->cfg |= WDSIZE_32;
			break;
		default:
			DMA_DBG ("Invalid tranfer_size \n");
			break;
			 
	}
	SSYNC();
}

/*------------------------------------------------------------------------------
* get_dma_transfer_size()
*-----------------------------------------------------------------------------*/
static int get_dma_transfer_size(unsigned int channel)
{
	unsigned int size;
	size = dma_ch[channel].regs->cfg;
	size &= 0x000C; 	/* Bits 2 & 3 represents the WDSIZE  */
	size >>=2;
	return size;
}
#endif

/*------------------------------------------------------------------------------
*		Enable stop mode for the specific DMA channel
*-----------------------------------------------------------------------------*/
static inline void enable_dma_stopmode(unsigned int channel)
{
	set_dma_type(channel, DMA_STOP);
}

/*------------------------------------------------------------------------------
*		Enable Autobuffer mode for the specific DMA channel
*-----------------------------------------------------------------------------*/
void enable_dma_autobuffer(unsigned int channel)
{
	set_dma_type(channel, DMA_AUTO);
}

/*------------------------------------------------------------------------------
*		Enable descriptor array mode for the specific DMA channel
*-------------------------------------------------------------------------------*/
static inline void enable_dma_descr_array(unsigned int channel)
{
	set_dma_type(channel, DMA_ARRAY);
}

/*------------------------------------------------------------------------------
*		Enable descriptor list (small) mode for the specific DMA channel
*-----------------------------------------------------------------------------*/
static inline void enable_dma_descr_small(unsigned int channel)
{
	set_dma_type(channel, DMA_SMALL);
}

/*------------------------------------------------------------------------------
*		Enable descriptor list (large) mode for the specific DMA channel
*-----------------------------------------------------------------------------*/
static inline void enable_dma_descr_large(unsigned int channel)
{
	set_dma_type(channel, DMA_LARGE);
}

/*------------------------------------------------------------------------------
* Get the content of curr_x_count register for the specific DMA	channel
*-----------------------------------------------------------------------------*/
static inline unsigned short get_dma_curr_x_count(unsigned int channel)
{
	return dma_ch[channel].regs->curr_x_count;
}

/*------------------------------------------------------------------------------
*	Get the content of curr_y_count register for the specific DMA channel
*-----------------------------------------------------------------------------*/
static inline unsigned short get_dma_curr_y_count(unsigned int channel)
{
	return dma_ch[channel].regs->curr_y_count;
}

/*------------------------------------------------------------------------------
*	Set the Buffer Clear bit in the Configuration register of specific DMA 
*	channel. This will stop the descriptor based DMA operation.
*-----------------------------------------------------------------------------*/
static void clear_dma_buffer(unsigned int channel)
{
	dma_ch[channel].regs->cfg |= RESTART;
	SSYNC();
}

static void disable_dma_buffer_clear(unsigned int channel)
{
	dma_ch[channel].regs->cfg &= ~RESTART;
	SSYNC();
}

/*------------------------------------------------------------------------------
*	Enable Data Interrupt Timing Select ( used in 2D DMA )
*-----------------------------------------------------------------------------*/
static void enable_dma_data_row_intr(unsigned int channel)
{
	/* Check whether this function is called from 2D-DMA only */
 	/* Interrupt After completing each row */
	dma_ch[channel].regs->cfg |= DI_SEL;
	SSYNC();
}

static void enable_dma_data_intr(unsigned int channel)
{
	/* enable Data Interrupt  */
	dma_ch[channel].regs->cfg |= DI_EN;
	SSYNC();
}

static void enable_dma_err_intr(unsigned int channel)
{
	/* enable Error Interrupt  */
	dma_ch[channel].regs->irq_status |= DMAERR;
	SSYNC();
}

/*------------------------------------------------------------------------------
*	Disable Data Interrupt Timing Select (used in 2D DMA )
*-----------------------------------------------------------------------------*/
static void inline disable_dma_data_row_intr(unsigned int channel)
{
	dma_ch[channel].regs->cfg &= ~DI_SEL;
	SSYNC();
}

static void inline disable_dma_data_intr(unsigned int channel)
{
	dma_ch[channel].regs->cfg &= ~DI_EN;
	SSYNC();
}

static void inline disable_dma_err_intr(unsigned int channel)
{
	dma_ch[channel].regs->irq_status &= ~DMAERR;
	SSYNC();
}

DMA_RESULT enable_dma_intr(unsigned int channel)
{
	if (dma_ch[channel].dma_channel_status != DMA_CHANNEL_REQUESTED)
		return DMA_FAIL;

	DMA_DBG("enable_dma_intr () : BEGIN \n");
	/* enable Data Interrupt */
	enable_dma_data_intr(channel);

	/* enable Data Interrupt */
	enable_dma_data_row_intr(channel);

	/* enable Error Interrupt */
	enable_dma_err_intr(channel);

	SSYNC();
	DMA_DBG("enable_dma_intr () : END \n");
	return DMA_SUCCESS;
}

static void disable_dma_intr(unsigned int channel)
{
	DMA_DBG("disable_dma_intr () : BEGIN \n");
	disable_dma_data_row_intr(channel);
	disable_dma_data_intr(channel);
	disable_dma_err_intr(channel);
	DMA_DBG("disable_dma_intr () : END \n");
}

/*------------------------------------------------------------------------------
*		Get the content of IRQ Status register of specific DMA channel
*-----------------------------------------------------------------------------*/
inline unsigned short get_dma_irq_stat(unsigned int channel)
{
	return dma_ch[channel].regs->irq_status;
}

void clr_dma_irq_stat(unsigned int channel)
{
	dma_ch[channel].regs->irq_status = BASE_VALUE;
	SSYNC();
}

void clr_dma_done_irq(unsigned int channel)
{
	dma_ch[channel].regs->irq_status |= DMA_DONE;
	SSYNC();
}

void clr_dma_err_irq(unsigned int channel)
{
	dma_ch[channel].regs->irq_status |= DMA_ERR;
	SSYNC();
}



#if !defined(REMOVE_DEAD_CODE)
/* NOTE: The descriptor must be aligned to 16-bit boundary */
/*------------------------------------------------------------------------------
*	Creates a new descriptor with the given type (Array,small,large)
*	flowtype:	The type of the DMA Descriptor to be created
*-----------------------------------------------------------------------------*/
static void* create_descriptor(int flowtype)
{
	void 		*pDescriptor = NULL;

	DMA_DBG("create_desriptor() : BEGIN \n");
	switch (flowtype){
		/* For Array Type DMA, the dynamic allocation is not required.
		   So the respective code is commented */
		case FLOW_SMALL:
			pDescriptor = 
			(dmasgsmall_t *)kmalloc(sizeof(dmasgsmall_t),GFP_KERNEL);
			break;
		case FLOW_LARGE:
			pDescriptor = 
			(dmasglarge_t *)kmalloc(sizeof(dmasglarge_t),GFP_KERNEL);
			break;
	}
	DMA_DBG("create_desriptor() : END \n");
	return pDescriptor;
}

/*------------------------------------------------------------------------------
 * dma_setup_desc()
*-----------------------------------------------------------------------------*/
/* This function is not used currently */
static void dma_setup_desc(	unsigned long desc,
							unsigned long next,
							unsigned long start_addr,
							unsigned short cfg,
							/* DMA_CONFIG_REG cfg, */
							unsigned short x_count,
							unsigned short x_modify,
							unsigned short y_count,
							unsigned short y_modify)
{
	DMA_DBG("dma_setup_desc () : BEGIN \n");

	/* Set the next addr  */
	/*
	((dmasglarge_t *) desc)->next_desc_ptr_lsb = (unsigned short) ((next) & LOW_WORD);
	((dmasglarge_t *) desc)->next_desc_ptr_msb = (unsigned short) (((next) >> 16) & LOW_WORD);
	*/

	/* Set the start  addr  */
	((dmasglarge_t *) desc)->start_addr = start_addr;

	/* Set the Configuaration Register */
	((dmasglarge_t *) desc)->cfg = cfg;

	/* Set the x-count */
	((dmasglarge_t *) desc)->x_count = x_count;

	/* Set the x-modify */
	((dmasglarge_t *) desc)->x_modify = x_modify;

	/* Set the y-count */
	((dmasglarge_t *) desc)->y_count = y_count;
	
	/* Set the y-modify */
	((dmasglarge_t *) desc)->y_modify = y_modify;

	DMA_DBG("dma_setup_desc () : END \n");
}

/*------------------------------------------------------------------------------
*	check_desc_size()
*		Checks the size of the descriptor set in the config register
*		based on the flow type
*-----------------------------------------------------------------------------*/
/* This function is not used currently */
static DMA_RESULT check_desc_size(unsigned int channel)
{
	unsigned short desc_size,flow_type = 0x0000;
	unsigned short cfg_word;

	cfg_word = dma_ch[channel].regs->cfg;
	flow_type = cfg_word & 0xF000;
	flow_type >>= 12;
	desc_size = cfg_word & 0x0F00;
	desc_size >>= 8;

	switch (flow_type){
		case DMA_STOP:
		case DMA_AUTO:
			if (desc_size)
				return DMA_BAD_DESCRIPTOR;
			break;
		case DMA_ARRAY:
			if (desc_size > NDSIZE_ARRAY )
				return DMA_BAD_DESCRIPTOR;
			break;
		case DMA_SMALL:
			if (desc_size > NDSIZE_SMALL )
				return DMA_BAD_DESCRIPTOR;
			break;
		case DMA_LARGE:
			if (desc_size > NDSIZE_LARGE )
				return DMA_BAD_DESCRIPTOR;
			break;
	}
	return DMA_SUCCESS;
}

static DMA_RESULT set_desc_startaddr(void *pDescriptor, unsigned long startaddr,
				 int flowtype)
{
	switch (flowtype){
		case DMA_ARRAY:
			((dmasgarray_t *)pDescriptor)->start_addr = startaddr;
			break;
		case DMA_SMALL:
			((dmasgsmall_t *)pDescriptor)->start_addr_lo =
						startaddr & LOW_WORD;
			((dmasgsmall_t *)pDescriptor)->start_addr_hi =
						(startaddr & HIGH_WORD ) >> 16 ;
			break;
		case DMA_LARGE:
			((dmasglarge_t *)pDescriptor)->start_addr = startaddr;
			break;
		default:
			break;
	}
	return DMA_SUCCESS;
}

static DMA_RESULT set_desc_xcount(void *pDescriptor, unsigned short x_count,
				 int flowtype)
{
	switch (flowtype){
		case DMA_ARRAY:
			((dmasgarray_t *)pDescriptor)->x_count = x_count;
			break;
		case DMA_SMALL:
			((dmasgsmall_t *)pDescriptor)->x_count = x_count;
			break;
		case DMA_LARGE:
			((dmasglarge_t *)pDescriptor)->x_count = x_count;
			break;
		default:
			break;
	}
	return DMA_SUCCESS;
}

static DMA_RESULT set_desc_xmodify(void *pDescriptor, unsigned short x_modify,
				int flowtype)
{
	switch (flowtype){
		case DMA_ARRAY:
			((dmasgarray_t *)pDescriptor)->x_modify = x_modify;
			break;
		case DMA_SMALL:
			((dmasgsmall_t *)pDescriptor)->x_modify = x_modify;
			break;
		case DMA_LARGE:
			((dmasglarge_t *)pDescriptor)->x_modify = x_modify;
			break;
		default:
			break;
	}
	return DMA_SUCCESS;
}

static DMA_RESULT set_desc_ycount(void *pDescriptor, unsigned short y_count,
				 int flowtype)
{
	switch (flowtype){
		case DMA_ARRAY:
			((dmasgarray_t *)pDescriptor)->y_count = y_count;
			break;
		case DMA_SMALL:
			((dmasgsmall_t *)pDescriptor)->y_count = y_count;
			break;
		case DMA_LARGE:
			((dmasglarge_t *)pDescriptor)->y_count = y_count;
			break;
		default:
			break;
	}
	return DMA_SUCCESS;
}

static DMA_RESULT set_desc_ymodify(void *pDescriptor, unsigned short y_modify,
				 int flowtype)
{
	switch (flowtype){
		case DMA_ARRAY:
			((dmasgarray_t *)pDescriptor)->y_modify = y_modify;
			break;
		case DMA_SMALL:
			((dmasgsmall_t *)pDescriptor)->y_modify = y_modify;
			break;
		case DMA_LARGE:
			((dmasglarge_t *)pDescriptor)->y_modify = y_modify;
			break;
		default:
			break;
	}
	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		dmaGetMapping()
* Description:
*		Get the pheripharal Mapping of the given channel
* Parameters:
*		channel:		DMA channel number.
* Return:
*		DMA_SUCCESS will be return for Success
*		DMA_BAD_DEVICE will be return for invalid Device
*-----------------------------------------------------------------------------*/
/* This function is not tested */
DMA_RESULT	dmaGetMapping(
		DMA_DEVICE_TYPE	DeviceType,
		unsigned int	DeviceNumber,
		unsigned int	*ControllerNumber,
		unsigned int	*ChannelNumber)
{
	int 		i;
	DMA_MAPPING	*pMapping;
	DMA_channel	*pChannel;

	assert(*ChannelNumber < MAX_BLACKFIN_DMA_CHANNEL);
	if (*ChannelNumber >= MAX_BLACKFIN_DMA_CHANNEL)
		return DMA_NO_SUCH_CHANNEL;

	for (pMapping = Mapping, i = 0 ;
		i < (sizeof (Mapping)/sizeof(DMA_MAPPING)); i++, pMapping++) {

		if ((pMapping->DeviceType == DeviceType) &&
			(pMapping->DeviceNumber == DeviceNumber)) {

			for (i=0; i < MAX_BLACKFIN_DMA_CHANNEL; i++) {

				pChannel = &dma_ch[i];
				if((pChannel->ControllerNumber == pMapping->ControllerNumber)
					&& (pChannel->PeripheralMap->b_PMAP == pMapping->PeripheralMap)) {

					*ControllerNumber = pChannel->ControllerNumber;
					*ChannelNumber = i;
					return DMA_SUCCESS;
				} /* End of if*/
			} /* End of For */
		} /* End of If */
	} /* End of for loop */
	return (DMA_BAD_DEVICE);
}

/*------------------------------------------------------------------------------
* Name:
*		dmaSetMapping()
* Description:
*		Get the pheripharal Mapping of the given channel
* Parameters:
*		DeviceType:		DMA Device Type.
*		DeviceNumber:		DMA Device Number.
*		ControllerNumber:	DMA Controller Number.
*		ChannelNumber:		DMA Channel Number.
* Return:
*		DMA_SUCCESS will be return for Success
*		DMA_BAD_DEVICE will be return for invalid Device 
*-----------------------------------------------------------------------------*/
/* This function is not tested */
DMA_RESULT	dmaSetMapping(
		DMA_DEVICE_TYPE		DeviceType,
		unsigned int		DeviceNumber,
		unsigned int		ControllerNumber,
		unsigned int		ChannelNumber)
{
	int 		i;		/* Generic Counter */
	DMA_MAPPING	*pMapping;	/* Pointer to the Mapping structure */
	DMA_channel	*pChannel;	/* pointer to the channel */

	for (pMapping = Mapping, i = 0;
		i < (sizeof (Mapping) / (sizeof (DMA_MAPPING)));
		i++, pMapping++ ){

		if ((pMapping->DeviceType == DeviceType) &&
			(pMapping->DeviceNumber == DeviceNumber)) {

			for (i=0; i < MAX_BLACKFIN_DMA_CHANNEL; i++) {
				pChannel = &dma_ch[i];
				if( (pChannel->ControllerNumber == ControllerNumber) &&
					( i  == ChannelNumber)) {
					/* Set the mapping to the device the client wants */
					pChannel->PeripheralMap->b_PMAP = pMapping->PeripheralMap;
					return DMA_SUCCESS;
				} /* End of if-loop*/
			} /* End of for-loop */
		} /* End of if-loop*/
	} /* End of for-loop */
	return (DMA_BAD_DEVICE);
}

/*------------------------------------------------------------------------------
*	Adds a new descriptor at the end of the existing descriptor list
*	of the given channel.
*	The last descriptor in the list will be in the stop mode
*	The flowtype can be  Array or Small or Large.
* Return:
*		DMA_NO_SUCH_CHANNEL: If the  channel number is invalid
*		DMA_BAD_DESCRIPTOR : If the Descriptor is NULL
*		DMA_SUCCESS : For successful execution
*-----------------------------------------------------------------------------*/
static DMA_RESULT add_descriptor(	void *pNewdescriptor,
				int  channel_number,
				int flowtype)
{
	DMA_CHANNEL *channel = &dma_ch[channel_number];
	DMA_RESULT 	retValue;
	void *last_descriptor = channel->last_descriptor;
	DMA_DBG (" add_descriptor(): BEGIN \n");
	if (( dma_ch[channel_number].regs->cfg ) & (DMAEN)) {
		down(&(dma_ch[channel_number].dmalock));
		retValue = 
			add_to_wait_descriptor(pNewdescriptor, 
						channel_number,flowtype);
		up(&(dma_ch[channel_number].dmalock));
		return retValue;
	}

	if (last_descriptor){ /* Channel has already a list of descriptors  */
		if (flowtype == FLOW_LARGE){
			/*set the next descriptor address of the newdescriptor*/
			((dmasglarge_t *)pNewdescriptor)->next_desc_addr =
				((dmasglarge_t *)last_descriptor)->next_desc_addr;
			/* update the  next descriptor address of the last
			descriptor in the existing list */
			((dmasglarge_t *)last_descriptor)->next_desc_addr =
				(unsigned long)pNewdescriptor;
			((dmasglarge_t *)last_descriptor)->cfg |= 0x7900;
		} else {
			/* If the new descriptor is 64K out of range of
			   previous descriptor then return error */
			int descr_base =
			(unsigned short)((unsigned long)pNewdescriptor & HIGH_WORD);
			if (channel->descr_base != descr_base){
				return DMA_BAD_DESCRIPTOR;
			}

			/* set the lower 4 bytes of the next descriptor address
			 of the new descriptor */
			((dmasgsmall_t *)pNewdescriptor)->next_desc_addr_lo =
				((dmasgsmall_t *)last_descriptor)->next_desc_addr_lo;

			/* update the lower 4 bytes of the  next descriptor
			address of the last descriptor in the existing
			list */
			((dmasgsmall_t *)last_descriptor)->next_desc_addr_lo =
				(unsigned short)((unsigned long)pNewdescriptor & LOW_WORD);

			/* In non-loopback mode, the last descriptor used to
			have STOP flow mode.  This is to be changed */
			((dmasgsmall_t *)last_descriptor)->cfg |= 0x6800;
		}
		
 	} else { /* Channel does not have any existing list of descriptors */
		if (flowtype == DMA_LARGE){
			((dmasglarge_t *)pNewdescriptor)->next_desc_addr =
				(unsigned long)pNewdescriptor;
			(dmasglarge_t *)(channel->first_descriptor) =
				(dmasglarge_t *)pNewdescriptor;
		} else{
			((dmasgsmall_t *)pNewdescriptor)->next_desc_addr_lo =
				(unsigned short)((unsigned long)pNewdescriptor & LOW_WORD);
			
			(dmasgsmall_t *)(channel->first_descriptor) =
				(dmasgsmall_t *)pNewdescriptor;

			channel->descr_base =
				(unsigned short)((unsigned long)pNewdescriptor & HIGH_WORD);
		}
	 }

	if (flowtype == DMA_LARGE){
		(dmasglarge_t *)(channel->last_descriptor) =
					(dmasglarge_t *)pNewdescriptor;
		((dmasgsmall_t *)pNewdescriptor)->cfg &= 0x0fff;
	} else {
		(dmasgsmall_t *)(channel->last_descriptor) =
					(dmasgsmall_t *)pNewdescriptor;
		((dmasgsmall_t *)pNewdescriptor)->cfg &= 0x0fff;
	}

	DMA_DBG (" add_descriptor(): END \n");
	return DMA_SUCCESS;
}

/*------------------------------------------------------------------------------
* Name:
*		add_to_wait_descriptor()
* Description:
*		Adds a new descriptor at the end of the existing Waiting
*		descriptor list	of the given channel.
* Parameters:
*		pNewDescriptor:	Pointer to the new descriptor to be addded.
*		channel_number:	Channel number.
*		flowtype:	The flow type of the descriptor
*				The flow type can be  Array or Small or Large.
* Return:
*		DMA_NO_SUCH_CHANNEL: If the  channel number is invalid
*		DMA_BAD_DESCRIPTOR : If the Descriptor is NULL
*		DMA_SUCCESS : For successful execution
*-----------------------------------------------------------------------------*/
static DMA_RESULT add_to_wait_descriptor(	void *pNewdescriptor,
					int  channel_number,
			 		int flowtype)
{
	DMA_CHANNEL *channel = &dma_ch[channel_number];
	void* last_descriptor;

	DMA_DBG (" add_to_wait_descriptor : BEGIN \n");

	if (flowtype == FLOW_SMALL){
		(dmasgsmall_t *)last_descriptor =
			(dmasgsmall_t *)(channel->wait_last_descriptor);
	} else{
		(dmasglarge_t *)last_descriptor =
			(dmasglarge_t *)(channel->wait_last_descriptor);
	}

	if (flowtype == DMA_SMALL){
		unsigned short base =
			(unsigned short)(((unsigned long)pNewdescriptor & HIGH_WORD)>>16);

		if ((channel->descr_base) && (base  != channel->descr_base)) {
			DMA_DBG ("Descriptor Out of Range \n");
			return DMA_BAD_DESCRIPTOR;
		}
	}

	if (last_descriptor){
		if (flowtype == DMA_LARGE){
			((dmasglarge_t *)pNewdescriptor)->next_desc_addr =
			((dmasglarge_t *)(channel->wait_last_descriptor))->next_desc_addr;

			((dmasglarge_t *)last_descriptor)->next_desc_addr =
						(unsigned long)pNewdescriptor;
		} else{ /* SMALL Descriptor Case */
			((dmasgsmall_t *)pNewdescriptor)->next_desc_addr_lo =
			((dmasgsmall_t *)(channel->wait_last_descriptor))->next_desc_addr_lo;

			((dmasgsmall_t *)(last_descriptor))->next_desc_addr_lo =
			(unsigned short)((unsigned long)pNewdescriptor & LOW_WORD);
		}
 	} else {
		if (flowtype == DMA_LARGE){
			((dmasglarge_t *)pNewdescriptor)->next_desc_addr =
				(unsigned long)pNewdescriptor;
			(dmasglarge_t *)(channel->wait_first_descriptor) =
				(dmasglarge_t *)pNewdescriptor;
		} else{
			((dmasgsmall_t *)pNewdescriptor)->next_desc_addr_lo =
				(unsigned short)((unsigned long)pNewdescriptor & LOW_WORD);

			(dmasgsmall_t *)(channel->wait_first_descriptor) =
			(dmasgsmall_t *)pNewdescriptor;
		}
	}

	if (flowtype == DMA_LARGE)
		(dmasglarge_t *)(channel->wait_last_descriptor) =
					(dmasglarge_t *)pNewdescriptor;
	else
		(dmasgsmall_t *)(channel->wait_last_descriptor) =
					(dmasgsmall_t *)pNewdescriptor;

	DMA_DBG (" add_to_wait_descriptor : END \n");
	return DMA_SUCCESS;
}

/***********************************************************
*
*   INTERRUPT RELATED FUNCTIONS
*
***********************************************************/
/*------------------------------------------------------------------------------
* Name:
*		testcallback()
* Description:
*		Callback function that will be called from ISR
*		This is a sample Test Program , for testing purpose
*		
* Parameters:
*		event:		The DMA_EVENT that caused to generate interrupt.
*		startAddress:	Starting address of the DMA in the descriptor
* Return: 
*		None
*-----------------------------------------------------------------------------*/

/* Current Implementation of callback function is for testing purpose  */
static void testcallback (DMA_EVENT event,  void *startAddress)
{
	DMA_DBG ("Callback Function is called \n");

	if (startAddress == NULL)
		return;

	switch (event){
		case DMA_ERROR_INTERRUPT:
			DMA_DBG ("DMA Error Interrupt  \n");
			break;
		case DMA_DESCRIPTOR_PROCESSED:
			DMA_DBG ("DMA Descriptor Event  \n");
			break;
		case DMA_INNER_LOOP_PROCESSED:
			DMA_DBG ("DMA Inner Loop processed Event  \n");
			break;
		case DMA_OUTER_LOOP_PROCESSED:
			DMA_DBG ("DMA Outer Loop processed Event  \n");
			break;
		case DMA_UNKNOWN_EVENT:
		default:
			DMA_DBG ("DMA Unknown Event  \n");
			break;
	}
	DMA_DBG ("\n Completed the Callback function processing \n");
}
/*------------------------------------------------------------------------------
*	Note: dma_interrupt was deleted, now we rely the device driver to handler 
*	the interrupt by themselves. The reason is: 
*		- Bfin map different channel's DMA interrupt to different irq number,
*		  not only one interrupt number;
*-------------------------------------------------------------------------------*/

/*------------------------------------------------------------------------------
*	Add a new descriptor to another descriptor. Currently this function 
*	is not used. In future we can enhanced to add a descriptor to the list of 
*	descriptors. 			
*-----------------------------------------------------------------------------*/
/* This function is not used */
static DMA_RESULT add_descriptor_descr(void *newdescriptor,
			void *previousdescriptor,
			int flowtype)
{
	dmasglarge_t* newdescr = (dmasglarge_t *)newdescriptor;
	dmasglarge_t* prevdescr = (dmasglarge_t *)previousdescriptor;
	DMA_DBG (" add_descriptor_descr \n");

	if (prevdescr) {
		newdescr->next_desc_addr = (unsigned long)prevdescr;
		prevdescr->next_desc_addr =  (unsigned long)newdescr;
	} else{
		newdescr->next_desc_addr = (unsigned long)newdescr;
	}
}
#endif

EXPORT_SYMBOL(bfin_request_dma);
EXPORT_SYMBOL(bfin_setupdma);
EXPORT_SYMBOL(bfin_startdma);
EXPORT_SYMBOL(bfin_stopdma);
EXPORT_SYMBOL(bfin_ack_dma_int);
EXPORT_SYMBOL(bfin_freedma);

EXPORT_SYMBOL(bfin_get_dma_status);
EXPORT_SYMBOL(bfin_clear_dma_done);
EXPORT_SYMBOL(bfin_clear_dma_err);
EXPORT_SYMBOL(bfin_get_curxcount);
EXPORT_SYMBOL(bfin_get_curycount);
