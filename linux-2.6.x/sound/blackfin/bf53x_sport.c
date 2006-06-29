
/*
 * File:         bf53x_sport.c 
 * Description:  low level driver for sportX/dmaY on blackfin 53x
 *               this should be moved to arch/blackfin/
 * Rev:          $Id$
 * Created:      Tue Sep 21 10:52:42 CEST 2004
 * Author:       Luuk van Dijk <blackfin@mdnmttr.nl>
 * Modifed by:	 Roy Huang <roy.huang@analog.com>
 * 
 * Copyright (C) 2006 Analog Device Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.
 * If not, write to the Free Software Foundation,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */


/*
 * notes:
 *
 *  - apparently you can't read back dma->start_addr, as it will stall
 *  the DMA (at least for tx)!  (learnt the hard way...)
 *
 */

#include <linux/slab.h>
#include <linux/delay.h>
#include <asm/bug.h>
#include <asm/dma.h>
#include <linux/dma-mapping.h>

#include "bf53x_sport.h"

//#define BF53X_SPORT_DEBUG

#ifdef  BF53X_SPORT_DEBUG
#define sport_printd(level, format, arg...) \
		printk(level "sport: " format, ## arg)
#define SPORT_ASSERT(expr) do {\
	if(unlikely(!(expr))) { \
		printk(KERN_ERR "%s: %d, bug\n", __FUNCTION__, __LINE__); \
	} \
} while(0)
#else
#define sport_printd(level, format, arg...)  
#define SPORT_ASSERT( expr ) 
#endif

#include <asm/blackfin.h>
#include <asm/dma.h>
#include <asm/cacheflush.h>

/* delay between frame sync pulse and first data bit in multichannel mode */ 
#define FRAME_DELAY (1<<12)  

#define SSYNC __builtin_bfin_ssync()

#if L1_DATA_A_LENGTH != 0
extern unsigned long l1_data_A_sram_alloc(unsigned long size);
extern int l1_data_A_sram_free(unsigned long addr);
#endif

static unsigned int sport_iobase[] = {SPORT0_TCR1, SPORT1_TCR1 };

static unsigned int dma_iobase[]   =
{
	DMA0_NEXT_DESC_PTR,
	DMA1_NEXT_DESC_PTR,
	DMA2_NEXT_DESC_PTR,
	DMA3_NEXT_DESC_PTR,
	DMA4_NEXT_DESC_PTR,
	DMA5_NEXT_DESC_PTR,
	DMA6_NEXT_DESC_PTR,
	DMA7_NEXT_DESC_PTR,
#if (defined(CONFIG_BF537) || defined(CONFIG_BF534) || defined(CONFIG_BF536))
	DMA8_NEXT_DESC_PTR,
	DMA9_NEXT_DESC_PTR,
	DMA10_NEXT_DESC_PTR,
	DMA11_NEXT_DESC_PTR,
#endif
	MDMA_D0_NEXT_DESC_PTR,
	MDMA_S0_NEXT_DESC_PTR,
	MDMA_D1_NEXT_DESC_PTR,
	MDMA_S1_NEXT_DESC_PTR
};

/* note: multichannel is in units of 8 channels, 
 * tdm_count is # channels NOT / 8 ! */
int bf53x_sport_set_multichannel( struct bf53x_sport* sport,
		int tdm_count, int packed)
{
	sport_printd( KERN_INFO, "%s( tdm_count=%d packed=%d )\n",
				__FUNCTION__, tdm_count, packed );

	if( (sport->regs->tcr1 & TSPEN) || (sport->regs->rcr1 & RSPEN) )
		return -EBUSY;

	if( tdm_count & 0x7 ) 
		return -EINVAL;

	if( tdm_count > 32 )
		return -EINVAL;  /* don't feel like overdoing it today :-) */

	SSYNC; /* is this really neccesary? */

	if( tdm_count ){

		int shift = 32 - tdm_count;    
		unsigned int mask = (0xffffffff >> shift);

		sport->regs->mcmc1 = ((tdm_count>>3)-1) << 12;
		sport->regs->mcmc2 = FRAME_DELAY| MCMEN | \
				( packed ? (MCDTXPE|MCDRXPE) : 0 );

		sport->regs->mtcs0 = mask; 
		sport->regs->mrcs0 = mask; 

	} else {

		sport->regs->mcmc1 = 0;
		sport->regs->mcmc2 = 0;

		sport->regs->mtcs0 = 0; 
		sport->regs->mrcs0 = 0; 
	}

	sport->regs->mtcs1 = 0; sport->regs->mtcs2 = 0; sport->regs->mtcs3 = 0;
	sport->regs->mrcs1 = 0; sport->regs->mrcs2 = 0; sport->regs->mrcs3 = 0;

	SSYNC;

	return 0;
}

int bf53x_sport_config_rx( struct bf53x_sport* sport, unsigned int rcr1,
		unsigned int rcr2, unsigned int clkdiv, unsigned int fsdiv )
{
	if( (sport->regs->tcr1 & TSPEN) || (sport->regs->rcr1 & RSPEN) )
		return -EBUSY;

	sport->regs->rcr1 = rcr1;
	sport->regs->rcr2 = rcr2;
	sport->regs->rclkdiv = clkdiv;
	sport->regs->rfsdiv = fsdiv;

	SSYNC;

	return 0;

}

int bf53x_sport_config_tx( struct bf53x_sport* sport, unsigned int tcr1,
		unsigned int tcr2, unsigned int clkdiv, unsigned int fsdiv )
{
	if( (sport->regs->tcr1 & TSPEN) || (sport->regs->rcr1 & RSPEN) )
		return -EBUSY;

	sport->regs->tcr1 = tcr1;
	sport->regs->tcr2 = tcr2;
	sport->regs->tclkdiv = clkdiv;
	sport->regs->tfsdiv = fsdiv;

	SSYNC;

	return 0;

}

static void setup_desc(dmasg_t* desc, void* buf, int fragcount,
		size_t fragsize, unsigned int cfg, 
		unsigned int x_count, unsigned int ycount, size_t size)
{

	int i;

	for( i=0; i<fragcount; ++i ){
		desc[i].next_desc_addr  = (unsigned long)&( desc[i + 1] );
		desc[i].start_addr = (unsigned long)buf + i*fragsize;
		desc[i].cfg = cfg;
		desc[i].x_count = x_count;
		desc[i].x_modify = size;
		desc[i].y_count = ycount;
		desc[i].y_modify = size;
	}

	/* make circular */
	desc[fragcount-1].next_desc_addr = (unsigned long)desc;

	/*  printk(KERN_ERR"setup desc: desc0=%p, next0=%lx, desc1=%p,"
		"next1=%lx\nx_count=%x,y_count=%x,addr=0x%lx,cfs=0x%x\n", 
		&(desc[0]), desc[0].next_desc_addr, 
		&(desc[1]), desc[1].next_desc_addr,
		desc[0].x_count, desc[0].y_count, 
		desc[0].start_addr,desc[0].cfg);
	 */
}

/* Stupid function for waiting, udelay make while does break,
 * msleep crash system.
 */
void waiting(unsigned long flags)
{
	unsigned long i, t;
	for(i=0; i<1000; i++) {
		t = flags;
	}
}	

static int sport_start(struct bf53x_sport* sport)
{ 
	enable_dma(sport->dma_rx_chan);
	enable_dma(sport->dma_tx_chan);
	sport->regs->tcr1 |= TSPEN;
	sport->regs->rcr1 |= RSPEN;
	SSYNC;

	return 0;
}

static int sport_stop(struct bf53x_sport* sport)
{
	sport->regs->tcr1 &= ~TSPEN;
	sport->regs->rcr1 &= ~RSPEN;
	SSYNC;

	disable_dma(sport->dma_rx_chan);
	disable_dma(sport->dma_tx_chan);

	return 0;
}

static inline int sport_hook_rx_dummy(struct bf53x_sport* sport)
{
	dmasg_t *desc, temp_desc;
	unsigned long flags;
	dma_register_t* dma = sport->dma_rx;

	SPORT_ASSERT(sport->dummy_rx_desc != NULL );
	SPORT_ASSERT(sport->curr_rx_desc != sport->dummy_rx_desc);
	
	/* Maybe the dummy buffer descriptor ring is damaged */
	sport->dummy_rx_desc->next_desc_addr = \
			(unsigned long)sport->dummy_rx_desc;

	local_irq_save(flags);
	desc = (dmasg_t*)dma->next_desc_ptr;
	/* Copy the descriptor which will be damaged to backup */
	temp_desc = *desc;
	desc->x_count=0x10;
	desc->y_count=0;
	desc->next_desc_addr = (unsigned int)(sport->dummy_rx_desc);
	local_irq_restore(flags);
	/* Waiting for dummy buffer descriptor is already hooked*/
	while(dma->curr_desc_ptr - sizeof(dmasg_t) != \
			(unsigned long)sport->dummy_rx_desc) {
		waiting(flags);
	}
	sport->curr_rx_desc = sport->dummy_rx_desc;
	/* Restore the damaged descriptor */
	*desc = temp_desc;

	return 0;
}

static inline int sport_rx_dma_start(struct bf53x_sport *sport, int dummy)
{
	dma_register_t* dma = sport->dma_rx;

	if(dummy) {
		sport->dummy_rx_desc->next_desc_addr = \
				(unsigned long) sport->dummy_rx_desc;
		sport->curr_rx_desc = sport->dummy_rx_desc;
	} else
		sport->curr_rx_desc = sport->dma_rx_desc;

	dma->next_desc_ptr = (unsigned int)(sport->curr_rx_desc);
	dma->cfg           = DMAFLOW | NDSIZE | WDSIZE_32 | WNR;
	dma->x_count       = 0;
	dma->x_modify      = 0;
	dma->y_count       = 0;
	dma->y_modify      = 0;

	SSYNC;

	return 0;
}

static inline int sport_tx_dma_start(struct bf53x_sport *sport, int dummy)
{
	dma_register_t* dma = sport->dma_tx;

	if(dummy) {
		sport->dummy_tx_desc->next_desc_addr = \
				(unsigned long) sport->dummy_tx_desc;
		sport->curr_tx_desc = sport->dummy_tx_desc;
	} else
		sport->curr_tx_desc = sport->dma_tx_desc;

	dma->next_desc_ptr = (unsigned int)(sport->curr_tx_desc);
	dma->cfg           = DMAFLOW | NDSIZE |WDSIZE_32 ;
	dma->x_count       = 0;
	dma->x_modify      = 0;
	dma->y_count       = 0;
	dma->y_modify      = 0;

	SSYNC;

	return 0;
}

int bf53x_sport_rx_start(struct bf53x_sport *sport)
{
	unsigned long flags;

	if (sport->rx_run)
		return -EBUSY;
	
	if (sport->tx_run) {
		/* tx is running, rx is not running */ 
		SPORT_ASSERT(sport->dma_rx_desc != NULL);
		SPORT_ASSERT(sport->curr_rx_desc == sport->dummy_rx_desc);
		local_irq_save(flags);
		sport->dummy_rx_desc->next_desc_addr = 	\
				(unsigned int)(sport->dma_rx_desc);
		local_irq_restore(flags);
		sport->curr_rx_desc = sport->dma_rx_desc;
	} else {
		sport_tx_dma_start(sport, 1);	
		sport_rx_dma_start(sport, 0);
		sport_start(sport);
	}

	sport->rx_run = 1;

	return 0;
}

int bf53x_sport_rx_stop(struct bf53x_sport *sport)
{
	if (!sport->rx_run)
		return 0;
	
	if (sport->tx_run) {
		/* TX dma is still running, hook the dummy buffer */
		sport_hook_rx_dummy(sport);
	} else {
		/* Both rx and tx dma will be stopped */
		sport_stop(sport);
		sport->curr_rx_desc = NULL;
		sport->curr_tx_desc = NULL;
	}

	sport->rx_run = 0;

	return 0;
}

static inline int sport_hook_tx_dummy(struct bf53x_sport* sport)
{
	dmasg_t *desc, temp_desc;
	unsigned long flags;
	dma_register_t* dma = sport->dma_tx;

	SPORT_ASSERT( sport->dummy_tx_desc != NULL );
	SPORT_ASSERT( sport->curr_tx_desc != sport->dummy_tx_desc );
	
	sport->dummy_tx_desc->next_desc_addr = \
			(unsigned long)sport->dummy_tx_desc;

	/* Shorten the time on last normal descriptor */
	local_irq_save(flags);
	desc = (dmasg_t*)dma->next_desc_ptr;
	/* Store the descriptor which will be damaged */
	temp_desc = *desc;
	desc->x_count = 0x10;
	desc->y_count = 0;
	desc->next_desc_addr = (unsigned int)(sport->dummy_tx_desc);
	local_irq_restore(flags);
	/* Waiting for dummy buffer descriptor is already hooked*/
//	printk(KERN_ERR"desc:0x%p, sport->dummy_tx_desc:0x%p\n", 
//			desc, sport->dummy_tx_desc);
	while((dma->curr_desc_ptr-sizeof(dmasg_t)) != \
			(unsigned long)sport->dummy_tx_desc){
		waiting(flags);
	}
	sport->curr_tx_desc = sport->dummy_tx_desc;
	/* Restore the damaged descriptor */
	*desc = temp_desc;

	return 0;
}

int bf53x_sport_tx_start(struct bf53x_sport *sport)
{
	unsigned flags;

	sport_printd(KERN_INFO, "%s: tx_run:%d, rx_run:%d\n",
			__FUNCTION__, sport->tx_run, sport->rx_run);
	if (sport->tx_run)
		return -EBUSY;
	
	if (sport->rx_run) {
		SPORT_ASSERT(sport->dma_tx_desc != NULL);
		SPORT_ASSERT(sport->curr_tx_desc == sport->dummy_tx_desc);
		/* Hook the normal buffer descriptor */
		local_irq_save(flags);
		sport->dummy_tx_desc->next_desc_addr = \
				(unsigned int)(sport->dma_tx_desc);
		local_irq_restore(flags);
		sport->curr_tx_desc = sport->dma_tx_desc;
	} else {
		sport_tx_dma_start(sport, 0);
		/* Let rx dma run the dummy buffer */
		sport_rx_dma_start(sport, 1);
		sport_start(sport);
	}
	sport->tx_run = 1;

	return 0;
}

int bf53x_sport_tx_stop(struct bf53x_sport *sport)
{
	if (!sport->tx_run)
		return 0;

	if (sport->rx_run) {
		/* RX is still running, hook the dummy buffer */
		sport_hook_tx_dummy(sport);
	} else {
		/* Both rx and tx dma stopped */
		sport_stop(sport);
		sport->curr_rx_desc = NULL;
		sport->curr_tx_desc = NULL;
	}

	sport->tx_run = 0;

	return 0;
}

static int inline compute_wdsize(size_t size)
{
	switch(size){
		case 1:
			return WDSIZE_8;
		case 2:
			return WDSIZE_16;
		case 4:
		default:
			return WDSIZE_32;
	}
}

int bf53x_sport_config_rx_dma( struct bf53x_sport* sport, void* buf, 
		int fragcount, size_t fragsize, size_t size)
{
	unsigned int x_count;
	unsigned int y_count;
	unsigned int cfg;
	dma_addr_t addr;

	sport_printd(KERN_INFO, "%s( %p, %d, %d )\n", __FUNCTION__, buf,
			fragcount,fragsize );

	/* for fragments larger than 32k words we use 2d dma, with the outer 
	   loop counting the number of 32k blocks. it follows that then
	   fragsize must be a power of two (and hence a multiple of 32k
	   the line below is the cheapest test I could think of :-) 
	 */

	if( fragsize > (0x8000*size) )
		if( (fragsize | (fragsize-1) ) != (2*fragsize - 1) )
			return -EINVAL;

	if (sport->dma_rx_desc) {
		dma_free_coherent(NULL, sport->rx_desc_bytes, \
				sport->dma_rx_desc, 0);
	}

	/* Allocate a new descritor ring as current one. */
	sport->dma_rx_desc = dma_alloc_coherent(NULL, \
			fragcount * sizeof( dmasg_t ),	&addr, 0);
	sport->rx_desc_bytes = fragcount * sizeof( dmasg_t);

	if( !sport->dma_rx_desc ) {
		return -ENOMEM;
	}

	sport->rx_buf = buf;

	x_count = fragsize/size;
	y_count = 0;
	cfg     = 0x7000 | DI_EN | compute_wdsize(size) | WNR | \
		  (DESC_ELEMENT_COUNT << 8); /* large descriptor mode */

	if( x_count > 0x8000 ){
		y_count = x_count >> 15;
		x_count = 0x8000;
		cfg |= DMA2D;
	}

	setup_desc( sport->dma_rx_desc, buf, fragcount, fragsize,
			cfg|DMAEN, x_count, y_count, size);

	return 0;
}

int bf53x_sport_config_tx_dma( struct bf53x_sport* sport, void* buf, 
		int fragcount, size_t fragsize, size_t size)
{
	unsigned int x_count;
	unsigned int y_count;
	unsigned int cfg;
	dma_addr_t addr;

	sport_printd(KERN_INFO, "%s( %p, %d, %d )\n", __FUNCTION__, buf,
			fragcount,fragsize );

	/* fragsize must be a power of two (line below is the cheapest test
	 * I could think of :-) */

	if( fragsize > (0x8000*size) )
		if( (fragsize | (fragsize-1) ) != (2*fragsize - 1) )
			return -EINVAL;

	if( sport->dma_tx_desc) {
		dma_free_coherent(NULL, sport->tx_desc_bytes, \
				sport->dma_tx_desc, 0);
	}

	sport->dma_tx_desc = dma_alloc_coherent(NULL, \
			fragcount * sizeof( dmasg_t ), &addr, 0);
	sport->tx_desc_bytes = fragcount * sizeof( dmasg_t);
//	printk(KERN_ERR "alloc dma_tx_desc:0x%p, size:0x%x\n", 
//	sport->dma_tx_desc, sport->tx_desc_bytes);
	if( !sport->dma_tx_desc ) {
		return -ENOMEM;
	}

	sport->tx_buf = buf;

	x_count = fragsize/size;
	y_count = 0;
	cfg     = 0x7000 | DI_EN | compute_wdsize(size) | \
		  ( DESC_ELEMENT_COUNT << 8); /* large descriptor mode */

	if( x_count > 0x8000 ){
		y_count = x_count >> 15;
		x_count = 0x8000;
		cfg |= DMA2D;
	}

	setup_desc( sport->dma_tx_desc, buf, fragcount, fragsize,
			cfg|DMAEN, x_count, y_count, size);

	return 0;
}

/* setup dummy dma descriptor ring, which don't generate interrupts,
 * the x_modify is set to 0 */
static int sport_config_rx_dummy(struct bf53x_sport *sport, size_t size)
{
	dma_register_t* dma;
	dmasg_t *desc;
	unsigned config;

	sport_printd(KERN_INFO, "%s entered\n", __FUNCTION__);
	dma = sport->dma_rx;
#if L1_DATA_A_LENGTH != 0
	desc = (dmasg_t*)l1_data_A_sram_alloc(2* sizeof(*desc));
#else
	{
		dma_addr_t addr;
		desc = dma_alloc_coherent(NULL, 2*sizeof(*desc), &addr, 0);
	}
#endif
	if (desc ==NULL)
		return -ENOMEM;

	sport->dummy_rx_desc = desc;

	desc->next_desc_addr = (unsigned long)desc;
	desc->start_addr = sport->dummy_buf;
	config = DMAFLOW | NDSIZE | compute_wdsize(size) | WNR | DMAEN;
	desc->cfg = config;
	desc->x_count = 0x80;
	desc->x_modify = 0;
	desc->y_count = 0;
	desc->y_modify = 0;

	return 0;
}

static int sport_config_tx_dummy(struct bf53x_sport *sport, size_t size)
{
	dma_register_t* dma;
	dmasg_t *desc;
	unsigned int config;

	sport_printd(KERN_INFO, "%s entered\n", __FUNCTION__);
	dma = sport->dma_tx;

#if L1_DATA_A_LENGTH != 0
	desc = (dmasg_t*)l1_data_A_sram_alloc(2* sizeof(*desc));
#else	
	{ 
		dma_addr_t addr;
		desc = dma_alloc_coherent(NULL, 2*sizeof(*desc), &addr, 0);
	}
#endif
	if (!desc)
		return -ENOMEM;

	sport->dummy_tx_desc = desc;

	desc->next_desc_addr = (unsigned long)desc;
	desc->start_addr = sport->dummy_buf + size;
	config = DMAFLOW | NDSIZE |compute_wdsize(size) | DMAEN;
	desc->cfg = config;
	desc->x_count = 0x80;
	desc->x_modify = 0;
	desc->y_count = 0;
	desc->y_modify = 0;

	return 0;
}

unsigned long bf53x_sport_curr_offset_rx( struct bf53x_sport* sport )
{
	dma_register_t* dma = sport->dma_rx;
	unsigned char *curr = *(unsigned char**) &(dma->curr_addr_ptr_lo);
	return (curr - sport->rx_buf);
}

unsigned long bf53x_sport_curr_offset_tx( struct bf53x_sport* sport )
{ 
	dma_register_t* dma = sport->dma_tx;
	unsigned char *curr = *(unsigned char**) &(dma->curr_addr_ptr_lo);
	return (curr - sport->tx_buf);
}

static int sport_check_status( struct bf53x_sport* sport, 
		unsigned int* sport_stat, 
		unsigned int* rx_stat, 
		unsigned int* tx_stat )
{

	int status=0;

	if( sport_stat ){
		SSYNC;
		status = sport->regs->stat;
		if( status & (TOVF|TUVF|ROVF|RUVF) )
			sport->regs->stat = (status & (TOVF|TUVF|ROVF|RUVF));
		SSYNC;
		*sport_stat = status;
	}

	if( rx_stat ){
		SSYNC;
		status = sport->dma_rx->irq_status;
		if( status & (DMA_DONE|DMA_ERR) )
			sport->dma_rx->irq_status = status & (DMA_DONE|DMA_ERR);
		SSYNC;
		*rx_stat = status;
	}

	if( tx_stat ){
		SSYNC;
		status = sport->dma_tx->irq_status;
		if( status & (DMA_DONE|DMA_ERR) )
			sport->dma_tx->irq_status = status & (DMA_DONE|DMA_ERR);
		SSYNC;
		*tx_stat = status;
	}

	return 0;
}

int  bf53x_sport_dump_stat(struct bf53x_sport* sport, char* buf, size_t len)
{
	int ret;

	ret = snprintf( buf, len, 
			"sport  %d sts: 0x%04x\n"
			"rx dma %d cfg: 0x%04x sts: 0x%04x\n"
			"tx dma %d cfg: 0x%04x sts: 0x%04x\n", 
			sport->sport_num,  sport->regs->stat,
			sport->dma_rx_chan, sport->dma_rx->cfg,
			sport->dma_rx->irq_status,
			sport->dma_tx_chan, sport->dma_tx->cfg,
			sport->dma_tx->irq_status);
	buf += ret;
	len -= ret;

	ret += snprintf(buf, len,
			"curr_rx_desc:0x%p, curr_tx_desc:0x%p\n"
			"dma_rx_desc:0x%p, dma_tx_desc:0x%p\n"
			"dummy_rx_desc:0x%p, dummy_tx_desc:0x%p\n",
			sport->curr_rx_desc, sport->curr_tx_desc, 
			sport->dma_rx_desc, sport->dma_tx_desc,
			sport->dummy_rx_desc, sport->dummy_tx_desc);

	return ret;
}
static irqreturn_t rx_handler(int irq, void *dev_id,
		struct pt_regs *regs)
{
	unsigned int rx_stat;
	struct bf53x_sport *sport = dev_id;

	sport_printd(KERN_INFO, "%s\n", __FUNCTION__);
	sport_check_status(sport, NULL, &rx_stat, NULL);
	if (!(rx_stat & DMA_DONE)) {
		printk(KERN_ERR "rx dma is already stopped\n");
	}
	if(sport->rx_callback) {
		sport->rx_callback(sport->data);
		return IRQ_HANDLED;
	}

	return IRQ_NONE;
}

static irqreturn_t tx_handler(int irq, void *dev_id,
		struct pt_regs *regs)
{
	unsigned int tx_stat;
	struct bf53x_sport *sport = dev_id;

//	sport_printd(KERN_INFO, "%s\n", __FUNCTION__);
	sport_check_status(sport, NULL, NULL, &tx_stat);
	if (!(tx_stat & DMA_DONE)) {
		printk(KERN_ERR "tx dma is already stopped\n");
		return IRQ_HANDLED;
	}
		
	if (sport->tx_callback) {
		sport->tx_callback(sport->data);
		return IRQ_HANDLED;
	}

	return IRQ_NONE;
}

static irqreturn_t err_handler(int irq, void *dev_id, 
		struct pt_regs *regs)
{
	unsigned int status;
	struct bf53x_sport *sport = dev_id;

	sport_printd(KERN_INFO, "%s\n", __FUNCTION__);
	if( sport_check_status(sport, &status, NULL, NULL) ){
		printk( KERN_ERR "error checking status ??" );
		return IRQ_NONE;
	}

	if( status & (TOVF|TUVF|ROVF|RUVF) ){
		printk( KERN_WARNING  "sport status error:%s%s%s%s\n", 
				status & TOVF ? " TOVF" : "", 
				status & TUVF ? " TUVF" : "", 
				status & ROVF ? " ROVF" : "", 
				status & RUVF ? " RUVF" : "" );
		sport_stop(sport);
	}

	if (sport->err_callback)
		sport->err_callback(sport->data);

	return IRQ_HANDLED;
}

struct bf53x_sport* bf53x_sport_init(int sport_num, 
		int dma_rx, void (*rx_callback)(void*),
		int dma_tx, void (*tx_callback)(void*),
		int err_irq, void (*err_callback)(void*),
		void *data)
{

	struct bf53x_sport* sport;

	sport = kmalloc( sizeof(struct bf53x_sport), GFP_KERNEL );

	if( !sport ) return NULL;

	SPORT_ASSERT( sizeof(struct sport_register) == 0x60 );

	memset(sport, 0, sizeof(struct bf53x_sport));
	sport->sport_num = sport_num;
	sport->regs = (struct sport_register*) sport_iobase[sport_num];

	sport_printd( KERN_INFO, "%p dma rx: %p tx: %p\n", 
			sport->regs, sport->dma_rx, sport->dma_tx );

	if(request_dma(dma_rx, "SPORT RX Data") == -EBUSY){
		printk( KERN_ERR"Failed to request RX dma %d\n", dma_rx);
		goto __init_err;
	}

	if( set_dma_callback(dma_rx, rx_handler, sport) != 0){
		printk( KERN_ERR"Failed to request RX irq %d\n", dma_rx);
		goto __init_err;
	}  

	if(request_dma(dma_tx, "SPORT TX Data") == -EBUSY){
		printk( KERN_ERR"Failed to request TX dma %d\n", dma_tx);
		goto __init_err;
	}

	if( set_dma_callback(dma_tx, tx_handler, sport) != 0){
		printk(KERN_ERR"Failed to request TX irq %d\n", dma_tx);
		goto __init_err;
	}  

	if (request_irq(err_irq, err_handler, SA_SHIRQ, "SPORT error", 
			sport)< 0) {
		printk(KERN_ERR"Failed to request err irq:%d\n", err_irq);
		goto __init_err;
	}
	
	sport->dma_rx_chan = dma_rx;
	sport->dma_rx = (dma_register_t*) dma_iobase[dma_rx];
	sport->dma_tx_chan = dma_tx;
	sport->dma_tx = (dma_register_t*) dma_iobase[dma_tx];
	sport->err_irq = err_irq;
	sport->rx_callback = rx_callback;
	sport->tx_callback = tx_callback;
	sport->err_callback = err_callback;
	sport->data = data;

#if L1_DATA_A_LENGTH != 0
	if ((sport->dummy_buf=l1_data_A_sram_alloc(DUMMY_BUF_LEN)) == 0) {
#else
	if ((sport->dummy_buf=(unsigned long)kmalloc(DUMMY_BUF_LEN, \
			GFP_KERNEL)) == NULL) {
#endif
		printk( KERN_ERR "Failed to allocate dummy buffer\n");
		goto __init_err;
 	}
 
 	sport_config_rx_dummy(sport, DUMMY_BUF_LEN/2);
	sport_config_tx_dummy(sport, DUMMY_BUF_LEN/2);

#if defined(CONFIG_BF534)|defined(CONFIG_BF536)|defined(CONFIG_BF537)
	if(sport->sport_num) {
		bfin_write_PORT_MUX(bfin_read_PORT_MUX() | PGTE|PGRE|PGSE);
		SSYNC;
		/*    printk("sport: mux=0x%x\n", bfin_read_PORT_MUX());*/
		bfin_write_PORTG_FER(bfin_read_PORTG_FER() | 0xFF00);
		SSYNC;
		/*    printk("sport: gfer=0x%x\n", bfin_read_PORTG_FER());*/
	} else {
		bfin_write_PORT_MUX(bfin_read_PORT_MUX() & ~(PJSE|PJCE(3)));
		SSYNC;
		/*    printk("sport: mux=0x%x\n", bfin_read_PORT_MUX());*/
	}
#endif

	return sport;

__init_err:
	free_dma(sport->dma_rx_chan);
	free_dma(sport->dma_tx_chan);
	free_irq(sport->err_irq, sport);
	kfree(sport);
	return NULL;
} 

void bf53x_sport_done(struct bf53x_sport* sport)
{
	if (sport == NULL)
		return ;

	sport_stop(sport);
	if( sport->dma_rx_desc ) 
		dma_free_coherent(NULL, sport->rx_desc_bytes, \
				sport->dma_rx_desc, 0);
	if( sport->dma_tx_desc ) 
		dma_free_coherent(NULL, sport->tx_desc_bytes, \
				sport->dma_tx_desc, 0);

#if L1_DATA_A_LENGTH != 0
	l1_data_A_sram_free((unsigned long)sport->dummy_rx_desc);
	l1_data_A_sram_free((unsigned long)sport->dummy_tx_desc);
	l1_data_A_sram_free((unsigned long)sport->dummy_buf);
#else
	dma_free_coherent(NULL, 2*sizeof(dmasg_t), sport->dummy_rx_desc, 0);
	dma_free_coherent(NULL, 2*sizeof(dmasg_t), sport->dummy_tx_desc, 0);
	kfree(dummy_buf);
#endif
	free_dma(sport->dma_rx_chan);
	free_dma(sport->dma_tx_chan);
	free_irq(sport->err_irq, sport);

	kfree(sport);
}
