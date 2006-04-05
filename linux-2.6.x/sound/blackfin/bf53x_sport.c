
/*
 * File:         bf53x_sport.c 
 * Description:  low level driver for sportX/dmaY on blackfin 53x
 *               this should be moved to arch/blackfin/
 * Rev:          $Id$
 * Created:      Tue Sep 21 10:52:42 CEST 2004
 * Author:       Luuk van Dijk
 * mail:         blackfin@mdnmttr.nl
 * 
 * Copyright (C) 2004 Luuk van Dijk, Mind over Matter B.V.
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

#define sport_printf(level, format, arg...)  printk(level "sport: " format, ## arg)

#ifdef  BF53X_SPORT_DEBUG
#define sport_printd(level, format, arg...)  printk(level "sport: " format, ## arg)
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
#define FRAME_DELAY (1<<12)  /* delay between frame sync pulse and first data bit
                              in multichannel mode */ 

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

struct bf53x_sport* 
bf53x_sport_init(int sport_chan, 
		int dma_rx, dma_interrupt_t rx_handler,
		int dma_tx, dma_interrupt_t tx_handler){

  struct bf53x_sport* sport = (struct bf53x_sport*) kmalloc( sizeof(struct bf53x_sport), GFP_KERNEL );
 
  if( !sport ) return NULL;

  SPORT_ASSERT( sizeof(struct sport_register) == 0x60 );

  sport->sport_chan = sport_chan;
  sport->regs = (struct sport_register*) sport_iobase[sport_chan];

  sport->dma_rx_chan = dma_rx;
  sport->dma_rx = (dma_register_t*) dma_iobase[dma_rx];
  sport->dma_tx_chan = dma_tx;
  sport->dma_tx = (dma_register_t*) dma_iobase[dma_tx];

  sport_printd( KERN_INFO, "%p dma rx: %p tx: %p\n", 
		sport->regs, sport->dma_rx, sport->dma_tx );

  if(request_dma(dma_rx, "SPORT RX Data") == -EBUSY){
     sport_printf( KERN_ERR, "Unable to allocate sport RX dma %d\n", dma_rx);
     kfree(sport);
     return NULL ;
  }

  if( set_dma_callback(dma_rx, rx_handler, NULL) != 0){
     sport_printf( KERN_ERR, "Unable to allocate sport RX dma %d\n", dma_rx);
     free_dma(dma_rx);
     kfree(sport);
     return NULL ;
   }  

  if(request_dma(dma_tx, "SPORT TX Data") == -EBUSY){
     sport_printf( KERN_ERR, "Unable to allocate sport TX dma %d\n", dma_tx);
     kfree(sport);
     return NULL ;
  }

  if( set_dma_callback(dma_tx, tx_handler, NULL) != 0){
     sport_printf( KERN_ERR, "Unable to allocate sport TX dma %d\n", dma_tx);
     free_dma(dma_tx);
     kfree(sport);
     return NULL ;
   }  
#ifdef BF53X_ANOMALY_29
  sport->is_running = 0;
#endif

  sport->dma_rx_desc = NULL;
  sport->dma_tx_desc = NULL;
  sport->dummy_rx_desc = NULL;
  sport->dummy_tx_desc = NULL;
  sport->dummy_rx_desc2 = NULL;
  sport->dummy_tx_desc2 = NULL;

  sport->curr_rx_desc = NULL;
  sport->curr_tx_desc = NULL;

#if defined(CONFIG_BF534)|defined(CONFIG_BF536)|defined(CONFIG_BF537)
  if(sport->sport_chan) {
    *pPORT_MUX |= PGTE|PGRE|PGSE;
    SSYNC;
/*    printk("sport: mux=0x%x\n", *pPORT_MUX);*/
    *pPORTG_FER |= 0xFF00;
    SSYNC;
/*    printk("sport: gfer=0x%x\n", *pPORTG_FER);*/
  }
  else {
    *pPORT_MUX &= ~(PJSE|PJCE(3));
    SSYNC;
/*    printk("sport: mux=0x%x\n", *pPORT_MUX);*/
  }
#endif
  
  return sport;
} 

void bf53x_sport_done(struct bf53x_sport* sport){
  if(sport) {
    bf53x_sport_stop(sport);
    if( sport->dma_rx_desc ) 
	dma_free_coherent(NULL, sport->rx_desc_bytes, sport->dma_rx_desc, 0);
    if( sport->dma_tx_desc ) 
	dma_free_coherent(NULL, sport->tx_desc_bytes, sport->dma_tx_desc, 0);

    if( sport->dummy_rx_desc)
#if L1_DATA_A_LENGTH != 0
	l1_data_A_sram_free((unsigned long)sport->dummy_rx_desc);
#else
	dma_free_coherent(NULL, 2*sizeof(dmasg_t), sport->dummy_rx_desc, 0);
#endif
    if( sport->dummy_tx_desc)
#if L1_DATA_A_LENGTH != 0
	l1_data_A_sram_free((unsigned long)sport->dummy_tx_desc);
#else
    	dma_free_coherent(NULL, 2*sizeof(dmasg_t), sport->dummy_tx_desc, 0);
#endif

    sport->dma_rx_desc = NULL;
    sport->dma_tx_desc = NULL;
    sport->dummy_rx_desc = NULL;
    sport->dummy_tx_desc = NULL;
    sport->dummy_rx_desc2 = NULL;
    sport->dummy_tx_desc2 = NULL;
  }
  kfree(sport);
}

/* note: multichannel is in units of 8 channels, tdm_count is # channels NOT / 8 ! */
int bf53x_sport_set_multichannel( struct bf53x_sport* sport, int tdm_count, int packed){

  sport_printd( KERN_INFO, "%s( tdm_count=%d packed=%d )\n", __FUNCTION__, tdm_count, packed );

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

    sport->regs->mcmc1 = ((tdm_count>>3)-1) << 12;  /* set WSIZE bits */
    sport->regs->mcmc2 = FRAME_DELAY| MCMEN | ( packed ? (MCDTXPE|MCDRXPE) : 0 );

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


int bf53x_sport_config_rx( struct bf53x_sport* sport, unsigned int rcr1, unsigned int rcr2, 
			   unsigned int clkdiv, unsigned int fsdiv ){


  if( (sport->regs->tcr1 & TSPEN) || (sport->regs->rcr1 & RSPEN) )
    return -EBUSY;

  sport->regs->rcr1 = rcr1;
  sport->regs->rcr2 = rcr2;
  sport->regs->rclkdiv = clkdiv;
  sport->regs->rfsdiv = fsdiv;

  SSYNC;

  return 0;

}

int bf53x_sport_config_tx( struct bf53x_sport* sport, unsigned int tcr1, unsigned int tcr2,
			   unsigned int clkdiv, unsigned int fsdiv ){

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
		size_t fragsize_bytes, unsigned int cfg, 
		unsigned int x_count, unsigned int ycount, size_t size)
{

  int i;

  for( i=0; i<fragcount; ++i ){
    desc[i].next_desc_addr  = (unsigned long)&( desc[i + 1] );
    desc[i].start_addr = (unsigned long)buf + i*fragsize_bytes;
    desc[i].cfg = cfg;
    desc[i].x_count = x_count;
    desc[i].x_modify = size;
    desc[i].y_count = ycount;
    desc[i].y_modify = size;
  }

  desc[fragcount-1].next_desc_addr = (unsigned long)desc; /* make circular */

/*  printk(KERN_ERR"setup desc: desc0=%p, next0=%lx, desc1=%p, next1=%lx\nx_count=%x,y_count=%x,addr=0x%lx,cfs=0x%x\n", 
  	&(desc[0]), desc[0].next_desc_addr, 
	&(desc[1]), desc[1].next_desc_addr,
	desc[0].x_count, desc[0].y_count, desc[0].start_addr,desc[0].cfg);
 */
}

/* Stupid function for waiting, udelay make while does break, msleep crash system */
void waiting(unsigned long flags)
{
	unsigned long i, t;
	for(i=0; i<1000; i++) {
		t = flags;
	}
}	

void bf53x_sport_hook_rx_desc( struct bf53x_sport* sport, int dummy)
{
  dma_register_t* dma = sport->dma_rx;
  dmasg_t *desc, temp_desc;
  unsigned long flags;
  
  sport_printd(KERN_INFO, "%s entered, dummy:%d\n", __FUNCTION__, dummy);

  if (dummy) {
    	/* Copy the dummy buffer descriptor from backup */
	*sport->dummy_rx_desc = *sport->dummy_rx_desc2;
  }

  if( sport->regs->rcr1 & RSPEN ) {
    /* Hook the dummy buffer descriptor */
    if (dummy) {
    	SPORT_ASSERT(sport->dummy_rx_desc != NULL );
    	if (sport->curr_rx_desc != sport->dummy_rx_desc) {
		local_irq_save(flags);
		desc = (dmasg_t*)dma->next_desc_ptr;
		/* Copy the descriptor which will be damaged to backup */
		temp_desc = *desc;
		desc->x_count=0x10;
		desc->y_count=0;
		desc->next_desc_addr = (unsigned int)(sport->dummy_rx_desc);
		local_irq_restore(flags);
		/* Waiting for dummy buffer descriptor is already hooked*/
		while(dma->curr_desc_ptr - sizeof(dmasg_t) != (unsigned long)sport->dummy_rx_desc) {
//			printk(KERN_INFO"curr_rx:0x%lx\n", dma->curr_desc_ptr);
//			udelay(1); /* DMA doesn't going on, cannot break loop*/
//			msleep(1);
			waiting(flags);
		}
		sport->curr_rx_desc = sport->dummy_rx_desc;
		/* Restore the damaged descriptor */
		*desc = temp_desc;
	}
    } else { /* Hook the normal buffer descriptor */
   	SPORT_ASSERT(sport->dma_rx_desc != NULL);
	if(sport->curr_rx_desc != sport->dma_rx_desc) {
		local_irq_save(flags);
		sport->dummy_rx_desc->next_desc_addr = (unsigned int)(sport->dma_rx_desc);
		local_irq_restore(flags);
		sport->curr_rx_desc = sport->dma_rx_desc;
	}
    }
  } else {
	if(dummy)
		sport->curr_rx_desc = sport->dummy_rx_desc;
	else
		sport->curr_rx_desc = sport->dma_rx_desc;
	dma->next_desc_ptr = (unsigned int)(sport->curr_rx_desc);
	dma->cfg           = DMAFLOW | NDSIZE | WDSIZE_32 | WNR;
	dma->x_count       = 0;
	dma->x_modify      = 0;
	dma->y_count       = 0;
	dma->y_modify      = 0;

	SSYNC;
  }
}

void bf53x_sport_hook_tx_desc( struct bf53x_sport* sport, int dummy)
{
  dma_register_t* dma = sport->dma_tx;
  dmasg_t *desc, temp_desc;
  unsigned long flags;
 
  sport_printd(KERN_INFO, "%s entered, dummy:%d\n", __FUNCTION__, dummy);

  if (dummy) {
  	*sport->dummy_tx_desc = *sport->dummy_tx_desc2;
  }

  if( sport->regs->tcr1 & TSPEN) {
    if (dummy) {
    	SPORT_ASSERT(sport->dummy_tx_desc != NULL);
    	if (sport->curr_tx_desc != sport->dummy_tx_desc) {
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
//		printk(KERN_ERR"desc:0x%p, sport->dummy_tx_desc:0x%p\n", desc, sport->dummy_tx_desc);
		while((dma->curr_desc_ptr-sizeof(dmasg_t)) != (unsigned long)sport->dummy_tx_desc){
//			printk(KERN_ERR"curr_desc:0x%lx\n", dma->curr_desc_ptr);/*Work*/
//			udelay(1);/*DMA doesn't going on, cannot break the loop */
//			msleep(1); /* System crash */
			waiting(flags);
		}
		sport->curr_tx_desc = sport->dummy_tx_desc;
		/* Restore the damaged descriptor */
		*desc = temp_desc;
	}
    } else { /* Hook the normal buffer descriptor */
   	SPORT_ASSERT(sport->dma_tx_desc != NULL);
	if(sport->curr_tx_desc != sport->dma_tx_desc) {
		local_irq_save(flags);
		sport->dummy_tx_desc->next_desc_addr = (unsigned int)(sport->dma_tx_desc);
		local_irq_restore(flags);
		sport->curr_tx_desc = sport->dma_tx_desc;
	}
    }
  } else {
	if(dummy)
		sport->curr_tx_desc = sport->dummy_tx_desc;
	else
		sport->curr_tx_desc = sport->dma_tx_desc;
 
	dma->next_desc_ptr = (unsigned int)(sport->curr_tx_desc);
	dma->cfg           = DMAFLOW | NDSIZE |WDSIZE_32 ;
	dma->x_count       = 0;
	dma->x_modify      = 0;
	dma->y_count       = 0;
	dma->y_modify      = 0;
  
	SSYNC;
  }
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
		       int fragcount, size_t fragsize_bytes, size_t size)
{
  unsigned int x_count;
  unsigned int y_count;
  unsigned int cfg;
  dma_addr_t addr;

  sport_printd(KERN_INFO, "%s( %p, %d, %d )\n", __FUNCTION__, buf, fragcount,fragsize_bytes );

  /* for fragments larger than 32k words we use 2d dma, with the outer loop counting
     the number of 32k blocks. it follows that then
     fragsize must be a power of two (and hence a multiple of 32k
     the line below is the cheapest test I could think of :-) 
  */

  if( fragsize_bytes > (0x8000*size) )
    if( (fragsize_bytes | (fragsize_bytes-1) ) != (2*fragsize_bytes - 1) )
      return -EINVAL;

  if (sport->dma_rx_desc) {
//	printk(KERN_ERR "free dma_rx_desc:0x%p\n", sport->dma_rx_desc);
	dma_free_coherent(NULL, sport->rx_desc_bytes, sport->dma_rx_desc, 0);
  }
 
  /* Allocate a new descritor ring as current one. */
//  sport->dma_rx_desc = kcalloc(1, fragcount * sizeof( dmasg_t ), GFP_KERNEL );
  sport->dma_rx_desc = dma_alloc_coherent(NULL, fragcount * sizeof( dmasg_t ),
  		&addr, 0);
  sport->rx_desc_bytes = fragcount * sizeof( dmasg_t);

//  printk(KERN_ERR "alloc dma_rx_desc:0x%p, sizes:0x%x\n", 
//			sport->dma_rx_desc, sport->rx_desc_bytes);
  if( !sport->dma_rx_desc ) {
    return -ENOMEM;
  }

  x_count = fragsize_bytes/size;
  y_count = 0;
  cfg     = 0x7000 | DI_EN | compute_wdsize(size) | WNR | \
  			(DESC_ELEMENT_COUNT << 8); /* large descriptor mode */

  if( x_count > 0x8000 ){
    y_count = x_count >> 15;
    x_count = 0x8000;
    cfg |= DMA2D;
  }

  setup_desc( sport->dma_rx_desc, buf, fragcount, fragsize_bytes,
  					cfg|DMAEN, x_count, y_count, size);

  return 0;

}

int bf53x_sport_config_tx_dma( struct bf53x_sport* sport, void* buf, 
			   int fragcount, size_t fragsize_bytes, size_t size)
{
  unsigned int x_count;
  unsigned int y_count;
  unsigned int cfg;
  dma_addr_t addr;

  sport_printd(KERN_INFO, "%s( %p, %d, %d )\n", __FUNCTION__, buf, fragcount,fragsize_bytes );

  /* fragsize must be a power of two (line below is the cheapest test I could think of :-) */

  if( fragsize_bytes > 0x8000*sizeof(long) )
    if( (fragsize_bytes | (fragsize_bytes-1) ) != (2*fragsize_bytes - 1) )
      return -EINVAL;

  if( sport->dma_tx_desc) {
	dma_free_coherent(NULL, sport->tx_desc_bytes, sport->dma_tx_desc, 0);
  }

//  sport->dma_tx_desc = kcalloc(1, fragcount * sizeof( dmasg_t ), GFP_KERNEL );
  sport->dma_tx_desc = dma_alloc_coherent(NULL, fragcount * sizeof( dmasg_t ),			&addr, 0);
  sport->tx_desc_bytes = fragcount * sizeof( dmasg_t);
//  printk(KERN_ERR "alloc dma_tx_desc:0x%p, size:0x%x\n", 
//		sport->dma_tx_desc, sport->tx_desc_bytes);
  if( !sport->dma_tx_desc ) {
    return -ENOMEM;
  }

  x_count = fragsize_bytes/sizeof(long);
  y_count = 0;
  cfg     = 0x7000 | DI_EN | compute_wdsize(size) | \
  			( DESC_ELEMENT_COUNT << 8); /* large descriptor mode */

  if( x_count > 0x8000 ){
    y_count = x_count >> 15;
    x_count = 0x8000;
    cfg |= DMA2D;
  }

  setup_desc( sport->dma_tx_desc, buf, fragcount, fragsize_bytes,
  			cfg|DMAEN, x_count, y_count, size);

  return 0;
}

/* setup dummy dma descriptor ring, which don't generate interrupts,
 * the x_modify is set to 0 */
int sport_config_rx_dummy(struct bf53x_sport *sport, size_t size)
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
	sport->dummy_rx_desc2 = desc+1;

	desc->next_desc_addr = (unsigned long)desc;
	desc->start_addr = sport->dummy_buf;
	config = DMAFLOW | NDSIZE | compute_wdsize(size) | WNR | DMAEN;
	desc->cfg = config;
	desc->x_count = 0x80;
	desc->x_modify = 0;
	desc->y_count = 0;
	desc->y_modify = 0;
	*sport->dummy_rx_desc2 = *sport->dummy_rx_desc;

	return 0;
}

int sport_config_tx_dummy(struct bf53x_sport *sport, size_t size)
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
	sport->dummy_tx_desc2 = desc+1;

	desc->next_desc_addr = (unsigned long)desc;
	desc->start_addr = sport->dummy_buf + size;
	config = DMAFLOW | NDSIZE |compute_wdsize(size) | DMAEN;
	desc->cfg = config;
	desc->x_count = 0x80;
	desc->x_modify = 0;
	desc->y_count = 0;
	desc->y_modify = 0;
	*sport->dummy_tx_desc2 = *sport->dummy_tx_desc;
	
	return 0;
}

void sport_disable_dma_rx(struct bf53x_sport* sport)
{ 
  disable_dma(sport->dma_rx_chan);
}

void sport_disable_dma_tx(struct bf53x_sport* sport)
{ 
  disable_dma(sport->dma_tx_chan);
}


int bf53x_sport_start(struct bf53x_sport* sport){ 

  enable_dma(sport->dma_rx_chan);
  enable_dma(sport->dma_tx_chan);
  sport->regs->tcr1 |= TSPEN;
  sport->regs->rcr1 |= RSPEN;

  SSYNC;

#ifdef BF53X_ANOMALY_29
  sport->is_running = 1;
#endif

  return 0;

}


int bf53x_sport_stop(struct bf53x_sport* sport){
  sport->regs->tcr1 &= ~TSPEN;
  sport->regs->rcr1 &= ~RSPEN;
  SSYNC;

  disable_dma(sport->dma_rx_chan);
  disable_dma(sport->dma_tx_chan);

#ifdef BF53X_ANOMALY_29
  sport->is_running = 0;
#endif

  return 0;

}

int bf53x_sport_is_running(struct bf53x_sport* sport){

#ifndef BF53X_ANOMALY_29

  unsigned int stat_rx, stat_tx;
  bf53x_sport_check_status(sport, NULL, &stat_rx, &stat_tx);
  return (stat_rx & DMA_RUN) || (stat_tx & DMA_RUN);

#else
#if 1
  return sport->is_running;
#else
  /* another possibility ... */
  return  sport->regs->tcr1 & TSPEN;
#endif
#endif

}

/*
 * the curr_XXX functions below 
 * use the shadow registers (when configured)
 */

/* for use in interrupt handler */
void* bf53x_sport_curr_addr_rx( struct bf53x_sport* sport ){  
  dma_register_t* dma = sport->dma_rx;
  void** curr = (void**) &(dma->curr_addr_ptr_lo);
  return *curr;
}

void* bf53x_sport_curr_addr_tx( struct bf53x_sport* sport ){ 
  dma_register_t* dma = sport->dma_tx;
  void** curr = (void**) &(dma->curr_addr_ptr_lo);
  return *curr;
}

int bf53x_sport_curr_frag_rx( struct bf53x_sport* sport ){  
  dma_register_t* dma = sport->dma_rx;
  /* use the fact that we use an contiguous array of descriptors */
  return ( (dmasg_t*)(dma->curr_desc_ptr) - sport->dma_rx_desc) / 
    sizeof( dmasg_t );
}


int bf53x_sport_curr_frag_tx( struct bf53x_sport* sport ){  
  dma_register_t* dma = sport->dma_tx;
  /* use the fact that we use an contiguous array of descriptors */
  return ((dmasg_t*)(dma->curr_desc_ptr) - sport->dma_tx_desc) / 
    sizeof( dmasg_t );
}


int bf53x_sport_check_status( struct bf53x_sport* sport, 
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
      sport->dma_rx->irq_status = status & (DMA_DONE|DMA_ERR) ;
    SSYNC;
    *rx_stat = status;
  }

  if( tx_stat ){
    SSYNC;
    status = sport->dma_tx->irq_status;
    if( status & (DMA_DONE|DMA_ERR) )
      sport->dma_tx->irq_status = status & (DMA_DONE|DMA_ERR) ;
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
		   sport->sport_chan,  sport->regs->stat,
		   sport->dma_rx_chan, sport->dma_rx->cfg, sport->dma_rx->irq_status,
		   sport->dma_tx_chan, sport->dma_tx->cfg, sport->dma_tx->irq_status);
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
