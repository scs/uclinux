/*
 * File:         bf53x_sport.c 
 * Description:  low level driver for sportX/dmaY on blackfin 53x
 *               this should be moved to arch/bfinnommu/
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


#include "bf53x_sport.h"


#ifdef __linux__

#include <linux/slab.h>
#include <asm/bug.h>
#define malloc(x) kmalloc(x, GFP_KERNEL)
#define free(x)   kfree(x)
#define printf(format, arg...)  printk( format, ## arg)
#define assert_(x) BUG_ON(!(x))

#include <asm/dma.h>

#else

#error "This is not gonna work..."

#include <assert.h>
#include <stdio.h>

#endif

#define BF53X_ANOMALY_29  /* don't use the DMA_RUN bit, keep track of running status ourselves */

#define BF53X_AUTOBUFFER_MODE  /* use autobuffer, or (undef) circular descriptor list  */


#define BF53X_SPORT_DEBUG

#define sport_printf(level, format, arg...)  printf(level "sport: " format, ## arg)

#ifdef  BF53X_SPORT_DEBUG
#define sport_printd(level, format, arg...)  printf(level "sport: " format, ## arg)
#define SPORT_ASSERT( x ) assert(x)
#else
#define sport_printd(level, format, arg...)  
#define SPORT_ASSERT( x ) 
#endif

#include <asm/blackfin.h>
#include <asm/dma.h>
#define FRAME_DELAY (1<<12)  /* delay between frame sync pulse and first data bit
                              in multichannel mode */ 

#define SSYNC asm( "nop;nop;nop;ssync;nop;nop;nop;\n\t" )

/*
 * source: ADSP-BF533 Blackfin Processor Hardware Reference, 
 * chapter 12, and appendix B-12 table  B10 
 */

struct sport_register {
  unsigned short tcr1;    unsigned short reserved0;
  unsigned short tcr2;    unsigned short reserved1;
  unsigned short tclkdiv; unsigned short reserved2;
  unsigned short tfsdiv;  unsigned short reserved3;
  unsigned long tx;
  unsigned long reserved_l0;
  unsigned long rx;
  unsigned long reserved_l1;
  unsigned short rcr1;    unsigned short reserved4;
  unsigned short rcr2;    unsigned short reserved5;
  unsigned short rclkdiv; unsigned short reserved6;
  unsigned short rfsdiv;  unsigned short reserved7;
  unsigned short stat;    unsigned short reserved8;
  unsigned short chnl;    unsigned short reserved9;
  unsigned short mcmc1;   unsigned short reserved10;
  unsigned short mcmc2;   unsigned short reserved11;
  unsigned long mtcs0;
  unsigned long mtcs1;
  unsigned long mtcs2;
  unsigned long mtcs3;
  unsigned long mrcs0;
  unsigned long mrcs1;
  unsigned long mrcs2;
  unsigned long mrcs3;
};


#ifndef BF53X_AUTOBUFFER_MODE

/* (large mode) descriptor arrays */
struct bf53x_dma_desc {
  struct bf53x_dma_desc* next_desc;
  void*                  start_addr;
};

#endif


struct bf53x_sport {
  int sport_chan;
  int dma_rx_chan;
  int dma_tx_chan;
  struct sport_register* regs;

  DMA_register* dma_rx;   /* a struct gratefully borrowed from asm/bf533_dma.h */
  DMA_register* dma_tx;

#ifdef BF53X_SHADOW_REGISTERS
  DMA_register* dma_shadow_rx;   /* a struct gratefully borrowed from asm/bf533_dma.h */
  DMA_register* dma_shadow_tx;
#endif

#ifndef BF53X_AUTOBUFFER_MODE
  struct bf53x_dma_desc* dma_rx_desc;
  struct bf53x_dma_desc* dma_tx_desc;
#endif

  unsigned int rcr1;
  unsigned int rcr2;
  int rx_tdm_count;

  unsigned int tcr1;
  unsigned int tcr2;
  int tx_tdm_count;

#ifdef BF53X_ANOMALY_29
  int is_running;   /* little kludge to work around anomaly 29: DMA_RUN bit unreliable */
#endif

};

static unsigned int sport_iobase[] = {0xffc00800, 0xffc00900 };
static unsigned int dma_iobase[]   = {0xffc00c00, 0xffc00c40, 0xffc00c80, 0xffc00cc0, 
				      0xffc00d00, 0xffc00d40, 0xffc00d80, 0xffc00dc0 }; 
struct bf53x_sport* 
bf53x_sport_init(int sport_chan, 
		int dma_rx, dma_interrupt_t rx_handler,
		int dma_tx, dma_interrupt_t tx_handler){

  struct bf53x_sport* sport = (struct bf53x_sport*) malloc( sizeof(struct bf53x_sport) );
 
  if( !sport ) return NULL;

  SPORT_ASSERT( sizeof(struct sport_register) == 0x60 );

  sport->sport_chan = sport_chan;
  sport->regs = (struct sport_register*) sport_iobase[sport_chan];

  sport->dma_rx_chan = dma_rx;
  sport->dma_rx = (DMA_register*) dma_iobase[dma_rx];
  sport->dma_tx_chan = dma_tx;
  sport->dma_tx = (DMA_register*) dma_iobase[dma_tx];

  sport_printd( KERN_INFO, "%p dma rx: %p tx: %p\n", 
		sport->regs, sport->dma_rx, sport->dma_tx );

  if(request_dma(dma_rx, "SPORT RX Data") == -EBUSY){
     sport_printf( KERN_ERR, "Unable to allocate sport RX dma %d\n", dma_rx);
     free(sport);
     return NULL ;
  }

  if( set_dma_callback(dma_rx, rx_handler, NULL) != 0){
     sport_printf( KERN_ERR, "Unable to allocate sport RX dma %d\n", dma_rx);
     free_dma(dma_rx);
     free(sport);
     return NULL ;
   }  

  if(request_dma(dma_tx, "SPORT TX Data") == -EBUSY){
     sport_printf( KERN_ERR, "Unable to allocate sport TX dma %d\n", dma_tx);
     free(sport);
     return NULL ;
  }

  if( set_dma_callback(dma_tx, tx_handler, NULL) != 0){
     sport_printf( KERN_ERR, "Unable to allocate sport TX dma %d\n", dma_tx);
     free_dma(dma_tx);
     free(sport);
     return NULL ;
   }  

#ifdef BF53X_SHADOW_REGISTERS

  sport->dma_shadow_rx = (DMA_register*) malloc( sizeof(DMA_register) );
  sport->dma_shadow_tx = (DMA_register*) malloc( sizeof(DMA_register) );

  if( !sport->dma_shadow_rx || !sport->dma_shadow_tx ){
    free( sport->dma_shadow_tx );
    free( sport->dma_shadow_rx );
    free( sport );
    return NULL;
  } 

#endif

  return sport;
} 

void bf53x_sport_done(struct bf53x_sport* sport){
  if(sport) {
    bf53x_sport_stop(sport);
#ifdef BF53X_SHADOW_REGISTERS
    free( sport->dma_shadow_tx );
    free( sport->dma_shadow_rx );
#endif
  }
  free(sport);
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

  SSYNC;

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

  SSYNC;

  sport->regs->tcr1 = tcr1;
  sport->regs->tcr2 = tcr2;
  sport->regs->tclkdiv = clkdiv;
  sport->regs->tfsdiv = fsdiv;

  SSYNC;

  return 0;

}


#ifndef BF53X_AUTOBUFFER_MODE  

static void setup_desc(struct bf53x_dma_desc* desc, void* buf, int fragcount, size_t fragsize_bytes ){

  int i;

  for( i=0; i<fragcount; ++i ){
    desc[i].next_desc  = &( desc[i + 1] );
    desc[i].start_addr = (char*)buf + i*fragsize_bytes;
  }

  desc[fragcount-1].next_desc = desc; /* make circular */

}

#endif



int bf53x_sport_config_rx_dma( struct bf53x_sport* sport, void* buf, 
			       int fragcount, size_t fragsize_bytes, 
			       unsigned int tdm_mask )
{

#ifdef BF53X_SHADOW_REGISTERS
  DMA_register* dma = sport->dma_shadow_rx;
#else
  DMA_register* dma = sport->dma_rx;
#endif

  sport_printd( KERN_INFO, "%s( %p, %d, %d, 0x%02x )\n", __FUNCTION__, buf, fragcount,fragsize_bytes, tdm_mask );

#ifdef BF53X_AUTOBUFFER_MODE  
  if( fragsize_bytes > 0x10000*sizeof(long) ) 
    return -EINVAL;
#else

  /* for fragments larger than 32k words we use 2d dma, with the outer loop counting
     the number of 32k blocks. it follows that then
     fragsize must be a power of two (and hence a multiple of 32k
     the line below is the cheapest test I could think of :-) 
  */
  if( fragsize_bytes > 0x8000*sizeof(long) )
    if( (fragsize_bytes | (fragsize_bytes-1) ) != (2*fragsize_bytes - 1) )
      return -EINVAL;

#endif

  SSYNC;
  
  if( sport->regs->rcr1 & RSPEN )
    return -EBUSY;

#ifdef BF53X_AUTOBUFFER_MODE  

  dma->start_addr = (unsigned int)buf; 
  dma->cfg        = ( 0x1000 | DI_EN | DI_SEL | DMA2D | WDSIZE_32 | WNR ); /* autobuffer mode */
  dma->x_count    = fragsize_bytes/sizeof(long);
  dma->x_modify   = sizeof(long);
  dma->y_count    = fragcount;
  dma->y_modify   = sizeof(long);

#else

  if( sport->dma_rx_desc ) 
    free( sport->dma_rx_desc );
  
  sport->dma_rx_desc = malloc( fragcount * sizeof( struct bf53x_dma_desc ) );
  
  if( !sport->dma_rx_desc )
    return -ENOMEM;

  setup_desc( sport->dma_rx_desc, buf, fragcount, fragsize_bytes );

  {
    
    unsigned int x_count = fragsize_bytes/sizeof(long);
    unsigned int y_count = 0;
    unsigned int cfg     = 0x7000 | DI_EN | WDSIZE_32 | WNR | (sizeof(struct bf53x_dma_desc) << 8); /* large descriptor mode */

    if( x_count > 0x8000 ){
      y_count = x_count >> 15;
      x_count = 0x8000;
    }

    dma->next_desc_ptr = (unsigned int)(sport->dma_rx_desc);
    dma->cfg           = cfg | (y_count ? DMA2D : 0);
    dma->x_count       = x_count;
    dma->x_modify      = sizeof(long);
    dma->y_count       = y_count;
    dma->y_modify      = sizeof(long);

  }

#endif  


#ifdef BF53X_SHADOW_REGISTERS
  {
    DMA_register* dma2 = sport->dma_rx;
    dma2->start_addr = dma->start_addr;
    dma2->next_desc_ptr = dma->next_desc_ptr;  
    dma2->cfg        = dma->cfg;
    dma2->x_count    = dma->x_count;
    dma2->x_modify   = dma->x_modify;
    dma2->y_count    = dma->y_count;
    dma2->y_modify   = dma->y_modify; 

    dma->curr_y_count = dma->y_count;
    dma->curr_addr_ptr_lo = dma->start_addr & 0xffff;
    dma->curr_addr_ptr_hi = dma->start_addr >> 16 ;
  }
#endif

  SSYNC;

  if( tdm_mask ) 
    sport->regs->mrcs0 = tdm_mask;

  SSYNC;

  return 0;

}

int bf53x_sport_config_tx_dma( struct bf53x_sport* sport, void* buf, 
			       int fragcount, size_t fragsize_bytes, 
			       unsigned int tdm_mask )
{
  
#ifdef BF53X_SHADOW_REGISTERS
  DMA_register* dma = sport->dma_shadow_tx;
#else
  DMA_register* dma = sport->dma_tx;
#endif

  sport_printd( KERN_INFO, "%s( %p, %d, %d, 0x%02x )\n", __FUNCTION__, buf, fragcount,fragsize_bytes, tdm_mask );

#ifdef BF53X_AUTOBUFFER_MODE  
  if( fragsize_bytes > 0x10000*sizeof(long) ) 
    return -EINVAL;
#else
  /* fragsize must be a power of two (line below is the cheapest test I could think of :-) */
  if( fragsize_bytes > 0x8000*sizeof(long) )
    if( (fragsize_bytes | (fragsize_bytes-1) ) != (2*fragsize_bytes - 1) )
      return -EINVAL;
#endif

  SSYNC;

  if( sport->regs->tcr1 & TSPEN ) 
    return -EBUSY;

#ifdef BF53X_AUTOBUFFER_MODE  

  dma->start_addr = (unsigned int) buf; 
  dma->cfg = ( 0x1000 | DI_EN | DI_SEL | DMA2D | WDSIZE_32  ) ; /* autobuffer mode */
  dma->x_count    = fragsize_bytes/sizeof(long);
  dma->x_modify   = sizeof(long);
  dma->y_count    = fragcount;
  dma->y_modify   = sizeof(long);
  
#else

  if( sport->dma_tx_desc ) free( sport->dma_tx_desc );
  
  sport->dma_tx_desc = malloc( fragcount * sizeof( struct bf53x_dma_desc ) );
  
  if( !sport->dma_tx_desc )
    return -ENOMEM;

  setup_desc( sport->dma_tx_desc, buf, fragcount, fragsize_bytes );

  {
    
    unsigned int x_count = fragsize_bytes/sizeof(long);
    unsigned int y_count = 0;
    unsigned int cfg     = 0x7000 | DI_EN | WDSIZE_32 | (sizeof(struct bf53x_dma_desc) << 8); /* large descriptor mode */

    if( x_count > 0x8000 ){
      y_count = x_count >> 15;
      x_count = 0x8000;
    }

    dma->next_desc_ptr = (unsigned int)(sport->dma_tx_desc);
    dma->cfg           = cfg | (y_count ? DMA2D : 0);
    dma->x_count       = x_count;
    dma->x_modify      = sizeof(long);
    dma->y_count       = y_count;
    dma->y_modify      = sizeof(long);

  }


#endif

#ifdef BF53X_SHADOW_REGISTERS
  {
    DMA_register* dma2 = sport->dma_tx;
    dma2->start_addr = dma->start_addr;
    dma2->next_desc_ptr = dma->next_desc_ptr;  
    dma2->cfg        = dma->cfg;
    dma2->x_count    = dma->x_count;
    dma2->x_modify   = dma->x_modify;
    dma2->y_count    = dma->y_count;
    dma2->y_modify   = dma->y_modify; 

    dma->curr_y_count = dma->y_count;
    dma->curr_addr_ptr_lo = dma->start_addr & 0xffff;
    dma->curr_addr_ptr_hi = dma->start_addr >> 16 ;
  }
#endif

  SSYNC;

  if( tdm_mask ) 
    sport->regs->mtcs0 = tdm_mask;

  SSYNC;

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

  SSYNC;

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

  SSYNC;

  sport->regs->tcr1 &= ~TSPEN;
  sport->regs->rcr1 &= ~RSPEN;
  disable_dma(sport->dma_rx_chan);
  disable_dma(sport->dma_tx_chan);

  SSYNC;

#ifdef BF53X_ANOMALY_29
  sport->is_running = 0;
#endif

  return 0;

}

int bf53x_sport_start_rx(struct bf53x_sport* sport){ 

  SSYNC;

  enable_dma(sport->dma_rx_chan);
  sport->regs->tcr1 |= TSPEN;
  sport->regs->rcr1 |= RSPEN;

  SSYNC;

#ifdef BF53X_ANOMALY_29
  sport->is_running = 1;
#endif

  return 0;

}


int bf53x_sport_stop_rx(struct bf53x_sport* sport){ 

  SSYNC;

  sport->regs->tcr1 &= ~TSPEN;
  sport->regs->rcr1 &= ~RSPEN;
  disable_dma(sport->dma_rx_chan);

  SSYNC;

#ifdef BF53X_ANOMALY_29
  sport->is_running = 0;
#endif

  return 0;

}

int bf53x_sport_start_tx(struct bf53x_sport* sport){ 

  SSYNC;

  enable_dma(sport->dma_tx_chan);
  sport->regs->tcr1 |= TSPEN;
  sport->regs->rcr1 |= RSPEN;

  SSYNC;

#ifdef BF53X_ANOMALY_29
  sport->is_running = 1;
#endif

  return 0;

}


int bf53x_sport_stop_tx(struct bf53x_sport* sport){ 

  SSYNC;

  sport->regs->tcr1 &= ~TSPEN;
  sport->regs->rcr1 &= ~RSPEN;
  disable_dma(sport->dma_tx_chan);

  SSYNC;

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
#ifdef BF53X_SHADOW_REGISTERS 
  DMA_register* dma = sport->dma_shadow_rx;
#else
  DMA_register* dma = sport->dma_rx;
#endif
  void** curr = (void**) &(dma->curr_addr_ptr_lo);
  return *curr;
}

void* bf53x_sport_curr_addr_tx( struct bf53x_sport* sport ){ 
#ifdef BF53X_SHADOW_REGISTERS 
  DMA_register* dma = sport->dma_shadow_tx;
#else
  DMA_register* dma = sport->dma_tx;
#endif
  void** curr = (void**) &(dma->curr_addr_ptr_lo);
  return *curr;
}

int bf53x_sport_curr_frag_rx( struct bf53x_sport* sport ){  
#ifdef BF53X_SHADOW_REGISTERS 
  DMA_register* dma = sport->dma_shadow_rx;
#else
  DMA_register* dma = sport->dma_rx;
#endif
#ifdef BF53X_AUTOBUFFER_MODE
  return dma->y_count - dma->curr_y_count; 
#else
  /* use the fact that we use an contiguous array of descriptors */
  return ( (struct bf53x_dma_desc*)(dma->curr_desc_ptr) - sport->dma_rx_desc) / 
    sizeof( struct bf53x_dma_desc );
#endif
}


int bf53x_sport_curr_frag_tx( struct bf53x_sport* sport ){  
#ifdef BF53X_SHADOW_REGISTERS 
  DMA_register* dma = sport->dma_shadow_tx;
#else
  DMA_register* dma = sport->dma_tx;
#endif
#ifdef BF53X_AUTOBUFFER_MODE
  return dma->y_count - dma->curr_y_count; 
#else
  /* use the fact that we use an contiguous array of descriptors */
  return ((struct bf53x_dma_desc*)(dma->curr_desc_ptr) - sport->dma_rx_desc) / 
    sizeof( struct bf53x_dma_desc );
#endif
}


/*
 * call these once per irq to update the relevant shadow registers
 * currently we only update curr_addr and 
 */


#ifdef BF53X_SHADOW_REGISTERS 

/*
 * currently, the registers below operate on the assumption
 * that we work on 2d dma with irq's on the inner loop.
 */


#ifndef BF53X_AUTOBUFFER_MODE
#error "Todo: update shadow registers in descriptor list mode"
#endif

void bf53x_sport_shadow_update_rx(struct bf53x_sport* sport){

  DMA_register* dma = sport->dma_shadow_rx;
  char** addr = (char**) &(dma-> start_addr);
  char** curr = (char**) &(dma->curr_addr_ptr_lo);

  if( --(dma->curr_y_count) == 0 )
    dma->curr_y_count = dma->y_count;
  
  /* assert( dma->cfg & WDSIZE_32 ) */

  *curr = *addr + (dma->y_count - dma->curr_y_count) * dma->x_count * sizeof(long);

  return;
}

void bf53x_sport_shadow_update_tx(struct bf53x_sport* sport){
  DMA_register* dma = sport->dma_shadow_tx;
  char** addr = (char**) &(dma-> start_addr);
  char** curr = (char**) &(dma->curr_addr_ptr_lo);

  if( --(dma->curr_y_count) == 0 )
    dma->curr_y_count = dma->y_count;
  
  /* assert( dma->cfg & WDSIZE_32 ) */

  *curr = *addr + (dma->y_count - dma->curr_y_count) * dma->x_count * sizeof(long);
}

#endif

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

int  bf53x_sport_dump_stat(struct bf53x_sport* sport, char* buf, size_t len){
  return snprintf( buf, len, 
		   "sport  %d sts: 0x%04x\n"
		   "rx dma %d cfg: 0x%04x sts: 0x%04x\n"
		   "tx dma %d cfg: 0x%04x sts: 0x%04x\n"
#ifdef BF53X_SHADOW_REGISTERS 
		   "tx curr y cnt: %d  shadow: %d\n"
		   "rx curr y cnt: %d  shadow: %d\n"
		   "tx curr addr : %p  shadow: %p\n"
		   "rx curr addr : %p  shadow: %p\n"
#endif
		   , 
		   sport->sport_chan,  sport->regs->stat,
		   sport->dma_rx_chan, sport->dma_rx->cfg, sport->dma_rx->irq_status,
		   sport->dma_tx_chan, sport->dma_tx->cfg, sport->dma_tx->irq_status
#ifdef BF53X_SHADOW_REGISTERS 
		   ,
		   sport->dma_rx->curr_y_count, sport->dma_shadow_rx->curr_y_count, 
		   sport->dma_tx->curr_y_count, sport->dma_shadow_tx->curr_y_count, 
		   *((void**)&(sport->dma_rx->curr_addr_ptr_lo)), 
		   *((void**)&(sport->dma_shadow_rx->curr_addr_ptr_lo)), 
		   *((void**)&(sport->dma_tx->curr_addr_ptr_lo)), 
		   *((void**)&(sport->dma_shadow_tx->curr_addr_ptr_lo))
#endif
		   );

}
