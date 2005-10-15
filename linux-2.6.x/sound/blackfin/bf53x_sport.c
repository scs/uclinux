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


/*#define BF53X_SPORT_DEBUG*/

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
#include <asm/cacheflush.h>
#define FRAME_DELAY (1<<12)  /* delay between frame sync pulse and first data bit
                              in multichannel mode */ 

#define SSYNC __builtin_bfin_ssync()


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
#ifdef BF53X_ANOMALY_29
  sport->is_running = 0;
#endif

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

  sport->dma_rx_desc = NULL;
  sport->dma_tx_desc = NULL;
  sport->dma_rx_expired_desc = NULL;
  sport->dma_tx_expired_desc = NULL;
  sport->dma_rx_expired2_desc = NULL;
  sport->dma_tx_expired2_desc = NULL;
  sport->dma_rx_desc_changed = 0;
  sport->dma_tx_desc_changed = 0;

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
      free(sport->dma_rx_desc);
    if( sport->dma_tx_desc ) 
      free(sport->dma_tx_desc);
    if( sport->dma_rx_expired_desc ) 
      free(sport->dma_rx_expired_desc);
    if( sport->dma_tx_expired_desc ) 
      free(sport->dma_tx_expired_desc);
    if( sport->dma_rx_expired2_desc ) 
      free(sport->dma_rx_expired2_desc);
    if( sport->dma_tx_expired2_desc ) 
      free(sport->dma_tx_expired2_desc);
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



static void setup_desc(struct bf53x_dma_desc* desc, void* buf, int fragcount, size_t fragsize_bytes,
		unsigned int cfg, unsigned int xcount, unsigned int ycount){

  int i;

  for( i=0; i<fragcount; ++i ){
    desc[i].next_desc  = (unsigned long)&( desc[i + 1] );
    desc[i].start_addr = (unsigned long)buf + i*fragsize_bytes;
    desc[i].cfg = cfg;
    desc[i].xcount = xcount;
    desc[i].xmodify = sizeof(long);
    desc[i].ycount = ycount;
    desc[i].ymodify = sizeof(long);
  }

  desc[fragcount-1].next_desc = (unsigned long)desc; /* make circular */

/*  printk("setup desc: desc0=%x, next0=%x, desc1=%x, next1=%x\nxcount=%d,ycount=%d,addr=0x%x,cfs=0x%x\n", 
  	&(desc[0]), desc[0].next_desc, 
	&(desc[1]), desc[1].next_desc,
	desc[0].xcount, desc[0].ycount, desc[0].start_addr,desc[0].cfg);
*/
  flush_dcache_range(desc, desc + fragcount*sizeof(struct bf53x_dma_desc));
}


void bf53x_sport_hook_rx_desc( struct bf53x_sport* sport)
{
#ifdef BF53X_SHADOW_REGISTERS
  DMA_register* dma = sport->dma_shadow_rx;
#else
  DMA_register* dma = sport->dma_rx;
#endif
  struct bf53x_dma_desc *desc;
  
  if( sport->regs->rcr1 & RSPEN ) {
    desc = (struct bf53x_dma_desc*)dma->next_desc_ptr;
    desc->next_desc = (unsigned int)(sport->dma_rx_desc);
    flush_dcache_range(desc, desc + sizeof(struct bf53x_dma_desc));
    /* Change the state to current descriptor ring is hooked into DMA. */
    sport->dma_rx_desc_changed=2;
/*    printk("rx: cur_desc=%x, xcount=%d, rx_desc=%x\n", dma->curr_desc_ptr, 
		dma->curr_x_count, sport->dma_rx_desc);
*/
  }
}

void bf53x_sport_hook_tx_desc( struct bf53x_sport* sport)
{
#ifdef BF53X_SHADOW_REGISTERS
  DMA_register* dma = sport->dma_shadow_tx;
#else
  DMA_register* dma = sport->dma_tx;
#endif
  struct bf53x_dma_desc *desc;
  
  if( sport->regs->tcr1 & TSPEN) {
    desc = (struct bf53x_dma_desc*)dma->next_desc_ptr;
    desc->next_desc = (unsigned int)(sport->dma_tx_desc);
    flush_dcache_range(desc, desc + sizeof(struct bf53x_dma_desc));
    /* Change the state to current descriptor ring is hooked into DMA. */
    sport->dma_tx_desc_changed=2;
/*    printk("tx: dma=%x, desc=%x, next=%x\n oldaddr=0x%x, oldxcount=%d\n", 
    	dma->next_desc_ptr, desc, desc->next_desc,
	sport->dma_tx_desc->start_addr, sport->dma_tx_desc->xcount);
*/
  }
}

int bf53x_sport_config_rx_dma( struct bf53x_sport* sport, void* buf, 
			       int fragcount, size_t fragsize_bytes)
{
#ifdef BF53X_SHADOW_REGISTERS
  DMA_register* dma = sport->dma_shadow_rx;
#else
  DMA_register* dma = sport->dma_rx;
#endif
  unsigned int x_count;
  unsigned int y_count;
  unsigned int cfg;

/*  printk( "%s( %p, %d, %d )\n", __FUNCTION__, buf, fragcount,fragsize_bytes );*/

  /* for fragments larger than 32k words we use 2d dma, with the outer loop counting
     the number of 32k blocks. it follows that then
     fragsize must be a power of two (and hence a multiple of 32k
     the line below is the cheapest test I could think of :-) 
  */
  if( fragsize_bytes > 0x8000*sizeof(long) )
    if( (fragsize_bytes | (fragsize_bytes-1) ) != (2*fragsize_bytes - 1) )
      return -EINVAL;

  if(sport->dma_rx_desc_changed==1)
    /* If current descriptor ring hasn't been hooked into DMA, free current descriptor ring.*/
    free(sport->dma_rx_desc);
  else {
    if( sport->dma_rx_expired_desc) {
      if(sport->dma_rx_desc_changed==0) 
        /* Only free last descriptor ring when DMA is walking through current descriptor ring.*/
        free(sport->dma_rx_expired_desc);
      else {
        /* If current descriptor ring has been hooked into DMA, back up last one as the one before last one. */
        if( sport->dma_rx_expired2_desc)
          free(sport->dma_rx_expired2_desc);
        sport->dma_rx_expired2_desc = sport->dma_rx_expired_desc;
      }
    }
      
    if( sport->dma_rx_desc ) 
      /* Back up current descritor ring as last one. */
      sport->dma_rx_expired_desc = sport->dma_rx_desc;
      
    if( sport->dma_rx_desc_changed==2)
      /* If current descriptor ring has been hooked into DMA, change the state to 
       * current descriptor ring is not hooked into DMA.
       */
      sport->dma_rx_desc_changed=1;
  }

  /* Allocate a new descritor ring as current one. */
  sport->dma_rx_desc = malloc( fragcount * sizeof( struct bf53x_dma_desc ) );
  
  if( !sport->dma_rx_desc ) {
    sport->dma_rx_desc = sport->dma_rx_expired_desc;
    sport->dma_rx_expired_desc = NULL;
    return -ENOMEM;
  }

  x_count = fragsize_bytes/sizeof(long);
  y_count = 0;
  cfg     = 0x7000 | DI_EN | WDSIZE_32 | WNR | (DESC_ELEMENT_COUNT << 8); /* large descriptor mode */

  if( x_count > 0x8000 ){
    y_count = x_count >> 15;
    x_count = 0x8000;
    cfg |= DMA2D;
  }

  setup_desc( sport->dma_rx_desc, buf, fragcount, fragsize_bytes , cfg|DMAEN, x_count, y_count);

  if( sport->regs->rcr1 & RSPEN ) {
     /* Change the state to current descriptor ring is not hooked into DMA. */
    sport->dma_rx_desc_changed=1;
  }
  else {  
    dma->next_desc_ptr = (unsigned int)(sport->dma_rx_desc);
    dma->cfg           = cfg;
    dma->x_count       = 0;
    dma->x_modify      = 0;
    dma->y_count       = 0;
    dma->y_modify      = 0;

    SSYNC;
  }
  

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

  return 0;

}

int bf53x_sport_config_tx_dma( struct bf53x_sport* sport, void* buf, 
			       int fragcount, size_t fragsize_bytes)
{
  
#ifdef BF53X_SHADOW_REGISTERS
  DMA_register* dma = sport->dma_shadow_tx;
#else
  DMA_register* dma = sport->dma_tx;
#endif
  unsigned int x_count;
  unsigned int y_count;
  unsigned int cfg;

/*  printk("%s( %p, %d, %d )\n", __FUNCTION__, buf, fragcount,fragsize_bytes );*/

  /* fragsize must be a power of two (line below is the cheapest test I could think of :-) */
  if( fragsize_bytes > 0x8000*sizeof(long) )
    if( (fragsize_bytes | (fragsize_bytes-1) ) != (2*fragsize_bytes - 1) )
      return -EINVAL;

  if(sport->dma_tx_desc_changed==1)
    /* If dma is asked to configure before the last configure takes effect, free last one.*/
     free(sport->dma_tx_desc);
  else {
    if( sport->dma_tx_expired_desc) {
      if(sport->dma_tx_desc_changed==0)
        /* Only free last descriptor ring when DMA is walking through current descriptor ring.*/
        free(sport->dma_tx_expired_desc);
      else {
        /* If current descriptor ring has been hooked into DMA, back up last one as the one before last one. */
        if( sport->dma_tx_expired2_desc)
          free(sport->dma_tx_expired2_desc);
        sport->dma_tx_expired2_desc = sport->dma_tx_expired_desc;
      }
    }
    
    if( sport->dma_tx_desc )
      /* Back up current descritor ring as last one. */
      sport->dma_tx_expired_desc = sport->dma_tx_desc;

    if( sport->dma_tx_desc_changed==2)
      /* If current descriptor ring has been hooked into DMA, change the state to 
       * current descriptor ring is not hooked into DMA.
       */
      sport->dma_tx_desc_changed=1;
  }

  sport->dma_tx_desc = malloc( fragcount * sizeof( struct bf53x_dma_desc ) );
  
  if( !sport->dma_tx_desc ) {
    sport->dma_tx_desc = sport->dma_tx_expired_desc;
    sport->dma_tx_expired_desc = NULL;
    return -ENOMEM;
  }

  x_count = fragsize_bytes/sizeof(long);
  y_count = 0;
  cfg     = 0x7000 | DI_EN | WDSIZE_32 | ( DESC_ELEMENT_COUNT << 8); /* large descriptor mode */

  if( x_count > 0x8000 ){
    y_count = x_count >> 15;
    x_count = 0x8000;
    cfg |= DMA2D;
  }

  setup_desc( sport->dma_tx_desc, buf, fragcount, fragsize_bytes, cfg|DMAEN, x_count, y_count);
    
  if( sport->regs->tcr1 & TSPEN ) {
     /* Change the state to current descriptor ring is not hooked into DMA. */
    sport->dma_tx_desc_changed=1;
  }
  else {
    dma->next_desc_ptr = (unsigned int)(sport->dma_tx_desc);
    dma->cfg           = cfg;
    dma->x_count       = 0;
    dma->x_modify      = 0;
    dma->y_count       = 0;
    dma->y_modify      = 0;
  
    SSYNC;
  }
  
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

int bf53x_sport_is_rx_desc_changed(struct bf53x_sport* sport){
#ifdef BF53X_SHADOW_REGISTERS
  DMA_register* dma = sport->dma_shadow_rx;
#else
  DMA_register* dma = sport->dma_rx;
#endif
  
  if( sport->dma_rx_desc_changed > 0) {
    if(dma->next_desc_ptr==(unsigned long)sport->dma_rx_desc) {
/*      printk("rx dma equal\n");*/
      sport->dma_rx_desc_changed = 0;
    }
    return 1;
  }
  return 0;
}

int bf53x_sport_is_tx_desc_changed(struct bf53x_sport* sport){
#ifdef BF53X_SHADOW_REGISTERS
  DMA_register* dma = sport->dma_shadow_tx;
#else
  DMA_register* dma = sport->dma_tx;
#endif
  
  if( sport->dma_tx_desc_changed > 0) {
    if(dma->next_desc_ptr==(unsigned long)sport->dma_tx_desc) {
/*    printk("tx dma equal\n");*/
      sport->dma_tx_desc_changed = 0;
    }
    return 1;
  }
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
  /* use the fact that we use an contiguous array of descriptors */
  return ( (struct bf53x_dma_desc*)(dma->curr_desc_ptr) - sport->dma_rx_desc) / 
    sizeof( struct bf53x_dma_desc );
}


int bf53x_sport_curr_frag_tx( struct bf53x_sport* sport ){  
#ifdef BF53X_SHADOW_REGISTERS 
  DMA_register* dma = sport->dma_shadow_tx;
#else
  DMA_register* dma = sport->dma_tx;
#endif
  /* use the fact that we use an contiguous array of descriptors */
  return ((struct bf53x_dma_desc*)(dma->curr_desc_ptr) - sport->dma_rx_desc) / 
    sizeof( struct bf53x_dma_desc );
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
