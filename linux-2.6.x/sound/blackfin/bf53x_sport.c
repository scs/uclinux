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

#define  BF53X_SPORT_DEBUG

#define sport_printf(level, format, arg...)  printf(level "sport: " format, ## arg)

#ifdef  BF53X_SPORT_DEBUG
#define sport_printd(level, format, arg...)  printf(level "sport: " format, ## arg)
#define SPORT_ASSERT( x ) assert(x)
#else
#define sport_printd(level, format, arg...)  
#define SPORT_ASSERT( x ) 
#endif

#include <asm/board/cdefBF532.h>
#include <asm/dma.h>
#define FRAME_DELAY (1<<12)  /* delay between frame sync pulse and first data bit
                              in multichannel mode */ 

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


struct bf53x_sport {
  int sport_chan;
  int dma_rx_chan;
  int dma_tx_chan;
  struct sport_register* regs;
  DMA_register* dma_rx;   /* struct gratefully borrowed from asm/bf533_dma.h */
  DMA_register* dma_tx;

  unsigned int rcr1;
  unsigned int rcr2;
  int rx_tdm_count;

  unsigned int tcr1;
  unsigned int tcr2;
  int tx_tdm_count;

  
  

};

static unsigned int sport_iobase[] = {0xffc00800, 0xffc00900 };
static unsigned int dma_iobase[]   = {0xffc00c00, 0xffc00c40, 0xffc00c80, 0xffc00cc0, 
				      0xffc00d00, 0xffc00d40, 0xffc00d80, 0xffd00dc0 }; 
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

  return sport;
} 

void bf53x_sport_done(struct bf53x_sport* sport){
  if(sport) bf53x_sport_stop(sport);
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

  asm( "ssync;\n\t" ); /* is this really neccesary? */

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

  asm( "ssync;\n\t" );

  return 0;

}


int bf53x_sport_config_rx( struct bf53x_sport* sport, unsigned int rcr1, unsigned int rcr2, 
			   unsigned int clkdiv, unsigned int fsdiv ){


  if( (sport->regs->tcr1 & TSPEN) || (sport->regs->rcr1 & RSPEN) )
    return -EBUSY;

  asm( "ssync;\n\t" );

  sport->regs->rcr1 = rcr1;
  sport->regs->rcr2 = rcr2;
  sport->regs->rclkdiv = clkdiv;
  sport->regs->rfsdiv = fsdiv;

  asm( "ssync;\n\t" );

  return 0;

}

int bf53x_sport_config_tx( struct bf53x_sport* sport, unsigned int tcr1, unsigned int tcr2,
			   unsigned int clkdiv, unsigned int fsdiv ){

  if( (sport->regs->tcr1 & TSPEN) || (sport->regs->rcr1 & RSPEN) )
    return -EBUSY;

  asm( "ssync;\n\t" );

  sport->regs->tcr1 = tcr1;
  sport->regs->tcr2 = tcr2;
  sport->regs->tclkdiv = clkdiv;
  sport->regs->tfsdiv = fsdiv;

  asm( "ssync;\n\t" );

  return 0;

}



int bf53x_sport_config_rx_dma( struct bf53x_sport* sport, void* buf, 
			       int fragcount, size_t fragsize_bytes, 
			       unsigned int tdm_mask )
{

  DMA_register* dma = sport->dma_rx;

  sport_printd( KERN_INFO, "%s( %p, %d, %d, 0x%02x )\n", __FUNCTION__, buf, fragcount,fragsize_bytes, tdm_mask );


  if( fragsize_bytes > 0x10000*sizeof(long) ) 
    return -EINVAL;

  asm( "ssync;\n\t" );

  if( sport->regs->rcr1 & RSPEN )
    return -EBUSY;
  
  dma->start_addr = (unsigned int)buf; 
  dma->cfg        = ( 0x1000 | DI_EN | DI_SEL | DMA2D | WDSIZE_32 | WNR ); /* autobuffer mode */
  dma->x_count    = fragsize_bytes/sizeof(long);
  dma->x_modify   = sizeof(long);
  dma->y_count    = fragcount;
  dma->y_modify   = sizeof(long);
  
  if( tdm_mask ) 
    sport->regs->mrcs0 = tdm_mask;

  asm( "ssync;\n\t" );

  return 0;

}

int bf53x_sport_config_tx_dma( struct bf53x_sport* sport, void* buf, 
			       int fragcount, size_t fragsize_bytes, 
			       unsigned int tdm_mask )
{
  
  DMA_register* dma = sport->dma_tx;

  sport_printd( KERN_INFO, "%s( %p, %d, %d, 0x%02x )\n", __FUNCTION__, buf, fragcount,fragsize_bytes, tdm_mask );

  if( fragsize_bytes > 0x10000*sizeof(long) ) 
    return -EINVAL;

  asm( "ssync;\n\t" );

  if( sport->regs->tcr1 & TSPEN ) 
    return -EBUSY;

  dma->start_addr = (unsigned int) buf; 
  dma->cfg = ( 0x1000 | DI_EN | DI_SEL | DMA2D | WDSIZE_32  ) ; /* autobuffer mode */
  dma->x_count    = fragsize_bytes/sizeof(long);
  dma->x_modify   = sizeof(long);
  dma->y_count    = fragcount;
  dma->y_modify   = sizeof(long);
  
  if( tdm_mask ) 
    sport->regs->mtcs0 = tdm_mask;

  asm( "ssync;\n\t" );

  return 0;

}

int sport_disable_dma_rx(struct bf53x_sport* sport)
{ 
  disable_dma(sport->dma_rx_chan);
}

int sport_disable_dma_tx(struct bf53x_sport* sport)
{ 
  disable_dma(sport->dma_tx_chan);
}


int bf53x_sport_start(struct bf53x_sport* sport){ 

  asm( "ssync;\n\t" );

  enable_dma(sport->dma_rx_chan);
  enable_dma(sport->dma_tx_chan);
  sport->regs->tcr1 |= TSPEN;
  sport->regs->rcr1 |= RSPEN;

  asm( "ssync;\n\t" );

  return 0;

}


int bf53x_sport_stop(struct bf53x_sport* sport){ 

  asm( "ssync;\n\t" );

  sport->regs->tcr1 &= ~TSPEN;
  sport->regs->rcr1 &= ~RSPEN;
  disable_dma(sport->dma_rx_chan);
  disable_dma(sport->dma_tx_chan);

  asm( "ssync;\n\t" );

  return 0;

}



/* for use in interrupt handler */
void* bf53x_sport_curr_addr_rx( struct bf53x_sport* sport ){  
  DMA_register* dma = sport->dma_rx;
  void** curr = &(dma->curr_addr_ptr_lo);
  return *curr;
}

void* bf53x_sport_curr_addr_tx( struct bf53x_sport* sport ){ 
  DMA_register* dma = sport->dma_tx;
  void** curr = &(dma->curr_addr_ptr_lo);
  return *curr;
}

int bf53x_sport_curr_frag_rx( struct bf53x_sport* sport ){  
  DMA_register* dma = sport->dma_rx;
  return dma->y_count - dma->curr_y_count; 
}


int bf53x_sport_curr_frag_tx( struct bf53x_sport* sport ){  
  DMA_register* dma = sport->dma_tx;
  return dma->y_count - dma->curr_y_count; 
}



int bf53x_sport_check_status( struct bf53x_sport* sport, 
			      unsigned int* sport_stat, 
			      unsigned int* rx_stat, 
			      unsigned int* tx_stat )
{

  asm( "ssync;\n\t" );

  if( sport_stat ){
    int status = sport->regs->stat;
    if( status & (TOVF|TUVF|ROVF|RUVF) )
      sport->regs->stat = (status & (TOVF|TUVF|ROVF|RUVF));
    *sport_stat = status;
  }

  if( rx_stat ){
    int status = sport->dma_rx->irq_status;
    if( status & (DMA_DONE|DMA_ERR) )
      sport->dma_rx->irq_status = status & (DMA_DONE|DMA_ERR) ;
    *rx_stat = status;
  }

  if( tx_stat ){
    int status = sport->dma_tx->irq_status;
    if( status & (DMA_DONE|DMA_ERR) )
      sport->dma_tx->irq_status = status & (DMA_DONE|DMA_ERR) ;
    *tx_stat = status;
  }

  return 0;

}

int  bf53x_sport_dump_stat(struct bf53x_sport* sport, char* buf, size_t len){
  return snprintf( buf, len, 
		   "sport  %d sts: 0x%04x\n"
		   "rx dma %d cfg: 0x%04x sts: 0x%04x\n"
		   "tx dma %d cfg: 0x%04x sts: 0x%04x\n", 
		   sport->sport_chan,  sport->regs->stat,
		   sport->dma_rx_chan, sport->dma_rx->cfg, sport->dma_rx->irq_status,
		   sport->dma_tx_chan, sport->dma_tx->cfg, sport->dma_tx->irq_status);

}
