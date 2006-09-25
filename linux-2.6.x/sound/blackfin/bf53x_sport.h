/*
 * File:         sound/blackfin/bf53x_sport.h
 * Based on:
 * Author:       Luuk van Dijk <blackfin@mdnmttr.nl>
 *
 * Created:      Tue Sep 21 10:52:42 CEST 2004
 * Description:  low level driver for sportX/dmaY on blackfin 53x
 *               this should be moved to arch/blackfin/
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

#ifndef __BF53X_SPORT_H__
#define __BF53X_SPORT_H__

#include <linux/types.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <asm/dma.h>

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

#define DESC_ELEMENT_COUNT 9

struct bf53x_sport {
	int sport_num;
	int dma_rx_chan;
	int dma_tx_chan;
	int err_irq;
	struct sport_register* regs;

	struct dma_register_t *dma_rx;
	struct dma_register_t *dma_tx;
	unsigned char *rx_buf;
	unsigned char *tx_buf;

#define DUMMY_BUF_LEN 8
	/* for dummy dma transfer */
	void *dummy_buf;

	/* DMA descriptor ring head of current audio stream*/
	struct dmasg_t *dma_rx_desc;
	struct dmasg_t *dma_tx_desc;
	unsigned int rx_desc_bytes;
	unsigned int tx_desc_bytes;

	unsigned int rx_run:1; /* rx is running */
	unsigned int tx_run:1; /* tx is running */

	struct dmasg_t *dummy_rx_desc;
	struct dmasg_t *dummy_tx_desc;

	struct dmasg_t *curr_rx_desc;
	struct dmasg_t *curr_tx_desc;

	unsigned int rcr1;
	unsigned int rcr2;
	int rx_tdm_count;

	unsigned int tcr1;
	unsigned int tcr2;
	int tx_tdm_count;

	wait_queue_head_t wqh_rx;
	wait_queue_head_t wqh_tx;
	
	unsigned int wait_dummy_rx:1;
	unsigned int wait_dummy_tx:1;

	struct dmasg_t bck_desc_rx;
	struct dmasg_t *bck_desc_rx_p;
	struct dmasg_t bck_desc_tx;
	struct dmasg_t *bck_desc_tx_p;

	void (*rx_callback)(void *data);
	void (*tx_callback)(void *data);
	void (*err_callback)(void *data);
	void *data;
};

struct bf53x_sport* bf53x_sport_init(int sport_num,
		int dma_rx, void (*rx_callback)(void *),
		int dma_tx, void (*tx_callback)(void *),
		int err_irq, void (*err_callback)(void *),
		void *data);

void bf53x_sport_done(struct bf53x_sport* sport);

/* first use these ...*/

/* note: multichannel is in units of 8 channels, tdm_count is # channels NOT / 8 ! */
/* all channels are enabled by default */
int bf53x_sport_set_multichannel(struct bf53x_sport* sport, int tdm_count, int packed);

int bf53x_sport_config_rx(struct bf53x_sport* sport,
		unsigned int rcr1, unsigned int rcr2,
		unsigned int clkdiv, unsigned int fsdiv);

int bf53x_sport_config_tx(struct bf53x_sport* sport,
		unsigned int tcr1, unsigned int tcr2,
		unsigned int clkdiv, unsigned int fsdiv);

/* ... then these: */

/* buffer size (in bytes) == fragcount * fragsize_bytes */

/* this is not a very general api, it sets the dma to 2d autobuffer mode */

int bf53x_sport_config_rx_dma(struct bf53x_sport* sport, void* buf,
		int fragcount, size_t fragsize_bytes, size_t size);

int bf53x_sport_config_tx_dma(struct bf53x_sport* sport, void* buf,
		int fragcount, size_t fragsize_bytes, size_t size);

int bf53x_sport_tx_start(struct bf53x_sport* sport);
int bf53x_sport_tx_stop(struct bf53x_sport* sport);
int bf53x_sport_rx_start(struct bf53x_sport* sport);
int bf53x_sport_rx_stop(struct bf53x_sport* sport);

/* for use in interrupt handler */
unsigned long bf53x_sport_curr_offset_rx(struct bf53x_sport* sport);
unsigned long bf53x_sport_curr_offset_tx(struct bf53x_sport* sport);

#endif /* BF53X_SPORT_H */
