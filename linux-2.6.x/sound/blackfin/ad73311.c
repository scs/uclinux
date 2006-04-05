/*
 * File:         ad73311L.c 
 * Description:  Driver for AD73311L sound chip connected to bf53x sport
 * Rev:          $Id$
 * Created:      Wed Jan 11 2006
 * Author:       Roy Huang
 * Email:        Roy.Huang@analog.com
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

/* AD73311L only support one channel ADC and one channel DAC, both are 16 bits.
 * SPORT is used to set AD73311L's register during initialization, then set
 * AD73311L to data mode. SPORT is used to transfer data and no register can be
 * modified until reset chip.
 */

#include <linux/init.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/dma-mapping.h>
#include <linux/delay.h>

#include <asm/blackfin.h>
#include <asm/cacheflush.h>
#include <asm/irq.h>

#include <sound/driver.h>
#include <sound/core.h>
#include <sound/info.h>
#include <sound/control.h>
#include <sound/pcm.h>
#include <sound/initval.h>

#include "ad73311.h"
#include "bf53x_sport.h"

#ifndef CONFIG_BFIN_DMA_5XX
#error "The sound driver requires the Blackfin Simple DMA"
#endif

#ifdef CONFIG_SND_DEBUG
#define snd_printk_marker() snd_printk( KERN_INFO "%s\n", __FUNCTION__ )
#else
#define snd_printk_marker() 
#endif

#define GPIO_SE CONFIG_SND_BFIN_AD73311_SE

#undef CONFIG_SND_DEBUG_CURRPTR  /* causes output every frame! */

#define PCM_BUFFER_MAX	0x10000	/* 64KB */
//#define FRAGMENT_SIZE_MIN	(4 * 1024)
#define FRAGMENT_SIZE_MIN	1024
#define FRAGMENTS_MIN	2
#define FRAGMENTS_MAX	16
#define WORD_LENGTH	2

#define CHIP_NAME "Analog Devices AD73311L"

/* ALSA boilerplate */
static int   index[SNDRV_CARDS]  = SNDRV_DEFAULT_IDX;
static char* id[SNDRV_CARDS]     = SNDRV_DEFAULT_STR;
static int   enable[SNDRV_CARDS] = SNDRV_DEFAULT_ENABLE_PNP;

#define ad73311_t_magic  0xa5a73311

typedef struct snd_ad73311 {
	snd_card_t*         card;
	struct bf53x_sport* sport;
	spinlock_t    ad73311_lock;

	snd_pcm_t* pcm;

	snd_pcm_substream_t* rx_substream;
	snd_pcm_substream_t* tx_substream;

	int runmode;
#define RUN_RX 0x1
#define RUN_TX 0x2
} ad73311_t;

#if L1_DATA_A_LENGTH != 0
extern unsigned long l1_data_A_sram_alloc(unsigned long size);
extern int l1_data_A_sram_free(unsigned long addr);
#else
#error "This driver need L1 data cache"
#endif

static int snd_ad73311_configure(void);
static int snd_ad73311_startup(void);
static void snd_ad73311_stop(void);


/*************************************************************
 *                pcm methods 
 *************************************************************/

static snd_pcm_hardware_t snd_ad73311_play_hw = {
	.info = (SNDRV_PCM_INFO_MMAP | SNDRV_PCM_INFO_INTERLEAVED |
			SNDRV_PCM_INFO_BLOCK_TRANSFER | SNDRV_PCM_INFO_MMAP_VALID),
	.formats =          SNDRV_PCM_FMTBIT_S16_LE,
	.rates =            SNDRV_PCM_RATE_8000,
	.rate_min =         8000,
	.rate_max =         8000,
	.channels_min =     1,
	.channels_max =     1,
	.buffer_bytes_max = PCM_BUFFER_MAX,
	.period_bytes_min = FRAGMENT_SIZE_MIN,
	.period_bytes_max = PCM_BUFFER_MAX/2,
	.periods_min =      FRAGMENTS_MIN,
	.periods_max =      FRAGMENTS_MAX,
};
static snd_pcm_hardware_t snd_ad73311_cap_hw = {
	.info = (SNDRV_PCM_INFO_MMAP | SNDRV_PCM_INFO_INTERLEAVED | 
			SNDRV_PCM_INFO_BLOCK_TRANSFER |  SNDRV_PCM_INFO_MMAP_VALID),
	.formats =          SNDRV_PCM_FMTBIT_S16_LE,
	.rates =            SNDRV_PCM_RATE_8000,
	.rate_min =         8000,
	.rate_max =         8000,
	.channels_min =     1,
	.channels_max =     1,
	.buffer_bytes_max = PCM_BUFFER_MAX,
	.period_bytes_min = FRAGMENT_SIZE_MIN,
	.period_bytes_max = PCM_BUFFER_MAX/2,
	.periods_min =      FRAGMENTS_MIN,
	.periods_max =      FRAGMENTS_MAX,
};

static int snd_ad73311_play_open(snd_pcm_substream_t* substream)
{
	ad73311_t* chip = snd_pcm_substream_chip(substream);

	snd_printk_marker();

	substream->runtime->hw = snd_ad73311_play_hw;
	chip->tx_substream = substream;

	return 0;
}

static int snd_ad73311_cap_open(snd_pcm_substream_t* substream)
{ 
	ad73311_t* chip = snd_pcm_substream_chip(substream);

	snd_printk_marker();

	substream->runtime->hw = snd_ad73311_cap_hw;
	chip->rx_substream = substream;

	return 0;
}


static int snd_ad73311_play_close(snd_pcm_substream_t* substream)
{
	ad73311_t* chip = snd_pcm_substream_chip(substream);
	snd_printk_marker();
	chip->tx_substream = NULL;

	return 0;
}


static int snd_ad73311_cap_close(snd_pcm_substream_t* substream)
{
	ad73311_t* chip = snd_pcm_substream_chip(substream);

	snd_printk_marker();
	chip->rx_substream = NULL;

	return 0;
}


static int snd_ad73311_hw_params( snd_pcm_substream_t* substream, snd_pcm_hw_params_t* hwparams)
{
	snd_printk_marker();
	if( snd_pcm_lib_malloc_pages(substream, params_buffer_bytes(hwparams)) < 0 )
		return -ENOMEM;

	return 0;
}

static int snd_ad73311_hw_free(snd_pcm_substream_t * substream)
{
	snd_printk_marker();
	snd_pcm_lib_free_pages(substream);

	return 0;
}

static int snd_ad73311_play_pre( snd_pcm_substream_t* substream )
{

	ad73311_t* chip = snd_pcm_substream_chip(substream);
	snd_pcm_runtime_t* runtime = substream->runtime;
	int period_bytes = frames_to_bytes(runtime, runtime->period_size);

	snd_assert( (substream == chip->tx_substream), return -EINVAL );

	snd_printk_marker();
	snd_printd(KERN_INFO "%s channels:%d, period_bytes:0x%x, periods:%d\n",
				__FUNCTION__, runtime->channels, period_bytes,
							runtime->periods);
	return bf53x_sport_config_tx_dma( chip->sport, runtime->dma_area, 
				runtime->periods, period_bytes, WORD_LENGTH);
}

static int snd_ad73311_cap_pre( snd_pcm_substream_t* substream )
{

	ad73311_t* chip = snd_pcm_substream_chip(substream);
	snd_pcm_runtime_t* runtime = substream->runtime;
	int  period_bytes = frames_to_bytes(runtime, runtime->period_size);

	snd_printk_marker();
	snd_assert( (substream == chip->rx_substream), return -EINVAL );

	snd_printd(KERN_INFO "%s channels:%d, period_bytes:%d, frag_count:%d\n",
				__FUNCTION__, runtime->channels, period_bytes,
							runtime->periods);
	return bf53x_sport_config_rx_dma( chip->sport, runtime->dma_area, 
				runtime->periods, period_bytes, WORD_LENGTH);
}


static int snd_ad73311_play_trigger( snd_pcm_substream_t* substream, 
								int cmd)
{
	ad73311_t* chip = snd_pcm_substream_chip(substream);

	spin_lock(&chip->ad73311_lock);
	switch(cmd){
		case SNDRV_PCM_TRIGGER_START: 
			bf53x_sport_hook_tx_desc(chip->sport, 0);
			if(!( chip->runmode & RUN_RX )) {
				snd_ad73311_startup();
				bf53x_sport_hook_rx_desc(chip->sport, 1);
				bf53x_sport_start(chip->sport);
			}
			chip->runmode |= RUN_TX;
			break;
		case SNDRV_PCM_TRIGGER_STOP:
			chip->runmode &= ~RUN_TX;
			if (chip->runmode & RUN_RX ) {
				bf53x_sport_hook_tx_desc(chip->sport, 1);
			} else {
				bf53x_sport_stop(chip->sport);
				snd_ad73311_stop();
			}
			/*      printk("stop tx\n");*/
			break;
		default:
			spin_unlock(&chip->ad73311_lock);
			return -EINVAL;
	}
	spin_unlock(&chip->ad73311_lock);

	snd_printd(KERN_INFO"cmd:%s,runmode:0x%x\n", cmd?"start":"stop", 
								chip->runmode);
	return 0;
}

static int snd_ad73311_cap_trigger( snd_pcm_substream_t* substream, int cmd)
{

	ad73311_t* chip = snd_pcm_substream_chip(substream);

	spin_lock(&chip->ad73311_lock);
	snd_assert(substream == chip->rx_substream, return -EINVAL);
	switch(cmd){
		case SNDRV_PCM_TRIGGER_START: 
			bf53x_sport_hook_rx_desc(chip->sport, 0);
			if (!(chip->runmode & RUN_TX)) { /* Sport isn't running  */
				snd_ad73311_startup();
				bf53x_sport_hook_tx_desc(chip->sport, 1);
				bf53x_sport_start(chip->sport);
			}
			chip->runmode |= RUN_RX;
//			printk("start rx\n");
			break;
		case SNDRV_PCM_TRIGGER_STOP:
			chip->runmode &= ~RUN_RX;
			if (chip->runmode & RUN_TX) {
				bf53x_sport_hook_rx_desc(chip->sport, 1);
			} else {
				bf53x_sport_stop(chip->sport);
				snd_ad73311_stop();
			}
//			printk("stop rx\n");
			break;
		default:
			spin_unlock(&chip->ad73311_lock);
			return -EINVAL;
	}
	spin_unlock(&chip->ad73311_lock);

//	printk(KERN_INFO"cmd:%s,runmode:0x%x\n", cmd?"start":"stop", chip->runmode); 
	return 0;
}

static snd_pcm_uframes_t snd_ad73311_play_ptr( snd_pcm_substream_t* substream )
{
	ad73311_t* chip = snd_pcm_substream_chip(substream);
	snd_pcm_runtime_t* runtime = substream->runtime;

	char* buf  = (char*) runtime->dma_area;
	char* curr = (char*) bf53x_sport_curr_addr_tx(chip->sport);
	unsigned long diff = curr - buf;
	unsigned long bytes_per_frame = runtime->frame_bits/8;
	size_t frames = diff / bytes_per_frame;

	if( frames >= runtime->buffer_size ) 
		frames = 0;

	return frames;
}

static snd_pcm_uframes_t snd_ad73311_cap_ptr( snd_pcm_substream_t* substream )
{
	ad73311_t* chip = snd_pcm_substream_chip(substream);
	snd_pcm_runtime_t* runtime = substream->runtime;

	char* buf  = (char*) runtime->dma_area;
	char* curr = (char*) bf53x_sport_curr_addr_rx(chip->sport);
	unsigned long diff = curr - buf;
	unsigned long bytes_per_frame = runtime->frame_bits/8;
	size_t frames = diff / bytes_per_frame;

#ifdef CONFIG_SND_DEBUG_CURRPTR
	snd_printk( KERN_INFO " cap pos: 0x%04lx / %lx\n", frames, runtime->buffer_size);
#endif 

	/* the loose syncing used here is accurate enough for alsa, but 
	   due to latency in the dma, the following may happen occasionally, 
	   and pcm_lib shouldn't complain */
	if( frames >= runtime->buffer_size ) 
		frames = 0;

	return frames;
}

/*
 *  Print data byte by byte without endianness getting in the way
 */
void print_32x4(void *data)
{
  unsigned char *p = (unsigned char *)data;
  printk( KERN_INFO
	"%02x%02x%02x%02x "
	"%02x%02x%02x%02x "
	"%02x%02x%02x%02x "
	"%02x%02x%02x%02x "
	"\n",
	 p[0],  p[1],  p[2],  p[3],
	 p[4],  p[5],  p[6],  p[7],
	 p[8],  p[9], p[10], p[11],
	p[12], p[13], p[14], p[15]
	);
}

static int snd_ad73311_play_copy(snd_pcm_substream_t *substream, int channel, 
		snd_pcm_uframes_t pos, void *src, snd_pcm_uframes_t count)
{
	unsigned char *dst = substream->runtime->dma_area;

//	printk(KERN_INFO "p: src %p, pos %x, count %x\n", src, (uint)pos, (uint)count);
	memcpy(dst + frames_to_bytes(substream->runtime, pos), src, 
				frames_to_bytes(substream->runtime, count));
//	print_32x4(src);

	return 0;
}

static int snd_ad73311_cap_copy(snd_pcm_substream_t *substream, int channel, 
		snd_pcm_uframes_t pos, void *dst, snd_pcm_uframes_t count)
{
	unsigned char *src = substream->runtime->dma_area;

//	printk(KERN_INFO "c: dst %p, pos %x, count %x\n", dst, (uint)pos, (uint)count);
	memcpy(dst, src + frames_to_bytes(substream->runtime, pos), 
				frames_to_bytes(substream->runtime, count));
//	print_32x4(dst);

	return 0;
}

/* pcm method tables */

static snd_pcm_ops_t snd_ad73311_play_ops = {
	.open      = snd_ad73311_play_open,
	.close     = snd_ad73311_play_close,
	.ioctl     = snd_pcm_lib_ioctl,
	.hw_params = snd_ad73311_hw_params,
	.hw_free   = snd_ad73311_hw_free,
	.prepare   = snd_ad73311_play_pre,
	.trigger   = snd_ad73311_play_trigger,
	.pointer   = snd_ad73311_play_ptr,
	.copy	   = snd_ad73311_play_copy,
};


static snd_pcm_ops_t snd_ad73311_cap_ops = {
	.open  = snd_ad73311_cap_open,
	.close = snd_ad73311_cap_close,
	.ioctl = snd_pcm_lib_ioctl,  
	.hw_params = snd_ad73311_hw_params,
	.hw_free   = snd_ad73311_hw_free,
	.prepare   = snd_ad73311_cap_pre,
	.trigger   = snd_ad73311_cap_trigger,
	.pointer   = snd_ad73311_cap_ptr,
	.copy	   = snd_ad73311_cap_copy,
};


/************************************************************* 
 *      card and device 
 *************************************************************/
static int snd_ad73311_free(ad73311_t *chip)
{
	/* TODO reset AD73311L by assert reset pin */
	kfree(chip);
	return 0;
}

/* component-destructor, wraps snd_ad73311_free for use in snd_device_ops_t
 */
static int snd_ad73311_dev_free(snd_device_t *device)
{
	ad73311_t *chip = (ad73311_t *)device->device_data;

	return snd_ad73311_free(chip);
}

static snd_device_ops_t snd_ad73311_ops = {
	.dev_free = snd_ad73311_dev_free,
};

static int snd_ad73311_startup( void )
{
	snd_printd(KERN_INFO "%s is called\n", __FUNCTION__);

	*(unsigned short*)FIO_DIR |= (1 << GPIO_SE);
	__builtin_bfin_ssync();

	*(unsigned short*)FIO_FLAG_S |= (1 << GPIO_SE);
	__builtin_bfin_ssync();
	
	return 0;
}

static void snd_ad73311_stop( void )
{
	snd_printd(KERN_INFO "%s is called\n", __FUNCTION__);

	*(unsigned short*)FIO_DIR |= (1 << GPIO_SE);
	__builtin_bfin_ssync();

	/* Pull down SE pin on AD73311L */
	*(unsigned short*)FIO_FLAG_C |= (1 << GPIO_SE);
	__builtin_bfin_ssync();
}

/* create the card struct, 
 *   add - low-level device, 
 *       - sport and registers, 
 *       - and a pcm device 
 */

static int __devinit snd_ad73311_create(snd_card_t *card,
		struct bf53x_sport* sport, 
		ad73311_t **rchip)
{

	ad73311_t *chip;
	int err;

	*rchip = NULL;

	chip = (ad73311_t*)kcalloc(1, sizeof(ad73311_t), GFP_KERNEL);
	if (chip == NULL)
		return -ENOMEM;

	chip->card  = card;
	chip->sport = sport;
	spin_lock_init(&chip->ad73311_lock);

	if ((sport->dummy_buf=l1_data_A_sram_alloc(DUMMY_BUF_LEN)) == 0) {
		printk(KERN_ERR "Unable to allocate dummy buffer in sram\n");
		err = -ENODEV;
		goto create_err1;
	}
	memset((void*)sport->dummy_buf, 0, DUMMY_BUF_LEN);

	err = snd_device_new(card, SNDRV_DEV_LOWLEVEL, chip, &snd_ad73311_ops);
	if(err) {
		printk(KERN_ERR "Failed to create sound card device\n");
		goto create_err2;
	}
	
	/* 1 playback and 1 capture substream */
	if ((err = snd_pcm_new(card, CHIP_NAME, 0, 1, 1, &chip->pcm))) {
		printk(KERN_ERR "Failed to create PCM device \n");
		goto create_err2;
	}

	chip->pcm->private_data = chip;
	strcpy(chip->pcm->name, CHIP_NAME);
	snd_pcm_set_ops(chip->pcm, SNDRV_PCM_STREAM_PLAYBACK,
						&snd_ad73311_play_ops);
	snd_pcm_set_ops(chip->pcm, SNDRV_PCM_STREAM_CAPTURE,
						&snd_ad73311_cap_ops);

	/* uncached DMA buffers */
	err = snd_pcm_lib_preallocate_pages_for_all(chip->pcm, 
				SNDRV_DMA_TYPE_DEV,NULL, PCM_BUFFER_MAX,
				PCM_BUFFER_MAX);
	if (err) {
		printk(KERN_ERR "Failed to allocate memory\n");
		goto create_err2;
	}

	err = bf53x_sport_config_rx(sport, RFSR, 0xF, 0, 0);
	err = err || bf53x_sport_config_tx(sport, TFSR, 0xF, 0, 0);
	err = err || sport_config_rx_dummy( sport, WORD_LENGTH );
	err = err || sport_config_tx_dummy( sport, WORD_LENGTH );
	if (err) {
		printk(KERN_ERR "Failed to configure dummy buffer\n");
		goto create_err2;
	}

	*rchip = chip;

	return 0;
	
create_err2:
	l1_data_A_sram_free((unsigned long)sport->dummy_buf);
create_err1:
	kfree(chip);

	return err;
}

/************************************************************* 
 *                 ALSA Card Level 
 *************************************************************/
static int snd_ad73311_configure(void)
{
	unsigned short ctrl_regs[6];
	unsigned short status = 0;
	int count = 0;

	/* Set registers on AD73311L through SPORT.  */
#if 0	
	/* DMCLK = MCLK/4 = 16.384/4 = 4.096 MHz
	 * SCLK = DMCLK/8 = 512 KHz
	 * Sample Rate = DMCLK/512 = 8 KHz */
	ctrl_regs[0] = AD_CONTROL | AD_WRITE | CTRL_REG_B | MCDIV(0x3) | \
								DIRATE(0x2) ;
#else
	/* DMCLK = MCLK = 16.384 MHz
	 * SCLK = DMCLK/8 = 2.048 MHz
	 * Sample Rate = DMCLK/2048  = 8 KHz */
	ctrl_regs[0] = AD_CONTROL | AD_WRITE | CTRL_REG_B | MCDIV(0) | \
							SCDIV(0) | DIRATE(0);

#endif
	ctrl_regs[1] = AD_CONTROL | AD_WRITE | CTRL_REG_C | PUDEV | PUADC | \
				PUDAC | PUREF | REFUSE ;/* Register C */
	ctrl_regs[2] = AD_CONTROL | AD_WRITE | CTRL_REG_D | OGS(0) | IGS(5);
	ctrl_regs[3] = AD_CONTROL | AD_WRITE | CTRL_REG_E | DA(0x1f);
	ctrl_regs[4] = AD_CONTROL | AD_WRITE | CTRL_REG_F | SEEN ;
//	ctrl_regs[4] = AD_CONTROL | AD_WRITE | CTRL_REG_F | ALB;
//	ctrl_regs[4] = AD_CONTROL | AD_WRITE | CTRL_REG_F | 0;
	/* Put AD73311L to data mode */
	ctrl_regs[5] = AD_CONTROL | AD_WRITE | CTRL_REG_A | MODE_DATA;
//	ctrl_regs[5] = AD_CONTROL | AD_WRITE | CTRL_REG_A | SLB | MODE_DATA;

#if 0
	printk(KERN_INFO "0x%04x 0x%04x 0x%04x 0x%04x 0x%4x 0x%4x\n", 
			ctrl_regs[0], ctrl_regs[1], ctrl_regs[2], 
			ctrl_regs[3], ctrl_regs[4], ctrl_regs[5]);
#endif

	local_irq_disable();
	snd_ad73311_startup();
	udelay(1);

	*(unsigned short*)SPORT_TCR1 = TFSR;
	*(unsigned short*)SPORT_TCR2 = 0xF;

	/* SPORT Tx Register is a 8 x 16 FIFO, all the data can be put to
	 * FIFO before enable SPORT to transfer the data */
	for( count = 0; count < 6; count++) {
		*(unsigned short*)SPORT_TX = ctrl_regs[count];
	}
	__builtin_bfin_ssync();

	*(unsigned short*)SPORT_TCR1 |= TSPEN;	
	__builtin_bfin_ssync();

	/* When TUVF is set, the data is already send out */
	while(! (status & TUVF) && count++ < 10000) {
		udelay(1);
		status = *(unsigned short *)SPORT_STAT;
		__builtin_bfin_ssync();
	}
	*(unsigned short*)SPORT_TCR1 &= ~TSPEN;
	__builtin_bfin_ssync();
	local_irq_enable();

	snd_ad73311_stop();

	if (count == 10000)
		return -1;

	return 0;
}

static int __devinit snd_ad73311_probe(struct bf53x_sport* sport, 
						snd_card_t** the_card)
{
	static int dev=0;
	snd_card_t *card;
	ad73311_t *chip;    
	int err;

	if (dev >= SNDRV_CARDS)  return -ENODEV;

	if (!enable[dev]) {
		dev++;
		return -ENOENT;
	}

	card = snd_card_new( index[dev], id[dev], THIS_MODULE, 0 );
	if( card == NULL ) {
		err = -ENOMEM;
		goto probe_err1;
	}
	
	if( (err = snd_ad73311_create(card, sport, &chip)) < 0 ) {
		printk(KERN_ERR "Failed to call create\n");
		goto probe_err2;
	}

	card->private_data = chip;
	strcpy(card->driver, "ad73311");
	strcpy(card->shortname, CHIP_NAME);
	sprintf(card->longname, "%s at SPORT%d rx/tx dma %d/%d err irq /%d ", 
			card->shortname, CONFIG_SND_BFIN_SPORT,
			SPORT_DMA_RX, SPORT_DMA_TX, SPORT_ERR_IRQ);

	if ((err = snd_card_register(card)) < 0) {
		printk(KERN_ERR "Failed to register card\n");
		goto probe_err2;
	}

	++dev;
	*the_card = card;

	return 0;
probe_err2:
	snd_card_free(card);
probe_err1:
	return err;
}

MODULE_AUTHOR("Roy Huang <roy.huang@analog.com>");
MODULE_DESCRIPTION("Blackfin/ADI AD73311L");
MODULE_LICENSE("GPL");

static snd_card_t*         card=NULL;
static struct bf53x_sport* sport=NULL;

static __devexit void snd_ad73311_remove(snd_card_t* card)
{
	l1_data_A_sram_free((unsigned long)sport->dummy_buf);
	snd_card_free(card);

	return;
}

static irqreturn_t sport_rx_hdlr(int irq, void *dev_id, struct pt_regs *regs)
{
	unsigned int rx_stat;
	ad73311_t *chip = card->private_data;
	
	bf53x_sport_check_status( chip->sport, NULL, &rx_stat, NULL );  
	if( !(rx_stat & DMA_DONE) ) {
		snd_printk(KERN_ERR"Error - RX DMA is already stopped\n");
		return IRQ_HANDLED;
	}

	if( (chip->rx_substream) && (chip->runmode & RUN_RX ))
		snd_pcm_period_elapsed(chip->rx_substream);

	return IRQ_HANDLED;
}

static irqreturn_t sport_tx_hdlr(int irq, void *dev_id, struct pt_regs *regs)
{
	unsigned int tx_stat;
	ad73311_t *chip = card->private_data;

	bf53x_sport_check_status( chip->sport, NULL, NULL, &tx_stat );  
	if( !(tx_stat & DMA_DONE)) {
		snd_printk(KERN_ERR"Error - TX DMA is already stopped\n");
		return IRQ_HANDLED;
	}
	if( (chip->tx_substream) && (chip->runmode & RUN_TX)) {
		snd_pcm_period_elapsed(chip->tx_substream);
	}

	return IRQ_HANDLED;
}

static irqreturn_t sport_err_hdlr(int irq, void *dev_id, struct pt_regs *regs)
{
	unsigned int status;

	if(!sport) return IRQ_NONE;
	if( bf53x_sport_check_status(sport, &status, NULL, NULL) ){
		snd_printk( KERN_ERR "error checking status ??" );
		return IRQ_NONE;
	}

	if( status & (TOVF|TUVF|ROVF|RUVF) ){
		snd_printk( KERN_WARNING  "sport status error:%s%s%s%s\n", 
				status & TOVF ? " TOVF" : "", 
				status & TUVF ? " TUVF" : "", 
				status & ROVF ? " ROVF" : "", 
				status & RUVF ? " RUVF" : "" );
		bf53x_sport_stop(sport);
	}

	return IRQ_HANDLED;
}

static int __init snd_ad73311_init(void)
{
	int err;

	if((err = snd_ad73311_configure()) < 0) {
		printk(KERN_ERR "Failed to configure ad73311\n");
		goto init_err1;
	}

	if( (sport = bf53x_sport_init(CONFIG_SND_BFIN_SPORT,  
			SPORT_DMA_RX, sport_rx_hdlr,
			SPORT_DMA_TX, sport_tx_hdlr) ) == NULL ){ 
		printk(KERN_ERR"Initialize sport failed\n");
		err = -EFAULT;
		goto init_err1;
	}

	if( request_irq(SPORT_ERR_IRQ, sport_err_hdlr, SA_SHIRQ, 
						"SPORT Error", sport )){
		printk(KERN_ERR"Request sport error IRQ failed:%d\n", 
							SPORT_ERR_IRQ);
		err = -ENODEV;
		goto init_err2;
	}

	if((err = snd_ad73311_probe(sport, &card)))
		goto init_err3;

	return 0;

init_err3:
	free_irq(SPORT_ERR_IRQ, sport);
init_err2:
	bf53x_sport_done(sport);
init_err1:

	return err;
}

static void __exit snd_ad73311_exit(void)
{
	if( card ){
		snd_ad73311_remove(card);
		card = NULL;
	}

	if( sport ){
		free_irq(SPORT_ERR_IRQ, sport);
		bf53x_sport_done(sport);
		sport = NULL;
	}

	return;
}

module_init(snd_ad73311_init);
module_exit(snd_ad73311_exit);
