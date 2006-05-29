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
#include <linux/platform_device.h>

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

#if CONFIG_SND_BFIN_SPORT == 0
#define SPORT_DMA_RX CH_SPORT0_RX
#define SPORT_DMA_TX CH_SPORT0_TX
#define SPORT_IRQ_ERR IRQ_SPORT0_ERROR
#else
#define SPORT_DMA_RX CH_SPORT1_RX
#define SPORT_DMA_TX CH_SPORT1_TX
#define SPORT_IRQ_ERR IRQ_SPORT1_ERROR
#endif

#define GPIO_SE CONFIG_SND_BFIN_AD73311_SE

#undef CONFIG_SND_DEBUG_CURRPTR  /* causes output every frame! */

#define PCM_BUFFER_MAX	0x10000	/* 64KB */
//#define FRAGMENT_SIZE_MIN	(4 * 1024)
#define FRAGMENT_SIZE_MIN	1024
#define FRAGMENTS_MIN	2
#define FRAGMENTS_MAX	16
#define WORD_LENGTH	2

#define DRIVER_NAME "snd-ad73311"
#define CHIP_NAME "Analog Devices AD73311L"
#define PCM_NAME "AD73311 PCM"

static struct platform_device *device = NULL;

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

static int snd_ad73311_hw_params( snd_pcm_substream_t* substream,
		snd_pcm_hw_params_t* hwparams)
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
			bf53x_sport_tx_start(chip->sport);
			if(!( chip->runmode & RUN_RX )) {
				snd_ad73311_startup();
			}
			chip->runmode |= RUN_TX;
			break;
		case SNDRV_PCM_TRIGGER_STOP:
			chip->runmode &= ~RUN_TX;
			bf53x_sport_tx_stop(chip->sport);
			if (!chip->runmode & RUN_RX ) {
				snd_ad73311_stop();
			}
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
			bf53x_sport_rx_start(chip->sport);
			if (!(chip->runmode & RUN_TX)) {
				snd_ad73311_startup();
			}
			chip->runmode |= RUN_RX;
			break;
		case SNDRV_PCM_TRIGGER_STOP:
			chip->runmode &= ~RUN_RX;
			bf53x_sport_rx_stop(chip->sport);
			if (!(chip->runmode & RUN_TX)) {
				snd_ad73311_stop();
			}
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

	unsigned long diff = bf53x_sport_curr_offset_tx(chip->sport);
	size_t frames = bytes_to_frames(substream->runtime, diff);

	if( frames >= substream->runtime->buffer_size ) 
		frames = 0;

	return frames;
}

static snd_pcm_uframes_t snd_ad73311_cap_ptr( snd_pcm_substream_t* substream )
{
	ad73311_t* chip = snd_pcm_substream_chip(substream);

	unsigned long diff = bf53x_sport_curr_offset_rx(chip->sport);
	size_t frames = bytes_to_frames(substream->runtime, diff);

#ifdef CONFIG_SND_DEBUG_CURRPTR
	snd_printk( KERN_INFO " cap pos: 0x%04lx / %lx\n", frames, runtime->buffer_size);
#endif 

	/* the loose syncing used here is accurate enough for alsa, but 
	   due to latency in the dma, the following may happen occasionally, 
	   and pcm_lib shouldn't complain */
	if( frames >= substream->runtime->buffer_size ) 
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

	memcpy(dst + frames_to_bytes(substream->runtime, pos), src, 
				frames_to_bytes(substream->runtime, count));

	return 0;
}

static int snd_ad73311_cap_copy(snd_pcm_substream_t *substream, int channel, 
		snd_pcm_uframes_t pos, void *dst, snd_pcm_uframes_t count)
{
	unsigned char *src = substream->runtime->dma_area;

	memcpy(dst, src + frames_to_bytes(substream->runtime, pos), 
				frames_to_bytes(substream->runtime, count));

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

static void snd_ad73311_dma_rx(void *data)
{
	struct snd_ad73311 *chip = data;

	if( (chip->rx_substream) && (chip->runmode & RUN_RX ))
		snd_pcm_period_elapsed(chip->rx_substream);
}

static void snd_ad73311_dma_tx(void *data)
{
	struct snd_ad73311 *chip = data;

	if( (chip->tx_substream) && (chip->runmode & RUN_TX)) {
		snd_pcm_period_elapsed(chip->tx_substream);
	}
}

static void snd_ad73311_sport_err(void *data)
{
	printk(KERN_ERR "%s: error happened on sport\n", __FUNCTION__);
}

/************************************************************* 
 *      card and device 
 *************************************************************/
static int snd_ad73311_startup( void )
{
	snd_printd(KERN_INFO "%s is called\n", __FUNCTION__);

	*(unsigned short*)FIO_DIR |= (1 << GPIO_SE);
	__builtin_bfin_ssync();

	*(unsigned short*)FIO_FLAG_S = (1 << GPIO_SE);
	__builtin_bfin_ssync();
	
	return 0;
}

static void snd_ad73311_stop( void )
{
	snd_printd(KERN_INFO "%s is called\n", __FUNCTION__);

	*(unsigned short*)FIO_DIR |= (1 << GPIO_SE);
	__builtin_bfin_ssync();

	/* Pull down SE pin on AD73311L */
	*(unsigned short*)FIO_FLAG_C = (1 << GPIO_SE);
	__builtin_bfin_ssync();
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

static int __devinit snd_ad73311_pcm(struct snd_ad73311 *ad73311)
{
	int err = 0;
	struct snd_pcm *pcm;
	
	/* 1 playback and 1 capture substream */
	if ((err = snd_pcm_new(ad73311->card, PCM_NAME, 0, 1, 1, &pcm))) {
		return err;
	}

	ad73311->pcm = pcm;
	strcpy(pcm->name, PCM_NAME);
	snd_pcm_set_ops(pcm, SNDRV_PCM_STREAM_PLAYBACK, 
			&snd_ad73311_play_ops);
	snd_pcm_set_ops(pcm, SNDRV_PCM_STREAM_CAPTURE,
			&snd_ad73311_cap_ops);

	pcm->private_data = ad73311;
	pcm->info_flags = 0;
	/* uncached DMA buffers */
	err = snd_pcm_lib_preallocate_pages_for_all(pcm, 
				SNDRV_DMA_TYPE_DEV,NULL, PCM_BUFFER_MAX,
				PCM_BUFFER_MAX);
	if (err) {
		return -ENOMEM;
	}

	return 0;
}

static int __devinit snd_ad73311_probe(struct platform_device *pdev)
{
	int err;
	struct snd_card *card;
	struct snd_ad73311 *ad73311;
	struct bf53x_sport *sport;

	if (device != NULL)
		return -ENOENT;

	if ((err = snd_ad73311_configure()) < 0)
		return -EFAULT;

	card = snd_card_new( -1, NULL, THIS_MODULE, sizeof(struct snd_ad73311));
	if( card == NULL )
		return -ENOMEM;
	
	ad73311 = card->private_data;
	ad73311->card = card;

	if ((sport = bf53x_sport_init(CONFIG_SND_BFIN_SPORT,
			SPORT_DMA_TX, snd_ad73311_dma_rx,
			SPORT_DMA_RX, snd_ad73311_dma_tx,
			SPORT_IRQ_ERR, snd_ad73311_sport_err, ad73311))
			== NULL) {
		err = -ENODEV;
		goto __nodev;
	}

	ad73311->sport = sport;

	if ((err = snd_ad73311_pcm(ad73311)) < 0)
		goto __nodev;

	err = bf53x_sport_config_rx(sport, RFSR, 0xF, 0, 0);
	err = err || bf53x_sport_config_tx(sport, TFSR, 0xF, 0, 0);
	if (err)
		goto __nodev;

	strcpy(card->driver, "ad73311");
	strcpy(card->shortname, CHIP_NAME);
	sprintf(card->longname, "Blackfin Stampboard Daughter Card, "
			"AD73311L soundcard");

	snd_card_set_dev(card, (&pdev->dev));
	if ((err = snd_card_register(card)) < 0) {
		goto __nodev;
	}

	platform_set_drvdata(pdev, card);

	return 0;

__nodev:
	snd_card_free(card);
	return err;
}

static int __devexit snd_ad73311_remove(struct platform_device *pdev)
{
	struct snd_card *card;
	struct snd_ad73311 *ad73311;

	card = platform_get_drvdata(pdev);
	ad73311 = card->private_data;
	
	snd_ad73311_stop();
	bf53x_sport_done(ad73311->sport);
	snd_card_free(card);

	platform_set_drvdata(pdev, NULL);

	return 0;
}

#ifdef CONFIG_PM
static int snd_ad73311_suspend(struct platform_device *pdev, pm_message_t state)
{
       		
	struct snd_card *card = platform_get_drvdata(pdev);
        struct snd_ad73311 *ad73311 = card->private_data;
	
        snd_power_change_state(card, SNDRV_CTL_POWER_D3hot);
        snd_pcm_suspend_all(ad73311->pcm);
	
	return 0;
}
static int snd_ad73311_resume(struct platform_device *pdev)
{
	struct snd_card *card = platform_get_drvdata(pdev);

	snd_power_change_state(card, SNDRV_CTL_POWER_D0);

	return 0;
}
#endif

static struct platform_driver snd_ad73311_driver = {
	.probe		= snd_ad73311_probe,
	.remove		= snd_ad73311_remove,
#ifdef CONFIG_PM
	.suspend	= snd_ad73311_suspend,
	.resume		= snd_ad73311_resume,
#endif
	.driver		= {
			.name = DRIVER_NAME,
	},
};

static int __init snd_ad73311_init(void)
{
	int err;

	if ((err = platform_driver_register(&snd_ad73311_driver))<0)
		return err;

	device = platform_device_register_simple(DRIVER_NAME, 0, NULL, 0);
	if (IS_ERR(device)) {
		err = PTR_ERR(device);
		platform_driver_unregister(&snd_ad73311_driver);
		return err;
	}
	
	return err;
}

static void __exit snd_ad73311_exit(void)
{
	platform_device_unregister(device);
	platform_driver_unregister(&snd_ad73311_driver);
}

MODULE_AUTHOR("Roy Huang <roy.huang@analog.com>");
MODULE_DESCRIPTION("Blackfin/ADI AD73311L");
MODULE_LICENSE("GPL");

module_init(snd_ad73311_init);
module_exit(snd_ad73311_exit);
