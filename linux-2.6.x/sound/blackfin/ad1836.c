/*
 * File:         ad1836.c 
 * Description:  driver for AD1836 sound chip connected to bf53x sport/spi
 * Rev:          $Id$
 * Created:      Tue Sep 21 10:52:42 CEST 2004
 * Author:       Luuk van Dijk <blackfin@mdnmttr.nl>
 * Modified by	 Roy Huang <roy.huang@analog.com>
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
 * credits: thanks to ADI for lending me the stamp & daugher boards
 *          thanks to Joep Duck for testing and useful comments
 *          Aidan Williams implemented CONFIG_BROKEN_PACKED_DMA and various fixes
 */

/*
 * Sonic Zhang (sonic.zhang@analog.com) solve the problem to record and play 
 * audio stream individually. The solution is based on the descriptor based DMA.
 * DMA and SPORT are always enabled.
 *
 * The macro CONFIG_BROKEN_PACKED_DMA is also removed, because current
 * implementation always transfer 8 channels in.
 */

/* notes: 
 * - once this code stabilizes, move the irq and dma stuff 
 *   into bf53x_spi.c and bf53x_sport.c
 * - the organisation of this file is as follows, in REVERSE order:
 *     * at the top level, the end of the file is the /module/
 *       it allocates the spi and sport, and probes for the /card/
 *     * the card allocates the /low-level device/, the /proc/, the /snd/ 
 *       and /mixer/ stuff
 *     * the /snd/ and /mixer/ stuff use the methods of the low level device
 *       to control the registers over the spi, and the methods of the sport
 * - there are useful proc entries for spi, sport and ad1836 register and irq 
 *   status. Since sash doesn't have redirection, you can use echo2 
 *    in the test/ directory. 
 *  - this can also be used to control the volume directly through setting
 *       the registers directly, eg.  echo2 /proc/asound/card0/registers 0x3000
 *       silences DAC_1_left
 *  - define/undef NOCONTROLS below to omit/include all the ALSA controls
 *    note that I have no idea if I chose the control names properly.
 *
 */

/* theory of operation:
 *
 *  the ad1836 is connected to the SPI and one of the SPORT ports.
 *  Over the spi, we send 16-bit commands that set the control
 *  registers.  since that is only 1 word at a time, and very rare, we
 *  do that non-dma, and we sleep until the spi irq handler wakes us
 *  up.
 *
 *  Over the sport we have 8 channel tdm pcm data, read/written by
 *  DMA.  the 8 channels correspond to pcm (dac0,1,2 and spdif) x
 *  (L,R) for output and pcm (adc0,1,spdif,unused) x (L,R) for input.
 *  The DMA operates in 2d autobuffer mode, with the outer loop
 *  counting the 'periods' (=ALSA term for what oss calls 'fragment')
 *  an irq is generated only once per period, (not once per frame like
 *  in the VSDP example)
 * 
 *  for 48khz and a relatively small fragment size of 16kb 
 *      = 512 samples/frame * 8 channels/sample * 4 bytes / channel
 *  that's an irq rate of 93hz, which is already quite affordable.
 * 
 *  the alsa device has 1 pcm that may be opened in 2,4,6 or 8 channel
 *  mode.  The DMA operates in 'packed' mode, which means that only
 *  enabled TDM channels are supposed to occur in the dma buffer.  to
 *  select which channels are enabled we use a configurable 'channel
 *  mask', that can be set through the /proc interface
 * 
 *  all knowledge from the bfin hwref guide has been encapsulated in
 *  separate files bf53x_sp{ort,i}.[hc]
 *
 *  Talkthrough mode support is removed.
 *
 * TODO: rething _prepare() and _trigger() to keep rx and tx out of eachothers way
 */

/* 1 AD1836 has 6 output channels, define them as 5.1 channels
 *	INTERNAL DAC L0:        Front Left (FL)
 *	INTERNAL DAC R0:        Front Right(FR)
 *	INTERNAL DAC L1:        Front Center(FC)
 *	INTERNAL DAC R1:        Low Frequency Effect(LFE)
 *	INTERNAL DAC L2:        Back Left (BL)
 *	INTERNAL DAC LR:        BACK Right(BR)
 *
 * 2 Assume multichannel wave data form
 *
 *	Channels 	  1    2     3   4    5   6
 *	stereo		| L  | R  |
 *
 *	3 Channels	| FL | FR | LFE|
 *	in 2.1
 *
 *	Quadraphonic	| FL | FR | BL | BR |

 *	5.1		| FL | FR | FC | LFE| BL |BR |

 *	out_chan_mask is also used to indicate location of audio.
 *	For expample 0x33 indicate Quadraphonic. DAC0 and DAC2 will be used to
 *     	    decode.
 *	when user play a 5.1 audio, the data will be put to DAC
 *	according to our definition.
 */
/*
 * There is a choice between 5.1 Channels mode or multiple substream mode. 
 * In multiple substream mode, 3 separate stereos are supported. 
 * /dev/dsp can be opened 3 times. Every time a new substream is opened.
 */

#include <linux/init.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/dma-mapping.h>
#include <linux/platform_device.h>
#include <asm/irq.h>
#include <asm/delay.h>

#include <sound/driver.h>
#include <sound/core.h>
#include <sound/info.h>
#include <sound/control.h>
#include <sound/pcm.h>
#define SNDRV_GET_ID
#include <sound/initval.h>

#include <asm/blackfin.h>
#include <asm/cacheflush.h>

#include "ad1836_spi.h"
#include "bf53x_sport.h"

#include "ad1836.h"

#if 0 == CONFIG_SND_BLACKFIN_SPORT
#define SPORT_DMA_RX CH_SPORT0_RX
#define SPORT_DMA_TX CH_SPORT0_TX
#define SPORT_IRQ_ERR IRQ_SPORT0_ERROR   /* periph irq 0 -> IVG 7 */
#else
#define SPORT_DMA_RX CH_SPORT1_RX
#define SPORT_DMA_TX CH_SPORT1_TX
#define SPORT_IRQ_ERR IRQ_SPORT1_ERROR
#endif

#ifndef CONFIG_BFIN_DMA_5XX
#error "The sound driver requires the Blackfin Simple DMA"
#endif

#ifdef CONFIG_SND_DEBUG
#define snd_printk_marker() snd_printk( KERN_INFO "%s\n", __FUNCTION__ )
#else
#define snd_printk_marker() 
#endif

/* When ADC2 works for Microphone, setting ADC2 in MUX/PGA mode.
 * Setting J12 on AD1836 daughter card to 1-3 & 2-4. If undefine 
 * ADC2_IS_MIC, setting J9 and J10  to 1-3 & 2-4, adc2 will work
 * as line in, just the same as ADC1.
 */
#define ADC2_IS_MIC

#ifdef CONFIG_SND_BLACKFIN_AD1836_I2S
#undef ADC2_IS_MIC
#endif

#undef CONFIG_SND_DEBUG_CURRPTR  /* causes output every frame! */
//#define CONFIG_SND_DEBUG_CURRPTR

#undef NOCONTROLS  /* define this to omit all the ALSA controls */

#ifdef CONFIG_SND_BLACKFIN_AD1836_MULSUB
#define MULTI_SUBSTREAM
#endif

#define DRIVER_NAME	"snd_ad1836"
#define CHIP_NAME	"AD1836"
#define PCM_NAME	"AD1836_PCM"

/* Only one AD1836 soundcard is supported */
static struct platform_device *device = NULL;
static struct ad1836_spi *ad1836_spi = NULL;
/* Chip level */
#ifdef CONFIG_SND_BLACKFIN_AD1836_TDM

#define AD1836_BUF_SZ 0x40000 /* 256kb */
/*In 2 channels mode, the buffer is quadrupled */
#define PCM_BUFFER_MAX	(AD1836_BUF_SZ / 4)
#define CHANNELS_MAX	8
#define CHANNELS_OUTPUT	6
#define CHANNELS_INPUT	4
#define FRAGMENT_SIZE_MIN	(4*1024)
#define FRAGMENTS_MIN	2	
#define FRAGMENTS_MAX	32

#elif defined(CONFIG_SND_BLACKFIN_AD1836_I2S)

#define AD1836_BUF_SZ 0x10000 /* 64kb */
#define PCM_BUFFER_MAX	AD1836_BUF_SZ
#define CHANNELS_MAX	2
#define CHANNELS_OUTPUT	2
#define CHANNELS_INPUT	2
#define FRAGMENT_SIZE_MIN	(1024)
#define FRAGMENTS_MIN	4
#define FRAGMENTS_MAX	32

#else
#error "An transfer mode must be choosed for audio"
#endif

#ifdef MULTI_SUBSTREAM
#define DMA_BUFFER_BYTES	AD1836_BUF_SZ
#define DMA_PERIOD_BYTES	(FRAGMENT_SIZE_MIN * 4)
#define DMA_PERIODS		(DMA_BUFFER_BYTES / DMA_PERIOD_BYTES)
#define DMA_FRAME_BYTES		32
#define DMA_BUFFER_FRAMES	(DMA_BUFFER_BYTES/DMA_FRAME_BYTES)
#define DMA_PERIOD_FRAMES	(DMA_PERIOD_BYTES/DMA_FRAME_BYTES)
#undef  CHANNELS_MAX
#define CHANNELS_MAX	2
#endif

#ifdef CONFIG_SND_BLACKFIN_AD1836_TDM
#ifdef CONFIG_SND_BLACKFIN_AD1836_5P1
static unsigned int out_chan_masks[] = {
	SP_FL, /* Mono */
	SP_STEREO, /* Stereo */
	SP_2DOT1, /* 2.1*/
	SP_QUAD,/*Quadraquic*/
	SP_FL | SP_FR | SP_FC | SP_BL | SP_BR,/*5 channels */
	SP_5DOT1, /* 5.1 */
	0,
	SPDIF_OUT_LEFT | SPDIF_OUT_RIGHT};
#endif

static unsigned int in_chan_masks[] = {CAP_LINE, CAP_MIC|CAP_LINE, CAP_SPDIF};
#endif

#ifdef MULTI_SUBSTREAM
typedef struct {
	snd_pcm_substream_t*	substream;
	snd_pcm_uframes_t	dma_offset;
	snd_pcm_uframes_t	buffer_frames;
	snd_pcm_uframes_t	period_frames;
	unsigned int		periods;
	unsigned int		frame_bytes;
	/* Information about DMA */
	snd_pcm_uframes_t	dma_inter_pos;
	snd_pcm_uframes_t	dma_last_pos;
	snd_pcm_uframes_t	dma_pos_base;
	/* Information on virtual buffer */
	snd_pcm_uframes_t	next_inter_pos;
	snd_pcm_uframes_t	data_count;
	snd_pcm_uframes_t	data_pos_base;
	snd_pcm_uframes_t	boundary;
} substream_info_t;
#endif

typedef struct snd_ad1836 ad1836_t;
struct snd_ad1836 {

	struct snd_card*         card;
	struct ad1836_spi*   spi;
	struct bf53x_sport* sport;
	spinlock_t    ad1836_lock;

	struct snd_pcm* pcm;

#ifdef CONFIG_SND_BLACKFIN_AD1836_TDM
	/* define correspondence of alsa channels to ad1836 channels */
	unsigned int out_chan_mask;
	unsigned int in_chan_mask;
#endif

	wait_queue_head_t   spi_waitq;
	uint16_t chip_registers[16];
	int      poll_reg;  /* index of the ad1836 register last queried */

	/* if non-null, current subtream running */
	snd_pcm_substream_t* rx_substream;  
#ifdef MULTI_SUBSTREAM
	int	tx_dma_started;
	int	tx_status;
#define RUN_TX0 0x1
#define RUN_TX1 0x2
#define RUN_TX2 0x4
#define RUN_TX_ALL (RUN_TX0 | RUN_TX1 | RUN_TX2)

	/* Allocate dma buffer by driver instead of ALSA */
	unsigned char* rx_dma_buf;
	unsigned char* tx_dma_buf;
	snd_pcm_uframes_t	dma_pos;
	snd_pcm_uframes_t	dma_offset[3];
	substream_info_t	tx_substreams[3];
#else
	/* if non-null, current subtream running */
	snd_pcm_substream_t* tx_substream;  
#endif

};

#ifdef MULTI_SUBSTREAM
static inline int find_substream(ad1836_t *chip,
		snd_pcm_substream_t *substream,	substream_info_t **info)
{
	if (chip->tx_substreams[0].substream == substream) {
		*info = &chip->tx_substreams[0];
		return 0;
	} else if (chip->tx_substreams[1].substream == substream) {
		*info = &chip->tx_substreams[1];
		return 1;
	} else if (chip->tx_substreams[2].substream == substream) {
		*info = &chip->tx_substreams[2];
		return 2;
	} else {
		*info = NULL;
		return -1;
	}
}
#endif

static int snd_ad1836_set_register(ad1836_t *chip, unsigned int reg, 
				unsigned int mask, unsigned int value)
{

	unsigned short data = (chip->chip_registers[reg] & ~mask) | \
						(value & mask);

	/*  snd_printk( KERN_INFO "spi set reg %d = 0x%04x\n", reg, data); */
	ad1836_spi_write(chip->spi, data);
	chip->chip_registers[reg] = data;

	return 0;
}

static void snd_ad1836_read_registers(ad1836_t *chip)
{
	int i;

	for (i = ADC_PEAK_1L; i <= ADC_PEAK_2R; i++) { 
		chip->poll_reg = i;
		ad1836_spi_read(chip->spi, (chip->poll_reg<<12) | \
					ADC_READ, &chip->chip_registers[i]);
	}
}

/*************************************************************
 *          controls 
 *************************************************************/

#ifndef NOCONTROLS

static int snd_ad1836_volume_info(snd_kcontrol_t *kcontrol, 
						snd_ctl_elem_info_t *uinfo)
{
	uinfo->type = SNDRV_CTL_ELEM_TYPE_INTEGER;
	uinfo->count = CHANNELS_OUTPUT;
	uinfo->value.integer.min = 0;
	uinfo->value.integer.max = 1023;
	return 0;
}


static int snd_ad1836_volume_get(snd_kcontrol_t *kcontrol, 
					snd_ctl_elem_value_t *ucontrol)
{
	ad1836_t *chip = snd_kcontrol_chip(kcontrol);
	int i;
	for(i=0;i<CHANNELS_OUTPUT;++i)
		ucontrol->value.integer.value[i] = 
			chip->chip_registers[DAC_VOL_1L+i] & DAC_VOL_MASK;
	return 0;
}


static int snd_ad1836_volume_put(snd_kcontrol_t *kcontrol, 
					snd_ctl_elem_value_t *ucontrol)
{

	ad1836_t *chip = snd_kcontrol_chip(kcontrol);
	int change=0;
	int i;

	for(i=0;i<CHANNELS_OUTPUT;++i){
		int vol  = ucontrol->value.integer.value[i];
		if (vol < 0) vol = 0; if (vol > 1023) vol = 1023;
		if((chip->chip_registers[DAC_VOL_1L+i] & DAC_VOL_MASK) != vol){
			change = 1;
			snd_ad1836_set_register(chip, DAC_VOL_1L+i, 
							DAC_VOL_MASK, vol);
		}
	}

	return change;
}

#ifdef ADC2_IS_MIC
static int snd_ad1836_adc_gain_info(snd_kcontrol_t *kcontrol, 
						snd_ctl_elem_info_t *uinfo)
{
	uinfo->type = SNDRV_CTL_ELEM_TYPE_INTEGER;
	uinfo->count = 2;
	uinfo->value.integer.min = 0;
	uinfo->value.integer.max = 4;
	return 0;
}

static int snd_ad1836_adc_gain_get(snd_kcontrol_t *kcontrol, 
						snd_ctl_elem_value_t *ucontrol)
{
	ad1836_t *chip = snd_kcontrol_chip(kcontrol);
	ucontrol->value.integer.value[0] = ADC_GAIN_LEFT( chip->chip_registers[ADC_CTRL_1]);
	ucontrol->value.integer.value[1] = ADC_GAIN_RIGHT(chip->chip_registers[ADC_CTRL_1]);
	return 0;
}

static int snd_ad1836_adc_gain_put(snd_kcontrol_t *kcontrol, 
					snd_ctl_elem_value_t *ucontrol)
{

	ad1836_t *chip = snd_kcontrol_chip(kcontrol);
	int change=0;

	int curr   = chip->chip_registers[ADC_CTRL_1];
	int left   = ucontrol->value.integer.value[0];
	int right  = ucontrol->value.integer.value[1];

	if( (ADC_GAIN_LEFT(curr)) != left ){
		change = 1;
		curr &= ~ ADC_GAIN_LEFT_MASK;
		curr |= (left << ADC_GAIN_LEFT_SHIFT) & ADC_GAIN_LEFT_MASK;
	}

	if( (ADC_GAIN_RIGHT(curr)) != right ){
		change = 1;
		curr &= ~ ADC_GAIN_RIGHT_MASK;
		curr |= (right) & ADC_GAIN_RIGHT_MASK;
	}

	if(change) 
		snd_ad1836_set_register(chip, ADC_CTRL_1, \
				ADC_GAIN_LEFT_MASK|ADC_GAIN_RIGHT_MASK, curr);

	return change;
}
#endif

static int snd_ad1836_playback_mute_info(snd_kcontrol_t *kcontrol, 
						snd_ctl_elem_info_t *uinfo)
{
	uinfo->type = SNDRV_CTL_ELEM_TYPE_BOOLEAN;
	uinfo->count = CHANNELS_OUTPUT;
	uinfo->value.integer.min = 0;
	uinfo->value.integer.max = 1;
	return 0;
}

static int snd_ad1836_playback_mute_get(snd_kcontrol_t *kcontrol, 
						snd_ctl_elem_value_t *ucontrol)
{
	ad1836_t *chip = snd_kcontrol_chip(kcontrol);
	int i;
	for(i=0;i<CHANNELS_OUTPUT;++i)
		ucontrol->value.integer.value[i] = 
			(chip->chip_registers[DAC_CTRL_2] & ( 1 << i )) ? 0:1;
	return 0;
}

static int snd_ad1836_playback_mute_put(snd_kcontrol_t *kcontrol,
					snd_ctl_elem_value_t *ucontrol)
{

	ad1836_t *chip = snd_kcontrol_chip(kcontrol);
	int curr =  chip->chip_registers[DAC_CTRL_2] &  DAC_MUTE_MASK ;
	int mute = 0;
	int i;

	for(i=0;i<CHANNELS_OUTPUT;++i)
		if( !ucontrol->value.integer.value[i] )
			mute |= (1<<i);

	if( curr != mute ){
		snd_ad1836_set_register(chip, DAC_CTRL_2, DAC_MUTE_MASK, mute);
		return 1;
	}

	return 0;
}


static int snd_ad1836_capture_mute_info(snd_kcontrol_t *kcontrol,
						snd_ctl_elem_info_t *uinfo)
{
	uinfo->type = SNDRV_CTL_ELEM_TYPE_BOOLEAN;
	uinfo->count = CHANNELS_INPUT;
	uinfo->value.integer.min = 0;
	uinfo->value.integer.max = 1;
	return 0;
}

static int snd_ad1836_capture_mute_get(snd_kcontrol_t *kcontrol,
					snd_ctl_elem_value_t *ucontrol)
{
	ad1836_t *chip = snd_kcontrol_chip(kcontrol);
	int i;
	for(i=0;i<CHANNELS_INPUT;++i)
		ucontrol->value.integer.value[i] = 
			(chip->chip_registers[ADC_CTRL_2] & ( 1 << i )) ? 1:0;
	return 0;
}

static int snd_ad1836_capture_mute_put(snd_kcontrol_t *kcontrol,
					snd_ctl_elem_value_t *ucontrol)
{

	ad1836_t *chip = snd_kcontrol_chip(kcontrol);
	int curr =  chip->chip_registers[ADC_CTRL_2] &  ADC_MUTE_MASK ;
	int mute = 0;
	int i;

	for(i=0;i<CHANNELS_INPUT;++i)
		if( ucontrol->value.integer.value[i] )
			mute |= (1<<i);

	if( curr != mute ){
		snd_ad1836_set_register(chip, ADC_CTRL_2, ADC_MUTE_MASK, mute);
		return 1;
	}

	return 0;

}

static int snd_ad1836_deemph_info(snd_kcontrol_t *kcontrol,
						snd_ctl_elem_info_t *uinfo)
{
	static const char* names[] = { "Off", "44.1kHz", "32kHz", "48kHz" };
	uinfo->type = SNDRV_CTL_ELEM_TYPE_ENUMERATED;
	uinfo->count = 1;
	if (uinfo->value.enumerated.item > 3)
		uinfo->value.enumerated.item = 3;
	strcpy(uinfo->value.enumerated.name, names[uinfo->value.enumerated.item]);
	return 0;  
}

static int snd_ad1836_deemph_get(snd_kcontrol_t *kcontrol, 
						snd_ctl_elem_value_t *ucontrol)
{
	ad1836_t *chip = snd_kcontrol_chip(kcontrol);
	ucontrol->value.enumerated.item[0] = 
			DAC_DEEMPH_VALUE( chip->chip_registers[DAC_CTRL_1] );
	return 0;
}

static int snd_ad1836_deemph_put(snd_kcontrol_t *kcontrol,
						snd_ctl_elem_value_t *ucontrol)
{

	ad1836_t *chip = snd_kcontrol_chip(kcontrol);
	if( ucontrol->value.enumerated.item[0] != 
			DAC_DEEMPH_VALUE( chip->chip_registers[DAC_CTRL_1]) ){
		snd_ad1836_set_register(chip, DAC_CTRL_1, DAC_DEEMPH_MASK, 
			ucontrol->value.enumerated.item[0] << DAC_DEEMPH_SHIFT);
		return 1;
	}
	return 0;

}

static int snd_ad1836_filter_info(snd_kcontrol_t *kcontrol,
						snd_ctl_elem_info_t *uinfo)
{
	uinfo->type = SNDRV_CTL_ELEM_TYPE_BOOLEAN;
	uinfo->count = 1;
	uinfo->value.integer.min = 0;
	uinfo->value.integer.max = 1;
	return 0;
}

static int snd_ad1836_filter_get(snd_kcontrol_t *kcontrol,
						snd_ctl_elem_value_t *ucontrol)
{
	ad1836_t *chip = snd_kcontrol_chip(kcontrol);
	ucontrol->value.integer.value[0] = 
			(chip->chip_registers[ADC_CTRL_1] & ADC_HIGHPASS) ? 1:0;
	return 0;
}

static int snd_ad1836_filter_put(snd_kcontrol_t *kcontrol,
						snd_ctl_elem_value_t *ucontrol)
{
	ad1836_t *chip = snd_kcontrol_chip(kcontrol);
	if( ucontrol->value.integer.value[0] != ((chip->chip_registers\
				[ADC_CTRL_1] & ADC_HIGHPASS) ? 1:0) ){
		snd_ad1836_set_register(chip, ADC_CTRL_1, ADC_HIGHPASS,
			(ucontrol->value.integer.value[0]?ADC_HIGHPASS:0) );
		return 1;
	}
	return 0;
}


static int snd_ad1836_diffip_info(snd_kcontrol_t *kcontrol,
						snd_ctl_elem_info_t *uinfo)
{
	uinfo->type = SNDRV_CTL_ELEM_TYPE_BOOLEAN;
	uinfo->count = 2;
	uinfo->value.integer.min = 0;
	uinfo->value.integer.max = 1;
	return 0;
}

static int snd_ad1836_diffip_get(snd_kcontrol_t *kcontrol,
						snd_ctl_elem_value_t *ucontrol)
{
	ad1836_t *chip = snd_kcontrol_chip(kcontrol);
	ucontrol->value.integer.value[0] = 
			(chip->chip_registers[ADC_CTRL_3] & ADC_LEFT_SE ) ? 1:0;
	ucontrol->value.integer.value[1] =
			(chip->chip_registers[ADC_CTRL_3] & ADC_RIGHT_SE) ? 1:0;
	return 0;
}

static int snd_ad1836_diffip_put(snd_kcontrol_t *kcontrol,
						snd_ctl_elem_value_t *ucontrol)
{
	ad1836_t *chip = snd_kcontrol_chip(kcontrol);
	int change = 0;

	if( ucontrol->value.integer.value[0] != ((chip->chip_registers[\
					ADC_CTRL_3] & ADC_LEFT_SE ) ? 1:0) )
		change = 1;
	if( ucontrol->value.integer.value[0] != ((chip->chip_registers[\
					ADC_CTRL_3] & ADC_RIGHT_SE ) ? 1:0) )
		change = 1;
	if( change ){
		int val  = ucontrol->value.integer.value[0] ? ADC_LEFT_SE : 0;
		val |= ucontrol->value.integer.value[1] ? ADC_RIGHT_SE : 0;
		snd_ad1836_set_register(chip, ADC_CTRL_3,
					ADC_LEFT_SE|ADC_RIGHT_SE, val );
	}
	return change;
}

#ifdef CONFIG_SND_BLACKFIN_AD1836_TDM

#define CAPTURE_SOURCE_NUMBER 2

static int snd_ad1836_mux_info(snd_kcontrol_t *kcontrol, 
					snd_ctl_elem_info_t *uinfo)
{
	static char *texts[CAPTURE_SOURCE_NUMBER] = {
		"Line", "Mic"
	};

	uinfo->type = SNDRV_CTL_ELEM_TYPE_ENUMERATED;
	uinfo->count = 1;
	uinfo->value.enumerated.items = CAPTURE_SOURCE_NUMBER;
	if (uinfo->value.enumerated.item >= CAPTURE_SOURCE_NUMBER)
		uinfo->value.enumerated.item = CAPTURE_SOURCE_NUMBER - 1;
	strcpy(uinfo->value.enumerated.name, texts[uinfo->value.enumerated.item]);
	return 0;
}

static int snd_ad1836_mux_get(snd_kcontrol_t *kcontrol,
					snd_ctl_elem_value_t *ucontrol)
{
	ad1836_t *chip = snd_kcontrol_chip(kcontrol);

	if (chip->in_chan_mask & CAP_MIC)
		ucontrol->value.integer.value[0] = 1;
	else
		ucontrol->value.integer.value[0] = 0;

	return 0;
}

static int snd_ad1836_mux_put(snd_kcontrol_t *kcontrol,
					snd_ctl_elem_value_t *ucontrol)
{
	ad1836_t *chip = snd_kcontrol_chip(kcontrol);
	int i;

	i = ucontrol->value.integer.value[0];
	if (i==0) /* Select Line */
		chip->in_chan_mask = CAP_LINE;
	else if(i==1) /* Select Mic */
		chip->in_chan_mask = CAP_MIC;

	return 1;
}

#define OUTPUT_NUMBER 3
static int snd_ad1836_playback_sel_info(snd_kcontrol_t *kcontrol,	
						snd_ctl_elem_info_t *uinfo)
{
	static char *texts[OUTPUT_NUMBER] = {"Line", "Black", "Orange"};

	uinfo->type = SNDRV_CTL_ELEM_TYPE_ENUMERATED;
	uinfo->count = 1;
	uinfo->value.enumerated.items = 3;
	if (uinfo->value.enumerated.item >= OUTPUT_NUMBER)
		uinfo->value.enumerated.item = OUTPUT_NUMBER - 1;
	strcpy(uinfo->value.enumerated.name, texts[uinfo->value.enumerated.item]);
	return 0;
}

static int snd_ad1836_playback_sel_get(snd_kcontrol_t *kcontrol,
					snd_ctl_elem_value_t *ucontrol)
{
	ad1836_t *chip = snd_kcontrol_chip(kcontrol);

	if (chip->out_chan_mask & (DAC0_LEFT | DAC0_RIGHT))
		ucontrol->value.enumerated.item[0] = 0;
	if (chip->out_chan_mask & (DAC1_LEFT | DAC1_RIGHT))
		ucontrol->value.enumerated.item[0] = 1;
	if (chip->out_chan_mask & (DAC2_LEFT | DAC2_RIGHT))
		ucontrol->value.enumerated.item[0] = 2;

	return 0;
}

static int snd_ad1836_playback_sel_put(snd_kcontrol_t *kcontrol,
					snd_ctl_elem_value_t *ucontrol)
{
	ad1836_t *chip = snd_kcontrol_chip(kcontrol);

	if (ucontrol->value.enumerated.item[0] >= OUTPUT_NUMBER )
		return -EINVAL;

	chip->out_chan_mask = 0;
	if (ucontrol->value.enumerated.item[0] == 0)
		chip->out_chan_mask = (DAC0_LEFT | DAC0_RIGHT);
	if (ucontrol->value.enumerated.item[0] == 1)
		chip->out_chan_mask = (DAC1_LEFT | DAC1_RIGHT);
	if (ucontrol->value.enumerated.item[0] == 2)
		chip->out_chan_mask = (DAC2_LEFT | DAC2_RIGHT);

	return 1;
}
#endif

static int snd_ad1836_vu_info(snd_kcontrol_t *kcontrol,
						snd_ctl_elem_info_t *uinfo)
{
	uinfo->type = SNDRV_CTL_ELEM_TYPE_INTEGER;
	uinfo->count = CHANNELS_INPUT;
	uinfo->value.integer.min = -60;
	uinfo->value.integer.max = 0;
	return 0;
}


static int snd_ad1836_vu_get(snd_kcontrol_t *kcontrol,
					snd_ctl_elem_value_t *ucontrol)
{
	ad1836_t *chip = snd_kcontrol_chip(kcontrol);
	int i;
	for(i=0;i<CHANNELS_INPUT;++i)
		ucontrol->value.integer.value[i] =
			ADC_PEAK_VALUE( chip->chip_registers[ADC_PEAK_1L + i] );
	return 0;
}

static int snd_ad1836_vu_put(snd_kcontrol_t *kcontrol, snd_ctl_elem_value_t *ucontrol){ return 0; }


#define KTRL( xiface, xname, xaccess, xfuncbase ) \
{ .iface = SNDRV_CTL_ELEM_IFACE_ ## xiface, .name  = xname, .index = 0, .access = xaccess, \
	.info  = xfuncbase ## _info, .get  = xfuncbase ## _get, .put  = xfuncbase ## _put, } 

#define KTRLRW( xiface, xname, xfuncbase ) \
	KTRL( xiface, xname, SNDRV_CTL_ELEM_ACCESS_READWRITE, xfuncbase ) 
#define KTRLRO( xiface, xname, xfuncbase )  \
	KTRL( xiface, xname, (SNDRV_CTL_ELEM_ACCESS_READ | \
	SNDRV_CTL_ELEM_ACCESS_VOLATILE), xfuncbase )

/* NOTE: I have no idea if I chose the .name fields properly.. */

static snd_kcontrol_new_t snd_ad1836_controls[] __devinitdata = { 
	KTRLRW( MIXER, "Master Playback Volume",   snd_ad1836_volume ),
#ifdef ADC2_IS_MIC
	KTRLRW( MIXER, "Mic Capture Volume",    snd_ad1836_adc_gain ),
#endif
	KTRLRW( MIXER, "Master Playback Switch",   snd_ad1836_playback_mute ),
	KTRLRW( MIXER, "Master Capture Switch",    snd_ad1836_capture_mute ),
	KTRLRW( MIXER, "Tone Contol DAC De-emphasis Switch", snd_ad1836_deemph ),
	KTRLRW( MIXER, "Tone Contol ADC High-pass Filter Switch", snd_ad1836_filter ),
	/* note: off = differential, on = single ended */
	KTRLRW( MIXER, "PCM Capture Differential Switch", snd_ad1836_diffip ),
#ifdef CONFIG_SND_BLACKFIN_AD1836_TDM
	KTRLRW( MIXER, "Capture Source",   snd_ad1836_mux ),
	KTRLRW( MIXER, "PCM Playback Route",   snd_ad1836_playback_sel ),
#endif
	KTRLRO( PCM,   "PCM Capture VU",           snd_ad1836_vu ),
};

#undef KTRL
#undef KTRLRW
#undef KTRLRO

#define AD1836_CONTROLS (sizeof(snd_ad1836_controls)/sizeof(snd_ad1836_controls[0]))

#endif /* ndef NOCONTROLS */


/*************************************************************
 *                pcm methods 
 *************************************************************/

static snd_pcm_hardware_t snd_ad1836_playback_hw = {
	.info = (SNDRV_PCM_INFO_MMAP | SNDRV_PCM_INFO_INTERLEAVED | \
			SNDRV_PCM_INFO_BLOCK_TRANSFER | \
			SNDRV_PCM_INFO_MMAP_VALID),
	.formats =          SNDRV_PCM_FMTBIT_S32_LE,
	.rates =            SNDRV_PCM_RATE_48000,
	.rate_min =         48000,
	.rate_max =         48000,
	.channels_min =     2,
	.channels_max =     CHANNELS_MAX,
	.buffer_bytes_max = PCM_BUFFER_MAX,
	.period_bytes_min = FRAGMENT_SIZE_MIN,
	.period_bytes_max = PCM_BUFFER_MAX/2,
	.periods_min =      FRAGMENTS_MIN,
	.periods_max =      FRAGMENTS_MAX,
};

static snd_pcm_hardware_t snd_ad1836_capture_hw = {
	.info = (SNDRV_PCM_INFO_MMAP | SNDRV_PCM_INFO_INTERLEAVED | \
			SNDRV_PCM_INFO_BLOCK_TRANSFER | \
			SNDRV_PCM_INFO_MMAP_VALID),
	.formats =          SNDRV_PCM_FMTBIT_S32_LE,
	.rates =            SNDRV_PCM_RATE_48000,
	.rate_min =         48000,
	.rate_max =         48000,
	.channels_min =     2,
	.channels_max =     CHANNELS_MAX,
	.buffer_bytes_max = PCM_BUFFER_MAX,
	.period_bytes_min = FRAGMENT_SIZE_MIN,
	.period_bytes_max = PCM_BUFFER_MAX/2,
	.periods_min =      FRAGMENTS_MIN,
	.periods_max =      FRAGMENTS_MAX,
};

static int snd_ad1836_playback_open(snd_pcm_substream_t* substream)
{
	ad1836_t* chip = snd_pcm_substream_chip(substream);

	snd_printk_marker();
#ifdef MULTI_SUBSTREAM
	{
		substream_info_t *sub_info = NULL;
		int index = find_substream(chip, NULL, &sub_info);

		if (index >= 0 && index <= 2 && sub_info) {
			sub_info->substream = substream;
		} else
			return -EBUSY;
	}
#else
	chip->tx_substream = substream;
#endif
	substream->runtime->hw = snd_ad1836_playback_hw;

	return 0;

}

static int snd_ad1836_capture_open(snd_pcm_substream_t* substream)
{
	ad1836_t* chip = snd_pcm_substream_chip(substream);

	snd_printk_marker();
	substream->runtime->hw = snd_ad1836_capture_hw;
	chip->rx_substream = substream;

	return 0;
}

static int snd_ad1836_playback_close(snd_pcm_substream_t* substream)
{
	ad1836_t* chip = snd_pcm_substream_chip(substream);

#ifdef MULTI_SUBSTREAM
	substream_info_t *sub_info = NULL;
	int index = find_substream(chip, substream, &sub_info);
	int i;

	snd_printd("%s, index:%d\n", __FUNCTION__, index);
	if ( index>= 0 && index <= 2) {
		sub_info->substream = NULL;
		for (i=0; i < DMA_BUFFER_FRAMES; i++) {
			*((unsigned int*)chip->tx_dma_buf+i*8 + index) = 0;
			*((unsigned int*)chip->tx_dma_buf+i*8 + index + 4) = 0;
		}
	}
#else
	chip->tx_substream = NULL;
#endif

	return 0;
}


static int snd_ad1836_capture_close(snd_pcm_substream_t* substream)
{
	ad1836_t* chip = snd_pcm_substream_chip(substream);

	snd_printk_marker();
	chip->rx_substream = NULL;

	return 0;
}

static int snd_ad1836_hw_params( snd_pcm_substream_t* substream,
					snd_pcm_hw_params_t* hwparams)
{
	/*
	 *  Allocate all available memory for our DMA buffer.
	 *  Necessary because we get a 4x increase in bytes for the 2 channel mode.
	 *  (we lie to the ALSA midlayer through the hwparams data)
	 *  We're relying on the driver not supporting full duplex mode
	 *  to allow us to grab all the memory.
	 */
#ifdef CONFIG_SND_BLACKFIN_AD1836_TDM   

#ifdef MULTI_SUBSTREAM
	substream_info_t *sub_info = NULL;
	ad1836_t *chip = snd_pcm_substream_chip(substream);
	int index = find_substream(chip, substream, &sub_info);

	if (chip->rx_substream == substream) {
		substream->runtime->dma_area = chip->rx_dma_buf;
		substream->runtime->dma_addr = (unsigned int)chip->rx_dma_buf;
		substream->runtime->dma_bytes = AD1836_BUF_SZ;
	} else if (index >= 0) {
		substream->runtime->dma_area = chip->tx_dma_buf;
		substream->runtime->dma_addr = (unsigned int)chip->tx_dma_buf;
		substream->runtime->dma_bytes = AD1836_BUF_SZ;
	}

#else
	if( snd_pcm_lib_malloc_pages(substream, AD1836_BUF_SZ) < 0 )
		return -ENOMEM;
#endif 

#else
	if( snd_pcm_lib_malloc_pages(substream, params_buffer_bytes(hwparams)) < 0 )
		return -ENOMEM;
#endif

	return 0;

}

static int snd_ad1836_hw_free(snd_pcm_substream_t * substream)
{
	snd_printk_marker();
#ifdef MULTI_SUBSTREAM
	substream->runtime->dma_area = NULL;
	substream->runtime->dma_addr = 0;
	substream->runtime->dma_bytes = 0;
#else
	snd_pcm_lib_free_pages(substream);
#endif
	return 0;
}

static int snd_ad1836_playback_prepare( snd_pcm_substream_t* substream )
{

	ad1836_t* chip = snd_pcm_substream_chip(substream);
	snd_pcm_runtime_t* runtime = substream->runtime;

#ifndef MULTI_SUBSTREAM
	int  fragsize_bytes = frames_to_bytes(runtime, runtime->period_size);
#endif
	int err=0;

#ifdef MULTI_SUBSTREAM
	substream_info_t *sub_info = NULL;
	int index = find_substream(chip, substream, &sub_info);

	snd_assert((index >= 0 && index <=2 && sub_info), return -EINVAL);

	sub_info->period_frames = runtime->period_size;
	sub_info->periods = runtime->periods;
	sub_info->buffer_frames = runtime->buffer_size;
	sub_info->frame_bytes = runtime->frame_bits / 8;
	sub_info->dma_inter_pos = 0;
	sub_info->dma_last_pos = 0;
	sub_info->dma_pos_base = 0;

	sub_info->next_inter_pos = sub_info->period_frames;
	sub_info->data_count = 0;
	sub_info->data_pos_base = 0;
	sub_info->boundary = DMA_BUFFER_FRAMES * sub_info->buffer_frames;

	while(sub_info->boundary * 2 <= (LONG_MAX - DMA_BUFFER_FRAMES * \
			sub_info->buffer_frames)) {
		sub_info->boundary *= 2;
	}
	sub_info->dma_offset = 0;
#else
	snd_assert( (substream == chip->tx_substream), return -EINVAL );
#endif

	snd_printk_marker();
	snd_printd(KERN_INFO "%s channels:%d, period_bytes:0x%x, periods:%d\n",
			__FUNCTION__, runtime->channels,
			frames_to_bytes(runtime, runtime->period_size),
			runtime->periods);
#ifndef MULTI_SUBSTREAM
#ifdef CONFIG_SND_BLACKFIN_AD1836_TDM
	fragsize_bytes /= runtime->channels;
	fragsize_bytes *= 8;/* inflate the fragsize to match */
#endif

	err = bf53x_sport_config_tx_dma( chip->sport, runtime->dma_area, 
			runtime->periods, fragsize_bytes, 4);
#endif

	return err;
}

static int snd_ad1836_capture_prepare( snd_pcm_substream_t* substream )
{

	ad1836_t* chip = snd_pcm_substream_chip(substream);
	snd_pcm_runtime_t* runtime = substream->runtime;

	void* buf_addr      = (void*) runtime->dma_area;
	int  fragcount      = runtime->periods;
	int  fragsize_bytes = frames_to_bytes(runtime, runtime->period_size);
	int err=0;

	snd_printk_marker();
	snd_assert( (substream == chip->rx_substream), return -EINVAL );

	snd_printd(KERN_INFO "%s channels:%d, fragsize_bytes:%d, frag_count:%d\n",
			__FUNCTION__, runtime->channels, fragsize_bytes, fragcount);
#ifdef CONFIG_SND_BLACKFIN_AD1836_TDM
	fragsize_bytes /= runtime->channels;
	fragsize_bytes *= 8; /* inflate the fragsize to match */
#endif

	err = bf53x_sport_config_rx_dma( chip->sport, buf_addr , fragcount, 
			fragsize_bytes, 4);

	return err;
}

static int snd_ad1836_playback_trigger( snd_pcm_substream_t* substream, int cmd)
{

	ad1836_t* chip = snd_pcm_substream_chip(substream);
#ifdef MULTI_SUBSTREAM
	substream_info_t *sub_info = NULL;
	int index = find_substream(chip, substream, &sub_info);
	snd_assert((index >= 0 && index <= 2 && sub_info), return -EINVAL);
#endif

	spin_lock(&chip->ad1836_lock);
	switch(cmd){
	case SNDRV_PCM_TRIGGER_START: 
#ifdef MULTI_SUBSTREAM
		if (!chip->tx_dma_started) {
			chip->dma_pos = 0;
			bf53x_sport_tx_start(chip->sport);
			chip->tx_dma_started = 1;
		}
		sub_info->dma_offset = chip->dma_pos;
		chip->tx_status |= (1 << index);
#else    
		bf53x_sport_tx_start(chip->sport);
#endif
		break;
	case SNDRV_PCM_TRIGGER_STOP:
#ifdef MULTI_SUBSTREAM
		chip->tx_status &= ~ (1 << index);
		if (!(chip->tx_status & RUN_TX_ALL)) {
			chip->tx_dma_started = 0;
			bf53x_sport_tx_stop(chip->sport);
		}
#else
		bf53x_sport_tx_stop(chip->sport);
#endif
		break;
	default:
		spin_unlock(&chip->ad1836_lock);
		return -EINVAL;
	}
	spin_unlock(&chip->ad1836_lock);

	snd_printd(KERN_INFO"playback cmd:%s\n", cmd?"start":"stop");

	return 0;
}

static int snd_ad1836_capture_trigger( snd_pcm_substream_t* substream, int cmd)
{

	ad1836_t* chip = snd_pcm_substream_chip(substream);

	spin_lock(&chip->ad1836_lock);
	snd_assert(substream == chip->rx_substream, return -EINVAL);
	switch(cmd){
	case SNDRV_PCM_TRIGGER_START: 
		bf53x_sport_rx_start(chip->sport);
		break;
	case SNDRV_PCM_TRIGGER_STOP:
		bf53x_sport_rx_stop(chip->sport);
		break;
	default:
		spin_unlock(&chip->ad1836_lock);
		return -EINVAL;
	}
	spin_unlock(&chip->ad1836_lock);

	snd_printd(KERN_ERR"capture cmd:%s\n", cmd?"start":"stop"); 
	return 0;
}

static snd_pcm_uframes_t snd_ad1836_playback_pointer( snd_pcm_substream_t* substream )
{
	ad1836_t* chip = snd_pcm_substream_chip(substream);
#ifdef MULTI_SUBSTREAM
	substream_info_t *sub_info = NULL;
#endif

#ifndef MULTI_SUBSTREAM
	snd_pcm_runtime_t* runtime = substream->runtime;
#endif
	unsigned long diff = bf53x_sport_curr_offset_tx(chip->sport);
#ifdef CONFIG_SND_BLACKFIN_AD1836_TDM
	unsigned long bytes_per_frame = 8*4;	/* always 8 channels in the DMA frame */
#else
	unsigned long bytes_per_frame = runtime->frame_bits/8;
#endif
	size_t frames = diff / bytes_per_frame;

#ifdef MULTI_SUBSTREAM
	find_substream(chip, substream, &sub_info);
	frames = (frames + DMA_BUFFER_FRAMES - sub_info->dma_offset) % \
						DMA_BUFFER_FRAMES;

	if (sub_info->dma_last_pos > frames) {
		sub_info->dma_pos_base += DMA_BUFFER_FRAMES;
		if (sub_info->dma_pos_base >= sub_info->boundary)
			sub_info->dma_pos_base -= sub_info->boundary;
	}
	sub_info->dma_last_pos = frames;
	frames = (frames + sub_info->dma_pos_base) % sub_info->buffer_frames;
#else

	/* the loose syncing used here is accurate enough for alsa, but 
	   due to latency in the dma, the following may happen occasionally, 
	   and pcm_lib shouldn't complain */
	if( frames >= runtime->buffer_size ) 
		frames = 0;
#endif
//	printk("%x ", frames);
	return frames;
}


static snd_pcm_uframes_t snd_ad1836_capture_pointer( 
					snd_pcm_substream_t* substream )
{
	ad1836_t* chip = snd_pcm_substream_chip(substream);
	snd_pcm_runtime_t* runtime = substream->runtime;

	unsigned long diff = bf53x_sport_curr_offset_rx(chip->sport);
#ifdef CONFIG_SND_BLACKFIN_AD1836_TDM 
	/* always 8 channels in the DMA frame */
	unsigned long bytes_per_frame = 8*4;
#else
	unsigned long bytes_per_frame = runtime->frame_bits/8;
#endif
	size_t frames = diff / bytes_per_frame;

#ifdef CONFIG_SND_DEBUG_CURRPTR
	snd_printk( KERN_INFO " capture pos: 0x%04x / %lx\n", frames,
						runtime->buffer_size);
#endif 

	/* the loose syncing used here is accurate enough for alsa, but 
	   due to latency in the dma, the following may happen occasionally, 
	   and pcm_lib shouldn't complain */
	if( frames >= runtime->buffer_size ) 
		frames = 0;

	return frames;

}

#ifdef CONFIG_SND_BLACKFIN_AD1836_TDM
static int snd_ad1836_playback_copy(snd_pcm_substream_t *substream, int channel,
		snd_pcm_uframes_t pos, void *src, snd_pcm_uframes_t count)
{
	ad1836_t *chip = snd_pcm_substream_chip(substream);
	unsigned int *isrc = (unsigned int *)src;
#ifdef MULTI_SUBSTREAM
	unsigned int *dst = (unsigned int*)chip->tx_dma_buf;
	substream_info_t *sub_info = NULL;
	int index = find_substream(chip, substream, &sub_info);
	snd_pcm_uframes_t start, temp_count, temp2_count;

	snd_assert( (index >= 0 && index <=2 && sub_info), return -EINVAL);

	if (index > 0 && index <=2 && !(chip->tx_status & (1<<index))) {
		sub_info->data_count += count;
		return 0;
	}

	start = (sub_info->data_pos_base + pos + sub_info->dma_offset) % \
							DMA_BUFFER_FRAMES;
	if( start + count > DMA_BUFFER_FRAMES) {
		temp_count = DMA_BUFFER_FRAMES - start;
		temp2_count = start + count - DMA_BUFFER_FRAMES;
	} else {
		temp_count = count;
		temp2_count = 0;
	}

	dst += start * 8;
	while(temp_count--) {
		*(dst + index) = *isrc++;
		*(dst + index + 4) = *isrc++;
		dst += 8;
	}

	if (temp2_count) {
		dst = (unsigned int*)chip->tx_dma_buf;
		while(temp2_count--) {
			*(dst + index) = *isrc++;
			*(dst + index + 4) = *isrc++;
			dst += 8;
		}
	}

	sub_info->data_count += count;
	if (sub_info->data_count >= sub_info->buffer_frames) {
		sub_info->data_count -= sub_info->buffer_frames;
		sub_info->data_pos_base += sub_info->buffer_frames;
		if (sub_info->data_pos_base >= sub_info->boundary)
			sub_info->data_pos_base -= sub_info->boundary;
	}
#else
	unsigned int *dst = (unsigned int *)substream->runtime->dma_area;
	unsigned int mask;
	if (chip->out_chan_mask)
		mask = chip->out_chan_mask;
	else
		mask = out_chan_masks[substream->runtime->channels - 1];
	/* assumes tx DMA buffer initialised with zeros */
	dst += pos * 8;
	/* Copy in order of data stream */
	while(count--) {
		if (mask & SP_FL)
			*dst = *isrc++;

		if (mask & SP_FR)
			*(dst+4) = *isrc++;

		if (mask & SP_FC)
			*(dst+1) = *isrc++;

		if (mask & SP_LFE)
			*(dst+5) = *isrc++;

		if (mask & SP_BL)
			*(dst+2) = *isrc++;

		if (mask & SP_BR)
			*(dst+6) = *isrc++;

		dst += 8;
	}
#endif
#ifdef CONFIG_SND_DEBUG_CURRPTR
	snd_printd(KERN_INFO "playback_copy: src %p, pos %x, count %x\n", 
						src, (uint)pos, (uint)count);
#endif
	return 0;
}

static int snd_ad1836_capture_copy(snd_pcm_substream_t *substream, int channel,
	snd_pcm_uframes_t pos, void *dst, snd_pcm_uframes_t count)
{
	ad1836_t *chip = snd_pcm_substream_chip(substream);
	unsigned int *src = (unsigned int *)substream->runtime->dma_area;
	unsigned int *idst = dst;
	unsigned int mask;
	if (chip->in_chan_mask)
		mask = chip->in_chan_mask;
	else
		mask = in_chan_masks[substream->runtime->channels/2 - 1];
#ifdef CONFIG_SND_DEBUG_CURRPTR
	snd_printd(KERN_INFO "capture_copy: dst %p, pos %x, count %x\n", 
						dst, (uint)pos, (uint)count);
#endif

	src += pos * 8;

	while(count--) {
		unsigned int c;
		for (c = 0; c < 8; c++) {
			if (mask & (1 << c)) {
				*idst++ = *src;
			}
			src++;
		}
	}
	return 0;
}

#elif defined(CONFIG_SND_BLACKFIN_AD1836_I2S)

static int snd_ad1836_playback_copy(snd_pcm_substream_t *substream, int channel,
		snd_pcm_uframes_t pos, void *src, snd_pcm_uframes_t count)
{
	int i, curr;
	unsigned long *ldst, *lsrc;

	ldst = (unsigned long *)substream->runtime->dma_area;
	lsrc = src;

	snd_printd(KERN_INFO "playback_copy: src %p, pos %x, count %x\n", 
						src, (uint)pos, (uint)count);
	i = frames_to_bytes(substream->runtime, count) / sizeof(unsigned long);
	curr = frames_to_bytes(substream->runtime, pos)/ sizeof(unsigned long);
	/* assumes tx DMA buffer initialised with zeros */
//		memcpy(ldst + frames_to_bytes(substream->runtime, pos),
//		src, frames_to_bytes(substream->runtime, count));
	while(i--) {
		/* Hardware support only 24 bits, remove the lowest byte*/
		*(ldst + curr + i) = *(lsrc + i)>>8;
	}
	//	print_32x4((dst + frames_to_bytes(substream->runtime, pos)));
	return 0;
}

static int snd_ad1836_capture_copy(snd_pcm_substream_t *substream, int channel,
		snd_pcm_uframes_t pos, void *dst, snd_pcm_uframes_t count)
{
	int i, curr;
	unsigned long *lsrc , *ldst;

	lsrc = (unsigned long *)substream->runtime->dma_area;
	ldst = dst;

	snd_printd(KERN_INFO "capture_copy: dst %p, pos %x, count %x\n",
					dst, (uint)pos, (uint)count);
	i = frames_to_bytes(substream->runtime, count) / sizeof(unsigned long);
	curr = frames_to_bytes(substream->runtime, pos) / sizeof(unsigned long);

//	print_32x4((lsrc + (frames_to_bytes(substream->runtime, pos)/4)));
//	memcpy(ldst, lsrc + frames_to_bytes(substream->runtime, pos),
//			frames_to_bytes(substream->runtime, count));
	while(i--) {
		/* The highest byte is invalid, remove it */
		*(ldst + i) = *(lsrc + i + curr)<<8;
	}

	return 0;
}
#endif

static int snd_ad1836_playback_silence(snd_pcm_substream_t *substream, 
		int channel, snd_pcm_uframes_t pos, snd_pcm_uframes_t count)
{
#ifdef CONFIG_SND_BLACKFIN_AD1836_TDM
#ifndef MULTI_SUBSTREAM
	unsigned char *buf = substream->runtime->dma_area;
	buf += pos * 8 * 4;
	memset(buf, '\0', count * 8 * 4);
#endif
#else
	unsigned char *buf = substream->runtime->dma_area;
	memset(buf + frames_to_bytes(substream->runtime, pos), '\0', 
			frames_to_bytes(substream->runtime, count));
#endif
#ifdef CONFIG_SND_DEBUG_CURRPTR
	snd_printk(KERN_INFO "silence: pos %x, count %x\n", (uint)pos, (uint)count);
#endif

	return 0;
}

static int snd_ad1836_capture_silence(snd_pcm_substream_t *substream, 
	int channel, snd_pcm_uframes_t pos, snd_pcm_uframes_t count)
{
	unsigned char *buf = substream->runtime->dma_area;

#ifdef CONFIG_SND_DEBUG
	snd_printk(KERN_INFO "silence: pos %x, count %x\n",
				(uint)pos, (uint)count);
#endif
#ifdef CONFIG_SND_BLACKFIN_AD1836_TDM
	buf += pos * 8 * 4;
	memset(buf, '\0', count * 8 * 4);
#else
	memset(buf + frames_to_bytes(substream->runtime, pos), '\0', 
			frames_to_bytes(substream->runtime, count));
#endif

	return 0;
}

/* pcm method tables */
static snd_pcm_ops_t snd_ad1836_playback_ops = {
	.open      = snd_ad1836_playback_open,
	.close     = snd_ad1836_playback_close,
	.ioctl     = snd_pcm_lib_ioctl,
	.hw_params = snd_ad1836_hw_params,
	.hw_free   = snd_ad1836_hw_free,
	.prepare   = snd_ad1836_playback_prepare,
	.trigger   = snd_ad1836_playback_trigger,
	.pointer   = snd_ad1836_playback_pointer,
	.copy      = snd_ad1836_playback_copy,
	.silence   = snd_ad1836_playback_silence,
};

static snd_pcm_ops_t snd_ad1836_capture_ops = {
	.open  = snd_ad1836_capture_open,
	.close = snd_ad1836_capture_close,
	.ioctl = snd_pcm_lib_ioctl,  
	.hw_params = snd_ad1836_hw_params,
	.hw_free   = snd_ad1836_hw_free,
	.prepare   = snd_ad1836_capture_prepare,
	.trigger   = snd_ad1836_capture_trigger,
	.pointer   = snd_ad1836_capture_pointer,
	.copy      = snd_ad1836_capture_copy,
	.silence   = snd_ad1836_capture_silence,
};

/************************************************************* 
 *      card and device 
 *************************************************************/
static int snd_ad1836_stop(struct snd_ad1836 *chip)
{
	snd_ad1836_set_register(chip, DAC_CTRL_2, DAC_MUTE_MASK, DAC_MUTE_MASK);
	snd_ad1836_set_register(chip, ADC_CTRL_2, ADC_MUTE_MASK, ADC_MUTE_MASK);
	snd_ad1836_set_register(chip, DAC_CTRL_1, DAC_PWRDWN, DAC_PWRDWN);
	snd_ad1836_set_register(chip, ADC_CTRL_1, ADC_PWRDWN, ADC_PWRDWN);

	return 0;
}

static int snd_ad1836_dev_free(snd_device_t *device)
{
	struct snd_ad1836 *chip = (ad1836_t *)device->device_data;

#ifdef MULTI_SUBSTREAM
	dma_free_coherent(NULL, AD1836_BUF_SZ, chip->rx_dma_buf, 0);
	dma_free_coherent(NULL, AD1836_BUF_SZ, chip->tx_dma_buf, 0);
#endif
	return snd_ad1836_stop(chip);
}

static snd_device_ops_t snd_ad1836_ops = {
	.dev_free = snd_ad1836_dev_free,
};

static int snd_bf53x_ad1836_reset(ad1836_t *chip)
{
#if defined(CONFIG_BFIN533_EZKIT)
	/*
	 *  On the EZKIT, the reset pin of the ad1836 is connected
	 *  to a programmable flag pin on one of the flash chips.
	 *  This code configures the flag pin and toggles it to
	 *  reset the ad1836 chip.  After reset, the chip takes
	 *  4500 cycles of MCLK @ 12.288MHz to recover, ie 367us.
	 *  Thanks to Joep Duck, Aidan Williams.
	 *
	 *  AD1836A data sheet:
	 * 	Reset will power down the chip and set the control registers
	 * 	to their default settings. After reset is de-asserted, an
	 * 	initialization routine will run inside the AD1836A to clear all
	 * 	memories to zero. This initialization lasts for approximately
	 * 	4500 MCLKs.
	 * 
	 * 	The power-down bit in the DAC Control Register 1 and ADC Control
	 * 	Register 1 will power down the respective digital section.
	 * 	The analog circuitry does not power down. All other register
	 * 	settings are retained.
	 * 
	 * 	To avoid possible synchronization problems, if MCLK is 512 fS
	 * 	or 768 fS, the clock rate should be set in ADC Control Register
	 * 	3  within the first 3072 MCLK cycles after reset, or DLRCLK and
	 * 	DBCLK should be withheld until after the internal initialization
	 * 	completes (see above).
	 */
#define FlashA_PortA_Dir	0x20270006
#define FlashA_PortA_Data	0x20270004

	bfin_write(FlashA_PortA_Dir,0x1);	/* configure flag as an output pin */

	snd_printk( KERN_INFO "resetting ezkit 1836 using flash flag pin\n" );
	bfin_write(FlashA_PortA_Data,0x0);	/* reset is active low */
	udelay(1);			/* hold low */

	bfin_write(FlashA_PortA_Data,0x1);	/* re-enable */
	udelay(400);			/* 4500 MCLK recovery time */

#endif /* CONFIG_BFIN533_EZKIT */

	return 0;
}

#ifdef CONFIG_SND_BLACKFIN_AD1836_TDM
static int snd_ad1836_configure(ad1836_t *chip)
{
	int err = 0;
	struct bf53x_sport *sport= chip->sport;

	snd_bf53x_ad1836_reset(chip);

	/* see if we are connected by writing (preferably something useful)
	 * to the chip, and see if we get an IRQ */
	/* power-up DAC and ADC */
	err = err || snd_ad1836_set_register(chip, DAC_CTRL_1, DAC_PWRDWN, 0);
	err = err || snd_ad1836_set_register(chip, ADC_CTRL_1, ADC_PWRDWN, 0);

	/* sport in aux/slave mode cf daughtercard schematics */
	err = err || snd_ad1836_set_register(chip, ADC_CTRL_2, 
			(ADC_AUX_MASTER|ADC_SOUT_MASK | ADC_MUTE_MASK),  
			( /*ADC_AUX_MASTER|*/ ADC_SOUT_PMAUX)); 
#ifdef ADC2_IS_MIC
	err = err || snd_ad1836_set_register(chip, ADC_CTRL_3, ADC_MODE_MASK, \
			ADC_LEFT_SE | ADC_RIGHT_SE | ADC_LEFT_MUX | \
			ADC_RIGHT_MUX);
#endif
	err = err || snd_ad1836_set_register(chip, DAC_CTRL_2, DAC_MUTE_MASK, 0);
	/* set volume to full scale, (you might assume these won't fail anymore) */
	err = err || snd_ad1836_set_register(chip, DAC_VOL_1L, DAC_VOL_MASK,
			DAC_VOL_MASK);
	err = err || snd_ad1836_set_register(chip, DAC_VOL_1R, DAC_VOL_MASK,
			DAC_VOL_MASK);
	err = err || snd_ad1836_set_register(chip, DAC_VOL_2L, DAC_VOL_MASK,
			DAC_VOL_MASK);
	err = err || snd_ad1836_set_register(chip, DAC_VOL_2R, DAC_VOL_MASK,
			DAC_VOL_MASK);
	err = err || snd_ad1836_set_register(chip, DAC_VOL_3L, DAC_VOL_MASK,
			DAC_VOL_MASK);
	err = err || snd_ad1836_set_register(chip, DAC_VOL_3R, DAC_VOL_MASK,
			DAC_VOL_MASK);
	if(err){
		snd_printk( KERN_ERR "Unable to set chip registers.\n");    
		snd_ad1836_stop(chip);
		return -ENODEV;
	}
	/* Set 32 bit word length */
	err = err || bf53x_sport_config_rx(sport, RFSR, 0x1f, 0, 0 );
	err = err || bf53x_sport_config_tx(sport, TFSR, 0x1f, 0, 0 );
	/*Set 8 channels and packed */
	err = err || bf53x_sport_set_multichannel(sport, 8, 1);

	if(err)
		snd_printk( KERN_ERR "Unable to set sport configuration\n");

#ifdef MULTI_SUBSTREAM
	err = bf53x_sport_config_tx_dma(chip->sport, chip->tx_dma_buf, 
			DMA_PERIODS, DMA_PERIOD_BYTES, 4);
#endif

	return err;
}

#elif defined(CONFIG_SND_BLACKFIN_AD1836_I2S)

static int snd_ad1836_configure(ad1836_t *chip)
{
	int err = 0;
	struct bf53x_sport *sport= chip->sport;

	snd_bf53x_ad1836_reset(chip);

	/* Power up DAC and ADC */
	err = err || snd_ad1836_set_register(chip, DAC_CTRL_1, DAC_PWRDWN, 0);
	err = err || snd_ad1836_set_register(chip, ADC_CTRL_1, ADC_PWRDWN, 0);

	/* sport in aux/slave mode cf daughtercard schematics */
	err = snd_ad1836_set_register(chip, DAC_CTRL_1, (DAC_DATA_MASK), (DAC_DATA_24));
	err = err || snd_ad1836_set_register(chip, DAC_CTRL_2, \
			(DAC_MUTE_MASK), (DAC_MUTE_DAC2|DAC_MUTE_DAC3));
	err = err || snd_ad1836_set_register(chip, ADC_CTRL_2, \
			(ADC_AUX_MASTER|ADC_SOUT_MASK|ADC_MUTE_MASK|ADC_DATA_MASK),
			(ADC_AUX_MASTER | ADC_SOUT_I2S | ADC_MUTE_ADC2 | ADC_DATA_24));  
	/* set volume to full scale */
	err = err || snd_ad1836_set_register(chip, DAC_VOL_1L, DAC_VOL_MASK, DAC_VOL_MASK);
	err = err || snd_ad1836_set_register(chip, DAC_VOL_1R, DAC_VOL_MASK, DAC_VOL_MASK);
	if(err){
		snd_printk( KERN_ERR "Unable to set chip registers.\n");    
		snd_ad1836_stop(chip);
		return -ENODEV;
	}
	/* Set word length to 24 bits */
	err = err || bf53x_sport_config_rx(sport, (RCKFE | RFSR), (RSFSE | 0x17), 0, 0 );
	err = err || bf53x_sport_config_tx(sport, (TCKFE | TFSR), (TSFSE | 0x17), 0, 0 );	
	if(err)
		snd_printk( KERN_ERR "Unable to set sport configuration\n");

	return err;
}
#endif

static void snd_ad1836_dma_rx(void *data)
{
	struct snd_ad1836 *ad1836 = data;
	
	if (ad1836->rx_substream) {
		snd_pcm_period_elapsed(ad1836->rx_substream);
	}
}

#ifdef MULTI_SUBSTREAM
static inline void snd_ad1836_update(substream_info_t *sub_info)
{
	sub_info->dma_inter_pos += DMA_PERIOD_FRAMES;
	if (sub_info->dma_inter_pos >= sub_info->boundary)
		sub_info->dma_inter_pos -= sub_info->boundary;

	if(sub_info->dma_inter_pos >= sub_info->next_inter_pos){
		snd_pcm_period_elapsed(sub_info->substream);
		sub_info->next_inter_pos += sub_info->period_frames;
		if (sub_info->next_inter_pos >= sub_info->boundary)
			sub_info->next_inter_pos -= sub_info->boundary;
	}
}
#endif

static void snd_ad1836_dma_tx(void *data)
{
	struct snd_ad1836 *ad1836 = data;
#ifdef MULTI_SUBSTREAM
	int index;
	substream_info_t *sub_info = NULL;

	ad1836->dma_pos = (ad1836->dma_pos + DMA_PERIOD_FRAMES) % \
						DMA_BUFFER_FRAMES;
	for(index = 0; index < 3; index++) {
		sub_info = &ad1836->tx_substreams[index];
		if (sub_info->substream && ad1836->tx_status & (1<<index)) {
			snd_ad1836_update(sub_info);	
		}
	}
#else
	if (ad1836->tx_substream) {
		snd_pcm_period_elapsed(ad1836->tx_substream);
	}
#endif
}

static void snd_ad1836_sport_err(void *data)
{
	printk(KERN_ERR "%s: err happened on sport\n", __FUNCTION__);
}

static void snd_ad1836_proc_registers_read( snd_info_entry_t * entry, 
						snd_info_buffer_t * buffer)
{
	int i;
	ad1836_t *chip = (ad1836_t*) entry->private_data;
	static const char* reg_names[] = {
		"DAC_CTRL_1 ", "DAC_CTRL_2 ", "DAC_VOL_1L ", "DAC_VOL_1R ", 
		"DAC_VOL_2L ", "DAC_VOL_2R ", "DAC_VOL_3L ", "DAC_VOL_3R ", 
		"ADC_PEAK_1L", "ADC_PEAK_1R", "ADC_PEAK_2L", "ADC_PEAK_2R", 
		"ADC_CTRL_1 ", "ADC_CTRL_2 ", "ADC_CTRL_3 ",  };

	for( i=DAC_CTRL_1; i<=DAC_VOL_3R;++i)
		snd_iprintf(buffer, "%s 0x%04x\n", reg_names[i], \
						chip->chip_registers[i] );

	snd_ad1836_read_registers(chip);

	for( i=ADC_PEAK_1L; i <= ADC_PEAK_2R; ++i )
		snd_iprintf(buffer, "%s 0x%04x %d dBFS\n", reg_names[i], 
			chip->chip_registers[i], 
				ADC_PEAK_VALUE(chip->chip_registers[i]) );

	for( i=ADC_CTRL_1; i<=ADC_CTRL_3;++i)
		snd_iprintf(buffer, "%s 0x%04x\n", reg_names[i], 
			chip->chip_registers[i] );

	return;
}

static void snd_ad1836_proc_registers_write( snd_info_entry_t * entry, 
						snd_info_buffer_t * buffer)
{
	ad1836_t *chip = (ad1836_t*) entry->private_data;
	char line[8];
	if( !snd_info_get_line(buffer, line, sizeof(line)) ){
		unsigned int val = simple_strtoul( line, NULL, 0 );
		int reg = val >> 12;
		snd_ad1836_set_register(chip, reg, 0x03ff, val);
	}
	return;
}

static int __devinit snd_ad1836_proc_create(struct snd_ad1836 *ad1836)
{
	int err;
	snd_info_entry_t* proc_entry;

	err = snd_card_proc_new(ad1836->card, "registers", &proc_entry); 
	if(err) goto __proc_err;
	snd_info_set_text_ops( proc_entry, ad1836, 1024,
				snd_ad1836_proc_registers_read);
				
	proc_entry->mode = S_IFREG | S_IRUGO | S_IWUSR;
	proc_entry->c.text.write_size = 8;
	proc_entry->c.text.write = snd_ad1836_proc_registers_write;

	return 0;

__proc_err:
	return err;
}

static int __devinit snd_ad1836_pcm(struct snd_ad1836 *ad1836)
{
	struct snd_pcm *pcm;
	int err = 0;

#ifdef MULTI_SUBSTREAM
	/* 3 playback and 1 capture substream, 2 channels each */
	err = snd_pcm_new(ad1836->card, PCM_NAME, 0, 3, 1, &pcm);
#else
	/* 1 playback and 1 capture substream, of 2-8 channels each */
	err = snd_pcm_new(ad1836->card, PCM_NAME, 0, 1, 1, &pcm);
#endif
	if(err)
		return err;

	ad1836->pcm = pcm;
	strcpy(pcm->name, PCM_NAME);
	snd_pcm_set_ops(pcm, SNDRV_PCM_STREAM_PLAYBACK, 
			&snd_ad1836_playback_ops);
	snd_pcm_set_ops(pcm, SNDRV_PCM_STREAM_CAPTURE,
			&snd_ad1836_capture_ops);
	pcm->private_data = ad1836;
	pcm->info_flags = 0;
#ifndef MULTI_SUBSTREAM
	/* uncached DMA buffers */
	snd_pcm_lib_preallocate_pages_for_all(ad1836->pcm, SNDRV_DMA_TYPE_DEV,
			NULL, AD1836_BUF_SZ, AD1836_BUF_SZ);
#endif

	return 0;
}

static int __devinit snd_ad1836_probe(struct platform_device *pdev)
{
	int i, err = 0;
	struct snd_card *card;
	struct snd_ad1836 *ad1836;
	struct bf53x_sport *sport;
#ifdef MULTI_SUBSTREAM
	dma_addr_t addr;
#endif

	if (device != NULL)
		return -ENOENT;

	
	card = snd_card_new(-1, NULL, THIS_MODULE, sizeof(struct snd_ad1836));
	if( card == NULL ) 
		return -ENOMEM;

	ad1836 = card->private_data;
	ad1836->card = card;
	ad1836->spi = ad1836_spi;

#ifdef MULTI_SUBSTREAM
	memset(ad1836->tx_substreams, 0, 3*sizeof(substream_info_t));
	ad1836->dma_pos = 0;
	ad1836->tx_dma_started = 0;
	ad1836->rx_dma_buf = NULL;
	ad1836->tx_dma_buf = NULL;
#endif

	init_waitqueue_head(&ad1836->spi_waitq);

	for(i=0; i<16; ++i)
		ad1836->chip_registers[i] = (i<<12);

	for(i=ADC_PEAK_1L; i<=ADC_PEAK_2R; ++i)
		ad1836->chip_registers[i] |= ADC_READ;

#ifdef MULTI_SUBSTREAM
	ad1836->rx_dma_buf = dma_alloc_coherent(NULL, AD1836_BUF_SZ, &addr, 0);
	ad1836->tx_dma_buf = dma_alloc_coherent(NULL, AD1836_BUF_SZ, &addr, 0);
	if (!ad1836->rx_dma_buf || !ad1836->tx_dma_buf) {
		printk(KERN_ERR"Failed to allocate DMA buffer\n");
		return -ENOMEM;
	} 
#endif

	if( (sport = bf53x_sport_init(CONFIG_SND_BLACKFIN_SPORT,  
			SPORT_DMA_RX, snd_ad1836_dma_rx,
			SPORT_DMA_TX, snd_ad1836_dma_tx,
			SPORT_IRQ_ERR, snd_ad1836_sport_err, ad1836))
			== NULL ){
		err = -ENODEV;
		goto __nodev;
	}

	ad1836->sport = sport;
#ifndef NOCONTROLS
	for( i=0; (i<AD1836_CONTROLS) && !err; ++i )
		err = snd_ctl_add(card, snd_ctl_new1( \
				&(snd_ad1836_controls[i]), ad1836));
	if (err)
		goto __nodev;
#endif

	err = snd_device_new(card, SNDRV_DEV_LOWLEVEL, ad1836, &snd_ad1836_ops);
	if (err)
		goto __nodev;

	if ((err = snd_ad1836_pcm(ad1836))<0)
		goto __nodev;

	if ((err= snd_ad1836_configure(ad1836))<0) {
		goto __nodev;
	}
	strcpy(card->driver, DRIVER_NAME);
	strcpy(card->shortname, CHIP_NAME);
	sprintf(card->longname, "%s at PF%d SPORT%d rx/tx dma %d/%d err irq %d", 
		  card->shortname,
		  CONFIG_SND_BLACKFIN_SPI_PFBIT,
		  CONFIG_SND_BLACKFIN_SPORT,
		  SPORT_DMA_RX, SPORT_DMA_TX, SPORT_IRQ_ERR);

	snd_card_set_dev(card, (&pdev->dev));
	snd_ad1836_proc_create(ad1836);

	if ((err = snd_card_register(card)) < 0) {
		goto __nodev;
	}

	platform_set_drvdata(pdev, card);

	return 0;

__nodev:
	snd_card_free(card);
	return err;
}

static int __devexit snd_ad1836_remove(struct platform_device *pdev)
{
	struct snd_card *card;
	struct snd_ad1836 *ad1836;
	
	card = platform_get_drvdata(pdev);
	ad1836 = card->private_data;

	snd_ad1836_stop(ad1836);
	ad1836_spi_done(ad1836->spi);
	bf53x_sport_done(ad1836->sport);

	snd_card_free(card);
	platform_set_drvdata(pdev, NULL);
	
	return 0;
}

#ifdef CONFIG_PM
static int snd_ad1836_suspend(struct platform_device *pdev, pm_message_t state)
{
	struct snd_card *card = platform_get_drvdata(pdev);
	struct snd_ad1836 *ad1836 = card->private_data;

	snd_power_change_state(card, SNDRV_CTL_POWER_D3hot);
	snd_pcm_suspend_all(ad1836->pcm);
	return 0;
}

static int snd_ad1836_resume(struct platform_device *pdev)
{
	struct snd_card *card = platform_get_drvdata(pdev);

	snd_power_change_state(card, SNDRV_CTL_POWER_D0);
	return 0;
}
#endif

static struct platform_driver snd_ad1836_driver = {
	.probe		= snd_ad1836_probe,
	.remove		= snd_ad1836_remove,
#ifdef CONFIG_PM
	.suspend	= snd_ad1836_suspend,
	.resume		= snd_ad1836_resume,
#endif
	.driver		= {
		.name	= DRIVER_NAME,
	},
};

void __init_or_module snd_ad1836_spi_probed(struct ad1836_spi *spi)
{
	int err;

	if (spi == NULL) {
		platform_driver_unregister(&snd_ad1836_driver);
		return;
	} else
		ad1836_spi = spi;

	device = platform_device_register_simple(DRIVER_NAME, 0, NULL, 0);
	if (IS_ERR(device)) {
		err = PTR_ERR(device);
		ad1836_spi_done(spi);
		platform_driver_unregister(&snd_ad1836_driver);
	}
}

static int __init snd_ad1836_init(void)
{
	int err;

	if ((err = platform_driver_register(&snd_ad1836_driver))<0)
		return err;

	if ((err = ad1836_spi_init())< 0) {
		platform_driver_unregister(&snd_ad1836_driver);
		return err;
	}
	
	return 0;
}

static void __exit snd_ad1836_exit(void)
{
	platform_device_unregister(device);
	platform_driver_unregister(&snd_ad1836_driver);
}

MODULE_AUTHOR("Luuk van Dijk <blackfin@mndmttr.nl>");
MODULE_DESCRIPTION("BF53x/AD1836");
MODULE_LICENSE("GPL");

module_init(snd_ad1836_init);
module_exit(snd_ad1836_exit);
