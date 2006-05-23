/*
 * File:         adi1836.c 
 * Description:  driver for ADI 1836 sound chip connected to bf53x sport/spi
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
 *     * the card allocates the /low-level device/, the /proc/, the /snd/ and /mixer/ stuff
 *     * the /snd/ and /mixer/ stuff use the methods of the low level device
 *       to control the registers over the spi, and the methods of the sport
 * - there are useful proc entries for spi, sport and ad1836 register and irq status.
 *       since sash doesn't have redirection, you can use echo2 in the test/ directory. 
 *  - this can also be used to control the volume directly through setting
 *       the registers directly, eg.  echo2 /proc/asound/card0/registers 0x3000
 *       silences DAC_1_left
 *  - the in_chan_mask and out_chan_mask facility is split into separate masks for rx and tx
 *       by duplicating it, and using the proper one in the hw_params callback
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
 *	For expample 0x33 indicate Quadraphonic. DAC0 and DAC2 will be used to decode.
 *	when user play a 5.1 audio, the data will be put to DAC
 *	according to our definition.
 */
/*
 * There is a choice between 5.1 Channels mode or multiple substream mode. In multiple 
 * substream mode, 3 seperate stereos are supported. /dev/dsp can be opened 3 times.
 * Every time a new substream is opened.
 */

#include <sound/driver.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <asm/irq.h>
#include <asm/delay.h>

#include <sound/core.h>
#include <sound/info.h>
#include <sound/control.h>
#include <sound/pcm.h>
#define SNDRV_GET_ID
#include <sound/initval.h>

#include <asm/blackfin.h>
#include <asm/cacheflush.h>
#include <linux/dma-mapping.h>

#include "ad1836_spi.h"
#include "bf53x_sport.h"

#include "adi1836.h"
#include "adi1836_config.h"

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

#ifdef CONFIG_SND_BLACKFIN_ADI1836_I2S
#undef ADC2_IS_MIC
#endif

#undef CONFIG_SND_DEBUG_CURRPTR  /* causes output every frame! */

#undef NOCONTROLS  /* define this to omit all the ALSA controls */

#ifdef CONFIG_SND_BLACKFIN_ADI1836_MULSUB
#define MULTI_SUBSTREAM
#endif

#define CHIP_NAME "Analog Devices AD1836A"

/* ALSA boilerplate */

static int   index[SNDRV_CARDS]  = SNDRV_DEFAULT_IDX;
static char* id[SNDRV_CARDS]     = SNDRV_DEFAULT_STR;
static int   enable[SNDRV_CARDS] = SNDRV_DEFAULT_ENABLE_PNP;


/* Chip level */

#ifdef CONFIG_SND_BLACKFIN_ADI1836_TDM

#define AD1836_BUFFER_SIZE 0x40000 /* 256kb */
/*In 2 channels mode, the buffer is quadrupled */
#define PCM_BUFFER_MAX	(AD1836_BUFFER_SIZE / 4)
#define CHANNELS_MAX	8
#define CHANNELS_OUTPUT	6
#define CHANNELS_INPUT	4
#define FRAGMENT_SIZE_MIN	(4*1024)
#define FRAGMENTS_MIN	2	
#define FRAGMENTS_MAX	32

#elif defined(CONFIG_SND_BLACKFIN_ADI1836_I2S)

#define AD1836_BUFFER_SIZE 0x10000 /* 64kb */
#define PCM_BUFFER_MAX	AD1836_BUFFER_SIZE
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
#define DMA_BUFFER_BYTES	AD1836_BUFFER_SIZE
#define DMA_PERIOD_BYTES	(FRAGMENT_SIZE_MIN * 4)
#define DMA_PERIODS		(DMA_BUFFER_BYTES / DMA_PERIOD_BYTES)
#define DMA_FRAME_BYTES		32
#define DMA_BUFFER_FRAMES	(DMA_BUFFER_BYTES/DMA_FRAME_BYTES)
#define DMA_PERIOD_FRAMES	(DMA_PERIOD_BYTES/DMA_FRAME_BYTES)
#undef  CHANNELS_MAX
#define CHANNELS_MAX	2
#endif

#define ad1836_t_magic  0xa15a4501

#ifdef CONFIG_SND_BLACKFIN_ADI1836_TDM
#ifdef CONFIG_SND_BLACKFIN_ADI1836_5P1
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

  snd_card_t*         card;
  struct ad1836_spi*   spi;
  struct bf53x_sport* sport;
  spinlock_t    ad1836_lock;

  snd_pcm_t* pcm;

#ifdef CONFIG_SND_BLACKFIN_ADI1836_TDM
  /* define correspondence of alsa channels to ad1836 channels */
  unsigned int out_chan_mask;
  unsigned int in_chan_mask;
#endif

  wait_queue_head_t   spi_waitq;
  int	spi_data_ready;
  uint16_t chip_registers[16];
  int      poll_reg;  /* index of the ad1836 register last queried */

  snd_pcm_substream_t* rx_substream;  /* if non-null, current subtream running */
#ifdef MULTI_SUBSTREAM
  int	tx_dma_started;

/* Allocate dma buffer by driver instead of ALSA */
  unsigned char* rx_dma_buf;
  unsigned char* tx_dma_buf;
  snd_pcm_uframes_t	dma_pos;
  snd_pcm_uframes_t	dma_offset[3];
  substream_info_t	tx_substreams[3];
#else
  snd_pcm_substream_t* tx_substream;  /* if non-null, current subtream running */
#endif

  /* stats for /proc/../sport */
  long sport_irq_timestamp;
  long sport_irq_count;
  long sport_irq_count_rx;
  long sport_irq_count_tx;

  long spi_irq_timestamp;
  long spi_irq_count;

  int runmode;
#define RUN_RX 0x1
#define RUN_TX 0x2

#ifdef MULTI_SUBSTREAM
#define RUN_TX0 0x2
#define RUN_TX1 0x4
#define RUN_TX2 0x8
#define RUN_TX_ALL (RUN_TX0 | RUN_TX1 | RUN_TX2)
#endif
};
static int snd_ad1836_startup(ad1836_t *chip);
//static void print_32x4(void*);

#ifndef NOCONTROLS
#define chip_t_magic ad1836_t_magic  /* move to include/sound/sndmagic.h in due time */
typedef ad1836_t chip_t; /* used in alsa macro's */
#endif

#if L1_DATA_A_LENGTH != 0
extern unsigned long l1_data_A_sram_alloc(unsigned long size);
extern int l1_data_A_sram_free(unsigned long addr);
#endif

#ifdef MULTI_SUBSTREAM
static inline int find_substream(ad1836_t *chip, snd_pcm_substream_t *substream, substream_info_t **info)
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

static int snd_ad1836_set_register(ad1836_t *chip, unsigned int reg, unsigned int mask, unsigned int value){

  unsigned short data = (chip->chip_registers[reg] & ~mask) | (value & mask);

/*  snd_printk( KERN_INFO "spi set reg %d = 0x%04x\n", reg, data); */
  ad1836_spi_write(chip->spi, data);

  chip->chip_registers[reg] = data;
  ad1836_spi_read(chip->spi, (1<<reg) | ADC_READ, &data);

  return 0;

}



static void snd_ad1836_reset_sport_stats(ad1836_t *chip ){
  chip->sport_irq_timestamp = jiffies;
  chip->sport_irq_count = 0;
  chip->sport_irq_count_rx = 0;
  chip->sport_irq_count_tx = 0;
}

static void snd_ad1836_reset_spi_stats(ad1836_t *chip ){
  chip->spi_irq_timestamp = jiffies;
  chip->spi_irq_count = 0;
}

//#ifdef CONFIG_SND_BLACKFIN_ADI1836_TDM
#if 0
/* define correspondence between ALSA and ad1836 channels, default '0123' */
static int ad1836_set_chan_masks(ad1836_t* chip, char* permutation, int out){

  int i,j,m;
  
  /* 4 characters */
  if( strlen(permutation) != 4 ) 
    return -EINVAL;

  /* between '0' and '3' inclusive */
  for( i=0;i<4; ++i )
    if( (permutation[i] < '0') || permutation[i] > '3' ) 
      return -EINVAL;

  /* a permutation, i.e. no duplicates */
  for(i=0;i<4;++i)
    for(j=i+1;j<4;++j)
      if( permutation[i] == permutation[j] )
	return -EINVAL;

  if(out) {  
    for( i=0;i<4; ++i )
      chip->out_chan_mask_str[i] = permutation[i];
    chip->out_chan_mask_str[4] = 0;
  }
  else {
    for( i=0;i<4; ++i )
      chip->in_chan_mask_str[i] = permutation[i];
    chip->in_chan_mask_str[4] = 0;
  }

  m = 0;
  for( i=0;i<4;++i ){
    int chan = (permutation[i]-'0');  /* 0...3 */
    int bit  = 1 << chan;             /* 0001b ... 1000b */
    int bits = bit | (bit << 4);      /* 0x11 .. 0x88 */
    m |= bits;                        /* 0x11 .. 0xff, in order of permutation */
    if(out)
      chip->out_chan_mask[i] = m;
    else
      chip->in_chan_mask[i] = m;
  }

  if(out)
    snd_printk( KERN_INFO "channel out masks set to %s = { %02x %02x %02x %02x }\n", 
	      permutation, chip->out_chan_mask[0], chip->out_chan_mask[1], chip->out_chan_mask[2], chip->out_chan_mask[3] );
  else
    snd_printk( KERN_INFO "channel in masks set to %s = { %02x %02x %02x %02x }\n", 
	      permutation, chip->in_chan_mask[0], chip->in_chan_mask[1], chip->in_chan_mask[2], chip->in_chan_mask[3] );
  return 0;

}
#endif // CONFIG_SND_BLACKFIN_ADI1836_TDM

static void snd_ad1836_read_registers(ad1836_t *chip)
{
	int i;
	
	for (i = ADC_PEAK_1L; i <= ADC_PEAK_2R; i++) { 
		chip->poll_reg = i;
		ad1836_spi_read(chip->spi, (chip->poll_reg<<12) |ADC_READ, &chip->chip_registers[i]);
	}
}

/*************************************************************
 *                 proc and control stuff 
 *************************************************************/
static void snd_ad1836_proc_registers_read( snd_info_entry_t * entry, snd_info_buffer_t * buffer){
  int i;
  ad1836_t *chip = (ad1836_t*) entry->private_data;
  static const char* reg_names[] = {
    "DAC_CTRL_1 ",    "DAC_CTRL_2 ",     "DAC_VOL_1L ",    "DAC_VOL_1R ", 
    "DAC_VOL_2L ",    "DAC_VOL_2R ",     "DAC_VOL_3L ",    "DAC_VOL_3R ",     
    "ADC_PEAK_1L",    "ADC_PEAK_1R",     "ADC_PEAK_2L",    "ADC_PEAK_2R", 
    "ADC_CTRL_1 ",    "ADC_CTRL_2 ",     "ADC_CTRL_3 ",  };

  for( i=DAC_CTRL_1; i<=DAC_VOL_3R;++i)
    snd_iprintf(buffer, "%s 0x%04x\n", reg_names[i], chip->chip_registers[i] );

  snd_ad1836_read_registers(chip);
  
  for( i=ADC_PEAK_1L; i <= ADC_PEAK_2R; ++i )
    snd_iprintf(buffer, "%s 0x%04x %d dBFS\n", reg_names[i], 
		chip->chip_registers[i], ADC_PEAK_VALUE(chip->chip_registers[i]) );

  for( i=ADC_CTRL_1; i<=ADC_CTRL_3;++i)
    snd_iprintf(buffer, "%s 0x%04x\n", reg_names[i], chip->chip_registers[i] );

  return;
}

static void snd_ad1836_proc_registers_write( snd_info_entry_t * entry, snd_info_buffer_t * buffer){
  ad1836_t *chip = (ad1836_t*) entry->private_data;
  char line[8];
  if( !snd_info_get_line(buffer, line, sizeof(line)) ){
    unsigned int val = simple_strtoul( line, NULL, 0 );
    int reg = val >> 12;
    snd_ad1836_set_register(chip, reg, 0x03ff, val);
  }
  return;
}

static void snd_ad1836_proc_spi_read( snd_info_entry_t * entry, snd_info_buffer_t * buffer){
  ad1836_t *chip = (ad1836_t*) entry->private_data;
  unsigned long timedif = jiffies - chip->spi_irq_timestamp;
  unsigned long freq = (chip->spi_irq_count*HZ*100);
  if(timedif > 0) freq /= timedif;
  snd_iprintf(buffer, "irq: %ld %ld/100s\n", chip->spi_irq_count, freq  );
  snd_ad1836_reset_spi_stats(chip);
  return;
}

static void snd_ad1836_proc_sport_read( snd_info_entry_t * entry, snd_info_buffer_t * buffer){
  ad1836_t *chip = (ad1836_t*) entry->private_data;
  unsigned long timedif = jiffies - chip->sport_irq_timestamp;
  unsigned long freq =    chip->sport_irq_count    *HZ*100;
  unsigned long freq_rx = chip->sport_irq_count_rx *HZ*100;
  unsigned long freq_tx = chip->sport_irq_count_tx *HZ*100;
  
  char buf[256];
  if(timedif > 0){
    freq /= timedif;
    freq_tx /= timedif;
    freq_rx /= timedif;
  } 
  snd_iprintf(buffer, "irq tot: %ld %ld/100s\n", chip->sport_irq_count, freq );
  snd_iprintf(buffer, "irq rx:  %ld %ld/100s\n", chip->sport_irq_count_rx, freq_rx );
  snd_iprintf(buffer, "irq tx:  %ld %ld/100s\n", chip->sport_irq_count_tx, freq_tx );
  snd_ad1836_reset_sport_stats(chip);
  bf53x_sport_dump_stat(chip->sport, buf, sizeof(buf));
  snd_iprintf(buffer, "%s", buf);
  return;
}

//#ifdef CONFIG_SND_BLACKFIN_ADI1836_TDM
#if 0
static void snd_ad1836_proc_outchanmask_read( snd_info_entry_t * entry, snd_info_buffer_t * buffer){
  ad1836_t *chip = (ad1836_t*) entry->private_data;
  snd_iprintf(buffer, "%s\n", chip->out_chan_mask_str );
  return;
}

static void snd_ad1836_proc_outchanmask_write( snd_info_entry_t * entry, snd_info_buffer_t * buffer){
  ad1836_t *chip = (ad1836_t*) entry->private_data;
  char line[5];
  if( snd_info_get_line(buffer, line, sizeof(line)) ) return;
  ad1836_set_chan_masks(chip, line, 1);
  return;
}

static void snd_ad1836_proc_inchanmask_read( snd_info_entry_t * entry, snd_info_buffer_t * buffer){
  ad1836_t *chip = (ad1836_t*) entry->private_data;
  snd_iprintf(buffer, "%s\n", chip->in_chan_mask_str );
  return;
}

static void snd_ad1836_proc_inchanmask_write( snd_info_entry_t * entry, snd_info_buffer_t * buffer){
  ad1836_t *chip = (ad1836_t*) entry->private_data;
  char line[5];
  if( snd_info_get_line(buffer, line, sizeof(line)) ) return;
  ad1836_set_chan_masks(chip, line, 0);
  return;
}
#endif //CONFIG_SND_BLACKFIN_ADI1836_TDM

/*************************************************************
 *          controls 
 *************************************************************/

#ifndef NOCONTROLS

static int snd_ad1836_volume_info(snd_kcontrol_t *kcontrol, snd_ctl_elem_info_t *uinfo)
{
  uinfo->type = SNDRV_CTL_ELEM_TYPE_INTEGER;
  uinfo->count = CHANNELS_OUTPUT;
  uinfo->value.integer.min = 0;
  uinfo->value.integer.max = 1023;
  return 0;
}


static int snd_ad1836_volume_get(snd_kcontrol_t *kcontrol, snd_ctl_elem_value_t *ucontrol)
{
  ad1836_t *chip = snd_kcontrol_chip(kcontrol);
  int i;
  for(i=0;i<CHANNELS_OUTPUT;++i)
    ucontrol->value.integer.value[i] = chip->chip_registers[DAC_VOL_1L+i] & DAC_VOL_MASK;
  return 0;
}


static int snd_ad1836_volume_put(snd_kcontrol_t *kcontrol, snd_ctl_elem_value_t *ucontrol)
{
  
  ad1836_t *chip = snd_kcontrol_chip(kcontrol);
  int change=0;
  int i;

  for(i=0;i<CHANNELS_OUTPUT;++i){
    int vol  = ucontrol->value.integer.value[i];
    if (vol < 0) vol = 0; if (vol > 1023) vol = 1023;
    if( (chip->chip_registers[DAC_VOL_1L+i]  & DAC_VOL_MASK) != vol ){
      change = 1;
      snd_ad1836_set_register(chip, DAC_VOL_1L+i, DAC_VOL_MASK, vol);
    }
  }
  return change;
  
}

#ifdef ADC2_IS_MIC
static int snd_ad1836_adc_gain_info(snd_kcontrol_t *kcontrol, snd_ctl_elem_info_t *uinfo)
{
  uinfo->type = SNDRV_CTL_ELEM_TYPE_INTEGER;
  uinfo->count = 2;
  uinfo->value.integer.min = 0;
  uinfo->value.integer.max = 4;
  return 0;
}

static int snd_ad1836_adc_gain_get(snd_kcontrol_t *kcontrol, snd_ctl_elem_value_t *ucontrol)
{
  ad1836_t *chip = snd_kcontrol_chip(kcontrol);
  ucontrol->value.integer.value[0] = ADC_GAIN_LEFT( chip->chip_registers[ADC_CTRL_1]);
  ucontrol->value.integer.value[1] = ADC_GAIN_RIGHT(chip->chip_registers[ADC_CTRL_1]);
  return 0;
}

static int snd_ad1836_adc_gain_put(snd_kcontrol_t *kcontrol, snd_ctl_elem_value_t *ucontrol)
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
    curr |= (right /* << ADC_GAIN_RIGHT_SHIFT */) & ADC_GAIN_RIGHT_MASK;
  }
  
  if(change) 
    snd_ad1836_set_register(chip, ADC_CTRL_1, ADC_GAIN_LEFT_MASK|ADC_GAIN_RIGHT_MASK, curr);

  return change;
}
#endif

static int snd_ad1836_playback_mute_info(snd_kcontrol_t *kcontrol, snd_ctl_elem_info_t *uinfo)
{
  uinfo->type = SNDRV_CTL_ELEM_TYPE_BOOLEAN;
  uinfo->count = CHANNELS_OUTPUT;
  uinfo->value.integer.min = 0;
  uinfo->value.integer.max = 1;
  return 0;
}

static int snd_ad1836_playback_mute_get(snd_kcontrol_t *kcontrol, snd_ctl_elem_value_t *ucontrol)
{
  ad1836_t *chip = snd_kcontrol_chip(kcontrol);
  int i;
  for(i=0;i<CHANNELS_OUTPUT;++i)
    ucontrol->value.integer.value[i] = (chip->chip_registers[DAC_CTRL_2] & ( 1 << i )) ? 0:1;
  return 0;
}

static int snd_ad1836_playback_mute_put(snd_kcontrol_t *kcontrol, snd_ctl_elem_value_t *ucontrol)
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


static int snd_ad1836_capture_mute_info(snd_kcontrol_t *kcontrol, snd_ctl_elem_info_t *uinfo)
{
  uinfo->type = SNDRV_CTL_ELEM_TYPE_BOOLEAN;
  uinfo->count = CHANNELS_INPUT;
  uinfo->value.integer.min = 0;
  uinfo->value.integer.max = 1;
  return 0;
}

static int snd_ad1836_capture_mute_get(snd_kcontrol_t *kcontrol, snd_ctl_elem_value_t *ucontrol)
{
  ad1836_t *chip = snd_kcontrol_chip(kcontrol);
  int i;
  for(i=0;i<CHANNELS_INPUT;++i)
    ucontrol->value.integer.value[i] = (chip->chip_registers[ADC_CTRL_2] & ( 1 << i )) ? 1:0;
  return 0;
}

static int snd_ad1836_capture_mute_put(snd_kcontrol_t *kcontrol, snd_ctl_elem_value_t *ucontrol)
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

static int snd_ad1836_deemph_info(snd_kcontrol_t *kcontrol, snd_ctl_elem_info_t *uinfo)
{
 static const char* names[] = { "Off", "44.1kHz", "32kHz", "48kHz" };
  uinfo->type = SNDRV_CTL_ELEM_TYPE_ENUMERATED;
  uinfo->count = 1;
  if (uinfo->value.enumerated.item > 3)
    uinfo->value.enumerated.item = 3;
  strcpy(uinfo->value.enumerated.name, names[uinfo->value.enumerated.item]);
  return 0;  
}

static int snd_ad1836_deemph_get(snd_kcontrol_t *kcontrol, snd_ctl_elem_value_t *ucontrol)
{
  ad1836_t *chip = snd_kcontrol_chip(kcontrol);
  ucontrol->value.enumerated.item[0] = DAC_DEEMPH_VALUE( chip->chip_registers[DAC_CTRL_1] );
  return 0;
}

static int snd_ad1836_deemph_put(snd_kcontrol_t *kcontrol, snd_ctl_elem_value_t *ucontrol)
{
  
  ad1836_t *chip = snd_kcontrol_chip(kcontrol);
  if( ucontrol->value.enumerated.item[0] != DAC_DEEMPH_VALUE( chip->chip_registers[DAC_CTRL_1]) ){
    snd_ad1836_set_register(chip, DAC_CTRL_1, DAC_DEEMPH_MASK, ucontrol->value.enumerated.item[0] << DAC_DEEMPH_SHIFT);
    return 1;
  }
  return 0;
  
}

static int snd_ad1836_filter_info(snd_kcontrol_t *kcontrol, snd_ctl_elem_info_t *uinfo)
{
  uinfo->type = SNDRV_CTL_ELEM_TYPE_BOOLEAN;
  uinfo->count = 1;
  uinfo->value.integer.min = 0;
  uinfo->value.integer.max = 1;
  return 0;
}

static int snd_ad1836_filter_get(snd_kcontrol_t *kcontrol, snd_ctl_elem_value_t *ucontrol)
{
  ad1836_t *chip = snd_kcontrol_chip(kcontrol);
  ucontrol->value.integer.value[0] = (chip->chip_registers[ADC_CTRL_1] & ADC_HIGHPASS) ? 1:0;
  return 0;
}

static int snd_ad1836_filter_put(snd_kcontrol_t *kcontrol, snd_ctl_elem_value_t *ucontrol)
{
  ad1836_t *chip = snd_kcontrol_chip(kcontrol);
  if( ucontrol->value.integer.value[0] != ((chip->chip_registers[ADC_CTRL_1] & ADC_HIGHPASS) ? 1:0) ){
    snd_ad1836_set_register(chip, ADC_CTRL_1, ADC_HIGHPASS, (ucontrol->value.integer.value[0]?ADC_HIGHPASS:0) );
    return 1;
  }
  return 0;
}


static int snd_ad1836_diffip_info(snd_kcontrol_t *kcontrol, snd_ctl_elem_info_t *uinfo)
{
  uinfo->type = SNDRV_CTL_ELEM_TYPE_BOOLEAN;
  uinfo->count = 2;
  uinfo->value.integer.min = 0;
  uinfo->value.integer.max = 1;
  return 0;
}

static int snd_ad1836_diffip_get(snd_kcontrol_t *kcontrol, snd_ctl_elem_value_t *ucontrol)
{
  ad1836_t *chip = snd_kcontrol_chip(kcontrol);
  ucontrol->value.integer.value[0] = (chip->chip_registers[ADC_CTRL_3] & ADC_LEFT_SE ) ? 1:0;
  ucontrol->value.integer.value[1] = (chip->chip_registers[ADC_CTRL_3] & ADC_RIGHT_SE) ? 1:0;
  return 0;
}

static int snd_ad1836_diffip_put(snd_kcontrol_t *kcontrol, snd_ctl_elem_value_t *ucontrol)
{
  ad1836_t *chip = snd_kcontrol_chip(kcontrol);
  int change = 0;

  if( ucontrol->value.integer.value[0] != ((chip->chip_registers[ADC_CTRL_3] & ADC_LEFT_SE ) ? 1:0) )
    change = 1;
  if( ucontrol->value.integer.value[0] != ((chip->chip_registers[ADC_CTRL_3] & ADC_RIGHT_SE ) ? 1:0) )
    change = 1;
  if( change ){
    int val  = ucontrol->value.integer.value[0] ? ADC_LEFT_SE : 0;
    val |= ucontrol->value.integer.value[1] ? ADC_RIGHT_SE : 0;
    snd_ad1836_set_register(chip, ADC_CTRL_3, ADC_LEFT_SE|ADC_RIGHT_SE, val );
  }
  return change;
}

#ifdef CONFIG_SND_BLACKFIN_ADI1836_TDM

#define CAPTURE_SOURCE_NUMBER 2

static int snd_ad1836_mux_info(snd_kcontrol_t *kcontrol, snd_ctl_elem_info_t *uinfo)
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

static int snd_ad1836_mux_get(snd_kcontrol_t *kcontrol, snd_ctl_elem_value_t *ucontrol)
{
  ad1836_t *chip = snd_kcontrol_chip(kcontrol);

  if (chip->in_chan_mask & CAP_MIC)
    ucontrol->value.integer.value[0] = 1;
  else
    ucontrol->value.integer.value[0] = 0;

  return 0;
}

static int snd_ad1836_mux_put(snd_kcontrol_t *kcontrol, snd_ctl_elem_value_t *ucontrol)
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
static int snd_ad1836_playback_sel_info(snd_kcontrol_t *kcontrol, snd_ctl_elem_info_t *uinfo)
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

static int snd_ad1836_playback_sel_get(snd_kcontrol_t *kcontrol, snd_ctl_elem_value_t *ucontrol)
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

static int snd_ad1836_playback_sel_put(snd_kcontrol_t *kcontrol, snd_ctl_elem_value_t *ucontrol)
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

static int snd_ad1836_vu_info(snd_kcontrol_t *kcontrol, snd_ctl_elem_info_t *uinfo)
{
  uinfo->type = SNDRV_CTL_ELEM_TYPE_INTEGER;
  uinfo->count = CHANNELS_INPUT;
  uinfo->value.integer.min = -60;
  uinfo->value.integer.max = 0;
  return 0;
}


static int snd_ad1836_vu_get(snd_kcontrol_t *kcontrol, snd_ctl_elem_value_t *ucontrol)
{
  ad1836_t *chip = snd_kcontrol_chip(kcontrol);
  int i;
  for(i=0;i<CHANNELS_INPUT;++i)
    ucontrol->value.integer.value[i] = ADC_PEAK_VALUE( chip->chip_registers[ADC_PEAK_1L + i] );
  return 0;
}

static int snd_ad1836_vu_put(snd_kcontrol_t *kcontrol, snd_ctl_elem_value_t *ucontrol){ return 0; }


#define KTRL( xiface, xname, xaccess, xfuncbase ) \
     { .iface = SNDRV_CTL_ELEM_IFACE_ ## xiface, .name  = xname, .index = 0, .access = xaccess, \
       .info  = xfuncbase ## _info, .get  = xfuncbase ## _get, .put  = xfuncbase ## _put, } 

#define KTRLRW( xiface, xname, xfuncbase )  KTRL( xiface, xname, SNDRV_CTL_ELEM_ACCESS_READWRITE, xfuncbase ) 
#define KTRLRO( xiface, xname, xfuncbase )  KTRL( xiface, xname, (SNDRV_CTL_ELEM_ACCESS_READ|SNDRV_CTL_ELEM_ACCESS_VOLATILE), xfuncbase ) 

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
  KTRLRW( MIXER, "PCM Capture Differential Switch", snd_ad1836_diffip ),  /* note: off = differential, on = single ended */
#ifdef CONFIG_SND_BLACKFIN_ADI1836_TDM
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
  .info = (SNDRV_PCM_INFO_MMAP | SNDRV_PCM_INFO_INTERLEAVED |
	   SNDRV_PCM_INFO_BLOCK_TRANSFER | SNDRV_PCM_INFO_MMAP_VALID),
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
  .info = (SNDRV_PCM_INFO_MMAP | SNDRV_PCM_INFO_INTERLEAVED | 
	   SNDRV_PCM_INFO_BLOCK_TRANSFER |  SNDRV_PCM_INFO_MMAP_VALID),
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

static int snd_ad1836_playback_open(snd_pcm_substream_t* substream){

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
static int snd_ad1836_capture_open(snd_pcm_substream_t* substream){ 

  ad1836_t* chip = snd_pcm_substream_chip(substream);

  snd_printk_marker();
 
  substream->runtime->hw = snd_ad1836_capture_hw;
  chip->rx_substream = substream;

  return 0;
}


static int snd_ad1836_playback_close(snd_pcm_substream_t* substream){

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


static int snd_ad1836_capture_close(snd_pcm_substream_t* substream){

  ad1836_t* chip = snd_pcm_substream_chip(substream);

  snd_printk_marker();

  chip->rx_substream = NULL;
 
  return 0;
}



static int snd_ad1836_hw_params( snd_pcm_substream_t* substream, snd_pcm_hw_params_t* hwparams){

  /*
   *  Allocate all available memory for our DMA buffer.
   *  Necessary because we get a 4x increase in bytes for the 2 channel mode.
   *  (we lie to the ALSA midlayer through the hwparams data)
   *  We're relying on the driver not supporting full duplex mode
   *  to allow us to grab all the memory.
   */
#ifdef CONFIG_SND_BLACKFIN_ADI1836_TDM   

#ifdef MULTI_SUBSTREAM
  substream_info_t *sub_info = NULL;
  ad1836_t *chip = snd_pcm_substream_chip(substream);
  int index = find_substream(chip, substream, &sub_info);

  if (chip->rx_substream == substream) {
  	substream->runtime->dma_area = chip->rx_dma_buf;
	substream->runtime->dma_addr = (unsigned int)chip->rx_dma_buf;
	substream->runtime->dma_bytes = AD1836_BUFFER_SIZE;
  } else if (index >= 0) {
  	substream->runtime->dma_area = chip->tx_dma_buf;
	substream->runtime->dma_addr = (unsigned int)chip->tx_dma_buf;
	substream->runtime->dma_bytes = AD1836_BUFFER_SIZE;
  }
  
#else
  if( snd_pcm_lib_malloc_pages(substream, AD1836_BUFFER_SIZE) < 0 )
    return -ENOMEM;
#endif 

#else
  if( snd_pcm_lib_malloc_pages(substream, params_buffer_bytes(hwparams)) < 0 )
    return -ENOMEM;
#endif

  return 0;

}

static int snd_ad1836_hw_free(snd_pcm_substream_t * substream){
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
 
  while(sub_info->boundary * 2 <= (LONG_MAX - DMA_BUFFER_FRAMES * sub_info->buffer_frames)) {
  	sub_info->boundary *= 2;
  }
  sub_info->dma_offset = 0;
#else
  snd_assert( (substream == chip->tx_substream), return -EINVAL );
#endif

  snd_printk_marker();
  snd_printd(KERN_INFO "%s channels:%d, period_bytes:0x%x, periods:%d\n",
  		__FUNCTION__, runtime->channels, frames_to_bytes(runtime, runtime->period_size)
		, runtime->periods);
#ifndef MULTI_SUBSTREAM
#ifdef CONFIG_SND_BLACKFIN_ADI1836_TDM
  fragsize_bytes /= runtime->channels;
  fragsize_bytes *= 8;				/* inflate the fragsize to match */
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
#ifdef CONFIG_SND_BLACKFIN_ADI1836_TDM
  fragsize_bytes /= runtime->channels;
  fragsize_bytes *= 8;				/* inflate the fragsize to match */
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
	  bf53x_sport_hook_tx_desc(chip->sport, 0);
	  if (!chip->runmode) {
	  	bf53x_sport_hook_rx_desc(chip->sport, 1);
		bf53x_sport_start(chip->sport);
	  }
          chip->tx_dma_started = 1;
      }
      chip->runmode |= 1 << (index + 1);
      sub_info->dma_offset = chip->dma_pos;
//      printk("start tx:%d,%lx\n", index, sub_info->dma_offset); 
#else    
      bf53x_sport_hook_tx_desc(chip->sport, 0);
      if(!chip->runmode) {
      	 bf53x_sport_hook_rx_desc(chip->sport, 1);
	 bf53x_sport_start(chip->sport);
      }
      chip->runmode |= RUN_TX;
#endif
    break;
  case SNDRV_PCM_TRIGGER_STOP:
#ifdef MULTI_SUBSTREAM
      chip->runmode &= ~ (1 << (index +1));
      if (!(chip->runmode & RUN_TX_ALL)) {
        chip->tx_dma_started = 0;
	if (!chip->runmode)
		bf53x_sport_stop(chip->sport);
	else
		bf53x_sport_hook_tx_desc(chip->sport, 1);
//	printk("stop tx\n"); 
      }
#else
      chip->runmode &= ~RUN_TX;
      if (!chip->runmode)
      	bf53x_sport_stop(chip->sport);
      else
        bf53x_sport_hook_tx_desc(chip->sport, 1);
/*      printk("stop tx\n");*/
#endif
    break;
  default:
    spin_unlock(&chip->ad1836_lock);
    return -EINVAL;
  }
  spin_unlock(&chip->ad1836_lock);
  
  snd_printd(KERN_INFO"cmd:%s,runmode:0x%x\n", cmd?"start":"stop", chip->runmode);
  return 0;
}

static int snd_ad1836_capture_trigger( snd_pcm_substream_t* substream, int cmd)
{

  ad1836_t* chip = snd_pcm_substream_chip(substream);

  spin_lock(&chip->ad1836_lock);
  snd_assert(substream == chip->rx_substream, return -EINVAL);
  switch(cmd){
  case SNDRV_PCM_TRIGGER_START: 
      bf53x_sport_hook_rx_desc(chip->sport, 0);
      if (!chip->runmode) { /* Sport isn't running  */
	bf53x_sport_hook_tx_desc(chip->sport, 1);
	bf53x_sport_start(chip->sport);
      }
      chip->runmode |= RUN_RX;
//    printk("start rx\n");
    break;
  case SNDRV_PCM_TRIGGER_STOP:
      chip->runmode &= ~RUN_RX;
      if (!chip->runmode) {
      	bf53x_sport_stop(chip->sport);
      } else 
	bf53x_sport_hook_rx_desc(chip->sport, 1);
//      printk("stop rx\n");
    break;
  default:
    spin_unlock(&chip->ad1836_lock);
    return -EINVAL;
  }
  spin_unlock(&chip->ad1836_lock);

//  printk(KERN_ERR"cmd:%s,runmode:0x%x\n", cmd?"start":"stop", chip->runmode); 
  return 0;
}

static snd_pcm_uframes_t snd_ad1836_playback_pointer( snd_pcm_substream_t* substream )
{
  ad1836_t* chip = snd_pcm_substream_chip(substream);
  snd_pcm_runtime_t* runtime = substream->runtime;

  char* buf  = (char*) runtime->dma_area;
  char* curr = (char*) bf53x_sport_curr_addr_tx(chip->sport);
  unsigned long diff = curr - buf;
#ifdef CONFIG_SND_BLACKFIN_ADI1836_TDM
  unsigned long bytes_per_frame = 8*4;	/* always 8 channels in the DMA frame */
#else
  unsigned long bytes_per_frame = runtime->frame_bits/8;
#endif
  size_t frames = diff / bytes_per_frame;
  
#ifdef MULTI_SUBSTREAM
  substream_info_t *sub_info = NULL;
  find_substream(chip, substream, &sub_info);
  frames = (frames + DMA_BUFFER_FRAMES - sub_info->dma_offset) % DMA_BUFFER_FRAMES;

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

  return frames;
}


static snd_pcm_uframes_t snd_ad1836_capture_pointer( snd_pcm_substream_t* substream ){

  ad1836_t* chip = snd_pcm_substream_chip(substream);
  snd_pcm_runtime_t* runtime = substream->runtime;

  char* buf  = (char*) runtime->dma_area;
  char* curr = (char*) bf53x_sport_curr_addr_rx(chip->sport);
  unsigned long diff = curr - buf;
#ifdef CONFIG_SND_BLACKFIN_ADI1836_TDM 
  unsigned long bytes_per_frame = 8*4;	/* always 8 channels in the DMA frame */
#else
  unsigned long bytes_per_frame = runtime->frame_bits/8;
#endif
  size_t frames = diff / bytes_per_frame;
  
#ifdef CONFIG_SND_DEBUG_CURRPTR
  snd_printk( KERN_INFO " capture pos: 0x%04lx / %lx\n", frames, runtime->buffer_size);
#endif 

  /* the loose syncing used here is accurate enough for alsa, but 
     due to latency in the dma, the following may happen occasionally, 
     and pcm_lib shouldn't complain */
  if( frames >= runtime->buffer_size ) 
    frames = 0;

  return frames;

}

#ifdef CONFIG_SND_BLACKFIN_ADI1836_TDM

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
  
  if (index > 0 && index <=2 && !(chip->runmode & (1<<(index+1)))) {
	sub_info->data_count += count;
	return 0;
  }
  
  start = (sub_info->data_pos_base + pos + sub_info->dma_offset) % DMA_BUFFER_FRAMES;
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
#ifdef CONFIG_SND_DEBUG_CURRPTR
  snd_printd(KERN_INFO "playback_copy: src %p, pos %x, count %x\n", src, (uint)pos, (uint)count);
#endif
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
  return 0;
}

static int snd_ad1836_capture_copy(snd_pcm_substream_t *substream, int channel, snd_pcm_uframes_t pos, void *dst, snd_pcm_uframes_t count){
  ad1836_t *chip = snd_pcm_substream_chip(substream);
  unsigned int *src = (unsigned int *)substream->runtime->dma_area;
  unsigned int *idst = dst;
  unsigned int mask;
  if (chip->in_chan_mask)
  	mask = chip->in_chan_mask;
  else
  	mask = in_chan_masks[substream->runtime->channels/2 - 1];
#ifdef CONFIG_SND_DEBUG_CURRPTR
  snd_printd(KERN_INFO "capture_copy: dst %p, pos %x, count %x\n", dst, (uint)pos, (uint)count);
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

#elif defined(CONFIG_SND_BLACKFIN_ADI1836_I2S)

static int snd_ad1836_playback_copy(snd_pcm_substream_t *substream, int channel, snd_pcm_uframes_t pos, void *src, snd_pcm_uframes_t count)
{
	int i, curr;
	unsigned long *ldst, *lsrc;
	
	ldst = (unsigned long *)substream->runtime->dma_area;
	lsrc = src;

	snd_printd(KERN_INFO "playback_copy: src %p, pos %x, count %x\n", src, (uint)pos, (uint)count);
	i = frames_to_bytes(substream->runtime, count) / sizeof(unsigned long);
	curr = frames_to_bytes(substream->runtime, pos)/ sizeof(unsigned long);
	/* assumes tx DMA buffer initialised with zeros */
//	memcpy(ldst + frames_to_bytes(substream->runtime, pos), src, frames_to_bytes(substream->runtime, count));
	while(i--) {
		/* Hardware support only 24 bits, remove the lowest byte*/
		*(ldst + curr + i) = *(lsrc + i)>>8;
	}
//	print_32x4((dst + frames_to_bytes(substream->runtime, pos)));
	return 0;
}

static int snd_ad1836_capture_copy(snd_pcm_substream_t *substream, int channel, snd_pcm_uframes_t pos, void *dst, snd_pcm_uframes_t count)
{
	int i, curr;
	unsigned long *lsrc , *ldst;
	
	lsrc = (unsigned long *)substream->runtime->dma_area;
	ldst = dst;

	snd_printd(KERN_INFO "capture_copy: dst %p, pos %x, count %x\n", dst, (uint)pos, (uint)count);
	i = frames_to_bytes(substream->runtime, count) / sizeof(unsigned long);
	curr = frames_to_bytes(substream->runtime, pos) / sizeof(unsigned long);

//	print_32x4((lsrc + (frames_to_bytes(substream->runtime, pos)/4)));
//	memcpy(ldst, lsrc + frames_to_bytes(substream->runtime, pos), frames_to_bytes(substream->runtime, count));
	while(i--) {
		/* The highest byte is invalid, remove it */
		*(ldst + i) = *(lsrc + i + curr)<<8;
	}

	return 0;
}
#endif

static int snd_ad1836_playback_silence(snd_pcm_substream_t *substream, int channel, snd_pcm_uframes_t pos, snd_pcm_uframes_t count){

#ifdef CONFIG_SND_BLACKFIN_ADI1836_TDM
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


static int snd_ad1836_capture_silence(snd_pcm_substream_t *substream, int channel, snd_pcm_uframes_t pos, snd_pcm_uframes_t count){
  unsigned char *buf = substream->runtime->dma_area;

#ifdef CONFIG_SND_DEBUG
  snd_printk(KERN_INFO "silence: pos %x, count %x\n", (uint)pos, (uint)count);
#endif
#ifdef CONFIG_SND_BLACKFIN_ADI1836_TDM
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


/* chip-specific destructor
 * (see "PCI Resource Managements")
 */
static int snd_ad1836_free(ad1836_t *chip)
{
  
  if( chip->spi ) {
    snd_ad1836_set_register(chip, DAC_CTRL_2, DAC_MUTE_MASK, DAC_MUTE_MASK);  /* mute DAC's */
    snd_ad1836_set_register(chip, ADC_CTRL_2, ADC_MUTE_MASK, ADC_MUTE_MASK);  /* mute ADC's */
    snd_ad1836_set_register(chip, DAC_CTRL_1, DAC_PWRDWN, DAC_PWRDWN);  /* power-down DAC's */
    snd_ad1836_set_register(chip, ADC_CTRL_1, ADC_PWRDWN, ADC_PWRDWN);  /* power-down ADC's */
  }
  
  kfree(chip);
  return 0;
}

/* component-destructor, wraps snd_ad1836_free for use in snd_device_ops_t
 */
static int snd_ad1836_dev_free(snd_device_t *device)
{
  ad1836_t *chip = (ad1836_t *)device->device_data;

#ifdef MULTI_SUBSTREAM
  dma_free_coherent(NULL, AD1836_BUFFER_SIZE, chip->rx_dma_buf, 0);
  dma_free_coherent(NULL, AD1836_BUFFER_SIZE, chip->tx_dma_buf, 0);
#endif
  return snd_ad1836_free(chip);
}

static snd_device_ops_t snd_ad1836_ops = {
  .dev_free = snd_ad1836_dev_free,
};


static int snd_bf53x_adi1836_reset(ad1836_t *chip)
{
#if defined(CONFIG_BFIN533_EZKIT)
  /*
   *  On the EZKIT, the reset pin of the adi1836 is connected
   *  to a programmable flag pin on one of the flash chips.
   *  This code configures the flag pin and toggles it to
   *  reset the adi1836 chip.  After reset, the chip takes
   *  4500 cycles of MCLK @ 12.288MHz to recover, ie 367us.
   *  Thanks to Joep Duck, Aidan Williams.
   *
   *  ADI 1836A data sheet:
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
#define pFlashA_PortA_Dir	(volatile unsigned char *)0x20270006
#define pFlashA_PortA_Data	(volatile unsigned char *)0x20270004

  *pFlashA_PortA_Dir = 0x1;	/* configure flag as an output pin */

  snd_printk( KERN_INFO "resetting ezkit 1836 using flash flag pin\n" );
  *pFlashA_PortA_Data = 0x0;	/* reset is active low */
  udelay(1);			/* hold low */

#if 0
  /* 256x fs is the default upon reset */
  if (chip) {
    if (snd_ad1836_set_register(chip, ADC_CTRL_3, ADC_CLOCK_MASK, ADC_CLOCK_512))
      snd_printk( KERN_ERR "failed to set clock mode 512x fs\n");
  }
#endif

  *pFlashA_PortA_Data = 0x1;	/* re-enable */
  udelay(400);			/* 4500 MCLK recovery time */

#endif /* CONFIG_BFIN533_EZKIT */

  return 0;
}

#ifdef CONFIG_SND_BLACKFIN_ADI1836_TDM
static int snd_ad1836_startup(ad1836_t *chip)
{
	int err = 0;
	struct bf53x_sport *sport= chip->sport;

	snd_bf53x_adi1836_reset(chip);

	/* see if we are connected by writing (preferably something useful)
	 * to the chip, and see if we get an IRQ */
	err = err || snd_ad1836_set_register(chip, DAC_CTRL_1, DAC_PWRDWN, 0);  /* power-up DAC's */
	err = err || snd_ad1836_set_register(chip, ADC_CTRL_1, ADC_PWRDWN, 0);  /* power-up ADC's */

	/* sport in aux/slave mode cf daughtercard schematics */
	err = err || snd_ad1836_set_register(chip, ADC_CTRL_2, (ADC_AUX_MASTER|ADC_SOUT_MASK | ADC_MUTE_MASK),  
			( /*ADC_AUX_MASTER|*/ ADC_SOUT_PMAUX));  
#ifdef ADC2_IS_MIC
	err = err || snd_ad1836_set_register(chip, ADC_CTRL_3, ADC_MODE_MASK, \
			ADC_LEFT_SE | ADC_RIGHT_SE | ADC_LEFT_MUX | ADC_RIGHT_MUX);
#endif
	err = err || snd_ad1836_set_register(chip, DAC_CTRL_2, DAC_MUTE_MASK, 0);  /* power-up ADC's */
	/* set volume to full scale, (you might assume these won't fail anymore) */
	err = err || snd_ad1836_set_register(chip, DAC_VOL_1L, DAC_VOL_MASK, DAC_VOL_MASK);
	err = err || snd_ad1836_set_register(chip, DAC_VOL_1R, DAC_VOL_MASK, DAC_VOL_MASK);
	err = err || snd_ad1836_set_register(chip, DAC_VOL_2L, DAC_VOL_MASK, DAC_VOL_MASK);
	err = err || snd_ad1836_set_register(chip, DAC_VOL_2R, DAC_VOL_MASK, DAC_VOL_MASK);
	err = err || snd_ad1836_set_register(chip, DAC_VOL_3L, DAC_VOL_MASK, DAC_VOL_MASK);
	err = err || snd_ad1836_set_register(chip, DAC_VOL_3R, DAC_VOL_MASK, DAC_VOL_MASK);
	if(err){
		snd_printk( KERN_ERR "Unable to set chip registers.\n");    
		snd_ad1836_free(chip);
		return -ENODEV;
	}
	bf53x_sport_stop(sport);
	err = err || bf53x_sport_config_rx(sport, RFSR, 0x1f /* 32 bit word len */, 0, 0 );
	err = err || bf53x_sport_config_tx(sport, TFSR, 0x1f /* 32 bit word len */, 0, 0 );
	err = err || bf53x_sport_set_multichannel(sport, 8 /* channels */, 1 /* packed */ );
	err = err || sport_config_rx_dummy( sport, 4 );
	err = err || sport_config_tx_dummy( sport, 4 );

	if(err)
		snd_printk( KERN_ERR "Unable to set sport configuration\n");

#ifdef MULTI_SUBSTREAM
	err = bf53x_sport_config_tx_dma(chip->sport, chip->tx_dma_buf, 
			DMA_PERIODS, DMA_PERIOD_BYTES, 4);
#endif

	return err;
}

#elif defined(CONFIG_SND_BLACKFIN_ADI1836_I2S)
static int snd_ad1836_startup(ad1836_t *chip)
{
	int err;
	struct bf53x_sport *sport= chip->sport;

	snd_bf53x_adi1836_reset(chip);

	err = err || snd_ad1836_set_register(chip, DAC_CTRL_1, DAC_PWRDWN, 0);  /* power-up DAC's */
	err = err || snd_ad1836_set_register(chip, ADC_CTRL_1, ADC_PWRDWN, 0);  /* power-up ADC's */

	/* sport in aux/slave mode cf daughtercard schematics */
	err = snd_ad1836_set_register(chip, DAC_CTRL_1, (DAC_DATA_MASK), (DAC_DATA_24));
	err = err || snd_ad1836_set_register(chip, DAC_CTRL_2, (DAC_MUTE_MASK), (DAC_MUTE_DAC2|DAC_MUTE_DAC3));
	err = err || snd_ad1836_set_register(chip, ADC_CTRL_2, (ADC_AUX_MASTER|ADC_SOUT_MASK|ADC_MUTE_MASK|ADC_DATA_MASK),
			(ADC_AUX_MASTER | ADC_SOUT_I2S | ADC_MUTE_ADC2 | ADC_DATA_24));  
	/* set volume to full scale */
	err = err || snd_ad1836_set_register(chip, DAC_VOL_1L, DAC_VOL_MASK, DAC_VOL_MASK);
	err = err || snd_ad1836_set_register(chip, DAC_VOL_1R, DAC_VOL_MASK, DAC_VOL_MASK);
	if(err){
		snd_printk( KERN_ERR "Unable to set chip registers.\n");    
		snd_ad1836_free(chip);
		return -ENODEV;
	}
	bf53x_sport_stop(sport);
	err = err || bf53x_sport_config_rx(sport, (RCKFE | RFSR), (RSFSE | 0x17) /* 24 bit word len */, 0, 0 );
	err = err || bf53x_sport_config_tx(sport, (TCKFE | TFSR), (TSFSE | 0x17) /* 24 bit word len */, 0, 0 );	
	err = err || sport_config_rx_dummy( sport, 4 );
	err = err || sport_config_tx_dummy( sport, 4 );
	if(err)
		snd_printk( KERN_ERR "Unable to set sport configuration\n");

	return err;
}
#endif

/* create the card struct, 
 *   add - low-level device, 
 *       - spi sport and registers, 
 *       - a proc entry, 
 *       - and a pcm device 
 */

static int __devinit snd_ad1836_create(snd_card_t *card,
				       struct ad1836_spi* spi, 
				       struct bf53x_sport* sport, 
				       ad1836_t **rchip)
{
  
  ad1836_t *chip;
  int err,i;
  
  *rchip = NULL;
  
  /* spi and sport availability have been ensured by caller (the module init) */
  
  /* allocate a chip-specific data with magic-alloc */
  chip = (ad1836_t*)kcalloc(1, sizeof(ad1836_t), GFP_KERNEL);
  if (chip == NULL)
    return -ENOMEM;
  
  chip->card  = card;
  chip->spi   = spi;
  chip->sport = sport;
  spin_lock(&chip->ad1836_lock);
#ifdef MULTI_SUBSTREAM
  memset(chip->tx_substreams, 0, 3*sizeof(substream_info_t));
  chip->dma_pos = 0;
  chip->tx_dma_started = 0;
  chip->rx_dma_buf = NULL;
  chip->tx_dma_buf = NULL;
#endif
  
  init_waitqueue_head(&chip->spi_waitq);
  
  chip->spi_data_ready = 0;

  snd_ad1836_reset_spi_stats(chip);

  for(i=0; i<16; ++i)
    chip->chip_registers[i] = (i<<12);
  
  for(i=ADC_PEAK_1L; i<=ADC_PEAK_2R; ++i)
    chip->chip_registers[i] |= ADC_READ;
  
#if L1_DATA_A_LENGTH != 0
  if ((sport->dummy_buf=l1_data_A_sram_alloc(DUMMY_BUF_LEN)) == 0) {
#else
  if ((sport->dummy_buf=(unsigned long)kmalloc(DUMMY_BUF_LEN, GFP_KERNEL)) == NULL) {
#endif
	snd_printk( KERN_ERR "Unable to allocate dummy buffer in sram\n");
	snd_ad1836_free(chip);
	return -ENODEV;
  }
  
  memset((void*)sport->dummy_buf, 0, DUMMY_BUF_LEN);
//  snd_printk(KERN_INFO "dummy_buf:0x%lx\n", sport->dummy_buf);
#ifdef MULTI_SUBSTREAM
{
	dma_addr_t addr;
	chip->rx_dma_buf = dma_alloc_coherent(NULL, AD1836_BUFFER_SIZE, &addr, 0);
	chip->tx_dma_buf = dma_alloc_coherent(NULL, AD1836_BUFFER_SIZE, &addr, 0);
	if (!chip->rx_dma_buf || !chip->tx_dma_buf) {
		printk("Failed to allocate DMA buffer\n");
		return -ENOMEM;
	} 
}
#endif

//#ifdef CONFIG_SND_BLACKFIN_ADI1836_TDM
#if 0
  /* set the chan mask of the output stream */
  ad1836_set_chan_masks(chip, "0123", 1);
  /* set the chan mask of the input stream */
  ad1836_set_chan_masks(chip, "0123", 0);
#endif

  err = snd_device_new(card, SNDRV_DEV_LOWLEVEL, chip, &snd_ad1836_ops);

  if(!err){
    snd_info_entry_t* proc_entry;
    err = snd_card_proc_new(card, "registers", &proc_entry); 
    if(!err)
      snd_info_set_text_ops( proc_entry, chip, 1024, snd_ad1836_proc_registers_read);
      proc_entry->mode = S_IFREG | S_IRUGO | S_IWUSR;
      proc_entry->c.text.write_size = 8;
      proc_entry->c.text.write = snd_ad1836_proc_registers_write;
  }

  if(!err){
    snd_info_entry_t* proc_entry;
    err = snd_card_proc_new(card, "spi", &proc_entry); 
    if(!err)
      snd_info_set_text_ops( proc_entry, chip, 1024, snd_ad1836_proc_spi_read);
  }

  if(!err){
    snd_info_entry_t* proc_entry;
    err = snd_card_proc_new(card, "sport", &proc_entry); 
    if(!err)
      snd_info_set_text_ops( proc_entry, chip, 1024, snd_ad1836_proc_sport_read);
  }

//#ifdef CONFIG_SND_BLACKFIN_ADI1836_TDM
#if 0
  if(!err){
    snd_info_entry_t* proc_entry;
    err = snd_card_proc_new(card, "out_chan_mask", &proc_entry); 
    if(!err){
      snd_info_set_text_ops( proc_entry, chip, 1024, snd_ad1836_proc_outchanmask_read);
      proc_entry->mode = S_IFREG | S_IRUGO | S_IWUSR;
      proc_entry->c.text.write_size = 5;
      proc_entry->c.text.write = snd_ad1836_proc_outchanmask_write;
    }
  }

  if(!err){
    snd_info_entry_t* proc_entry;
    err = snd_card_proc_new(card, "in_chan_mask", &proc_entry); 
    if(!err){
      snd_info_set_text_ops( proc_entry, chip, 1024, snd_ad1836_proc_inchanmask_read);
      proc_entry->mode = S_IFREG | S_IRUGO | S_IWUSR;
      proc_entry->c.text.write_size = 5;
      proc_entry->c.text.write = snd_ad1836_proc_inchanmask_write;
    }
  }
#endif

#ifndef NOCONTROLS
  if(!err)
    for( i=0; (i<AD1836_CONTROLS) && !err; ++i )
      err = snd_ctl_add(card, snd_ctl_new1(&(snd_ad1836_controls[i]), chip));
#endif

  if(!err){
    snd_pcm_t* pcm;
    /* 1 playback and 1 capture substream, of 2-8 channels each */
#ifdef MULTI_SUBSTREAM
    err = snd_pcm_new(card, CHIP_NAME, 0, 3, 1, &pcm);
#else
    err = snd_pcm_new(card, CHIP_NAME, 0, 1, 1, &pcm);
#endif
    if(!err){
      pcm->private_data = chip;
      chip->pcm = pcm;
      strcpy(pcm->name, CHIP_NAME);
      snd_pcm_set_ops(pcm, SNDRV_PCM_STREAM_PLAYBACK, &snd_ad1836_playback_ops);
      snd_pcm_set_ops(pcm, SNDRV_PCM_STREAM_CAPTURE,  &snd_ad1836_capture_ops);
      
#ifndef MULTI_SUBSTREAM
      /* uncached DMA buffers */
      snd_pcm_lib_preallocate_pages_for_all(chip->pcm, SNDRV_DMA_TYPE_DEV,NULL,
      				AD1836_BUFFER_SIZE, AD1836_BUFFER_SIZE);
      snd_assert( ((ad1836_t*)(pcm->private_data))->pcm == pcm, panic("inconsistency") );
#endif
    }
  }

  if(err) {
    bf53x_sport_stop(sport);
#if L1_DATA_A_LENGTH != 0
//    l1_data_A_sram_free((unsigned long)sport->dummy_buf_rx);
    l1_data_A_sram_free((unsigned long)sport->dummy_buf);
#else
//    kfree(dummy_buf_rx);
    kfree(dummy_buf);
#endif

    snd_ad1836_free(chip);
    return err;
  }

  *rchip = chip;
  return 0;
  
}



/************************************************************* 
 *                 ALSA Card Level 
 *************************************************************/


/* probe for an ad1836 connected to spi and sport, and initialize *the_card */

static int __devinit snd_bf53x_adi1836_probe(struct ad1836_spi** spi, 
					     struct bf53x_sport* sport, 
					     snd_card_t** the_card)
{

  static int dev=0;
  snd_card_t *card;   
  ad1836_t *chip;    
  int err;

  if (dev >= SNDRV_CARDS)  return -ENODEV;

  if (!enable[dev]) {
    dev++;
    return -ENOENT;
  }


  card = snd_card_new( index[dev], id[dev], THIS_MODULE, 0 );
  if( card == NULL ) 
    return -ENOMEM;

 if( !(*spi = ad1836_spi_init())) {
    snd_card_free(card);
    return -EFAULT;
  }

  if( (err = snd_ad1836_create(card, *spi, sport, &chip)) < 0 ) {
    snd_card_free(card);
    return err;
  }

  card->private_data = (void*) chip;

  snd_assert( ((ad1836_t*)(card->private_data))->card == card, panic("inconsistency") );

  if ((err= snd_ad1836_startup(chip))<0) {
    snd_card_free(card);
    return err;
  }
  strcpy(card->driver, "adi1836");
  strcpy(card->shortname, CHIP_NAME);
  sprintf(card->longname, "%s at SPORT%d rx/tx dma %d/%d err irq /%d ", 
	  card->shortname,
	  CONFIG_SND_BLACKFIN_SPORT,          /* and we set them ourselves below anyway */
	  CONFIG_SND_BLACKFIN_SPORT_DMA_RX,
	  CONFIG_SND_BLACKFIN_SPORT_DMA_TX,
	  CONFIG_SND_BLACKFIN_SPORT_IRQ_ERR
	  );

  if ((err = snd_card_register(card)) < 0) {
    snd_card_free(card);
    return err;
  }

  *the_card = card;
  ++dev;

  return 0;
}


static __devexit void snd_bf53x_adi1836_remove(snd_card_t* card){

  snd_card_free(card);

  return;
}

#ifdef CONFIG_SND_DEBUG
/*
 *  Print data byte by byte without endianness getting in the way
 */
void print_32x4(void *data)
{
  unsigned char *p = (unsigned char *)data;
  snd_printk( KERN_INFO
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

/*
 *  Print the last 16 bits of 8 longs byte by byte
 */
void print_16x8(void *data)
{
  unsigned char *p = (unsigned char *)data;
  snd_printk( KERN_INFO
	"%02x%02x %02x%02x "
	"%02x%02x %02x%02x "
	"%02x%02x %02x%02x "
	"%02x%02x %02x%02x "
	"\n",
	 p[2],  p[3],  p[6],  p[7],
	p[10], p[11], p[14], p[15],
	p[18], p[19], p[22], p[23],
	p[26], p[27], p[30], p[31]
	);
}
#endif //CONFIG_SND_DEBUG
/*
 *  Square fill.
 *  Fill sequence: {256 max values, 256 min values}
 */
void square_fill(void *data, size_t size)
{
  int i;
  static unsigned int period = 0;
  int *idata = data;

  if (size < 512) {
    snd_printk( KERN_INFO "ack, size < 512 bytes!\n" );
    return;
  }

  for (i=0; i < size/sizeof(int); i++) {
    idata[i] = (period & 256) ? 0x00000000 : 0x7fffff00;
    ++period;
  }
}

static inline void* frag2addr( void* buf, int frag, size_t fragsize_bytes){
  char* addr = buf;
  return addr + frag*fragsize_bytes;
}

/* sport irq handler, called directly from module level */
static irqreturn_t snd_adi1836_sport_handler_rx(ad1836_t* chip, int irq){
  
  unsigned int rx_stat;
    
  ++(chip->sport_irq_count);
  
  bf53x_sport_check_status( chip->sport, NULL, &rx_stat, NULL );  
    
  if( !(rx_stat & DMA_DONE) ) {
    snd_printk(KERN_ERR"Error - Receive DMA is already stopped\n");
    return IRQ_HANDLED;
  }
        
  ++(chip->sport_irq_count_rx);
  
  if( (chip->rx_substream) && (chip->runmode & RUN_RX )) {
    /*square_fill(chip->rx_substream->runtime->dma_area, chip->rx_substream->runtime->dma_bytes);*/
    /*print_16x8(chip->rx_substream->runtime->dma_area);*/
    snd_pcm_period_elapsed(chip->rx_substream);
  }

  return IRQ_HANDLED;

} /* sport handler rx */
  
static irqreturn_t snd_adi1836_sport_handler_tx(ad1836_t* chip, int irq){

  unsigned int tx_stat;

  ++(chip->sport_irq_count);
  
  bf53x_sport_check_status( chip->sport, NULL, NULL, &tx_stat );  
  
  if( !(tx_stat & DMA_DONE)) {
    snd_printk(KERN_ERR"Error - Transfer DMA is already stopped\n");
    return IRQ_HANDLED;
  }

  ++(chip->sport_irq_count_tx);

#ifdef MULTI_SUBSTREAM
{
  int index;
  substream_info_t *sub_info = NULL;
  
  chip->dma_pos = (chip->dma_pos + DMA_PERIOD_FRAMES) % DMA_BUFFER_FRAMES;
  for(index = 0; index < 3; index++) {
  	sub_info = &chip->tx_substreams[index];
  	if (sub_info->substream && chip->runmode & (1<<(index+1))) {
		sub_info->dma_inter_pos += DMA_PERIOD_FRAMES;
		if (sub_info->dma_inter_pos >= sub_info->boundary)
			sub_info->dma_inter_pos -= sub_info->boundary;
	
		if(sub_info->dma_inter_pos >= sub_info->next_inter_pos) {
			snd_pcm_period_elapsed(sub_info->substream);
			sub_info->next_inter_pos += sub_info->period_frames;
			if (sub_info->next_inter_pos >= sub_info->boundary)
				sub_info->next_inter_pos -= sub_info->boundary;
		}
	}
  }
}
#else
  if( (chip->tx_substream) && (chip->runmode & RUN_TX)) {
    snd_pcm_period_elapsed(chip->tx_substream);
    /*square_fill(chip->tx_substream->runtime->dma_area, chip->tx_substream->runtime->dma_bytes);*/
    /*print_16x8(chip->tx_substream->runtime->dma_area);*/
  }
#endif

  return IRQ_HANDLED;
  
} /* sport handler tx */

/* ************************************************************
 * Module level
 *
 * tie the spi, the sport and the card into a module
 * this module probes for 1 chip, connected to the 
 * SPORT configured at compile time, and to the SPI.
 * this assumes this sound driver is the only one 
 * using the SPI.  
 *
 * TODO: move the spi and sport api's to arch/blackfin
 *
 *************************************************************/


MODULE_AUTHOR("Luuk van Dijk <blackfin@mndmttr.nl>");
MODULE_DESCRIPTION("BF53x/ADI 1836");
MODULE_LICENSE("GPL");


static struct ad1836_spi*   spi=NULL;
static struct bf53x_sport* sport=NULL;
static snd_card_t*         card=NULL;



static irqreturn_t sport_handler_rx(int irq, void *dev_id, struct pt_regs *regs){
  /*  snd_printk( KERN_INFO "in module sport handler\n" );  */
  if(card) 
    return snd_adi1836_sport_handler_rx( (ad1836_t*)(card->private_data), irq );
  return IRQ_NONE;
}

static irqreturn_t sport_handler_tx(int irq, void *dev_id, struct pt_regs *regs){
  /*  snd_printk( KERN_INFO "in module sport handler\n" );  */
  if(card) 
    return snd_adi1836_sport_handler_tx( (ad1836_t*)(card->private_data), irq );
  return IRQ_NONE;
}

static irqreturn_t sport_error_handler(int irq, void *dev_id, struct pt_regs *regs){

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


/* idempotent cleanup, used in __init as well, so no __exit */
/* TODO: should release dma and irq's */

static void __exit  snd_bf53x_adi1836_exit(void)
{

  free_irq(CONFIG_SND_BLACKFIN_SPORT_IRQ_ERR, &card);

  if( card ){
    snd_card_t*  tmp_card = card;
    card = NULL;
    snd_bf53x_adi1836_remove(tmp_card);
  }

  if( sport ){
    struct bf53x_sport* tmp_sport = sport;
    sport = NULL;
    bf53x_sport_done( tmp_sport );
  }

  if( spi ){
    struct ad1836_spi* tmp_spi = spi;
    spi=NULL;
    ad1836_spi_done(tmp_spi);
  }

  return;

}


/* TODO: failure to alloc spi or sport should release dma and irq's */
static int __init snd_bf53x_adi1836_init(void){
  
  int err;
  
  if( (sport = bf53x_sport_init(CONFIG_SND_BLACKFIN_SPORT,  
				CONFIG_SND_BLACKFIN_SPORT_DMA_RX, sport_handler_rx,
				CONFIG_SND_BLACKFIN_SPORT_DMA_TX, sport_handler_tx ) ) == NULL ){ 
    snd_bf53x_adi1836_exit();
    return -ENOMEM;
  }

  /* further configuration of the sport is in the device constuctor */
  if( request_irq(CONFIG_SND_BLACKFIN_SPORT_IRQ_ERR, &sport_error_handler, SA_SHIRQ, "SPORT Error", &card ) ){
    snd_printk( KERN_ERR "Unable to allocate sport error IRQ %d\n", CONFIG_SND_BLACKFIN_SPORT_IRQ_ERR);
    snd_bf53x_adi1836_exit();
    return -ENODEV;
  }

  /* sport_init() requested the dma channel through the official api, 
   * but we override the irq, because 
   * the implementation in blackfin/kernel/dma.c adds a lot of overhead, 
   * without actually solving any problem for us.  
   */

  err = snd_bf53x_adi1836_probe(&spi, sport, &card);

  if(err)
    snd_bf53x_adi1836_exit();

  return err;

}


module_init(snd_bf53x_adi1836_init);
module_exit(snd_bf53x_adi1836_exit);
