#ifndef ADI_1836_DRIVER_H
#define ADI_1836_DRIVER_H

//--------------------------------------------------------------------------//
// Header files																//
//--------------------------------------------------------------------------//
#ifdef LINUX
#include <linux/module.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/ioport.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/sound.h>
#include <linux/slab.h>
#include <linux/soundcard.h>
#include <asm/io.h>
#include <asm/dma.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <asm/uaccess.h>
#include <asm/hardirq.h>
#include <asm/irq.h>
#include <linux/devfs_fs_kernel.h>
#else
#include "linuxcompat.h"
#endif
#include <cdefBF533.h>
#include <sysreg.h>

// When a /dev/dsp is opened, a adi_sport_1836_instance is
// created. Each /dev/dsp instance can be mapped to one or
// more 1836 channels
struct adi_sport_1836_instance{
	unsigned int channels_used; // default to 1, if stereo use 2, more can be set
	struct adi_sport_1836_channel **physical_channels; // the physical channels used
	unsigned int mode; // read / write
};

/* TODO : an instance of the adi_sport_1836_channel */
/* current_buffer_pointer points to the current position in the circular buffer */
/* queue flag for reads / writes to wait on */
struct adi_sport_1836_channel{
  unsigned int      current_buffer_position; // index into dma buffer
  volatile int   *dma_buffer; // read or write buffer
  wait_queue_head_t wait;           // head_t
  unsigned int      slot;    // slot to this channel in the SPORT-1836 TDM frame
  unsigned int      virt;    // virtual channel number assigned to this
  unsigned int      used;    // set to true when opened, wait would be defined
  unsigned int      mode;    // open mode, FMODE_READ or FMODE_WRITE
};

#define SPORT_FRAME_SIZE 8

/* adi_sport_1836_card actually in our case represents a 1836 chip.
   We have called it a card for uniformity with the PCI world.
   We dont expect multiple "cards" either.
*/
#define SPORT_TDM

struct adi_sport_1836_card {
#ifdef SPORT_TDM /* upto 3 stereo pairs of 48kHz channels */
#define MAX_DAC_CHANNELS 6
#define MAX_ADC_CHANNELS 4
#define MAX_DAC_RATE 48000
#define MAX_ADC_RATE 48000
#else /* I2S, only 1 stereo pair channels supported */
#define MAX_DAC_CHANNELS 2
#define MAX_ADC_CHANNELS 2
#define MAX_DAC_RATE 96000
#define MAX_ADC_RATE 96000
#endif
    // the physical channels
	struct adi_sport_1836_channel dac_channel[MAX_DAC_CHANNELS];
	struct adi_sport_1836_channel adc_channel[MAX_ADC_CHANNELS];

	/* TODO : soundcore stuff */
	int dev_audio;
	int irq;
	int lock;

  /* Function support */
  struct adi_sport_1836_channel *(*alloc_dac_pcm_channel)(struct adi_sport_1836_card *, int channel);
  struct adi_sport_1836_channel *(*alloc_adc_pcm_channel)(struct adi_sport_1836_card *, int channel);
  void (*free_dac_pcm_channel)(struct adi_sport_1836_card *, int chan);
  void (*free_adc_pcm_channel)(struct adi_sport_1836_card *, int chan);
  struct adi_sport_1836_instance *(*alloc_instance)(struct adi_sport_1836_card *card, int mode);
};

//--------------------------------------------------------------------------//
// Symbolic constants														//
//--------------------------------------------------------------------------//
// addresses for Port B in Flash A
#define pFlashA_PortA_Dir	(volatile unsigned char *)0x20270006
#define pFlashA_PortA_Data	(volatile unsigned char *)0x20270004

/* Array of the 1836 registers. 
   Each register has 2 parts - address and data.
      Register  Read /  Rsvd  Data
      Address   Write         Field
Bit   15:12 	11 	10    9:0
Info  4 Bits 	1 = R   0     10 Bits
		0 = W
	
DAC Control Register 1
Bit   15:12     11      10    9,8       7,6,5         4,3           2          1               0
Info  Addr      R/W     Rscd  De-empha  Serial Mode   Data word     power      interpolator    Rsvd
                              sis                     Width         down       mode
Value 0000 	0 	0     00 = None	000 = I2S     00 = 24 Bits  0 = Normal 0 = 8× (48 kHz) 0
			      01 = 44.1	001 = RJ      01 = 20 Bits  1 = PWRDWN 1 = 4× (96 kHz)
			      10 = 32.0 010 = DSP     10 = 16 Bits
			      11 = 48.0	011 = LJ      11 = Reserved
			           kHz  100 = Pack 256
			                101 = Pack 128
			                110 = Reserved
			                111 = Reserved
*/
#define DAC_C1_DEEMPH_NONE 0
#define DAC_C1_DEEMPH_44_1 0x0100
#define DAC_C1_DEEMPH_32_0 0x0200
#define DAC_C1_DEEMPH_48_0 0x0300

#define DAC_C1_I2S         0x0000
#define DAC_C1_RJ          0x0020
#define DAC_C1_DSP         0x0040
#define DAC_C1_LJ          0x0060
#define DAC_C1_PACK_256    0x0080
#define DAC_C1_PACK_128    0x00C0

#define DAC_C1_DATA_WIDTH_24  0x0000
#define DAC_C1_DATA_WIDTH_20  0x0008
#define DAC_C1_DATA_WIDTH_16  0x0018

#define DAC_C1_POWER_NML   0x0000
#define DAC_C1_POWER_DWN   0x0004

#define DAC_C1_48_KHZ      0x0000
#define DAC_C1_96_KHZ      0x0002

/*

DAC Control Register 2
Bit   15:12     11      10    9:6   5      4      3      2      1      0
Info  Addr      R/W     Rsvd  Rsvd  DAC3R  DAC3L  DAC2R  DAC2L  DAC1R  DAC1L
Value 0001      0       0     0     0=on   0=on   0=on   0=on   0=on   0=on   
                                    1=mute 1=mute 1=mute 1=mute 1=mute 1=mute 
*/

#define DAC_C2_MUTE_1L	0x0001
#define DAC_C2_MUTE_1R	0x0002
#define DAC_C2_MUTE_2L	0x0004
#define DAC_C2_MUTE_2R	0x0008
#define DAC_C2_MUTE_3L	0x0010
#define DAC_C2_MUTE_3R	0x0020
/*
DAC Volume Registers
Bit   15:12       11      10    9:0
Info  Addr        R/W     Rsvd  Volume
Value 0010: DAC1L 0       0     0 to 1023 in 1024 Linear Steps
      0011: DAC1R
      0100: DAC2L
      0101: DAC2R
      0110: DAC3L
      0111: DAC3R
*/

#define DAC_VOLUME_1L(volume)  (0x2000 | volume)
#define DAC_VOLUME_1R(volume)  (0x3000 | volume)
#define DAC_VOLUME_2L(volume)  (0x4000 | volume)
#define DAC_VOLUME_2R(volume)  (0x5000 | volume)
#define DAC_VOLUME_3L(volume)  (0x6000 | volume)
#define DAC_VOLUME_3R(volume)  (0x7000 | volume)

/*

ADC Control Register 1
Bit   15:12     11      10    9    8      7        6         5:3         2:0
Info  Addr      R/W     Rsvd  Rsvd Filter Power    Sample    Left        Right
                                          down     rate      gain        gain
Value 1100      0       0     0    0=dc   0=normal 0 = 48kHz 000 = 0db   000 = 0db
                                   1=high 1=pwrdwn 1 = 96kHz 001 = 3db   001 = 3db
                                     pass                    010 = 6dB   010 = 6dB
                                                             011 = 9dB   011 = 9dB
                                                             100 = 12dB  100 = 12dB
                                                             101 = Rsvd  101 = Rsvd
                                                             110 = Rsvd  110 = Rsvd
                                                             111 = Rsvd  111 = Rsvd

*/


// names for codec registers, used for iCodec1836TxRegs[]
#define DAC_CONTROL_1		0x0000
#define DAC_CONTROL_2		0x1000
#define DAC_VOLUME_0		0x2000
#define DAC_VOLUME_1		0x3000
#define DAC_VOLUME_2		0x4000
#define DAC_VOLUME_3		0x5000
#define DAC_VOLUME_4		0x6000
#define DAC_VOLUME_5		0x7000
#define ADC_0_PEAK_LEVEL	0x8000
#define ADC_1_PEAK_LEVEL	0x9000
#define ADC_2_PEAK_LEVEL	0xA000
#define ADC_3_PEAK_LEVEL	0xB000
#define ADC_CONTROL_1		0xC000
#define ADC_CONTROL_2		0xD000
#define ADC_CONTROL_3		0xE000

#define DAC_CONTROL_1_INDEX 0
#define DAC_CONTROL_2_INDEX 1
#define DAC_VOLUME_0_INDEX  2
#define DAC_VOLUME_1_INDEX  3
#define DAC_VOLUME_2_INDEX  4
#define DAC_VOLUME_3_INDEX  5
#define DAC_VOLUME_4_INDEX  6
#define DAC_VOLUME_5_INDEX  7
#define ADC_0_PEAK_LEVEL_INDEX 8
#define ADC_1_PEAK_LEVEL_INDEX 9
#define ADC_2_PEAK_LEVEL_INDEX 10
#define ADC_3_PEAK_LEVEL_INDEX 11
#define ADC_CONTROL_1_INDEX 12
#define ADC_CONTROL_2_INDEX 13
#define ADC_CONTROL_3_INDEX 14

// names for slots in ad1836 audio frame
#define INTERNAL_ADC_L0			0
#define INTERNAL_ADC_L1			1
#define INTERNAL_ADC_R0			4
#define INTERNAL_ADC_R1			5
#define INTERNAL_DAC_L0			0
#define INTERNAL_DAC_L1			1
#define INTERNAL_DAC_L2			2
#define INTERNAL_DAC_R0			4
#define INTERNAL_DAC_R1			5
#define INTERNAL_DAC_R2			6

// size of array iCodec1836TxRegs and iCodec1836RxRegs
#define CODEC_1836_REGS_LENGTH	11

// SPI transfer mode
#define TIMOD_DMA_TX 0x0003

// SPORT0 word length
#define SLEN_32	0x001f

// DMA flow mode
#define FLOW_1	0x1000
extern volatile short sCodec1836TxRegs[];
extern volatile int iRxBuffer1[];
extern volatile int iTxBuffer1[];

//--------------------------------------------------------------------------//
// Prototypes																//
//--------------------------------------------------------------------------//
// in file Initialisation.c
#ifndef LINUX
void Init_EBIU(void);
#endif

void Init_Flash(void);
void Init1836(void);
void Init_Sport0(void);
void Init_DMA(void);
int Init_Sport_Interrupts(void);
void Enable_DMA_Sport(void);

#ifdef LINUX
#else
// in file ISRs.c
EX_INTERRUPT_HANDLER(Sport0_RX_ISR);
#endif

#define BUF_SIZE 768 


#endif /* 1836_DRIVER_H */
