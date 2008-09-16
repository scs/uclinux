/*
 * Wildcard TDM400P TDM FXS/FXO Interface Driver for Zapata Telephony interface
 *
 * Written by Mark Spencer <markster@linux-support.net>
 *            Matthew Fredrickson <creslin@linux-support.net>
 *
 * Copyright (C) 2001, Linux Support Services, Inc.
 *
 * All rights reserved.
 *
 * Adapted to the Blackfin by David Rowe 2005.
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA. 
 *
 */

#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/proc_fs.h>
#include "proslic.h"
#include "wcfxs.h"
#include "bfsi.h"
#include "bfsi.c"

/*
 *  Define for audio vs. register based ring detection
 *  
 */
/* #define AUDIO_RINGCHECK  */

/*
  Experimental max loop current limit for the proslic
  Loop current limit is from 20 mA to 41 mA in steps of 3
  (according to datasheet)
  So set the value below to:
  0x00 : 20mA (default)
  0x01 : 23mA
  0x02 : 26mA
  0x03 : 29mA
  0x04 : 32mA
  0x05 : 35mA
  0x06 : 37mA
  0x07 : 41mA
*/
static int loopcurrent = 20;

static alpha  indirect_regs[] =
{
{0,255,"DTMF_ROW_0_PEAK",0x55C2},
{1,255,"DTMF_ROW_1_PEAK",0x51E6},
{2,255,"DTMF_ROW2_PEAK",0x4B85},
{3,255,"DTMF_ROW3_PEAK",0x4937},
{4,255,"DTMF_COL1_PEAK",0x3333},
{5,255,"DTMF_FWD_TWIST",0x0202},
{6,255,"DTMF_RVS_TWIST",0x0202},
{7,255,"DTMF_ROW_RATIO_TRES",0x0198},
{8,255,"DTMF_COL_RATIO_TRES",0x0198},
{9,255,"DTMF_ROW_2ND_ARM",0x0611},
{10,255,"DTMF_COL_2ND_ARM",0x0202},
{11,255,"DTMF_PWR_MIN_TRES",0x00E5},
{12,255,"DTMF_OT_LIM_TRES",0x0A1C},
{13,0,"OSC1_COEF",0x7B30},
{14,1,"OSC1X",0x0063},
{15,2,"OSC1Y",0x0000},
{16,3,"OSC2_COEF",0x7870},
{17,4,"OSC2X",0x007D},
{18,5,"OSC2Y",0x0000},
{19,6,"RING_V_OFF",0x0000},
{20,7,"RING_OSC",0x7EF0},
{21,8,"RING_X",0x0160},
{22,9,"RING_Y",0x0000},
{23,255,"PULSE_ENVEL",0x2000},
{24,255,"PULSE_X",0x2000},
{25,255,"PULSE_Y",0x0000},
//{26,13,"RECV_DIGITAL_GAIN",0x4000},	// playback volume set lower
{26,13,"RECV_DIGITAL_GAIN",0x2000},	// playback volume set lower
{27,14,"XMIT_DIGITAL_GAIN",0x4000},
//{27,14,"XMIT_DIGITAL_GAIN",0x2000},
{28,15,"LOOP_CLOSE_TRES",0x1000},
{29,16,"RING_TRIP_TRES",0x3600},
{30,17,"COMMON_MIN_TRES",0x1000},
{31,18,"COMMON_MAX_TRES",0x0200},
{32,19,"PWR_ALARM_Q1Q2",0x07C0},
{33,20,"PWR_ALARM_Q3Q4",0x2600},
{34,21,"PWR_ALARM_Q5Q6",0x1B80},
{35,22,"LOOP_CLOSURE_FILTER",0x8000},
{36,23,"RING_TRIP_FILTER",0x0320},
{37,24,"TERM_LP_POLE_Q1Q2",0x008C},
{38,25,"TERM_LP_POLE_Q3Q4",0x0100},
{39,26,"TERM_LP_POLE_Q5Q6",0x0010},
{40,27,"CM_BIAS_RINGING",0x0C00},
{41,64,"DCDC_MIN_V",0x0C00},
{42,255,"DCDC_XTRA",0x1000},
{43,66,"LOOP_CLOSE_TRES_LOW",0x1000},
};

static struct fxo_mode {
	char *name;
	/* FXO */
	int ohs;
	int ohs2;
	int rz;
	int rt;
	int ilim;
	int dcv;
	int mini;
	int acim;
	int ring_osc;
	int ring_x;
} fxo_modes[] =
{
	{ "FCC", 0, 0, 0, 1, 0, 0x3, 0, 0 }, 	/* US, Canada */
	{ "TBR21", 0, 0, 0, 0, 1, 0x3, 0, 0x2, 0x7e6c, 0x023a },
										/* Austria, Belgium, Denmark, Finland, France, Germany, 
										   Greece, Iceland, Ireland, Italy, Luxembourg, Netherlands,
										   Norway, Portugal, Spain, Sweden, Switzerland, and UK */
	{ "ARGENTINA", 0, 0, 0, 0, 0, 0x3, 0, 0 },
	{ "AUSTRALIA", 1, 0, 0, 0, 0, 0, 0x3, 0x3 },
	{ "AUSTRIA", 0, 1, 0, 0, 1, 0x3, 0, 0x3 },
	{ "BAHRAIN", 0, 0, 0, 0, 1, 0x3, 0, 0x2 },
	{ "BELGIUM", 0, 1, 0, 0, 1, 0x3, 0, 0x2 },
	{ "BRAZIL", 0, 0, 0, 0, 0, 0, 0x3, 0 },
	{ "BULGARIA", 0, 0, 0, 0, 1, 0x3, 0x0, 0x3 },
	{ "CANADA", 0, 0, 0, 0, 0, 0x3, 0, 0 },
	{ "CHILE", 0, 0, 0, 0, 0, 0x3, 0, 0 },
	{ "CHINA", 0, 0, 0, 0, 0, 0, 0x3, 0xf },
	{ "COLUMBIA", 0, 0, 0, 0, 0, 0x3, 0, 0 },
	{ "CROATIA", 0, 0, 0, 0, 1, 0x3, 0, 0x2 },
	{ "CYRPUS", 0, 0, 0, 0, 1, 0x3, 0, 0x2 },
	{ "CZECH", 0, 0, 0, 0, 1, 0x3, 0, 0x2 },
	{ "DENMARK", 0, 1, 0, 0, 1, 0x3, 0, 0x2 },
	{ "ECUADOR", 0, 0, 0, 0, 0, 0x3, 0, 0 },
	{ "EGYPT", 0, 0, 0, 0, 0, 0, 0x3, 0 },
	{ "ELSALVADOR", 0, 0, 0, 0, 0, 0x3, 0, 0 },
	{ "FINLAND", 0, 1, 0, 0, 1, 0x3, 0, 0x2 },
	{ "FRANCE", 0, 1, 0, 0, 1, 0x3, 0, 0x2 },
	{ "GERMANY", 0, 1, 0, 0, 1, 0x3, 0, 0x3 },
	{ "GREECE", 0, 1, 0, 0, 1, 0x3, 0, 0x2 },
	{ "GUAM", 0, 0, 0, 0, 0, 0x3, 0, 0 },
	{ "HONGKONG", 0, 0, 0, 0, 0, 0x3, 0, 0 },
	{ "HUNGARY", 0, 0, 0, 0, 0, 0x3, 0, 0 },
	{ "ICELAND", 0, 1, 0, 0, 1, 0x3, 0, 0x2 },
	{ "INDIA", 0, 0, 0, 0, 0, 0x3, 0, 0x4 },
	{ "INDONESIA", 0, 0, 0, 0, 0, 0x3, 0, 0 },
	{ "IRELAND", 0, 1, 0, 0, 1, 0x3, 0, 0x2 },
	{ "ISRAEL", 0, 0, 0, 0, 1, 0x3, 0, 0x2 },
	{ "ITALY", 0, 1, 0, 0, 1, 0x3, 0, 0x2 },
	{ "JAPAN", 0, 0, 0, 0, 0, 0, 0x3, 0 },
	{ "JORDAN", 0, 0, 0, 0, 0, 0, 0x3, 0 },
	{ "KAZAKHSTAN", 0, 0, 0, 0, 0, 0x3, 0 },
	{ "KUWAIT", 0, 0, 0, 0, 0, 0x3, 0, 0 },
	{ "LATVIA", 0, 0, 0, 0, 1, 0x3, 0, 0x2 },
	{ "LEBANON", 0, 0, 0, 0, 1, 0x3, 0, 0x2 },
	{ "LUXEMBOURG", 0, 1, 0, 0, 1, 0x3, 0, 0x2 },
	{ "MACAO", 0, 0, 0, 0, 0, 0x3, 0, 0 },
	{ "MALAYSIA", 0, 0, 0, 0, 0, 0, 0x3, 0 },	/* Current loop >= 20ma */
	{ "MALTA", 0, 0, 0, 0, 1, 0x3, 0, 0x2 },
	{ "MEXICO", 0, 0, 0, 0, 0, 0x3, 0, 0 },
	{ "MOROCCO", 0, 0, 0, 0, 1, 0x3, 0, 0x2 },
	{ "NETHERLANDS", 0, 1, 0, 0, 1, 0x3, 0, 0x2 },
	{ "NEWZEALAND", 0, 0, 0, 0, 0, 0x3, 0, 0x4 },
	{ "NIGERIA", 0, 0, 0, 0, 0x1, 0x3, 0, 0x2 },
	{ "NORWAY", 0, 1, 0, 0, 1, 0x3, 0, 0x2 },
	{ "OMAN", 0, 0, 0, 0, 0, 0, 0x3, 0 },
	{ "PAKISTAN", 0, 0, 0, 0, 0, 0, 0x3, 0 },
	{ "PERU", 0, 0, 0, 0, 0, 0x3, 0, 0 },
	{ "PHILIPPINES", 0, 0, 0, 0, 0, 0, 0x3, 0 },
	{ "POLAND", 0, 0, 1, 1, 0, 0x3, 0, 0 },
	{ "PORTUGAL", 0, 1, 0, 0, 1, 0x3, 0, 0x2 },
	{ "ROMANIA", 0, 0, 0, 0, 0, 3, 0, 0 },
	{ "RUSSIA", 0, 0, 0, 0, 0, 0, 0x3, 0 },
	{ "SAUDIARABIA", 0, 0, 0, 0, 0, 0x3, 0, 0 },
	{ "SINGAPORE", 0, 0, 0, 0, 0, 0x3, 0, 0 },
	{ "SLOVAKIA", 0, 0, 0, 0, 0, 0x3, 0, 0x3 },
	{ "SLOVENIA", 0, 0, 0, 0, 0, 0x3, 0, 0x2 },
	{ "SOUTHAFRICA", 1, 0, 1, 0, 0, 0x3, 0, 0x3 },
	{ "SOUTHKOREA", 0, 0, 0, 0, 0, 0x3, 0, 0 },
	{ "SPAIN", 0, 1, 0, 0, 1, 0x3, 0, 0x2 },
	{ "SWEDEN", 0, 1, 0, 0, 1, 0x3, 0, 0x2 },
	{ "SWITZERLAND", 0, 1, 0, 0, 1, 0x3, 0, 0x2 },
	{ "SYRIA", 0, 0, 0, 0, 0, 0, 0x3, 0 },
	{ "TAIWAN", 0, 0, 0, 0, 0, 0, 0x3, 0 },
	{ "THAILAND", 0, 0, 0, 0, 0, 0, 0x3, 0 },
	{ "UAE", 0, 0, 0, 0, 0, 0x3, 0, 0 },
	{ "UK", 0, 1, 0, 0, 1, 0x3, 0, 0x5 },
	{ "USA", 0, 0, 0, 0, 0, 0x3, 0, 0 },
	{ "YEMEN", 0, 0, 0, 0, 0, 0x3, 0, 0 },
};

#ifdef STANDALONE_ZAPATA
#include "zaptel.h"
#else
#include <linux/zaptel.h>
#endif

#ifdef LINUX26
#include <linux/moduleparam.h>
#endif

#define NUM_FXO_REGS 60

#define WC_MAX_IFACES 128

#define WC_CNTL    	0x00
#define WC_OPER		0x01
#define WC_AUXC    	0x02
#define WC_AUXD    	0x03
#define WC_MASK0   	0x04
#define WC_MASK1   	0x05
#define WC_INTSTAT 	0x06
#define WC_AUXR		0x07

#define WC_DMAWS	0x08
#define WC_DMAWI	0x0c
#define WC_DMAWE	0x10
#define WC_DMARS	0x18
#define WC_DMARI	0x1c
#define WC_DMARE	0x20

#define WC_AUXFUNC	0x2b
#define WC_SERCTL	0x2d
#define WC_FSCDELAY	0x2f

#define WC_REGBASE	0xc0

#define WC_SYNC		0x0
#define WC_TEST		0x1
#define WC_CS		0x2
#define WC_VER		0x3

/* ------------------------ Blackfin -------------------------*/

#define SPI_BAUDS   4 /* 12.5 MHz for 100MHz system clock */
#define SPI_SPISEL3 3
#define RESET_BIT   4 /* GPIO bit tied to nRESET on Si chips */

#define __write_8bits(X, Y) bfsi_spi_write_8_bits(Y)
#define __read_8bits(X) bfsi_spi_read_8_bits()
#define __reset_spi(X) do {} while(0)

/* ------------------------ Blackfin -------------------------*/


#define FLAG_EMPTY	0
#define FLAG_WRITE	1
#define FLAG_READ	2

#define RING_DEBOUNCE	64		/* Ringer Debounce (in ms) */
#define BATT_DEBOUNCE	64		/* Battery debounce (in ms) */
#define POLARITY_DEBOUNCE 64           /* Polarity debounce (in ms) */
#define BATT_THRESH	3		/* Anything under this is "no battery" */

#define OHT_TIMER		6000	/* How long after RING to retain OHT */

#define FLAG_3215	(1 << 0)

#define NUM_CARDS 4

#define MAX_ALARMS 10

#define MOD_TYPE_FXS	0
#define MOD_TYPE_FXO	1

#define MINPEGTIME	10 * 8		/* 30 ms peak to peak gets us no more than 100 Hz */
#define PEGTIME		50 * 8		/* 50ms peak to peak gets us rings of 10 Hz or more */
#define PEGCOUNT	5		/* 5 cycles of pegging means RING */

#define NUM_CAL_REGS 12

struct calregs {
	unsigned char vals[NUM_CAL_REGS];
};

struct wcfxs {
	int   irq;
	char *variety;
	struct zt_span span;
	unsigned char ios;
	int usecount;
	unsigned int intcount;
	int dead;
	int pos;
	int flags[NUM_CARDS];
	int freeregion;
	int alt;
	int curcard;
	int cards;
	int cardflag;		/* Bit-map of present cards */
	spinlock_t lock;

	/* FXO Stuff */
	union {
		struct {
#ifdef AUDIO_RINGCHECK
			unsigned int pegtimer[NUM_CARDS];
			int pegcount[NUM_CARDS];
			int peg[NUM_CARDS];
			int ring[NUM_CARDS];
#else			
			int wasringing[NUM_CARDS];
#endif			
			int ringdebounce[NUM_CARDS];
			int offhook[NUM_CARDS];
			int battdebounce[NUM_CARDS];
			int nobatttimer[NUM_CARDS];
			int battery[NUM_CARDS];
		        int lastpol[NUM_CARDS];
		        int polarity[NUM_CARDS];
		        int polaritydebounce[NUM_CARDS];
		} fxo;
		struct {
			int oldrxhook[NUM_CARDS];
			int debouncehook[NUM_CARDS];
			int lastrxhook[NUM_CARDS];
			int debounce[NUM_CARDS];
			int ohttimer[NUM_CARDS];
			int idletxhookstate[NUM_CARDS];		/* IDLE changing hook state */
			int lasttxhook[NUM_CARDS];
			int palarms[NUM_CARDS];
			struct calregs calregs[NUM_CARDS];
		} fxs;
	} mod;

	/* Receive hook state and debouncing */
	int modtype[NUM_CARDS];

	unsigned long ioaddr;
	dma_addr_t 	readdma;
	dma_addr_t	writedma;
	volatile int *writechunk;					/* Double-word aligned write memory */
	volatile int *readchunk;					/* Double-word aligned read memory */
	struct zt_chan chans[NUM_CARDS];
};


struct wcfxs_desc {
	char *name;
	int flags;
};

static struct wcfxs_desc wcfxs_bf = { "Blackfin STAMP", 0 };
static int acim2tiss[16] = { 0x0, 0x1, 0x4, 0x5, 0x7, 0x0, 0x0, 0x6, 0x0, 0x0, 0x0, 0x2, 0x0, 0x3 };

static struct wcfxs *ifaces[WC_MAX_IFACES];

static void wcfxs_release(struct wcfxs *wc);

#ifdef OLD_DR
static void init_sport0(void);
static void init_dma_wc(void);
static int init_sport_interrupts(void);
static void enable_dma_sport0(void);
static void disable_sport0(void);
int wcfxs_proc_read(char *buf, char **start, off_t offset, 
		    int count, int *eof, void *data);
#endif

static int debug = 1;
static int robust = 0;
static int timingonly = 0;
static int lowpower = 0;
static int boostringer = 0;
static int _opermode = 0;
static char *opermode = "FCC";
static int fxshonormode = 0;
static struct wcfxs *devs;

/* added for uCasterisk/Blackfin */

static int loopback = 0;
static int reg5, reg12, loop_i, line_v;

#ifdef TMP_DR
static int internalclock = 0;
static int init_ok = 0;

static int readchunk_first = 0;
static int readchunk_second = 0;
static int readchunk_didntswap = 0;
static unsigned char* lastreadchunk;

static int writechunk_first = 0;
static int writechunk_second = 0;
static int writechunk_didntswap = 0;
static unsigned char* lastwritechunk;
static int rx1;
static int rx2;
static int tx1;
static int tx2;

#ifdef TMP_DR
/* SPORT0 DMA transmit buffer */
volatile char iTxBuffer1[8*ZT_CHUNKSIZE*2];
/* SPORT0 DMA receive buffer */
volatile char iRxBuffer1[8*ZT_CHUNKSIZE*2];
#else
volatile char *iTxBuffer1;
volatile char *iRxBuffer1;
#endif
#endif

#ifdef TMP_DR
#if L1_DATA_A_LENGTH != 0

extern unsigned long l1_data_A_sram_alloc(unsigned long size);

extern int l1_data_A_sram_free(unsigned long addr);

#endif
#endif

static int wcfxs_init_proslic(struct wcfxs *wc, int card, int fast , int manual, int sane);
static void wait_just_a_bit(int foo);

#ifdef AUDIO_RINGCHECK
static inline void ring_check(struct wcfxs *wc, int card)
{
	int x;
	short sample;
	if (wc->modtype[card] != MOD_TYPE_FXO)
		return;
	wc->mod.fxo.pegtimer[card] += ZT_CHUNKSIZE;
	for (x=0;x<ZT_CHUNKSIZE;x++) {
		/* Look for pegging to indicate ringing */
		sample = ZT_XLAW(wc->chans[card].readchunk[x], (&(wc->chans[card])));
		if ((sample > 10000) && (wc->mod.fxo.peg[card] != 1)) {
			if (debug > 1) printk("High peg!\n");
			if ((wc->mod.fxo.pegtimer[card] < PEGTIME) && (wc->mod.fxo.pegtimer[card] > MINPEGTIME))
				wc->mod.fxo.pegcount[card]++;
			wc->mod.fxo.pegtimer[card] = 0;
			wc->mod.fxo.peg[card] = 1;
		} else if ((sample < -10000) && (wc->mod.fxo.peg[card] != -1)) {
			if (debug > 1) printk("Low peg!\n");
			if ((wc->mod.fxo.pegtimer[card] < (PEGTIME >> 2)) && (wc->mod.fxo.pegtimer[card] > (MINPEGTIME >> 2)))
				wc->mod.fxo.pegcount[card]++;
			wc->mod.fxo.pegtimer[card] = 0;
			wc->mod.fxo.peg[card] = -1;
		}
	}
	if (wc->mod.fxo.pegtimer[card] > PEGTIME) {
		/* Reset pegcount if our timer expires */
		wc->mod.fxo.pegcount[card] = 0;
	}
	/* Decrement debouncer if appropriate */
	if (wc->mod.fxo.ringdebounce[card])
		wc->mod.fxo.ringdebounce[card]--;
	if (!wc->mod.fxo.offhook[card] && !wc->mod.fxo.ringdebounce[card]) {
		if (!wc->mod.fxo.ring[card] && (wc->mod.fxo.pegcount[card] > PEGCOUNT)) {
			/* It's ringing */
			if (debug)
				printk("RING on %d/%d!\n", wc->span.spanno, card + 1);
			if (!wc->mod.fxo.offhook[card])
				zt_hooksig(&wc->chans[card], ZT_RXSIG_RING);
			wc->mod.fxo.ring[card] = 1;
		}
		if (wc->mod.fxo.ring[card] && !wc->mod.fxo.pegcount[card]) {
			/* No more ring */
			if (debug)
				printk("NO RING on %d/%d!\n", wc->span.spanno, card + 1);
			zt_hooksig(&wc->chans[card], ZT_RXSIG_OFFHOOK);
			wc->mod.fxo.ring[card] = 0;
		}
	}
}
#endif
static char digital_milliwatt[] = {0x1e,0x0b,0x0b,0x1e,0x9e,0x8b,0x8b,0x9e};
int swi = 0;
static short sw[] = {2048, 1023, -1024, -2048, -1023, 1024};

#define LOG_LEN 64
#define LOG_START 0
int logdma1[LOG_LEN];
int logdma2[20];
int logdma3[20];
int ilogdma = 0;
int serialnum = 0;
int notzero=0;

static inline void wcfxs_transmitprep(struct wcfxs *wc, u8 *writechunk)
{
	int x;

#ifdef OLD_DR
	volatile unsigned char *writechunk;

	/* select which ping-pong buffer to write to */

	x = (int)(*pDMA2_CURR_ADDR) - (int)iTxBuffer1;

	/* for some reason x for tx tends to be 0xe and 0x4e, whereas
	   x for rx is 0x40 and 0x80.  Note sure why they would be
	   different.  We could perhaps consider having
	   different interrupts for tx and rx side.  Hope this
	   offset doesnt kill the echo cancellation, e.g. if we
	   get echo samples in rx before tx has sent them!
	*/
	if (x >= 8*ZT_CHUNKSIZE) {
		writechunk = (unsigned char*)iTxBuffer1;
		writechunk_first++;
		tx1 = x;
	}
	else {
		writechunk = (unsigned char*)iTxBuffer1 + ZT_CHUNKSIZE*8;
		writechunk_second++;
		tx2 = x;
	}

	/* make sure writechunk actually ping pongs */

	if (writechunk == lastwritechunk) {
		writechunk_didntswap++;
	}
	lastwritechunk = (unsigned char*)writechunk;
#endif
	/* Calculate Transmission */
	zt_transmit(&wc->span);

	for (x=0;x<ZT_CHUNKSIZE;x++) {
		if (wc->cardflag & (1 << 3))
			writechunk[8*x+3] = wc->chans[3].writechunk[x];
		if (wc->cardflag & (1 << 2))
			writechunk[8*x+2] = wc->chans[2].writechunk[x];
		if (wc->cardflag & (1 << 1))
			writechunk[8*x+1] = wc->chans[1].writechunk[x];
		if (wc->cardflag & (1 << 0)) {
			writechunk[8*x+0] = wc->chans[0].writechunk[x];
			//writechunk[8*x+0] = ZT_LIN2MU(sw[swi++]);
			//if (swi == 6) swi = 0;
		}
	}
}

static inline void wcfxs_receiveprep(struct wcfxs *wc, u8 *readchunk)
{
	int x;
	int echo_before;
#ifdef OLD_DR
	volatile unsigned char *readchunk;

	serialnum++;

	/* select which ping-pong buffer to write to */

	x = (int)*pDMA1_CURR_ADDR - (int)iRxBuffer1;
	/* possible values for x are 8*ZT_CHUNKSIZE=0x40 at the end of the 
	   first row and 2*8*ZT_CHUNKSIZE=0x80 at the end of the second
	   row */
	if (x == 8*ZT_CHUNKSIZE) {
		readchunk = iRxBuffer1;
		readchunk_first++;
		rx1 = x;
	}
	else {
		readchunk = iRxBuffer1 + ZT_CHUNKSIZE*8;
		readchunk_second++;
		rx2 = x;
	}

	/* make sure readchunk actually ping pongs */

	if (readchunk == lastreadchunk) {
		readchunk_didntswap++;
	}
	lastreadchunk = (unsigned char*)readchunk;
#endif

	for (x=0;x<ZT_CHUNKSIZE;x++) {
		if (wc->cardflag & (1 << 3))
			wc->chans[3].readchunk[x] = readchunk[8*x+3];
		if (wc->cardflag & (1 << 2))
			wc->chans[2].readchunk[x] = readchunk[8*x+2];
		if (wc->cardflag & (1 << 1))
			wc->chans[1].readchunk[x] = readchunk[8*x+1];
		if (wc->cardflag & (1 << 0)) {
			wc->chans[0].readchunk[x] = readchunk[8*x+0];
			if ((serialnum > LOG_START) && (ilogdma < LOG_LEN))
				logdma1[ilogdma++] = readchunk[8*x+0];
			if (readchunk[8*x+0] != 0)
				notzero++;
		}
	}
#ifdef AUDIO_RINGCHECK
	for (x=0;x<wc->cards;x++)
		ring_check(wc, x);
#endif		
	/* XXX We're wasting 8 taps.  We should get closer :( */
	echo_before = cycles();
	for (x=0;x<wc->cards;x++) {
		if (wc->cardflag & (1 << x))
			zt_ec_chunk(&wc->chans[x], wc->chans[x].readchunk, wc->chans[x].writechunk);
	}
	echo_sams = cycles() - echo_before;
	zt_receive(&wc->span);
}

#ifdef OLD_BIT_BASH
static inline void __write_8bits(struct wcfxs *wc, unsigned char bits)
{
	/* Drop chip select */
	int x;

	/* DR 6/11/05: Note that it is important to have a delay or
	   alternatively a ssync after we assert BIT_CLK and before we
	   drop CS, otherwise sometimes CS doesnt get taken low and
	   the whole SPI protocol gets messed up (I found this out the
	   hard way).  I think quick sucessive write to CS and the CLK
	   bits mess each other up for some reason, but I am not
	   sure.  Also, it is only a problem in this function, not
	   __read_8bits() - I have no idea why.

	   I found the problem by performing a 1000 reads with 100ms
	   gaps between then, and stopping on a bad read (ie expected
	   value not read).  The 100ms gap meant my storage CRO would
	   trigger on the last read, and I noted that CS wasnt going low
	   in some cases.  Another way to trap it it to read the CS bit
	   and printk an error message if it isnt low as expected.

	   The main symptom of this bug is bad values when reading a register
	   from the Si chips.
	*/

	*pFIO_FLAG_S = BIT_SCLK;
	udelay(DELAY);

	*pFIO_FLAG_C = BIT_CS;
	udelay(DELAY);

	/* debug code used to trap CS problem discussed above 
	if (*pFIO_FLAG_D & BIT_CS)
		printk("Error: CS is high! 0x%4x\n", *pFIO_FLAG_D);
	*/

	for (x=0;x<8;x++) {
		/* Send out each bit, MSB first, drop SCLK as we do so */
		*pFIO_FLAG_C = BIT_SCLK;
		if (bits & 0x80) {
			
			*pFIO_FLAG_S = BIT_SDI;
		}
		else {
			*pFIO_FLAG_C = BIT_SDI;
		}
		udelay(DELAY);

		/* Now raise SCLK high again and repeat */
		*pFIO_FLAG_S = BIT_SCLK;
		udelay(DELAY);

		bits <<= 1;
	}

	/* Finally raise CS back high again */
	*pFIO_FLAG_S = BIT_CS;
	udelay(DELAY);

}

static inline void __reset_spi(struct wcfxs *wc)
{
	/* Drop chip select and clock once and raise and clock once */

	*pFIO_FLAG_S = BIT_SCLK;
	udelay(DELAY);

	*pFIO_FLAG_C = BIT_CS;
	udelay(DELAY);

	*pFIO_FLAG_C = BIT_SCLK;
	udelay(DELAY);

	/* Now raise SCLK high again and repeat */

	*pFIO_FLAG_S = BIT_SCLK;
	udelay(DELAY);

	/* Finally raise CS back high again */

	*pFIO_FLAG_S = BIT_CS;
	udelay(DELAY);

	/* Clock again */

	*pFIO_FLAG_C = BIT_SCLK;
	udelay(DELAY);

	/* Now raise SCLK high again and repeat */

	*pFIO_FLAG_S = BIT_SCLK;
	udelay(DELAY);	
}

static inline unsigned char __read_8bits(struct wcfxs *wc)
{
	unsigned char res=0;
	int x;

	*pFIO_FLAG_S = BIT_SCLK;
	udelay(DELAY);

	/* Drop chip select */

	*pFIO_FLAG_C = BIT_CS;
	udelay(DELAY);
	
	for (x=0;x<8;x++) {
		res <<= 1;
		/* reset SCLK */

		*pFIO_FLAG_C = BIT_SCLK;
		udelay(DELAY);

		/* Read back the value */

		if (*pFIO_FLAG_D & BIT_SDO)
			res |= 1;

		/* Now raise SCLK high again */

		*pFIO_FLAG_S = BIT_SCLK;
		udelay(DELAY);
		
	}

	/* Finally raise CS back high again */

	/* error trapping code used during blackfin debugging
	if (*pFIO_FLAG_D & BIT_CS)
		printk("Error: CS is high! 0x%4x\n", *pFIO_FLAG_D);
	*/
	*pFIO_FLAG_S = BIT_CS;
	udelay(DELAY);

	/* And return our result */
	return res;
}
#endif

/* we have only one card at the moment */

static inline void __wcfxs_setcard(struct wcfxs *wc, int card)
{
	if (wc->curcard != card) {
                #ifdef NOT_NEEDED
		__wcfxs_setcreg(wc, WC_CS, (1 << card));
                #endif
#ifdef FXS_FXO_CARD
		bfsi_spi_set_cs(card);	
#endif
	   wc->curcard = card;
	}
}

static void __wcfxs_setreg(struct wcfxs *wc, int card, unsigned char reg, unsigned char value)
{
	__wcfxs_setcard(wc, card);
	if (wc->modtype[card] == MOD_TYPE_FXO) {
		__write_8bits(wc, 0x20+daisy_chip_addr[card]);
		__write_8bits(wc, reg & 0x7f);
	} else {
	        #define DAISY
	        #ifdef DAISY
	        __write_8bits(wc, daisy_chip_addr[card]); // 3210 daisy chain mode
		#endif
		__write_8bits(wc, reg & 0x7f);
	}
	__write_8bits(wc, value);
}

static void wcfxs_setreg(struct wcfxs *wc, int card, unsigned char reg, unsigned char value)
{
	unsigned long flags;
	spin_lock_irqsave(&wc->lock, flags);
	__wcfxs_setreg(wc, card, reg, value);
	spin_unlock_irqrestore(&wc->lock, flags);
}

static unsigned char __wcfxs_getreg(struct wcfxs *wc, int card, unsigned char reg)
{
	__wcfxs_setcard(wc, card);
	if (wc->modtype[card] == MOD_TYPE_FXO) {
		__write_8bits(wc, 0x60+daisy_chip_addr[card]);
		__write_8bits(wc, reg & 0x7f);
	} else {
	        #ifdef DAISY
	        __write_8bits(wc, daisy_chip_addr[card]); // 3210 daisy chain mode
		#endif
		__write_8bits(wc, reg | 0x80);
	}
	return __read_8bits(wc);
}

static inline void reset_spi(struct wcfxs *wc, int card)
{
	unsigned long flags;
	spin_lock_irqsave(&wc->lock, flags);
	__wcfxs_setcard(wc, card);
	__reset_spi(wc);
	__reset_spi(wc);
	spin_unlock_irqrestore(&wc->lock, flags);
}

static unsigned char wcfxs_getreg(struct wcfxs *wc, int card, unsigned char reg)
{
	unsigned long flags;
	unsigned char res;
	spin_lock_irqsave(&wc->lock, flags);
	res = __wcfxs_getreg(wc, card, reg);
	spin_unlock_irqrestore(&wc->lock, flags);
	return res;
}

static int __wait_access(struct wcfxs *wc, int card)
{
    unsigned char data;
    long origjiffies;
    int count = 0;

    #define MAX 6000 /* attempts */


    origjiffies = jiffies;
    /* Wait for indirect access */
    while (count++ < MAX)
	 {
		data = __wcfxs_getreg(wc, card, I_STATUS);

		if (!data)
			return 0;

	 }

    if(count > (MAX-1)) printk(" ##### Loop error (%02x) #####\n", data);

	return 0;
}

static unsigned char translate_3215(unsigned char address)
{
	int x;
	for (x=0;x<sizeof(indirect_regs)/sizeof(indirect_regs[0]);x++) {
		if (indirect_regs[x].address == address) {
			address = indirect_regs[x].altaddr;
			break;
		}
	}
	return address;
}

static int wcfxs_proslic_setreg_indirect(struct wcfxs *wc, int card, unsigned char address, unsigned short data)
{
	unsigned long flags;
	int res = -1;
	/* Translate 3215 addresses */
	if (wc->flags[card] & FLAG_3215) {
		address = translate_3215(address);
		if (address == 255)
			return 0;
	}
	spin_lock_irqsave(&wc->lock, flags);
	if(!__wait_access(wc, card)) {
		__wcfxs_setreg(wc, card, IDA_LO,(unsigned char)(data & 0xFF));
		__wcfxs_setreg(wc, card, IDA_HI,(unsigned char)((data & 0xFF00)>>8));
		__wcfxs_setreg(wc, card, IAA,address);
		res = 0;
	};
	spin_unlock_irqrestore(&wc->lock, flags);
	return res;
}

static int wcfxs_proslic_getreg_indirect(struct wcfxs *wc, int card, unsigned char address)
{ 
	unsigned long flags;
	int res = -1;
	char *p=NULL;
	/* Translate 3215 addresses */
	if (wc->flags[card] & FLAG_3215) {
		address = translate_3215(address);
		if (address == 255)
			return 0;
	}
	spin_lock_irqsave(&wc->lock, flags);
	if (!__wait_access(wc, card)) {
		__wcfxs_setreg(wc, card, IAA, address);
		if (!__wait_access(wc, card)) {
			unsigned char data1, data2;
			data1 = __wcfxs_getreg(wc, card, IDA_LO);
			data2 = __wcfxs_getreg(wc, card, IDA_HI);
			res = data1 | (data2 << 8);
		} else
			p = "Failed to wait inside\n";
	} else
		p = "failed to wait\n";
	spin_unlock_irqrestore(&wc->lock, flags);
	if (p)
		printk(p);
	return res;
}

static int wcfxs_proslic_init_indirect_regs(struct wcfxs *wc, int card)
{
	unsigned char i;

	for (i=0; i<sizeof(indirect_regs) / sizeof(indirect_regs[0]); i++)
	{
		if(wcfxs_proslic_setreg_indirect(wc, card, indirect_regs[i].address,indirect_regs[i].initial))
			return -1;
	}

	return 0;
}

static int wcfxs_proslic_verify_indirect_regs(struct wcfxs *wc, int card)
{ 
	int passed = 1;
	unsigned short i, initial;
	int j;

	for (i=0; i<sizeof(indirect_regs) / sizeof(indirect_regs[0]); i++) 
	{
		if((j = wcfxs_proslic_getreg_indirect(wc, card, (unsigned char) indirect_regs[i].address)) < 0) {
			printk("Failed to read indirect register %d\n", i);
			return -1;
		}
		initial= indirect_regs[i].initial;

		if ( j != initial && (!(wc->flags[card] & FLAG_3215) || (indirect_regs[i].altaddr != 255)))
		{
			 printk("!!!!!!! %s  iREG %X = %X  should be %X\n",
				indirect_regs[i].name,indirect_regs[i].address,j,initial );
			 passed = 0;
		}	
	}

    if (passed) {
		if (debug)
			printk("Init Indirect Registers completed successfully.\n");
    } else {
		printk(" !!!!! Init Indirect Registers UNSUCCESSFULLY.\n");
		return -1;
    }
    return 0;
}

static inline void wcfxs_voicedaa_check_hook(struct wcfxs *wc, int card)
{
#ifndef AUDIO_RINGCHECK
	unsigned char res;
#endif	
	signed char b;
	int poopy = 0;
	/* Try to track issues that plague slot one FXO's */
	b = wcfxs_getreg(wc, card, 5);
	if ((b & 0x2) || !(b & 0x8)) {
		/* Not good -- don't look at anything else */
		if (debug)
			printk("Poopy (%02x) on card %d!\n", b, card + 1); 
		poopy++;
	}
	b &= 0x9b;
	reg5 = b;
	reg12 = wcfxs_getreg(wc, card, 12);
	loop_i = wcfxs_getreg(wc, card, 28);
	line_v = wcfxs_getreg(wc, card, 29);
	if (wc->mod.fxo.offhook[card]) {
		if (b != 0x9)
			wcfxs_setreg(wc, card, 5, 0x9);
	} else {
		if (b != 0x8)
			wcfxs_setreg(wc, card, 5, 0x8);
	}
	if (poopy)
		return;
#ifndef AUDIO_RINGCHECK
	if (!wc->mod.fxo.offhook[card]) {
		res = wcfxs_getreg(wc, card, 5);
		if ((res & 0x60) && wc->mod.fxo.battery[card]) {
			wc->mod.fxo.ringdebounce[card] += (ZT_CHUNKSIZE * 4);
			if (wc->mod.fxo.ringdebounce[card] >= ZT_CHUNKSIZE * 64) {
				if (!wc->mod.fxo.wasringing[card]) {
					wc->mod.fxo.wasringing[card] = 1;
					zt_hooksig(&wc->chans[card], ZT_RXSIG_RING);
					if (debug)
						printk("RING on %d/%d!\n", wc->span.spanno, card + 1);
				}
				wc->mod.fxo.ringdebounce[card] = ZT_CHUNKSIZE * 64;
			}
		} else {
			wc->mod.fxo.ringdebounce[card] -= ZT_CHUNKSIZE;
			if (wc->mod.fxo.ringdebounce[card] <= 0) {
				if (wc->mod.fxo.wasringing[card]) {
					wc->mod.fxo.wasringing[card] =0;
					zt_hooksig(&wc->chans[card], ZT_RXSIG_OFFHOOK);
					if (debug)
						printk("NO RING on %d/%d!\n", wc->span.spanno, card + 1);
				}
				wc->mod.fxo.ringdebounce[card] = 0;
			}
				
		}
	}
#endif
	b = wcfxs_getreg(wc, card, 29);
#if 0 
	{
		static int count = 0;
		if (!(count++ % 100)) {
			printk("Card %d: Voltage: %d  Debounce %d\n", card + 1, 
			       b, wc->mod.fxo.battdebounce[card]);
		}
	}
#endif	
	if (abs(b) < BATT_THRESH) {
		wc->mod.fxo.nobatttimer[card]++;
#if 0
		if (wc->mod.fxo.battery[card])
			printk("Battery loss: %d (%d debounce)\n", b, wc->mod.fxo.battdebounce[card]);
#endif
		if (wc->mod.fxo.battery[card] && !wc->mod.fxo.battdebounce[card]) {
			if (debug)
				printk("NO BATTERY on %d/%d!\n", wc->span.spanno, card + 1);
			wc->mod.fxo.battery[card] =  0;
#ifdef	JAPAN
			if ((!wc->ohdebounce) && wc->offhook) {
				zt_hooksig(&wc->chans[card], ZT_RXSIG_ONHOOK);
				if (debug)
					printk("Signalled On Hook\n");
#ifdef	ZERO_BATT_RING
				wc->onhook++;
#endif
			}
#else
			zt_hooksig(&wc->chans[card], ZT_RXSIG_ONHOOK);
#endif
			wc->mod.fxo.battdebounce[card] = BATT_DEBOUNCE;
		} else if (!wc->mod.fxo.battery[card])
			wc->mod.fxo.battdebounce[card] = BATT_DEBOUNCE;
	} else if (abs(b) > BATT_THRESH) {
		if (!wc->mod.fxo.battery[card] && !wc->mod.fxo.battdebounce[card]) {
			if (debug)
				printk("BATTERY on %d/%d (%s)!\n", wc->span.spanno, card + 1, 
					(b < 0) ? "-" : "+");			    
#ifdef	ZERO_BATT_RING
			if (wc->onhook) {
				wc->onhook = 0;
				zt_hooksig(&wc->chans[card], ZT_RXSIG_OFFHOOK);
				if (debug)
					printk("Signalled Off Hook\n");
			}
#else
			zt_hooksig(&wc->chans[card], ZT_RXSIG_OFFHOOK);
#endif
			wc->mod.fxo.battery[card] = 1;
			wc->mod.fxo.nobatttimer[card] = 0;
			wc->mod.fxo.battdebounce[card] = BATT_DEBOUNCE;
		} else if (wc->mod.fxo.battery[card])
			wc->mod.fxo.battdebounce[card] = BATT_DEBOUNCE;

		if (wc->mod.fxo.lastpol[card] >= 0) {
		    if (b < 0) {
			wc->mod.fxo.lastpol[card] = -1;
			wc->mod.fxo.polaritydebounce[card] = POLARITY_DEBOUNCE;
		    }
		} 
		if (wc->mod.fxo.lastpol[card] <= 0) {
		    if (b > 0) {
			wc->mod.fxo.lastpol[card] = 1;
			wc->mod.fxo.polaritydebounce[card] = POLARITY_DEBOUNCE;
		    }
		}
	} else {
		/* It's something else... */
		wc->mod.fxo.battdebounce[card] = BATT_DEBOUNCE;
	}
	if (wc->mod.fxo.battdebounce[card])
		wc->mod.fxo.battdebounce[card]--;
	if (wc->mod.fxo.polaritydebounce[card]) {
	        wc->mod.fxo.polaritydebounce[card]--;
		if (wc->mod.fxo.polaritydebounce[card] < 1) {
		    if (wc->mod.fxo.lastpol[card] != wc->mod.fxo.polarity[card]) {
			if (debug)
				printk("%lu Polarity reversed (%d -> %d)\n", jiffies, 
			       wc->mod.fxo.polarity[card], 
			       wc->mod.fxo.lastpol[card]);
			if (wc->mod.fxo.polarity[card])
			    zt_qevent_lock(&wc->chans[card], ZT_EVENT_POLARITY);
			wc->mod.fxo.polarity[card] = wc->mod.fxo.lastpol[card];
		    }
		}
	}
}

static inline void wcfxs_proslic_check_hook(struct wcfxs *wc, int card)
{
	char res;
	int hook;

	/* For some reason we have to debounce the
	   hook detector.  */

	res = wcfxs_getreg(wc, card, 68);
	hook = (res & 1);
	if (hook != wc->mod.fxs.lastrxhook[card]) {
		/* Reset the debounce (must be multiple of 4ms) */
		wc->mod.fxs.debounce[card] = 8 * (4 * 8);
#if 0
		printk("Resetting debounce card %d hook %d, %d\n", card, hook, wc->mod.fxs.debounce[card]);
#endif
	} else {
		if (wc->mod.fxs.debounce[card] > 0) {
			wc->mod.fxs.debounce[card]-= 4 * ZT_CHUNKSIZE;
#if 0
			printk("Sustaining hook %d, %d\n", hook, wc->mod.fxs.debounce[card]);
#endif
			if (!wc->mod.fxs.debounce[card]) {
#if 0
				printk("Counted down debounce, newhook: %d...\n", hook);
#endif
				wc->mod.fxs.debouncehook[card] = hook;
			}
			if (!wc->mod.fxs.oldrxhook[card] && wc->mod.fxs.debouncehook[card]) {
				/* Off hook */
#if 1
				if (debug)
#endif				
					printk("wcfxs: Card %d Going off hook\n", card);
				zt_hooksig(&wc->chans[card], ZT_RXSIG_OFFHOOK);
				if (robust)
					wcfxs_init_proslic(wc, card, 1, 0, 1);
				wc->mod.fxs.oldrxhook[card] = 1;
			
			} else if (wc->mod.fxs.oldrxhook[card] && !wc->mod.fxs.debouncehook[card]) {
				/* On hook */
#if 1
				if (debug)
#endif				
					printk("wcfxs: Card %d Going on hook\n", card);
				zt_hooksig(&wc->chans[card], ZT_RXSIG_ONHOOK);
				wc->mod.fxs.oldrxhook[card] = 0;
			}
		}
	}
	wc->mod.fxs.lastrxhook[card] = hook;

	
}

static inline void wcfxs_proslic_recheck_sanity(struct wcfxs *wc, int card)
{
	int res;
	/* Check loopback */
	res = wcfxs_getreg(wc, card, 8);
	if (res) {
		printk("Ouch, part reset, quickly restoring reality (%d)\n", card);
		wcfxs_init_proslic(wc, card, 1, 0, 1);
	} else {
		res = wcfxs_getreg(wc, card, 64);
		if (!res && (res != wc->mod.fxs.lasttxhook[card])) {
			if (wc->mod.fxs.palarms[card]++ < MAX_ALARMS) {
				printk("Power alarm on module %d, resetting!\n", card + 1);
				if (wc->mod.fxs.lasttxhook[card] == 4)
					wc->mod.fxs.lasttxhook[card] = 1;
				wcfxs_setreg(wc, card, 64, wc->mod.fxs.lasttxhook[card]);
			} else {
				if (wc->mod.fxs.palarms[card] == MAX_ALARMS)
					printk("Too many power alarms on card %d, NOT resetting!\n", card + 1);
			}
		}
	}
}

#ifdef NOT_NEEDED_YET
#ifdef LINUX26
static irqreturn_t wcfxs_interrupt(int irq, void *dev_id, struct pt_regs *regs)
#else
static void wcfxs_interrupt(int irq, void *dev_id, struct pt_regs *regs)
#endif
{
	struct wcfxs *wc = dev_id;
	unsigned char ints;
	int x;

	ints = inb(wc->ioaddr + WC_INTSTAT);
	outb(ints, wc->ioaddr + WC_INTSTAT);

	if (!ints)
#ifdef LINUX26
		return IRQ_NONE;
#else
		return;
#endif		

	if (ints & 0x10) {
		/* Stop DMA, wait for watchdog */
		printk("TDM PCI Master abort\n");
		wcfxs_stop_dma(wc);
#ifdef LINUX26
		return IRQ_RETVAL(1);
#else
		return;
#endif		
	}
	
	if (ints & 0x20) {
		printk("PCI Target abort\n");
#ifdef LINUX26
		return IRQ_RETVAL(1);
#else
		return;
#endif		
	}

	for (x=0;x<4;x++) {
		if ((x < wc->cards) && (wc->cardflag & (1 << x)) &&
			(wc->modtype[x] == MOD_TYPE_FXS)) {
			if (wc->mod.fxs.lasttxhook[x] == 0x4) {
				/* RINGing, prepare for OHT */
				wc->mod.fxs.ohttimer[x] = OHT_TIMER << 3;
				wc->mod.fxs.idletxhookstate[x] = 0x2;	/* OHT mode when idle */
			} else {
				if (wc->mod.fxs.ohttimer[x]) {
					wc->mod.fxs.ohttimer[x]-= ZT_CHUNKSIZE;
					if (!wc->mod.fxs.ohttimer[x]) {
						wc->mod.fxs.idletxhookstate[x] = 0x1;	/* Switch to active */
						if (wc->mod.fxs.lasttxhook[x] == 0x2) {
							/* Apply the change if appropriate */
							wc->mod.fxs.lasttxhook[x] = 0x1;
							wcfxs_setreg(wc, x, 64, wc->mod.fxs.lasttxhook[x]);
						}
					}
				}
			}
		}
	}

#ifdef LINUX26
	return IRQ_RETVAL(1);
#endif		
	
}
#endif

/* handles regular interrupt processing, called every time we get a DMA
   interrupt which is every 1ms with ZT_CHUNKSIZE == 8 */

void regular_interrupt_processing(u8 *read_samples, u8 *write_samples) {
  struct wcfxs *wc = devs;

	int x;

	wc->intcount++;
	x = wc->intcount % 4;

	/* check hook switch (FXS) and ringing (FXO) */

	if ((x < wc->cards) && (wc->cardflag & (1 << x))) {
		if (wc->modtype[x] == MOD_TYPE_FXS) {
			wcfxs_proslic_check_hook(wc, x);
			if (!(wc->intcount & 0xfc))
				wcfxs_proslic_recheck_sanity(wc, x);
		} else if (wc->modtype[x] == MOD_TYPE_FXO) {
			/* ring detection, despite name */
			wcfxs_voicedaa_check_hook(wc, x); 
		}
	}

	if (!(wc->intcount % 10000)) {
		/* Accept an alarm once per 10 seconds */
		for (x=0;x<4;x++) 
			if (wc->modtype[x] == MOD_TYPE_FXS) {
				if (wc->mod.fxs.palarms[x])
					wc->mod.fxs.palarms[x]--;
			}
	}

	/* handle speech samples */

	wcfxs_transmitprep(wc, write_samples);
	wcfxs_receiveprep(wc, read_samples);
}

static int wcfxs_voicedaa_insane(struct wcfxs *wc, int card)
{
	int blah;
	
	blah = wcfxs_getreg(wc, card, 2);
	if (debug) {
		printk("Testing for DAA...\n");
	}
	if (blah != 0x3) {
		printk("  DAA not found! (blah = 0x%x)\n", blah);
		return -2;
	}
	blah = wcfxs_getreg(wc, card, 11);
	if (debug)
		printk("  VoiceDAA System: %02x\n", blah & 0xf);
	return 0;
}

static int wcfxs_proslic_insane(struct wcfxs *wc, int card)
{
	int blah,insane_report;
	insane_report=0;

	blah = wcfxs_getreg(wc, card, 0);
	if (debug) {
		printk("Testing for ProSLIC\n");
	}
#if 0
	if ((blah & 0x30) >> 4) {
		printk("ProSLIC on module %d is not a 3210.\n", card);
		return -1;
	}
#endif
	if (((blah & 0xf) == 0) || ((blah & 0xf) == 0xf)) {
		if (debug) {
			    printk("  ProSLIC not loaded...\n");
		}
		return -1;
	}
	if (debug) {
		printk("ProSLIC module %d, product %d, version %d\n", card, (blah & 0x30) >> 4, (blah & 0xf));
	}
	if ((blah & 0xf) < 2) {
		printk("ProSLIC 3210 version %d is too old\n", blah & 0xf);
		return -1;
	}
	if ((blah & 0xf) == 2) {
		/* ProSLIC 3215, not a 3210 */
		wc->flags[card] |= FLAG_3215;
	}
	blah = wcfxs_getreg(wc, card, 8);
	if (blah != 0x2) {
		printk("ProSLIC on module %d insane (1) %d should be 2\n", card, blah);
		return -1;
	} else if ( insane_report)
		printk("ProSLIC on module %d Reg 8 Reads %d Expected is 0x2\n",card,blah);

	blah = wcfxs_getreg(wc, card, 64);
	if (blah != 0x0) {
		printk("ProSLIC on module %d insane (2)\n", card);
		return -1;
	} else if ( insane_report)
		printk("ProSLIC on module %d Reg 64 Reads %d Expected is 0x0\n",card,blah);

	blah = wcfxs_getreg(wc, card, 11);
	if (blah != 0x33) {
		printk("ProSLIC on module %d insane (3)\n", card);
		return -1;
	} else if ( insane_report)
		printk("ProSLIC on module %d Reg 11 Reads %d Expected is 0x33\n",card,blah);

	/* Just be sure it's setup right. */
	wcfxs_setreg(wc, card, 30, 0);

	if (debug) 
		printk("ProSLIC on module %d seems sane.\n", card);
	return 0;
}

static int wcfxs_proslic_powerleak_test(struct wcfxs *wc, int card)
{
	unsigned long origjiffies;
	unsigned char vbat;

	/* Turn off linefeed */
	wcfxs_setreg(wc, card, 64, 0);

	/* Power down */
	wcfxs_setreg(wc, card, 14, 0x10);

	/* Wait for one second */
	origjiffies = jiffies;

	while((vbat = wcfxs_getreg(wc, card, 82)) > 0x6) {
		if ((jiffies - origjiffies) >= (HZ/2))
			break;;
	}

	if (vbat < 0x06) {
		printk("Excessive leakage detected on module %d: %d volts (%02x) after %d ms\n", card,
		       376 * vbat / 1000, vbat, (int)((jiffies - origjiffies) * 1000 / HZ));
		return -1;
	} else if (debug) {
		printk("Post-leakage voltage: %d volts\n", 376 * vbat / 1000);
	}
	return 0;
}

static int wcfxs_powerup_proslic(struct wcfxs *wc, int card, int fast)
{
	unsigned char vbat;
	unsigned long origjiffies;
	int lim;

	/* Set period of DC-DC converter to 1/64 khz */
	wcfxs_setreg(wc, card, 92, 0xff /* was 0xff */);

	/* Wait for VBat to powerup */
	origjiffies = jiffies;

	/* Disable powerdown */
	wcfxs_setreg(wc, card, 14, 0);

	/* If fast, don't bother checking anymore */
	if (fast)
		return 0;

	while((vbat = wcfxs_getreg(wc, card, 82)) < 0xc0) {
		/* Wait no more than 500ms */
		if ((jiffies - origjiffies) > HZ/2) {
			break;
		}
	}

	printk("reg 0: 0x%x \n", wcfxs_getreg(wc, card, 0));
	printk("reg 14: 0x%x \n", wcfxs_getreg(wc, card, 14));
	printk("reg 74: 0x%x \n", wcfxs_getreg(wc, card, 74));
	printk("reg 80: 0x%x \n", wcfxs_getreg(wc, card, 80));
	printk("reg 81: 0x%x \n", wcfxs_getreg(wc, card, 81));
	printk("reg 92: 0x%x \n", wcfxs_getreg(wc, card, 92));
	printk("reg 82: 0x%x \n", wcfxs_getreg(wc, card, 82));
	printk("reg 83: 0x%x \n", wcfxs_getreg(wc, card, 83));
        //return -1;

	if (vbat < 0xc0) {
		printk("ProSLIC on module %d failed to powerup within %d ms (%d mV only)\n\n -- DID YOU REMEMBER TO PLUG IN THE HD POWER CABLE TO THE TDM400P??\n",
		       card, (int)(((jiffies - origjiffies) * 1000 / HZ)),
			vbat * 375);
		return -1;
	} else if (debug) {
		printk("ProSLIC on module %d powered up to -%d volts (%02x) in %d ms\n",
		       card, vbat * 376 / 1000, vbat, (int)(((jiffies - origjiffies) * 1000 / HZ)));
	}

        /* Proslic max allowed loop current, reg 71 LOOP_I_LIMIT */
        /* If out of range, just set it to the default value     */
        lim = (loopcurrent - 20) / 3;
        if ( loopcurrent > 41 ) {
                lim = 0;
                if (debug)
                        printk("Loop current out of range! Setting to default 20mA!\n");
        }
        else if (debug)
                        printk("Loop current set to %dmA!\n",(lim*3)+20);
        wcfxs_setreg(wc,card,LOOP_I_LIMIT,lim);

	/* Engage DC-DC converter */
	wcfxs_setreg(wc, card, 93, 0x19 /* was 0x19 */);
#if 0
	origjiffies = jiffies;
	while(0x80 & wcfxs_getreg(wc, card, 93)) {
		if ((jiffies - origjiffies) > 2 * HZ) {
			printk("Timeout waiting for DC-DC calibration on module %d\n", card);
			return -1;
		}
	}

#if 0
	/* Wait a full two seconds */
	while((jiffies - origjiffies) < 2 * HZ);

	/* Just check to be sure */
	vbat = wcfxs_getreg(wc, card, 82);
	printk("ProSLIC on module %d powered up to -%d volts (%02x) in %d ms\n",
		       card, vbat * 376 / 1000, vbat, (int)(((jiffies - origjiffies) * 1000 / HZ)));
#endif
#endif
	return 0;

}

static int wcfxs_proslic_manual_calibrate(struct wcfxs *wc, int card){
	unsigned long origjiffies;
	unsigned char i;

	printk("Start manual calibration\n");

	wcfxs_setreg(wc, card, 21, 0);//(0)  Disable all interupts in DR21
	wcfxs_setreg(wc, card, 22, 0);//(0)Disable all interupts in DR21
	wcfxs_setreg(wc, card, 23, 0);//(0)Disable all interupts in DR21
	wcfxs_setreg(wc, card, 64, 0);//(0)

	wcfxs_setreg(wc, card, 97, 0x18); //(0x18)Calibrations without the ADC and DAC offset and without common mode calibration.
	wcfxs_setreg(wc, card, 96, 0x47); //(0x47)	Calibrate common mode and differential DAC mode DAC + ILIM

	origjiffies=jiffies;
	while( wcfxs_getreg(wc,card,96)!=0 ){
		if((jiffies-origjiffies)>80)
			return -1;
	}
//Initialized DR 98 and 99 to get consistant results.
// 98 and 99 are the results registers and the search should have same intial conditions.

/*******************************The following is the manual gain mismatch calibration****************************/
/*******************************This is also available as a function *******************************************/
	// Delay 10ms
	origjiffies=jiffies; 
	while((jiffies-origjiffies)<1);
	wcfxs_proslic_setreg_indirect(wc, card, 88,0);
	wcfxs_proslic_setreg_indirect(wc,card,89,0);
	wcfxs_proslic_setreg_indirect(wc,card,90,0);
	wcfxs_proslic_setreg_indirect(wc,card,91,0);
	wcfxs_proslic_setreg_indirect(wc,card,92,0);
	wcfxs_proslic_setreg_indirect(wc,card,93,0);

	wcfxs_setreg(wc, card, 98,0x10); // This is necessary if the calibration occurs other than at reset time
	wcfxs_setreg(wc, card, 99,0x10);

	for ( i=0x1f; i>0; i--)
	{
		wcfxs_setreg(wc, card, 98,i);
		origjiffies=jiffies; 
		while((jiffies-origjiffies)<4);
		if((wcfxs_getreg(wc,card,88)) == 0)
			break;
	} // for

	for ( i=0x1f; i>0; i--)
	{
		wcfxs_setreg(wc, card, 99,i);
		origjiffies=jiffies; 
		while((jiffies-origjiffies)<4);
		if((wcfxs_getreg(wc,card,89)) == 0)
			break;
	}//for

/*******************************The preceding is the manual gain mismatch calibration****************************/
/**********************************The following is the longitudinal Balance Cal***********************************/
	wcfxs_setreg(wc,card,64,1);
	while((jiffies-origjiffies)<10); // Sleep 100?

	wcfxs_setreg(wc, card, 64, 0);
	wcfxs_setreg(wc, card, 23, 0x4);  // enable interrupt for the balance Cal
	wcfxs_setreg(wc, card, 97, 0x1); // this is a singular calibration bit for longitudinal calibration
	wcfxs_setreg(wc, card, 96,0x40);

	wcfxs_getreg(wc,card,96); /* Read Reg 96 just cause */

	wcfxs_setreg(wc, card, 21, 0xFF);
	wcfxs_setreg(wc, card, 22, 0xFF);
	wcfxs_setreg(wc, card, 23, 0xFF);

	/**The preceding is the longitudinal Balance Cal***/
	return(0);

}
#if 1
static int wcfxs_proslic_calibrate(struct wcfxs *wc, int card)
{
	unsigned long origjiffies;
	int x;

	printk("Start automatic calibration\n");

	/* Perform all calibrations */
	wcfxs_setreg(wc, card, 97, 0x1f);
	
	/* Begin, no speedup */
	wcfxs_setreg(wc, card, 96, 0x5f);

	/* Wait for it to finish */
	origjiffies = jiffies;
	while(wcfxs_getreg(wc, card, 96)) {
		if ((jiffies - origjiffies) > 2 * HZ) {
			printk("Timeout waiting for calibration of module %d\n", card);
			return -1;
		}
	}
	
	if (debug) {
		/* Print calibration parameters */
		printk("Calibration Vector Regs 98 - 107: \n");
		for (x=98;x<108;x++) {
			printk("%d: %02x\n", x, wcfxs_getreg(wc, card, x));
		}
	}
	return 0;
}
#endif

/* wait 'foo' jiffies then return.  

   DR - modified to use a better delay mechanism that the orginal
   busy-waiting method, which locked the kernel up for some rather
   long times (e.g. seconds), at least on non-preemptable kernels.
*/

static void wait_just_a_bit(int foo)
{
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(foo);
}

static int wcfxs_init_voicedaa(struct wcfxs *wc, int card, int fast, int manual, int sane)
{
	unsigned char reg16=0, reg26=0, reg30=0, reg31=0;
	long newjiffies;
//	wc->modtype[card] = MOD_TYPE_FXO;
	
	//printk("Entering: wcfxs_init_voicedaa\n");

	/* Sanity check */
	//bfsi_reset(RESET_BIT);
	if (!sane && wcfxs_voicedaa_insane(wc, card))
		return -2;

	/* Software reset */
	wcfxs_setreg(wc, card, 1, 0x80);

	/* Wait just a bit */
	wait_just_a_bit(HZ/10);

	/* Enable PCM, ulaw */
	wcfxs_setreg(wc, card, 33, 0x28);

	/* Set On-hook speed, Ringer impedence, and ringer threshold */
	reg16 |= (fxo_modes[_opermode].ohs << 6);
	reg16 |= (fxo_modes[_opermode].rz << 1);
	reg16 |= (fxo_modes[_opermode].rt);
	wcfxs_setreg(wc, card, 16, reg16);
	
	/* Set DC Termination:
	   Tip/Ring voltage adjust, minimum operational current, current limitation */
	reg26 |= (fxo_modes[_opermode].dcv << 6);
	reg26 |= (fxo_modes[_opermode].mini << 4);
	reg26 |= (fxo_modes[_opermode].ilim << 1);
	wcfxs_setreg(wc, card, 26, reg26);

	/* Set AC Impedence */
	reg30 = (fxo_modes[_opermode].acim);
	wcfxs_setreg(wc, card, 30, reg30);

	/* Misc. DAA parameters */
	reg31 = 0xa3;
	reg31 |= (fxo_modes[_opermode].ohs2 << 3);
	wcfxs_setreg(wc, card, 31, reg31);

	/* Set Transmit/Receive timeslot */
	wcfxs_setreg(wc, card, 34, (card) * 8);
	wcfxs_setreg(wc, card, 35, 0x00);
	wcfxs_setreg(wc, card, 36, (card) * 8);
	wcfxs_setreg(wc, card, 37, 0x00);

	/* Enable ISO-Cap */
	wcfxs_setreg(wc, card, 6, 0x00);

	/* Wait 1000ms for ISO-cap to come up */
	newjiffies = jiffies;
	newjiffies += 2 * HZ;
	while((jiffies < newjiffies) && !(wcfxs_getreg(wc, card, 11) & 0xf0))
		wait_just_a_bit(HZ/10);

	if (!(wcfxs_getreg(wc, card, 11) & 0xf0)) {
		printk("VoiceDAA did not bring up ISO link properly!\n");
		return -1;
	}
	if (debug)
		printk("  ISO-Cap is now up, line side: %02x rev %02x\n", 
		       wcfxs_getreg(wc, card, 11) >> 4,
		       (wcfxs_getreg(wc, card, 13) >> 2) & 0xf);

	/* Enable on-hook line monitor */
	wcfxs_setreg(wc, card, 5, 0x08);

	/* DR 6/1105: Debug code used to trap bad reads, 
	   see notes in __write_8bits 
	{
	        int i;
		unsigned char r;

		for(i=0; i<1000; i++) {
			r = wcfxs_getreg(wc, card, 31);
			if (r != 0xa3) {
				printk("bad read! Check if CS is going low\n");
				break;
			}

		}
       		printk("  1000 reads OK!\n");
	}
	*/
	
	/* Optional digital loopback, used for testing Blackfin DMA */

	if (loopback) {
		wcfxs_setreg(wc, card, 10, 0x01);
		printk("loopback enabled\n");
	}

	return 0;
}

static int wcfxs_init_proslic(struct wcfxs *wc, int card, int fast, int manual, int sane)
{

	unsigned short tmp[5];
	unsigned char r19;
	int x;
	int fxsmode=0;

	manual = 1;

	/* By default, don't send on hook */
	wc->mod.fxs.idletxhookstate [card] = 1;

	/* Sanity check the ProSLIC */
	if (!sane && wcfxs_proslic_insane(wc, card))
		return -2;
	
	if (sane) {
		/* Make sure we turn off the DC->DC converter to prevent anything from blowing up */
		wcfxs_setreg(wc, card, 14, 0x10);
	}

	if (wcfxs_proslic_init_indirect_regs(wc, card)) {
		printk(KERN_INFO "Indirect Registers failed to initialize on module %d.\n", card);
		return -1;
	}

	/* Clear scratch pad area */
	wcfxs_proslic_setreg_indirect(wc, card, 97,0);

	/* Clear digital loopback */
	wcfxs_setreg(wc, card, 8, 0);

	/* Revision C optimization */
	wcfxs_setreg(wc, card, 108, 0xeb);

	/* Disable automatic VBat switching for safety to prevent
	   Q7 from accidently turning on and burning out. */
	wcfxs_setreg(wc, card, 67, 0x17);

	/* Turn off Q7 */
	wcfxs_setreg(wc, card, 66, 1);

	/* Flush ProSLIC digital filters by setting to clear, while
	   saving old values */
	for (x=0;x<5;x++) {
		tmp[x] = wcfxs_proslic_getreg_indirect(wc, card, x + 35);
		wcfxs_proslic_setreg_indirect(wc, card, x + 35, 0x8000);
	}

	/* Power up the DC-DC converter */
	if (wcfxs_powerup_proslic(wc, card, fast)) {
		printk("Unable to do INITIAL ProSLIC powerup on module %d\n", card);
		return -1;
	}

	if (!fast) {

		/* Check for power leaks */
		if (wcfxs_proslic_powerleak_test(wc, card)) {
			printk("ProSLIC module %d failed leakage test.  Check for short circuit\n", card);
		}
		/* Power up again */
		if (wcfxs_powerup_proslic(wc, card, fast)) {
			printk("Unable to do FINAL ProSLIC powerup on module %d\n", card);
			return -1;
		}
#ifndef NO_CALIBRATION
		/* Perform calibration */
		if(manual) {
			if (wcfxs_proslic_manual_calibrate(wc, card)) {
				//printk("Proslic failed on Manual Calibration\n");
				if (wcfxs_proslic_manual_calibrate(wc, card)) {
					printk("Proslic Failed on Second Attempt to Calibrate Manually. (Try -DNO_CALIBRATION in Makefile)\n");
					return -1;
				}
				printk("Proslic Passed Manual Calibration on Second Attempt\n");
			}
		}
		else {
			if(wcfxs_proslic_calibrate(wc, card))  {
				//printk("ProSlic died on Auto Calibration.\n");
				if (wcfxs_proslic_calibrate(wc, card)) {
					printk("Proslic Failed on Second Attempt to Auto Calibrate\n");
					return -1;
				}
				printk("Proslic Passed Auto Calibration on Second Attempt\n");
			}
		}
		/* Perform DC-DC calibration */
		wcfxs_setreg(wc, card, 93, 0x99);
		r19 = wcfxs_getreg(wc, card, 107);
		if ((r19 < 0x2) || (r19 > 0xd)) {
			printk("DC-DC cal has a surprising direct 107 of 0x%02x!\n", r19);
			wcfxs_setreg(wc, card, 107, 0x8);
		}

		/* Save calibration vectors */
		for (x=0;x<NUM_CAL_REGS;x++)
			wc->mod.fxs.calregs[card].vals[x] = wcfxs_getreg(wc, card, 96 + x);
#endif

	} else {
		/* Restore calibration registers */
		for (x=0;x<NUM_CAL_REGS;x++)
			wcfxs_setreg(wc, card, 96 + x, wc->mod.fxs.calregs[card].vals[x]);
	}
	/* Calibration complete, restore original values */
	for (x=0;x<5;x++) {
		wcfxs_proslic_setreg_indirect(wc, card, x + 35, tmp[x]);
	}

	if (wcfxs_proslic_verify_indirect_regs(wc, card)) {
		printk(KERN_INFO "Indirect Registers failed verification.\n");
		return -1;
	}


#if 0
    /* Disable Auto Power Alarm Detect and other "features" */
    wcfxs_setreg(wc, card, 67, 0x0e);
    blah = wcfxs_getreg(wc, card, 67);
#endif

#if 0
    if (wcfxs_proslic_setreg_indirect(wc, card, 97, 0x0)) { // Stanley: for the bad recording fix
		 printk(KERN_INFO "ProSlic IndirectReg Died.\n");
		 return -1;
	}
#endif

    wcfxs_setreg(wc, card, 1, 0x28);
 	// U-Law 8-bit interface
    wcfxs_setreg(wc, card, 2, (card) * 8);    // Tx Start count low byte  0
    wcfxs_setreg(wc, card, 3, 0);    // Tx Start count high byte 0
    wcfxs_setreg(wc, card, 4, (card) * 8);    // Rx Start count low byte  0
    wcfxs_setreg(wc, card, 5, 0);    // Rx Start count high byte 0
    wcfxs_setreg(wc, card, 18, 0xff);     // clear all interrupt
    wcfxs_setreg(wc, card, 19, 0xff);
    wcfxs_setreg(wc, card, 20, 0xff);
    wcfxs_setreg(wc, card, 73, 0x04);
	if (fxshonormode) {
		fxsmode = acim2tiss[fxo_modes[_opermode].acim];
		wcfxs_setreg(wc, card, 10, 0x08 | fxsmode);
		if (fxo_modes[_opermode].ring_osc)
			wcfxs_proslic_setreg_indirect(wc, card, 20, fxo_modes[_opermode].ring_osc);
		if (fxo_modes[_opermode].ring_x)
			wcfxs_proslic_setreg_indirect(wc, card, 21, fxo_modes[_opermode].ring_x);
	}
    if (lowpower)
    	wcfxs_setreg(wc, card, 72, 0x10);

#if 0
    wcfxs_setreg(wc, card, 21, 0x00); 	// enable interrupt
    wcfxs_setreg(wc, card, 22, 0x02); 	// Loop detection interrupt
    wcfxs_setreg(wc, card, 23, 0x01); 	// DTMF detection interrupt
#endif

#if 0
    /* Enable loopback */
    wcfxs_setreg(wc, card, 8, 0x2);
    wcfxs_setreg(wc, card, 14, 0x0);
    wcfxs_setreg(wc, card, 64, 0x0);
    wcfxs_setreg(wc, card, 1, 0x08);
#endif

	/* Beef up Ringing voltage to 89V */
	if (boostringer) {
		if (wcfxs_proslic_setreg_indirect(wc, card, 21, 0x1d1)) 
			return -1;
		printk("Boosting ringinger on slot %d (89V peak)\n", card + 1);
	} else if (lowpower) {
		if (wcfxs_proslic_setreg_indirect(wc, card, 21, 0x108)) 
			return -1;
		printk("Reducing ring power on slot %d (50V peak)\n", card + 1);
	}
	wcfxs_setreg(wc, card, 64, 0x01);
	return 0;
}

static int wcfxs_ioctl(struct zt_chan *chan, unsigned int cmd, unsigned long data)
{
	struct wcfxs_stats stats;
	struct wcfxs_regs regs;
	struct wcfxs_regop regop;
	struct wcfxs *wc = chan->pvt;
	int x;
	switch (cmd) {
	case ZT_ONHOOKTRANSFER:
		if (wc->modtype[chan->chanpos - 1] != MOD_TYPE_FXS)
			return -EINVAL;
		if (get_user(x, (int *)data))
			return -EFAULT;
		wc->mod.fxs.ohttimer[chan->chanpos - 1] = x << 3;
		wc->mod.fxs.idletxhookstate[chan->chanpos - 1] = 0x2;	/* OHT mode when idle */
		if (wc->mod.fxs.lasttxhook[chan->chanpos - 1] == 0x1) {
				/* Apply the change if appropriate */
				wc->mod.fxs.lasttxhook[chan->chanpos - 1] = 0x2;
				wcfxs_setreg(wc, chan->chanpos - 1, 64, wc->mod.fxs.lasttxhook[chan->chanpos - 1]);
		}
		break;
	case WCFXS_GET_STATS:
		if (wc->modtype[chan->chanpos - 1] == MOD_TYPE_FXS) {
			stats.tipvolt = wcfxs_getreg(wc, chan->chanpos - 1, 80) * -376;
			stats.ringvolt = wcfxs_getreg(wc, chan->chanpos - 1, 81) * -376;
			stats.batvolt = wcfxs_getreg(wc, chan->chanpos - 1, 82) * -376;
		} else if (wc->modtype[chan->chanpos - 1] == MOD_TYPE_FXO) {
			stats.tipvolt = (signed char)wcfxs_getreg(wc, chan->chanpos - 1, 29) * 1000;
			stats.ringvolt = (signed char)wcfxs_getreg(wc, chan->chanpos - 1, 29) * 1000;
			stats.batvolt = (signed char)wcfxs_getreg(wc, chan->chanpos - 1, 29) * 1000;
		} else 
			return -EINVAL;
		if (copy_to_user((struct wcfxs_stats *)data, &stats, sizeof(stats)))
			return -EFAULT;
		break;
	case WCFXS_GET_REGS:
		if (wc->modtype[chan->chanpos - 1] == MOD_TYPE_FXS) {
			for (x=0;x<NUM_INDIRECT_REGS;x++)
				regs.indirect[x] = wcfxs_proslic_getreg_indirect(wc, chan->chanpos -1, x);
			for (x=0;x<NUM_REGS;x++)
				regs.direct[x] = wcfxs_getreg(wc, chan->chanpos - 1, x);
		} else {
			memset(&regs, 0, sizeof(regs));
			for (x=0;x<NUM_FXO_REGS;x++)
				regs.direct[x] = wcfxs_getreg(wc, chan->chanpos - 1, x);
		}
		if (copy_to_user((struct wcfxs_regs *)data, &regs, sizeof(regs)))
			return -EFAULT;
		break;
	case WCFXS_SET_REG:
		if (copy_from_user(&regop, (struct wcfxs_regop *)data, sizeof(regop)))
			return -EFAULT;
		if (regop.indirect) {
			if (wc->modtype[chan->chanpos - 1] != MOD_TYPE_FXS)
				return -EINVAL;
			printk("Setting indirect %d to 0x%04x on %d\n", regop.reg, regop.val, chan->chanpos);
			wcfxs_proslic_setreg_indirect(wc, chan->chanpos - 1, regop.reg, regop.val);
		} else {
			regop.val &= 0xff;
			printk("Setting direct %d to %04x on %d\n", regop.reg, regop.val, chan->chanpos);
			wcfxs_setreg(wc, chan->chanpos - 1, regop.reg, regop.val);
		}
		break;
	default:
		return -ENOTTY;
	}
	return 0;

}

static int wcfxs_open(struct zt_chan *chan)
{
	struct wcfxs *wc = chan->pvt;
	if (!(wc->cardflag & (1 << (chan->chanpos - 1))))
		return -ENODEV;
	if (wc->dead)
		return -ENODEV;
	wc->usecount++;
#ifndef LINUX26
	MOD_INC_USE_COUNT;
#else
	try_module_get(THIS_MODULE);
#endif	
	return 0;
}

static int wcfxs_watchdog(struct zt_span *span, int event)
{
	printk("TDM: Restarting DMA\n");
#ifdef NOT_NEEDED_YET
	wcfxs_restart_dma(span->pvt);
#endif
	return 0;
}

static int wcfxs_close(struct zt_chan *chan)
{
	struct wcfxs *wc = chan->pvt;
	wc->usecount--;
#ifndef LINUX26
	MOD_DEC_USE_COUNT;
#else
	module_put(THIS_MODULE);
#endif
	if (wc->modtype[chan->chanpos - 1] == MOD_TYPE_FXS)
		wc->mod.fxs.idletxhookstate[chan->chanpos - 1] = 1;

	/* If we're dead, release us now */
	if (!wc->usecount && wc->dead) 
		wcfxs_release(wc);
	return 0;
}

static int wcfxs_hooksig(struct zt_chan *chan, zt_txsig_t txsig)
{
	struct wcfxs *wc = chan->pvt;
	int reg=0;
	if (wc->modtype[chan->chanpos - 1] == MOD_TYPE_FXO) {
		/* XXX Enable hooksig for FXO XXX */
		switch(txsig) {
		case ZT_TXSIG_START:
		case ZT_TXSIG_OFFHOOK:
			wc->mod.fxo.offhook[chan->chanpos - 1] = 1;
			wcfxs_setreg(wc, chan->chanpos - 1, 5, 0x9);
			break;
		case ZT_TXSIG_ONHOOK:
			wc->mod.fxo.offhook[chan->chanpos - 1] = 0;
			wcfxs_setreg(wc, chan->chanpos - 1, 5, 0x8);
			break;
		default:
			printk("wcfxo: Can't set tx state to %d\n", txsig);
		}
	} else {
		switch(txsig) {
		case ZT_TXSIG_ONHOOK:
			switch(chan->sig) {
			case ZT_SIG_EM:
			case ZT_SIG_FXOKS:
			case ZT_SIG_FXOLS:
				wc->mod.fxs.lasttxhook[chan->chanpos-1] = wc->mod.fxs.idletxhookstate[chan->chanpos-1];
				break;
			case ZT_SIG_FXOGS:
				wc->mod.fxs.lasttxhook[chan->chanpos-1] = 3;
				break;
			}
			break;
		case ZT_TXSIG_OFFHOOK:
			switch(chan->sig) {
			case ZT_SIG_EM:
				wc->mod.fxs.lasttxhook[chan->chanpos-1] = 5;
				break;
			default:
				wc->mod.fxs.lasttxhook[chan->chanpos-1] = wc->mod.fxs.idletxhookstate[chan->chanpos-1];
				break;
			}
			break;
		case ZT_TXSIG_START:
			wc->mod.fxs.lasttxhook[chan->chanpos-1] = 4;
			break;
		case ZT_TXSIG_KEWL:
			wc->mod.fxs.lasttxhook[chan->chanpos-1] = 0;
			break;
		default:
			printk("wcfxs: Can't set tx state to %d\n", txsig);
		}
		if (debug)
			printk("Setting FXS hook state to %d (%02x)\n", txsig, reg);

#if 1
		wcfxs_setreg(wc, chan->chanpos - 1, 64, wc->mod.fxs.lasttxhook[chan->chanpos-1]);
#endif
	}
	return 0;
}

static int wcfxs_initialize(struct wcfxs *wc)
{
	int x;

	/* Zapata stuff */
	sprintf(wc->span.name, "WCTDM/%d", wc->pos);
	sprintf(wc->span.desc, "%s Board %d", wc->variety, wc->pos + 1);
	wc->span.deflaw = ZT_LAW_MULAW;
	for (x=0;x<wc->cards;x++) {
		sprintf(wc->chans[x].name, "WCTDM/%d/%d", wc->pos, x);
		wc->chans[x].sigcap = ZT_SIG_FXOKS | ZT_SIG_FXOLS | ZT_SIG_FXOGS | ZT_SIG_SF | ZT_SIG_EM | ZT_SIG_CLEAR;
		wc->chans[x].sigcap |= ZT_SIG_FXSKS | ZT_SIG_FXSLS | ZT_SIG_SF | ZT_SIG_CLEAR;
		wc->chans[x].chanpos = x+1;
		wc->chans[x].pvt = wc;
	}
	wc->span.chans = wc->chans;
	wc->span.channels = wc->cards;
	wc->span.hooksig = wcfxs_hooksig;
	wc->span.open = wcfxs_open;
	wc->span.close = wcfxs_close;
	wc->span.flags = ZT_FLAG_RBS;
	wc->span.ioctl = wcfxs_ioctl;
	wc->span.watchdog = wcfxs_watchdog;
	init_waitqueue_head(&wc->span.maintq);

	wc->span.pvt = wc;
	if (zt_register(&wc->span, 0)) {
		printk("Unable to register span with zaptel\n");
		return -1;
	}
	return 0;
}

static void wcfxs_post_initialize(struct wcfxs *wc)
{
	int x;
	/* Finalize signalling  */
	for (x=0;x<wc->cards;x++) {
		if (wc->cardflag & (1 << x)) {
			if (wc->modtype[x] == MOD_TYPE_FXO)
				wc->chans[x].sigcap = ZT_SIG_FXSKS | ZT_SIG_FXSLS | ZT_SIG_SF | ZT_SIG_CLEAR;
			else
				wc->chans[x].sigcap = ZT_SIG_FXOKS | ZT_SIG_FXOLS | ZT_SIG_FXOGS | ZT_SIG_SF | ZT_SIG_EM | ZT_SIG_CLEAR;
		}
	}
}

int wcfxs_proc_read(char *buf, char **start, off_t offset, 
		    int count, int *eof, void *data)
{
	int len;

	len = sprintf(buf, 
		      "3050 reg5.....: 0x%x\n"
		      "3050 reg12....: 0x%x\n"
		      "3050 loop_i...: 0x%x\n"
		      "3050 line_v...: 0x%x\n",
		      reg5, reg12, loop_i, line_v);

	*eof=1;
	return len;
}

static int wcfxs_hardware_init(struct wcfxs *wc)
{
	/* Hardware stuff */
	unsigned char x;

	bfsi_spi_init(SPI_BAUDS);
        create_proc_read_entry("wcfxs", 0, NULL, wcfxs_proc_read, NULL);

	#ifdef DR_OLD
	init_sport0();
	init_dma_wc();

	/* Si3050 data sheet Table 6, FYSNC/PCLK relationship must be
	   fixed after reset, as we generate FSYNC from the serial
	   port this means we must start the serial port and DMA
	   interrupts before resetting the 3050 */

	/* Enable interrupts and DMA */
	if (init_sport_interrupts()) {
		return -1;
	}
	enable_dma_sport0();
	#endif

	bfsi_sport_init(regular_interrupt_processing, ZT_CHUNKSIZE, debug);
	bfsi_reset(RESET_BIT);

	#ifdef DAISY
	/* put 3210 in daisy chain mode */
	bfsi_spi_set_cs(0);
	__write_8bits(wc, 0x00); /* reg 0 write */
	__write_8bits(wc, 0x80); /* value to write (set bit 7) */
	#endif

	/* configure daughter cards */

	for (x=0;x<wc->cards;x++) {
		int sane=0,ret=0,readi=0;

		if(wc->modtype[x] == MOD_TYPE_FXS){
			/* Init with Auto Calibration */
			if (!(ret=wcfxs_init_proslic(wc, x, 0, 0, sane))) {
				wc->cardflag |= (1 << x);
                        	if (debug) {
                                	readi = wcfxs_getreg(wc,x,LOOP_I_LIMIT);
                                	printk("Proslic module %d loop current is %dmA\n",x,
                                	((readi*3)+20));
                        	}
				printk("Module %d: Installed -- AUTO FXS/DPO\n",x);
			} else {
				if(ret!=-2) {
					sane=1;
					/* Init with Manual Calibration */
					if (!wcfxs_init_proslic(wc, x, 0, 1, sane)) {
						wc->cardflag |= (1 << x);
                                		if (debug) {
                                        		readi = wcfxs_getreg(wc,x,LOOP_I_LIMIT);
                                        		printk("Proslic module %d loop current is %dmA\n",x,
                                        		((readi*3)+20));
                               	 		}
						printk("Module %d: Installed -- MANUAL FXS\n",x);
					} else {
						printk("Module %d: FAILED FXS (%s)\n", x, fxshonormode ? fxo_modes[_opermode].name : "FCC");
					} 
				} 
			}
		}else { 
printk("FXO detect.....\n");
			if (!(ret = wcfxs_init_voicedaa(wc, x, 0, 0, sane))) {
				wc->cardflag |= (1 << x);
				printk("Module %d: Installed -- AUTO FXO (%s mode)\n",x, fxo_modes[_opermode].name);
			} else
				printk("Module %d: Not installed\n", x);
		}
	}

	/* Return error if nothing initialized okay. */
	if (!wc->cardflag && !timingonly) {
		disable_sport0();
		free_irq(wc->irq, NULL);
		return -1;
	}
	return 0;
}

static int wcfxs_init_one(struct wcfxs_desc *d)
{
	int res;
	struct wcfxs *wc;
	int x;
	int y;
	static int initd_ifaces=0;
	
	init_ok = 0;

	if(initd_ifaces){
		memset((void *)ifaces,0,(sizeof(struct wcfxs *))*WC_MAX_IFACES);
		initd_ifaces=1;
	}
	for (x=0;x<WC_MAX_IFACES;x++)
		if (!ifaces[x]) break;
	if (x >= WC_MAX_IFACES) {
		printk("Too many interfaces\n");
		return -EIO;
	}
	
	wc = kmalloc(sizeof(struct wcfxs), GFP_KERNEL);
	if (wc) {
		ifaces[x] = wc;
		memset(wc, 0, sizeof(struct wcfxs));
		spin_lock_init(&wc->lock);
		wc->curcard = -1;
		wc->cards = NUM_CARDS;
		wc->modtype[0] = MOD_TYPE_FXS;
		wc->modtype[1] = MOD_TYPE_FXS;
		wc->modtype[2] = MOD_TYPE_FXO;
		wc->modtype[3] = MOD_TYPE_FXO;
		wc->pos = x;
		wc->variety = d->name;
		wc->irq = IRQ_SPORT0_RX;
		devs = wc;
		for (y=0;y<NUM_CARDS;y++)
			wc->flags[y] = d->flags;

		if (wcfxs_initialize(wc)) {
			printk("wcfxs: Unable to intialize FXS\n");
			kfree(wc);
			return -EIO;
		}

		if (wcfxs_hardware_init(wc)) {
			zt_unregister(&wc->span);
			kfree(wc);
			return -EIO;
		}

 		init_ok = 1;

		wcfxs_post_initialize(wc);
			
		printk("Found: %s (%d modules)\n", wc->variety, wc->cards);
		res = 0;
	} else
		res = -ENOMEM;

	return res;
}

static void wcfxs_release(struct wcfxs *wc)
{
	/* disable serial port, this will stop DMA and interrupts */
	disable_sport0();

	if (init_ok) {
		free_irq(wc->irq, NULL);
		zt_unregister(&wc->span);
		kfree(wc);
	}
        remove_proc_entry("wcfxs", NULL);
	printk("Freed a Wildcard\n");
}

static int __init wcfxs_init(void)
{
	int x;
	for (x=0;x<(sizeof(fxo_modes) / sizeof(fxo_modes[0])); x++) {
		if (!strcmp(fxo_modes[x].name, opermode))
			break;
	}
	if (x < sizeof(fxo_modes) / sizeof(fxo_modes[0])) {
		_opermode = x;
	} else {
		printk("Invalid/unknown operating mode '%s' specified.  Please choose one of:\n", opermode);
		for (x=0;x<sizeof(fxo_modes) / sizeof(fxo_modes[0]); x++)
			printk("  %s\n", fxo_modes[x].name);
		printk("Note this option is CASE SENSITIVE!\n");
		return -ENODEV;
	}

	#ifdef DR_OLD
	if (loopback) {
		memset((char*)iTxBuffer1, 0, sizeof(iTxBuffer1));
		for(i=0; i<ZT_CHUNKSIZE*2; i++)
			iTxBuffer1[i*8] = 0x7f;
		//for(i=0; i<ZT_CHUNKSIZE-1; i++) {
		//	iTxBuffer1[(i+1)*8] = digital_milliwatt[i];
		//	iTxBuffer1[(i+1+ZT_CHUNKSIZE)*8] = digital_milliwatt[i];
		//}
		//iTxBuffer1[0] = digital_milliwatt[ZT_CHUNKSIZE-1];
		//iTxBuffer1[(ZT_CHUNKSIZE)*8] = digital_milliwatt[ZT_CHUNKSIZE-1];
	}
	#endif

	wcfxs_init_one(&wcfxs_bf);   

	wait_just_a_bit(10);

	return 0;
}

static void __exit wcfxs_cleanup(void)
{

	wcfxs_release(devs);

	#ifdef OLD_DR
	if (loopback) {
		for(r=0; r<ZT_CHUNKSIZE*2; r++) {
			printk("[%03d] ", r*8);
			for(c=0; c<8; c++) {
				printk("0x%02x 0x%02x  ", 
				       iTxBuffer1[r*8+c]&0xff, 
				       iRxBuffer1[r*8+c]&0xff);
			}
			printk("\n");
		}
		//for(r=0; r<10; r++) {
		//	printk("[%03d] 0x%04x 0x%04x %d\n", r, logdma1[r], logdma2[r], logdma3[r]);
		//}
		for(r=0; r<LOG_LEN; r++) {
			printk("[%03d] %d\n", r, logdma1[r]);
		}
		printk("serialnum = %d ilogdma = %d\n",serialnum, ilogdma);
	}
	#endif
}

module_param(debug, int, 0600);
module_param(loopcurrent, int, 0600);
module_param(robust, int, 0600);
module_param(_opermode, int, 0600);
module_param(opermode, charp, 0600);
module_param(timingonly, int, 0600);
module_param(lowpower, int, 0600);
module_param(boostringer, int, 0600);
module_param(fxshonormode, int, 0600);
module_param(loopback, int, 0600); /* uCasterisk test mode */
module_param(internalclock, int, 0600); /* uCasterisk test mode */

MODULE_DESCRIPTION("Wildcard TDM400P Zaptel Driver");
MODULE_AUTHOR("Mark Spencer <markster@digium.com>");
#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif

module_init(wcfxs_init);
module_exit(wcfxs_cleanup);

#ifdef OLD_DR
/*--------------------------------------------------------------------------*\

                        BLACKFIN SPECIFIC FUNCTIONS

\*--------------------------------------------------------------------------*/

/* Init serial port but dont enable just yet, we need to set up DMA first */

static void init_sport0(void)
{
	/* set up FSYNC and optionally SCLK using Blackfin Serial port */

	/* Note: internalclock option not working at this stage - Tx side
	   appears not to work, e.g. TFS pin never gets asserted. Not a 
	   huge problem as the BF internal clock is not at quite the
	   right frequency (re-crystal of STAMP probably required), so 
	   we really need an external clock anyway.  However it would
	   be nice to know why it doesnt work! */

	if (internalclock) {
		*pSPORT0_RCLKDIV = 24;  /* approx 2.048MHz PCLK            */
		*pSPORT0_RFSDIV = 255;  /* 8 kHz FSYNC with 2.048MHz PCLK  */
	}		
	else {
		*pSPORT0_RFSDIV = 255;  /* 8 kHz FSYNC with 2.048MHz PCLK  */
	}

	/* external tx clk, not data dependant, MSB first */
	*pSPORT0_TCR2 = 7;      /* 8 bit word length      */
	*pSPORT0_TCR1 = 0;

	/* rx enabled, MSB first, internal frame sync     */
	*pSPORT0_RCR2 = 7;      /* 8 bit word length      */
	if (internalclock) {
		*pSPORT0_RCR1 = IRFS | IRCLK;
	}
	else {
		*pSPORT0_RCR1 = IRFS;
	}

	/* Enable MCM 8 transmit & receive channels       */
	*pSPORT0_MTCS0 = 0x000000FF;
	*pSPORT0_MRCS0 = 0x000000FF;
	
	/* MCM window size of 8 with 0 offset             */
	*pSPORT0_MCMC1 = 0x0000;

	/* 0 bit delay between FS pulse and first data bit,
	   multichannel frame mode enabled, 
	   multichannel tx and rx DMA packing enabled */
	*pSPORT0_MCMC2 = 0x001c;
}

/* init DMA for autobuffer mode, but dont enable yet */

static void init_dma_wc(void)
{
	/* Set up DMA1 to receive, map DMA1 to Sport0 RX */
	*pDMA1_PERIPHERAL_MAP = 0x1000;
	
	*pDMA1_IRQ_STATUS |= 0x2;

	iRxBuffer1 = (char*)l1_data_A_sram_alloc(2*ZT_CHUNKSIZE*8);
	printk("iRxBuffer1 = 0x%x\n", (int)iRxBuffer1);

	/* Start address of data buffer */
	*pDMA1_START_ADDR = iRxBuffer1;

	/* DMA inner loop count */
	*pDMA1_X_COUNT = ZT_CHUNKSIZE*8;

	/* Inner loop address increment */
	*pDMA1_X_MODIFY	= 1;
	*pDMA1_Y_MODIFY = 1;
	*pDMA1_Y_COUNT = 2;	
	
	/* Configure DMA1
	   8-bit transfers, Interrupt on completion, Autobuffer mode */
	*pDMA1_CONFIG = WNR | WDSIZE_8 | DI_EN | 0x1000 | DI_SEL | DMA2D; 

	/* Set up DMA2 to transmit, map DMA2 to Sport0 TX */
	*pDMA2_PERIPHERAL_MAP = 0x2000;
	
	/* Configure DMA2 8-bit transfers, Autobuffer mode */
	*pDMA2_CONFIG = WDSIZE_8 | 0x1000 | DMA2D;

	iTxBuffer1 = (char*)l1_data_A_sram_alloc(2*ZT_CHUNKSIZE*8);
	printk("iTxBuffer1 = 0x%x\n", (int)iTxBuffer1);

	/* Start address of data buffer */
	*pDMA2_START_ADDR = iTxBuffer1;

	/* DMA inner loop count */
	*pDMA2_X_COUNT = ZT_CHUNKSIZE*8;

	/* Inner loop address increment */
	*pDMA2_X_MODIFY	= 1;
	*pDMA2_Y_MODIFY = 1;
	*pDMA2_Y_COUNT = 2;

	/* init test variables */

	lastreadchunk = (unsigned char*)&iRxBuffer1[8*ZT_CHUNKSIZE];
	lastwritechunk = (unsigned char*)&iTxBuffer1[8*ZT_CHUNKSIZE];
}

static irqreturn_t sport0_rx_isr(int irq, void *dev_id, struct pt_regs * regs)
{
	
	/* confirm interrupt handling, write 1 to DMA_DONE bit */
	*pDMA1_IRQ_STATUS = 0x0001;
	__builtin_bfin_ssync(); /* note without this line ints dont
                                   occur every 1ms, but get sporadic.
                                   Why?  Is it something to do with
				   next line? How could we "lose"
                                   the write to IRQ_STATUS without
				   this ssync? Maybe it just happens
				   after the ISR has finished sometimes
				   which messes things up */

	*pFIO_FLAG_S = (1<<12);
	__builtin_bfin_ssync();
	regular_interrupt_processing(devs);
	*pFIO_FLAG_C = (1<<12);
	__builtin_bfin_ssync();


	return IRQ_HANDLED;
}

static int init_sport_interrupts(void)
{
  	if(request_irq(IRQ_SPORT0_RX, sport0_rx_isr, 
		       SA_INTERRUPT, "sport wcfxs", NULL) != 0) {
    		return -EBUSY;
	}
	if (debug) {
		printk("wcfxs: ISR installed OK\n");
	}

	/* enable DMA1 sport0 Rx interrupt */
	*pSIC_IMASK |= 0x00000200;
	__builtin_bfin_ssync();

	return 0;
}

static void enable_dma_sport0(void)
{
	/* enable DMAs */
	*pDMA2_CONFIG |= DMAEN;
	*pDMA1_CONFIG |= DMAEN;
	__builtin_bfin_ssync();

	/* enable sport0 Tx and Rx */
	*pSPORT0_TCR1 |= TSPEN;
	*pSPORT0_RCR1 |= RSPEN;

	__builtin_bfin_ssync();

	l1_data_A_sram_free((unsigned long)iTxBuffer1);
	l1_data_A_sram_free((unsigned long)iRxBuffer1);

}

static void disable_sport0(void)
{
	/* disable sport0 Tx and Rx */
	*pSPORT0_TCR1 &= ~TSPEN;
	*pSPORT0_RCR1 &= ~RSPEN;
	__builtin_bfin_ssync();

	/* disable DMA1 and DMA2 */
	*pDMA2_CONFIG &= ~DMAEN;
	*pDMA1_CONFIG &= ~DMAEN;
	__builtin_bfin_ssync();

	*pSIC_IMASK &= ~0x00000200;
	__builtin_bfin_ssync();
}

int wcfxs_proc_read(char *buf, char **start, off_t offset, 
		    int count, int *eof, void *data)
{
	int len;

	len = sprintf(buf, 
		      "readchunk_first.....: %d\n"
		      "readchunk_second....: %d\n"
		      "readchunk_didntswap.: %d\n"
		      "writechunk_first....: %d\n"
		      "writechunk_second...: %d\n"
		      "writechunk_didntswap: %d\n"
		      "rx1: 0x%x\n"
		      "rx2: 0x%x\n"
		      "tx1: 0x%x\n"
		      "tx2: 0x%x\n"
		      "notzero: %d\n",
		      readchunk_first,
		      readchunk_second,
		      readchunk_didntswap,
		      writechunk_first,
		      writechunk_second,
		      writechunk_didntswap,
		      rx1, rx2, tx1, tx2, notzero);

	*eof=1;
	return len;
}
#endif
