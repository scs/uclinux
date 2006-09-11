/*
  bfsi.c
  David Rowe 21 June 2006
 
  Functions for Linux device drivers on the Blackfin that
  support interfacing the Blackfin to Silicon Labs chips.

  These functions are in a separate file from the target wcfxs driver
  so they can be re-used with different drivers, for example unit
  test software.
 
  For various reasons the CPHA=1 (sofware controlled SPISEL)
  mode needs to be used, for example the SiLabs chip expects
  SPISEL to go high between 8 bit transfers and the timing
  the Si3050 expects (Figs 3 & 38 of 3050 data sheet) are
  closest to Fig 10-12 of the BF533 hardware reference manual.

  See also unittest tspi.c
*/

/*
  Copyright (C) 2006 David Rowe
 
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA. 
*/

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/bfin5xx_spi.h>
#include <linux/delay.h>
//#include <asm-blackfin/mach-bf533/dma.h>
#include <asm/dma.h>
//#include <asm-blackfin/mach-bf533/irq.h>
#include <asm/irq.h>
#include <linux/proc_fs.h>
#include <linux/platform_device.h>
#include <linux/spi/spi.h>

/* enable this define to get verbose debugging info */
//#define BFIN_SPI_DEBUG  1

#ifdef BFIN_SPI_DEBUG
#define PRINTK(args...) printk(args)
#else
#define PRINTK(args...)
#endif

/* 
   I found these macros from the bfin5xx_spi.c driver by Luke Yang 
   useful - thanks Luke :-) 
*/

#define DEFINE_SPI_REG(reg, off) \
static inline u16 read_##reg(void) \
            { return *(volatile unsigned short*)(SPI0_REGBASE + off); } \
static inline void write_##reg(u16 v) \
            {*(volatile unsigned short*)(SPI0_REGBASE + off) = v;\
             __builtin_bfin_ssync();}

DEFINE_SPI_REG(CTRL, 0x00)
DEFINE_SPI_REG(FLAG, 0x04)
DEFINE_SPI_REG(STAT, 0x08)
DEFINE_SPI_REG(TDBR, 0x0C)
DEFINE_SPI_REG(RDBR, 0x10)
DEFINE_SPI_REG(BAUD, 0x14)
DEFINE_SPI_REG(SHAW, 0x18)

/* constants for isr cycle averaging */

#define TC    1024 /* time constant    */
#define LTC   10   /* base 2 log of TC */

/* use L1 SRAM if we can otherwise (e.g BF532) no big deal */
/*
#if L1_DATA_A_LENGTH != 0
extern unsigned long l1_data_A_sram_alloc(unsigned long size);
extern int l1_data_A_sram_free(unsigned long addr);
#endif
*/

static u8 *iTxBuffer1;
static u8 *iRxBuffer1;

static int samples_per_chunk;
static int internalclock = 0;
static int bfsi_debug = 0;
static int init_ok = 0;

/* isr callback installed by user */

static void (*bfsi_isr_callback)(u8 *read_samples, u8 *write_samples) = NULL;

/* debug variables */

static int readchunk_first = 0;
static int readchunk_second = 0;
static int readchunk_didntswap = 0;
static unsigned char* lastreadchunk;

static int writechunk_first = 0;
static int writechunk_second = 0;
static int writechunk_didntswap = 0;
static unsigned char* lastwritechunk;

/* previous and worst case number of cycles we took to process an
   interrupt */

static u16 isr_cycles_last = 0;
static u32 isr_cycles_worst = 0;
static u32 isr_cycles_average = 0; /* scaled up by 2x */
static u32 echo_sams = 0;

/* remember SPI chip select */
static int chip_select;

/* sample cycles register of Blackfin */

static inline unsigned int cycles(void) {
  int ret;

   __asm__ __volatile__ 
   (
   "%0 = CYCLES;\n\t"
   : "=&d" (ret)
   : 
   : "R1"
   );

   return ret;
}

/*------------------------- SPI FUNCTIONS -----------------------------*/

/* 
   After much experimentation I found that (i) TIMOD=00 (i.e. using
   read_RDBR() to start transfer) was the best way to start transfers
   and (ii) polling RXS was the best way to end transfers, see p10-30
   and p10-31 of BF533 data book.

   chip_select is the _number_ of the chip select line, e.g. to use
   SPISEL2 chip_select = 2.
*/

void bfsi_spi_write_8_bits(u8 bits)
{
  u16 flag_enable, flag;

  flag = read_FLAG();
  flag_enable = flag & ~(1 << (chip_select + 8));
  PRINTK("write: flag: 0x%04x flag_enable: 0x%04x \n", 
	 flag, flag_enable);

  /* drop SPISEL */
  write_FLAG(flag_enable); 

  /* read kicks off transfer, detect end by polling RXS */
  write_TDBR(bits);
  read_RDBR(); __builtin_bfin_ssync();
  do {} while (!(read_STAT() & RXS) );

  /* raise SPISEL */
  write_FLAG(flag); 
}

u8 bfsi_spi_read_8_bits(void)
{
  u16 flag_enable, flag;
  u8  bits;

  flag = read_FLAG();
  flag_enable = flag & ~(1 << (chip_select + 8));
  PRINTK("read: flag: 0x%04x flag_enable: 0x%04x \n", 
	 flag, flag_enable);

  /* drop SPISEL */
  write_FLAG(flag_enable); 

  /* read kicks off transfer, detect end by polling RXS, we
     read the shadow register to prevent another transfer
     being started */
  read_RDBR(); __builtin_bfin_ssync();
  do {} while (!(read_STAT() & RXS) );
  bits = bfin_read_SPI_SHADOW();

  /* raise SPISEL */
  write_FLAG(flag); 

  return bits;
}

static int card_cs[] = {FXS_CS, FXS_CS, FXO_CS, FXO_CS};
void bfsi_spi_set_cs(int card)
{
	int chip_select_mask;
	u16 flag;

	chip_select = card_cs[card];
	chip_select_mask = 1<<chip_select;
	flag = 0xff00 | chip_select_mask;
	write_FLAG(flag);
}

/* 
   chip_select_mask: the logical OR of all the chip selects we wish
   to use for SPI, for example if we wish to use SPISEL2 and SPISEL3
   chip_select_mask = (1<<2) | (1<<3).

   baud:  The SPI clk divider value, see Blackfin Hardware data book,
   maximum speed when baud = 2, minimum when baud = 0xffff (0 & 1
   disable SPI port).

   The maximum SPI clk for the Si Labs 3050 is 16.4MHz.  On a 
   100MHz system clock Blackfin this means baud=4 minimum (12.5MHz).
*/

void bfsi_spi_init(int baud) 
{
	u16 ctl_reg;

  	if (baud < 4) {
    		printk("baud = %d may mean SPI clock too fast for Si labs 3050"
	   		"consider baud == 4 or greater", baud);
  	}

  	/* note TIMOD = 00 - reading SPI_RDBR kicks off transfer */
  	ctl_reg = SPE | MSTR | CPOL | CPHA | SZ;
  	write_FLAG(0xff00);
  	write_BAUD(baud);
  	write_CTRL(ctl_reg);
}

/*-------------------------- RESET FUNCTION ----------------------------*/

void bfsi_reset(int pf_bit) {
  PRINTK("toggle reset\n");
  
  bfin_write_FIO_DIR(bfin_read_FIO_DIR() | (1<<pf_bit)); 
  __builtin_bfin_ssync();

  bfin_write_FIO_FLAG_C((1<<pf_bit)); 
  __builtin_bfin_ssync();
  udelay(100);

  bfin_write_FIO_FLAG_S((1<<pf_bit));
  __builtin_bfin_ssync();

  /* 
     p24 3050 data sheet, allow 1ms for PLL lock, with
     less than 1ms (1000us) I found register 2 would have
     a value of 0 rather than 3, indicating a bad reset.
  */
  udelay(1000); 
}

/*-------------------------- SPORT FUNCTIONS ----------------------------*/

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
		bfin_write_SPORT0_RCLKDIV(24);  /* approx 2.048MHz PCLK            */
		bfin_write_SPORT0_RFSDIV(255);  /* 8 kHz FSYNC with 2.048MHz PCLK  */
	}		
	else {
		bfin_write_SPORT0_RFSDIV(255);  /* 8 kHz FSYNC with 2.048MHz PCLK  */
	}

	/* external tx clk, not data dependant, MSB first */
	bfin_write_SPORT0_TCR2(7);      /* 8 bit word length      */
	bfin_write_SPORT0_TCR1(0);

	/* rx enabled, MSB first, internal frame sync     */
	bfin_write_SPORT0_RCR2(7);      /* 8 bit word length      */
	if (internalclock) {
		bfin_write_SPORT0_RCR1(IRFS | IRCLK);
	}
	else {
		bfin_write_SPORT0_RCR1(IRFS);
	}

	/* Enable MCM 8 transmit & receive channels       */
	bfin_write_SPORT0_MTCS0(0x000000FF);
	bfin_write_SPORT0_MRCS0(0x000000FF);
	
	/* MCM window size of 8 with 0 offset             */
	bfin_write_SPORT0_MCMC1(0x0000);

	/* 0 bit delay between FS pulse and first data bit,
	   multichannel frame mode enabled, 
	   multichannel tx and rx DMA packing enabled */
	bfin_write_SPORT0_MCMC2(0x001c);
}

/* init DMA for autobuffer mode, but dont enable yet */

static void init_dma_wc(void)
{
  /* Set up DMA1 to receive, map DMA1 to Sport0 RX */
  bfin_write_DMA1_PERIPHERAL_MAP(0x1000);
	
  bfin_write_DMA1_IRQ_STATUS(bfin_read_DMA1_IRQ_STATUS() | 0x2);

#if L1_DATA_A_LENGTH != 0
  iRxBuffer1 = (char*)l1_data_A_sram_alloc(2*samples_per_chunk*8);
#else	
  { 
    dma_addr_t addr;
    iRxBuffer1 = (char*)dma_alloc_coherent(NULL, 2*samples_per_chunk*8, &addr, 0);
  }
#endif
  if (bfsi_debug)
    printk("iRxBuffer1 = 0x%x\n", (int)iRxBuffer1);

  /* Start address of data buffer */
  bfin_write_DMA1_START_ADDR(iRxBuffer1);

  /* DMA inner loop count */
  bfin_write_DMA1_X_COUNT(samples_per_chunk*8);

  /* Inner loop address increment */
  bfin_write_DMA1_X_MODIFY(1);
  bfin_write_DMA1_Y_MODIFY(1);
  bfin_write_DMA1_Y_COUNT(2);	
	
  /* Configure DMA1
     8-bit transfers, Interrupt on completion, Autobuffer mode */
  bfin_write_DMA1_CONFIG(WNR | WDSIZE_8 | DI_EN | 0x1000 | DI_SEL | DMA2D); 

  /* Set up DMA2 to transmit, map DMA2 to Sport0 TX */
  bfin_write_DMA2_PERIPHERAL_MAP(0x2000);
	
  /* Configure DMA2 8-bit transfers, Autobuffer mode */
  bfin_write_DMA2_CONFIG(WDSIZE_8 | 0x1000 | DMA2D);

#if L1_DATA_A_LENGTH != 0
  iTxBuffer1 = (char*)l1_data_A_sram_alloc(2*samples_per_chunk*8);
#else	
  { 
    dma_addr_t addr;
    iTxBuffer1 = (char*)dma_alloc_coherent(NULL, 2*samples_per_chunk*8, &addr, 0);
  }
#endif
  if (bfsi_debug)
    printk("iTxBuffer1 = 0x%x\n", (int)iTxBuffer1);

  /* Start address of data buffer */
  bfin_write_DMA2_START_ADDR(iTxBuffer1);

  /* DMA inner loop count */
  bfin_write_DMA2_X_COUNT(samples_per_chunk*8);

  /* Inner loop address increment */
  bfin_write_DMA2_X_MODIFY(1);
  bfin_write_DMA2_Y_MODIFY(1);
  bfin_write_DMA2_Y_COUNT(2);

  /* init test variables */

  lastreadchunk = (unsigned char*)&iRxBuffer1[8*samples_per_chunk];
  lastwritechunk = (unsigned char*)&iTxBuffer1[8*samples_per_chunk];
}

/* works out which write buffer is available for writing */

static u8 *isr_write_processing(void) {
	u8 *writechunk;
	int x;

	/* select which ping-pong buffer to write to */

	x = (int)(bfin_read_DMA2_CURR_ADDR()) - (int)iTxBuffer1;

	/* for some reason x for tx tends to be 0xe and 0x4e, whereas
	   x for rx is 0x40 and 0x80.  Note sure why they would be
	   different.  We could perhaps consider having
	   different interrupts for tx and rx side.  Hope this
	   offset doesnt kill the echo cancellation, e.g. if we
	   get echo samples in rx before tx has sent them!
	*/
	if (x >= 8*samples_per_chunk) {
		writechunk = (unsigned char*)iTxBuffer1;
		writechunk_first++;
	}
	else {
		writechunk = (unsigned char*)iTxBuffer1 + samples_per_chunk*8;
		writechunk_second++;
	}

	/* make sure writechunk actually ping pongs */

	if (writechunk == lastwritechunk) {
		writechunk_didntswap++;
	}
	lastwritechunk = (unsigned char*)writechunk;

	return writechunk;
}

/* works out which read buffer is available for reading */

static u8 *isr_read_processing(void) {
	u8 *readchunk;
	int x;

	/* select which ping-pong buffer to write to */

	x = (int)bfin_read_DMA1_CURR_ADDR() - (int)iRxBuffer1;
	/* possible values for x are 8*samples_per_chunk=0x40 at the
	   end of the first row and 2*8*samples_per_chunk=0x80 at the
	   end of the second row */
	if (x == 8*samples_per_chunk) {
		readchunk = iRxBuffer1;
		readchunk_first++;
	}
	else {
		readchunk = iRxBuffer1 + samples_per_chunk*8;
		readchunk_second++;
	}

	/* make sure readchunk actually ping pongs */

	if (readchunk == lastreadchunk) {
		readchunk_didntswap++;
	}
	lastreadchunk = (unsigned char*)readchunk;

	return readchunk;
}

/* called each time the DMA finishes one "line" */

static irqreturn_t sport0_rx_isr(int irq, void *dev_id, struct pt_regs * regs)
{
  unsigned int  start_cycles = cycles();
  u8           *read_samples;
  u8           *write_samples;

  /* confirm interrupt handling, write 1 to DMA_DONE bit */
  bfin_write_DMA1_IRQ_STATUS(0x0001);
  __builtin_bfin_ssync(); /* note without this line ints dont
			     occur every 1ms, but get sporadic.
			     Why?  Is it something to do with
			     next line? How could we "lose"
			     the write to IRQ_STATUS without
			     this ssync? Maybe it just happens
			     after the ISR has finished sometimes
			     which messes things up */

  __builtin_bfin_ssync();

  read_samples = isr_read_processing();
  write_samples = isr_write_processing();
  if (bfsi_isr_callback != NULL) {
    bfsi_isr_callback(read_samples, write_samples);
  }

  __builtin_bfin_ssync();

  /* some stats to help monitor the cycles used by ISR processing */

  /* 
     Simple IIR averager: 

       y(n) = (1 - 1/TC)*y(n) + (1/TC)*x(n)

     After conversion to fixed point:

       2*y(n) = ((TC-1)*2*y(n) + 2*x(n) + half_lsb ) >> LTC 
  */

  isr_cycles_average = ( (u32)(TC-1)*isr_cycles_average + 
			 (((u32)isr_cycles_last)<<1) + TC) >> LTC;

  if (isr_cycles_last > isr_cycles_worst)
    isr_cycles_worst = isr_cycles_last;

  /* we sample right at the end to make sure we count cycles used to 
     measure cycles! */
  isr_cycles_last = cycles() - start_cycles;
  
  return IRQ_HANDLED;
}

static int init_sport_interrupts(void)
{
	//unsigned int data32;
	
  	if(request_irq(IRQ_SPORT0_RX, sport0_rx_isr, 
		       SA_INTERRUPT, "sport0 rx", NULL) != 0) {
    		return -EBUSY;
	}
	if (bfsi_debug) {
		printk("ISR installed OK\n");
	}

	/* enable DMA1 sport0 Rx interrupt */
	bfin_write_SIC_IMASK(bfin_read_SIC_IMASK() | 0x00000200);
	__builtin_bfin_ssync();

	return 0;
}

static void enable_dma_sport0(void)
{
	/* enable DMAs */
	bfin_write_DMA2_CONFIG(bfin_read_DMA2_CONFIG() | DMAEN);
	bfin_write_DMA1_CONFIG(bfin_read_DMA1_CONFIG() | DMAEN);
	__builtin_bfin_ssync();

	/* enable sport0 Tx and Rx */
	bfin_write_SPORT0_TCR1(bfin_read_SPORT0_TCR1() | TSPEN);
	bfin_write_SPORT0_RCR1(bfin_read_SPORT0_RCR1() | RSPEN);

	__builtin_bfin_ssync();
}

static void disable_sport0(void)
{
	/* disable sport0 Tx and Rx */
	bfin_write_SPORT0_TCR1(bfin_read_SPORT0_TCR1() & (~TSPEN));
	bfin_write_SPORT0_RCR1(bfin_read_SPORT0_RCR1() & (~RSPEN));
	__builtin_bfin_ssync();

	/* disable DMA1 and DMA2 */
	bfin_write_DMA2_CONFIG(bfin_read_DMA2_CONFIG() & (~DMAEN));
	bfin_write_DMA1_CONFIG(bfin_read_DMA1_CONFIG() & (~DMAEN));
	__builtin_bfin_ssync();

	bfin_write_SIC_IMASK(bfin_read_SIC_IMASK() & (~0x00000200));
	__builtin_bfin_ssync();
}

int bfsi_proc_read(char *buf, char **start, off_t offset, 
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
		      "isr_cycles_last.....: %d\n"
		      "isr_cycles_worst....: %d\n"
		      "isr_cycles_average..: %d\n"
		      "echo_sams...........: %d\n",
		      readchunk_first,
		      readchunk_second,
		      readchunk_didntswap,
		      writechunk_first,
		      writechunk_second,
		      writechunk_didntswap,
		      isr_cycles_last,
		      isr_cycles_worst,
		      isr_cycles_average>>1,
		      echo_sams);

	*eof=1;
	return len;
}

/* 
   Wrapper for entire SPORT setup, returns 1 for success, 0 for failure.

   The SPORT code is designed to deliver small arrays of size samples
   every (125us * samples).  A ping-pong arrangement is used, so the
   address of the buffer will alternate every call between two possible
   values.

   The callback functions privide to the address of the current buffer
   for the read and write channels.  Read means the data was just
   read from the SPORT, so this is the "receive" PCM samples.  Write
   is the PCM data to be written to the SPORT.
   
   The callbacks are called in the context of an interrupt service
   routine, so treat any code them like an ISR.

   Once this function returns successfully the SPORT/DMA will be up
   and running, and calls to the isr callback will start.  For testing
   it is OK to set the callback function pointer to NULL, say if you
   just want to look at the debug information.
   
   If debug==1 then "cat /proc/bfsi" will display some debug
   information, something like:

     readchunk_first.....: 9264
     readchunk_second....: 9264
     readchunk_didntswap.: 0
     writechunk_first....: 9264
     writechunk_second...: 9264
     writechunk_didntswap: 0

   If all is well then "readchunk_didntswap" and "writechunk_didntswap"
   will be static and some very small number.  The first and second
   values should be at most one value different.  These variables
   indicate sucessful ping-pong operation.

   The numbers are incremented ever interrupt, for example if samples=8
   (typical for zaptel), then we get one interrupt every ms, or 1000
   interrupts per second.  This means the values for each first/second
   entry should go up 500 times per second.

   8 channels are sampled at once, so the size of the samples buffers
   is 8*samples (typically 64 bytes for zaptel).

   TODO:

   1/ It might be nice to modify this function allow user defined
      SPORT control reg settings, for example to change clock
      dividers and frame sync sources.  Or posible provide
      a bfsi_sport_set() function.

   2/ Modify the callbacks to provide user-dfine context information.

   3/ Modify init to define max number of channels, it is currently
      hard coded at 8.
*/

int bfsi_sport_init(
  void (*isr_callback)(u8 *read_samples, u8 *write_samples), 
  int samples,
  int debug
)
{
  if (debug) {
    create_proc_read_entry("bfsi", 0, NULL, bfsi_proc_read, NULL);
    bfsi_debug = debug;
  }

  bfsi_isr_callback = isr_callback;
  samples_per_chunk = samples;

  init_sport0();
  init_dma_wc();
  enable_dma_sport0();

  if (init_sport_interrupts())
    init_ok = 0;
  else
    init_ok = 1;

  return init_ok;
}

/* shut down SPORT operation cleanly */

void bfsi_sport_close(void)
{
  disable_sport0();

  if (init_ok) {
    free_irq(IRQ_SPORT0_RX, NULL);
  }
#if L1_DATA_A_LENGTH != 0
  l1_data_A_sram_free(iTxBuffer1);
  l1_data_A_sram_free(iRxBuffer1);
#else
  dma_free_coherent(NULL, 2*samples_per_chunk*8, iTxBuffer1, 0);
  dma_free_coherent(NULL, 2*samples_per_chunk*8, iRxBuffer1, 0);
#endif
  remove_proc_entry("bfsi", NULL);
}
