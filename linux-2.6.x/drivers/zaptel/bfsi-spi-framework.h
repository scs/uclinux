/*
  bfsi.h
  David Rowe 21 June 2006
 
  Header file for bfsi.h
*/

#ifndef __BFSI__
#define __BFSI__

#define FXS_FXO_CARD
/*
static int wcfxs_setreg(struct wcfxs *wc, int card, unsigned reg, unsigned char value);
static unsigned char wcfxs_getreg(struct wcfxs *wc, int card, unsigned char reg);
static int wcfxs_proslic_setreg_indirect(struct wcfxs *wc, int card, unsigned char address, unsigned short data);
static int wcfxs_proslic_getreg_indirect(struct wcfxs *wc, int card, unsigned char address);
void bfsi_spi_init(struct wcfxs *wc);
*/
void bfsi_reset(void);

int  bfsi_sport_init(
  void (*isr_callback)(u8 *read_samples, u8 *write_samples), 
  int   num_samples,
  int   debug
);
void bfsi_sport_close(void);

static int daisy_chip_addr[]={0x1,0x02,0x0,0x8};

#endif
