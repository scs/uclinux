/*
  bfsi.h
  David Rowe 21 June 2006
 
  Header file for bfsi.h
*/

#ifndef __BFSI__
#define __BFSI__

#define FXS_FXO_CARD
#define FXS_CS	CFG_SPI_CHIPSEL3
#define FXO_CS	CFG_SPI_CHIPSEL2

void bfsi_reset(int pf_bit);
void bfsi_spi_init(int baud);
u8   bfsi_spi_read_8_bits(void);
void bfsi_spi_write_8_bits(u8 bits);

int  bfsi_sport_init(
  void (*isr_callback)(u8 *read_samples, u8 *write_samples), 
  int   num_samples,
  int   debug
);
void bfsi_sport_close(void);
void bfsi_spi_set_cs(int card);

static int daisy_chip_addr[]={0x1,0x02,0x0,0x8};

#endif
