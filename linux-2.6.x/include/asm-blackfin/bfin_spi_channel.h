/************************************************************
*
* Copyright (C) 2003, Motorola. All Rights Reserved
*
* FILE spi.h
* PROGRAMMER(S): J.X.Chang (jxchang@motorola.com)
*
*
* DATE OF CREATION: March 8, 2003
*
* SYNOPSIS:
*
* DESCRIPTION: It's driver of SPI in ADSP25535(ADI's DSP). It can
*              only be used in unix or linux.
* CAUTION:     User should use 'ioctl' to change it's 
               configuration just after openning device.
**************************************************************
* MODIFICATION HISTORY:
* March 8, 2003   File spi.h Created.
************************************************************/

#ifndef _SPI_CHANNEL_H_
#define _SPI_CHANNEL_H_

#include <linux/kernel.h>

#define SPI0_REGBASE       0xffc00500

#define SPI_READ              0
#define SPI_WRITE             1   

typedef struct Spi_Device_t
{
	char  *dev_name;

	unsigned short     flag;
	unsigned short     bdrate;
	
	unsigned short     enable;
	unsigned short     master;
	unsigned short     out_opendrain; 
	unsigned short     polar;
	unsigned short     phase;
	unsigned short     byteorder;  /* 0: MSB first; 1: LSB first; */
	unsigned short     size;     /* 0: 8 bits; 1: 16 bits */
	unsigned short     emiso;
	unsigned short     send_zero;
	unsigned short     more_data;
	unsigned short     slave_sel;
	unsigned short     ti_mod;

	unsigned short     dma;         /* use dma mode or not */
	unsigned short     dma_config;  /* only valid if dma enabled */
	
	irqreturn_t        (*irq_handler)(int irq, void *dev_id, struct pt_regs *regs);
	void               *priv_data;
}spi_device_t;


#define SPI_CTRL_OFF            0x0
#define SPI_FLAG_OFF            0x4
#define SPI_STAU_OFF            0x8
#define SPI_TXBUFF_OFF          0xc
#define SPI_RXBUFF_OFF          0x10
#define SPI_BAUD_OFF            0x14
#define SPI_SHAW_OFF            0x18

#define CMD_SPI_OUT_ENABLE    1
#define CMD_SPI_SET_BAUDRATE  2
#define CMD_SPI_SET_POLAR     3
#define CMD_SPI_SET_PHASE     4
#define CMD_SPI_SET_MASTER    5
#define CMD_SPI_SET_SENDOPT   6  
#define CMD_SPI_SET_RECVOPT   7   
#define CMD_SPI_SET_ORDER     8
#define CMD_SPI_SET_LENGTH16  9
#define CMD_SPI_GET_STAT      11
#define CMD_SPI_GET_CFG       12
#define CMD_SPI_SET_CSAVAIL   13
#define CMD_SPI_SET_CSHIGH    14 /* CS unavail */
#define CMD_SPI_SET_CSLOW     15 /* CS avail */
#define CMD_SPI_MISO_ENABLE   16
#define CMD_SPI_SET_CSENABLE  17
#define CMD_SPI_SET_CSDISABLE 18

#define CMD_SPI_SET_TRIGGER_MODE  19		
#define CMD_SPI_SET_TRIGGER_SENSE 20		
#define CMD_SPI_SET_TRIGGER_EDGE  21		
#define CMD_SPI_SET_TRIGGER_LEVEL 22		
                                  		
#define CMD_SPI_SET_TIME_SPS 	  23		
#define CMD_SPI_SET_TIME_SAMPLES  24		
#define CMD_SPI_GET_SYSTEMCLOCK   25		

#define CMD_SPI_SET_WRITECONTINUOUS     26

#define CMD_SPI_GET_ALLCONFIG 32 /* For debug */

#define SPI_DEFAULT_BARD    0x0100

#define SPI0_IRQ_NUM        20
#define SPI_ERR_TRIG	   -1

#define BIT_CTL_ENABLE      0x4000
#define BIT_CTL_OPENDRAIN   0x2000
#define BIT_CTL_MASTER      0x1000
#define BIT_CTL_POLAR       0x0800
#define BIT_CTL_PHASE       0x0400
#define BIT_CTL_BITORDER    0x0200
#define BIT_CTL_WORDSIZE    0x0100
#define BIT_CTL_MISOENABLE  0x0020
#define BIT_CTL_RXMOD       0x0000
#define BIT_CTL_TXMOD       0x0001
#define BIT_CTL_TIMOD_DMA_TX 0x0003
#define BIT_CTL_TIMOD_DMA_RX 0x0002
#define BIT_CTL_SENDOPT     0x0004

#define BIT_STU_SENDOVER    0x0001
#define BIT_STU_RECVFULL    0x0020

#define CFG_SPI_ENABLE      1
#define CFG_SPI_DISABLE     0

#define CFG_SPI_OUTENABLE   1
#define CFG_SPI_OUTDISABLE  0

#define CFG_SPI_ACTLOW      1
#define CFG_SPI_ACTHIGH     0

#define CFG_SPI_PHASESTART  1
#define CFG_SPI_PHASEMID    0

#define CFG_SPI_MASTER      1
#define CFG_SPI_SLAVE       0

#define CFG_SPI_SENELAST    1
#define CFG_SPI_SENDZERO    0

#define CFG_SPI_RCVFLUSH    1
#define CFG_SPI_RCVDISCARD  0

#define CFG_SPI_LSBFIRST    1
#define CFG_SPI_MSBFIRST    0

#define CFG_SPI_WORDSIZE16  1
#define CFG_SPI_WORDSIZE8   0

#define CFG_SPI_MISOENABLE   1
#define CFG_SPI_MISODISABLE  0

#define CFG_SPI_CSCLEARALL  0x0000
#define CFG_SPI_CHIPSEL1    0x0002
#define CFG_SPI_CHIPSEL2    0x0004
#define CFG_SPI_CHIPSEL3    0x0008
#define CFG_SPI_CHIPSEL4    0x0010
#define CFG_SPI_CHIPSEL5    0x0020
#define CFG_SPI_CHIPSEL6    0x0040
#define CFG_SPI_CHIPSEL7    0x0080

#define CFG_SPI_CS1VALUE    0x0200
#define CFG_SPI_CS2VALUE    0x0400
#define CFG_SPI_CS3VALUE    0x0800
#define CFG_SPI_CS4VALUE    0x1000
#define CFG_SPI_CS5VALUE    0x2000
#define CFG_SPI_CS6VALUE    0x4000
#define CFG_SPI_CS7VALUE    0x8000


void spi_send_data(unsigned short data);
unsigned short spi_receive_data(void);
void spi_enable(spi_device_t *spi_dev);
void spi_disable(spi_device_t *spi_dev);
int spi_dma_read(spi_device_t *spi_dev, void *buffer, unsigned int count);
int spi_dma_write(spi_device_t *spi_dev, void *buffer, unsigned int count);
void spi_clear_irqstat(spi_device_t *spi_dev);
void spi_set_ctl(spi_device_t *spi_dev);
void spi_get_stat(unsigned short *data);
void spi_get_ctl(unsigned short *data);
int spi_channel_request(spi_device_t *spi_dev);
int spi_channel_release (spi_device_t *spi_dev);

#endif /* _SPI_CHANNEL_H_ */
