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

#ifndef _SPI_H_
#define _SPI_H_

#define SPI_CTRL            0x0
#define SPI_FLAG            0x4
#define SPI_STAU            0x8
#define SPI_TXBUFF          0xc
#define SPI_RXBUFF          0x10
#define SPI_BAUD            0x14
#define SPI_SHAW            0x18

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

#define CMD_SPI_GET_ALLCONFIG 32 /* For debug */



#define SPI_DEFAULT_BARD    0x0100

#define SPI0_IRQ_NUM        20


#define BIT_CTL_ENABLE      0x4000
#define BIT_CTL_OPENDRAIN   0x2000
#define BIT_CTL_MASTER      0x1000
#define BIT_CTL_POLAR       0x0800
#define BIT_CTL_PHASE       0x0400
#define BIT_CTL_BITORDER    0x0200
#define BIT_CTL_WORDSIZE    0x0100
#define BIT_CTL_MISOENABLE  0x0020
#define BIT_CTL_TXMOD       0x0001
#define BIT_CTL_SENDOPT     0x0004

#define BIT_STU_SENDOVER    0x0001
#define BIT_STU_RECVFULL    0x0020

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

#endif /* _SPI_H_ */
