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
* DESCRIPTION: It's driver of SPI in ADSP-BF533 It can
*              only be used in unix or linux.
* CAUTION:     User should use 'ioctl' to change it's 
               configuration just after openning device.
**************************************************************
* MODIFICATION HISTORY:
* March 8, 2003   File spi.h Created.
* Sept 10, 2004   adsp-spiadc.c Created/Merged spic.h M.Hennerich
************************************************************
*
* This program is free software; you can distribute it and/or modify it
* under the terms of the GNU General Public License (Version 2) as
* published by the Free Software Foundation.
*
* This program is distributed in the hope it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
* FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
* for more details.
*
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 59 Temple Place - Suite 330, Boston MA 02111-1307, USA.
*
************************************************************/

#ifndef _ADSP_SPIADC_H_
#define _ADSP_SPIADC_H_

#define SPI_READ              0
#define SPI_WRITE             1   

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

#define SPI_IRQ_NUM        20
#define SPI_ERR_TRIG	   -1


#define BIT_CTL_ENABLE      0x4000
#define BIT_CTL_OPENDRAIN   0x2000
#define BIT_CTL_MASTER      0x1000
#define BIT_CTL_POLAR       0x0800
#define BIT_CTL_PHASE       0x0400
#define BIT_CTL_BITORDER    0x0200
#define BIT_CTL_WORDSIZE    0x0100
#define BIT_CTL_MISOENABLE  0x0020
#define BIT_CTL_TXMOD       0x0001
#define BIT_CTL_TIMOD_DMA_TX 0x0003
#define BIT_CTL_TIMOD_DMA_RX 0x0002		
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

#define CFG_SPI_CSCLEARALL  0
#define CFG_SPI_CHIPSEL1    1
#define CFG_SPI_CHIPSEL2    2
#define CFG_SPI_CHIPSEL3    3 
#define CFG_SPI_CHIPSEL4    4 
#define CFG_SPI_CHIPSEL5    5 
#define CFG_SPI_CHIPSEL6    6 
#define CFG_SPI_CHIPSEL7    7 

#define CFG_SPI_CS1VALUE    1
#define CFG_SPI_CS2VALUE    2
#define CFG_SPI_CS3VALUE    3
#define CFG_SPI_CS4VALUE    4
#define CFG_SPI_CS5VALUE    5
#define CFG_SPI_CS6VALUE    6
#define CFG_SPI_CS7VALUE    7

#endif /* _ADSP_SPIADC_H_ */
