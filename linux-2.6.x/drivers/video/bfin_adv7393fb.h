/************************************************************
*
* Copyright (C) 2006, Analog Devices. All Rights Reserved
*
* FILE linux/drivers/video/bfin_adv7393fb.h
* PROGRAMMER(S): Michael Hennerich (Analog Devices Inc.)
*
* $Id$
*
* DATE OF CREATION: May. 24th 2006
*
* SYNOPSIS:
*
* DESCRIPTION: Frame buffer driver for ADV7393/2 video encoder
*              
* CAUTION:
**************************************************************
* MODIFICATION HISTORY:
*
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
typedef unsigned short RGB565;

#ifdef CONFIG_NTSC

#define RGB_WIDTH		720
#define RGB_HEIGHT		480
#define ACTIVE_LINES	240
#define PPI_DELAY_CNT	122
#define DMA_X_CNT 		(RGB_WIDTH+16)
#define DMA_Y_MODIFY	((RGB_WIDTH-16) * sizeof(RGB565))
#define LINES_PER_FRAME	525
#define VB1_LINES		22
#define VB2_LINES		23

#else /* CONFIG_PAL */

#define RGB_WIDTH		720
#define RGB_HEIGHT		576
#define ACTIVE_LINES	288
#define PPI_DELAY_CNT	132
#define DMA_X_CNT		(RGB_WIDTH+12)
#define DMA_Y_MODIFY	((RGB_WIDTH-12) * sizeof(RGB565))
#define LINES_PER_FRAME	625
#define VB1_LINES		24
#define VB2_LINES		25

#endif /* CONFIG_NTSC */

#define RGB_PHYS_SIZE	(RGB_WIDTH * RGB_HEIGHT * sizeof(RGB565))


#if defined(CONFIG_BF537) || defined(CONFIG_BF536) || defined(CONFIG_BF534)
#define DMA_CFG_VAL 	0x7935	//Set Sync Bit
#define VB_DUMMY_MEMORY_SOURCE	L1_DATA_B_START
#endif

#if defined(CONFIG_BF533) || defined(CONFIG_BF532) || defined(CONFIG_BF531)
#define DMA_CFG_VAL 	0x7915
#define VB_DUMMY_MEMORY_SOURCE  BOOT_ROM_START
#endif

typedef struct _DMA_CONFIG
{
  unsigned short b_DMA_EN:1;	//Bit 0 : DMA Enable
  unsigned short b_WNR:1;	//Bit 1 : DMA Direction
  unsigned short b_WDSIZE:2;	//Bit 2 & 3 : DMA Tranfer Word size
  unsigned short b_DMA2D:1;	//Bit 4 : DMA Mode 2D or 1D
  unsigned short b_RESTART:1;	//Bit 5 : Retain the FIFO
  unsigned short b_DI_SEL:1;	//Bit 6 : Data Interrupt Timing Select
  unsigned short b_DI_EN:1;	//Bit 7 : Data Interrupt Enable
  unsigned short b_NDSIZE:4;	//Bit 8 to 11 : Flex descriptor Size
  unsigned short b_FLOW:3;	//Bit 12 to 14 : FLOW
} DMA_CONFIG_REG;


struct adv7393
{
  unsigned char reg[128];

  int norm;
  int input;
  int enable;
  int bright;
  int contrast;
  int hue;
  int sat;
};

#define   I2C_ADV7393        0x54

enum
{
  DESTRUCT,
  BUILD,
};

