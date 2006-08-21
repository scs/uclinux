/*
 * File:         drivers/char/bfin_ppifcd.h
 * Based on:
 * Author:       Michael Hennerich
 *
 * Created:      12.07.2005 17:09
 * Description:  Simple PPI Frame Capture driver for ADSP-BF5xx
 *
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright 2005-2006 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
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
 * along with this program; if not, see the file COPYING, or write
 * to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _ADSP_PPIADC_H_
#define _ADSP_PPIADC_H_

#define PPI_READ              0
#define PPI_WRITE             1

#define CMD_PPI_SET_PIXELS_PER_LINE   0
#define CMD_PPI_SET_LINES_PER_FRAME   1
#define CMD_PPI_SET_PPICONTROL_REG    2
#define CMD_PPI_SET_PPIDEALY_REG      3
#define CMD_PPI_SET_PPICOUNT_REG      4
#define CMD_SET_TRIGGER_GPIO          5
#define CMD_PPI_GET_SYSTEMCLOCK       6
#define CMD_PPI_GET_ALLCONFIG 		  7 /* For debug */

#define TRIGGER_PF0 0
#define TRIGGER_PF1 1
#define TRIGGER_PF2 2
#define TRIGGER_PF3 3
#define TRIGGER_PF4 4
#define TRIGGER_PF5 5
#define TRIGGER_PF6 6
#define TRIGGER_PF7 7
#define TRIGGER_PF8 8
#define TRIGGER_PF9 9
#define TRIGGER_PF10 10
#define TRIGGER_PF11 11
#define TRIGGER_PF12 12
#define TRIGGER_PF13 13
#define TRIGGER_PF14 14
#define TRIGGER_PF15 15

#define NO_TRIGGER  16


/* Some Sensor Sepcific Defaults */

#define MT9M001
#undef  MT9V022

#ifdef MT9M001
#define POL_C 			0x4000
#define POL_S 			0x0000
#define PIXEL_PER_LINE	1280
#define LINES_PER_FRAME	1024
#define CFG_GP_Input_3Syncs 	0x0020
#define GP_Input_Mode			0x000C
#define PPI_DATA_LEN				DLEN_8
#define PPI_PACKING					PACK_EN
#define DMA_FLOW_MODE			0x0000 //STOPMODE
#define DMA_WDSIZE_16			WDSIZE_16
#endif

#ifdef MT9V022
#define POL_C 			0x0000
#define POL_S 			0x0000
#define PIXEL_PER_LINE	720
#define LINES_PER_FRAME	488
#define CFG_GP_Input_3Syncs 	0x0020
#define GP_Input_Mode			0x000C
#define PPI_DATA_LEN			DLEN_8
#define PPI_PACKING				PACK_EN
#define DMA_FLOW_MODE			0x0000 //STOPMODE
#define DMA_WDSIZE_16			WDSIZE_16
#endif

#endif /* _ADSP_PPIADC_H_ */
