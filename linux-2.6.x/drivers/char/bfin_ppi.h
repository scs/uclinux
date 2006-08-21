/*
 * File:         drivers/char/bfin_ppi.h
 * Based on:
 * Author:       John DeHority <john.dehority@NOSPAM@kodak.com>
 *
 * Created:      May 5, 2005
 * Description:  It's driver of PPI in Analog Devices BF533 DSP
 *
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright (C) 2005 Eastman Kodak Company
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

#ifndef __BFIN_PPI_H__
#define __BFIN_PPI_H__

/*
** FYI:  Blackfin PPI register masks and offsets are defined in
** mach-bfin533/defBF532.h
*/

/*
** ioctl commands
*/
#define CMD_PPI_PORT_ENABLE    1
#define CMD_PPI_PORT_DIRECTION 2
#define CMD_PPI_XFR_TYPE       3
#define CMD_PPI_PORT_CFG       4
#define CMD_PPI_FIELD_SELECT   5
#define CMD_PPI_PACKING        6
#define CMD_PPI_SKIPPING       7
#define CMD_PPI_SKIP_ODDEVEN   8
#define CMD_PPI_DATALEN        9
#define	CMD_PPI_CLK_EDGE      10
#define CMD_PPI_TRIG_EDGE     11
#define CMD_PPI_LINELEN		  12
#define CMD_PPI_NUMLINES      13
#define CMD_PPI_SET_WRITECONTINUOUS 14
#define CMD_PPI_SET_DIMS	  15
#define CMD_PPI_DELAY	  	  16
#define	CMD_PPI_SETGPIO		  17

#define CMD_PPI_GET_ALLCONFIG 32 /* For debug */

#define PPI_IRQ_NUM        23
#define PPI_DMA_MAXSIZE	(64*1024)
#define PPI_READ 0
#define PPI_WRITE 1

#define PPI_READ_DELAY 1

#define CFG_PPI_PORT_ENABLE  1
#define CFG_PPI_PORT_DISABLE 0

#define CFG_PPI_PORT_DIR_RX  0
#define CFG_PPI_PORT_DIR_TX  1

#define CFG_PPI_XFR_TYPE_646_AF  0
#define CFG_PPI_XFR_TYPE_646_EF  1
#define CFG_PPI_XFR_TYPE_646_VB  2
#define CFG_PPI_XFR_TYPE_NON646  3

#define CFG_PPI_XFR_TYPE_NO_SYNC 0
#define CFG_PPI_XFR_TYPE_SYNC    3

/* Receive Modes */
#define CFG_PPI_PORT_CFG_XSYNC1  0
#define CFG_PPI_PORT_CFG_ISYNC23 1
#define CFG_PPI_PORT_CFG_XSYNC23 2
#define CFG_PPI_PORT_CFG_NOSYNC  3

/* Transmit Modes */
#define CFG_PPI_PORT_CFG_SYNC1	 0
#define CFG_PPI_PORT_CFG_SYNC23  1
#define CFG_PPI_PORT_CFG_NA      2
#define CFG_PPI_PORT_CFG_SYNC_FS2 3

#define CFG_PPI_FIELD_SELECT_1	   0
#define CFG_PPI_FIELD_SELECT_12	   1

/* Receive Mode */
#define CFG_PPI_FIELD_SELECT_XT    0
#define CFG_PPI_FIELD_SELECT_IT    1

#define CFG_PPI_PACK_DISABLE       0
#define CFG_PPI_PACK_ENABLE        1

#define CFG_PPI_SKIP_DISABLE       0
#define CFG_PPI_SKIP_ENABLE        1

#define CFG_PPI_SKIP_ODD           0
#define CFG_PPI_SKIP_EVEN          1

#define CFG_PPI_DATALEN_8        0
#define CFG_PPI_DATALEN_10       1
#define CFG_PPI_DATALEN_11       2
#define CFG_PPI_DATALEN_12       3
#define CFG_PPI_DATALEN_13       4
#define CFG_PPI_DATALEN_14       5
#define CFG_PPI_DATALEN_15       6
#define CFG_PPI_DATALEN_16       7

#define CFG_PPI_CLK_EDGE_RISE      0
#define CFG_PPI_CLK_EDGE_FALL      1

#define CFG_PPI_TRIG_EDGE_RISE      0
#define CFG_PPI_TRIG_EDGE_FALL      1

#define CFG_PPI_DIMS_UNDEF			0
#define	CFG_PPI_DIMS_1D				1
#define CFG_PPI_DIMS_2D				2

#define POLFS	0x8000
#define POLC	0x4000

#endif /* __BFIN_PPI_H__ */
