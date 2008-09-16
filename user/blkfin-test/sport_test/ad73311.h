/*
 * File:         sound/blackfin/ad73311.h
 * Based on:
 * Author:       Roy Huang <Roy.Huang@analog.com>
 *
 * Created:      Wed Jan 11, 2006
 * Description:  definitions for AD73311 registers
 *
 * Rev:          $Id: ad73311.h 3620 2006-09-06 06:45:56Z royhuang $
 *
 * Modified:
 *               Copyright 2006 Analog Devices Inc.
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

#ifndef __AD73311_H__
#define __AD73311_H__

#if CONFIG_SND_BFIN_SPORT == 0
#define SPORT_ERR_IRQ	IRQ_SPORT0_ERROR
#define SPORT_DMA_RX	CH_SPORT0_RX
#define SPORT_DMA_TX	CH_SPORT0_TX
#define bfin_write_SPORT_TCR1	bfin_write_SPORT0_TCR1
#define bfin_read_SPORT_TCR1	bfin_read_SPORT0_TCR1
#define bfin_write_SPORT_TCR2	bfin_write_SPORT0_TCR2
#define bfin_write_SPORT_TX16	bfin_write_SPORT0_TX16
#define bfin_read_SPORT_STAT	bfin_read_SPORT0_STAT
#else
#define SPORT_ERR_IRQ	IRQ_SPORT1_ERROR
#define SPORT_DMA_RX	CH_SPORT1_RX
#define SPORT_DMA_TX	CH_SPORT1_TX
#define bfin_write_SPORT_TCR1	bfin_write_SPORT1_TCR1
#define bfin_read_SPORT_TCR1	bfin_read_SPORT1_TCR1
#define bfin_write_SPORT_TCR2	bfin_write_SPORT1_TCR2
#define bfin_write_SPORT_TX16	bfin_write_SPORT1_TX16
#define bfin_read_SPORT_STAT	bfin_read_SPORT1_STAT
#endif

#define AD_CONTROL	0x8000
#define AD_DATA		0x0000
#define AD_READ		0x4000
#define AD_WRITE	0x0000

/* Control register A */
#define CTRL_REG_A	(0 << 8)

#define MODE_PRO	0x00
#define MODE_DATA	0x01
#define MODE_MIXED	0x03
#define DLB		0x04
#define SLB		0x08
#define DEVC(x)		((x & 0x7) << 4)
#define RESET		0x80

/* Control register B */
#define CTRL_REG_B	(1 << 8)

#define DIRATE(x)	(x & 0x3)
#define SCDIV(x)	((x & 0x3) << 2)
#define MCDIV(x)	((x & 0x7) << 4)
#define CEE		(1 << 7)

/* Control register C */
#define CTRL_REG_C	(2 << 8)

#define PUDEV		( 1 << 0 )
#define PUADC		( 1 << 3 )
#define PUDAC		( 1 << 4 )
#define PUREF		( 1 << 5 )
#define REFUSE		( 1 << 6 )

/* Control register D */
#define CTRL_REG_D	(3 << 8)

#define IGS(x)		(x & 0x7)
#define RMOD		( 1 << 3 )
#define OGS(x)		((x & 0x7) << 4)
#define MUTE		(x << 7)

/* Control register E */
#define CTRL_REG_E	(4 << 8)

#define DA(x)		(x & 0x1f)
#define IBYP		( 1 << 5 )

/* Control register F */
#define CTRL_REG_F	(5 << 8)

#define SEEN		( 1 << 5 )
#define INV		( 1 << 6 )
#define ALB		( 1 << 7 )

#endif
