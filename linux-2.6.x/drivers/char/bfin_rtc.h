/*
 * File:         drivers/char/bfin_rtc.h
 * Based on:
 * Author:
 *
 * Created:
 * Description:
 *
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright 2004-2006 Analog Devices Inc.
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

/* bit define */
#define DAY_BITS_OFF     17
#define HOUR_BITS_OFF    12
#define MIN_BITS_OFF     6
#define SEC_BITS_OFF     0

#define MIN_TO_SECS(_x_) (60 * _x_)
#define HRS_TO_SECS(_x_) (60 * 60 * _x_)
#define DAYS_TO_SECS(_x_) (24 * 60 * 60 * _x_)

#define NUM_SECS_IN_DAY (24 * 3600)
#define NUM_SECS_IN_HOUR (3600)
#define NUM_SECS_IN_MIN (60)

/*RTC Interrupt Control Register Bit Define*/
#define STPW_INT_EN     0x0001
#define ALM_INT_EN      0x0002
#define SEC_INT_EN      0x0004
#define MIN_INT_EN      0x0008
#define H_INT_EN        0x0010
#define H24_INT_EN      0x0020
#define DAY_INT_EN      0x0040
#define WC_INT_EN       0x8000

/*RTC Interrupt Status Register  bit define */
#define STPW_EVT_FG     0x0001
#define ALM_EVT_FG      0x0002
#define SEC_EVT_FG      0x0004
#define MIN_EVT_FG      0x0008
#define H_EVT_FG        0x0010
#define H24_EVT_FG      0x0020
#define DAY_EVT_FG      0x0040
#define WP_EVT_FG       0x4000
#define WC_EVT_FG       0x8000

/* PreScaler Enable Register bit define */
#define PRESCALE_EN     0x0001
#define RTC_SWCNT_OFF   _IO('p', 0xF0)
#define RTC_SWCNT_ON    _IO('p', 0xF1)
#define RTC_SWCNT_SET   _IOW('p', 0xF2, unsigned long)
#define RTC_SWCNT_RD    _IOR('p', 0xF3, unsigned long)
