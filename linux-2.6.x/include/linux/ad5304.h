/*
 * File:         include/linux/ad5304.h
 * Created:      Dec 2006
 * Description:  Control AD53{0,1,2}4 DACs over SPI
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

#ifndef __LINUX_AD5304_H__
#define __LINUX_AD5304_H__

#include <linux/types.h>
#include <linux/ioctl.h>

#define AD5304_SET_DAC    _IOW(0x6B, 0x01, __u32)

#define AD5304_DACA       0x0000
#define AD5304_DACB       0x4000
#define AD5304_DACC       0x8000
#define AD5304_DACD       0xC000

#define AD5304_PD         0x2000
#define AD5304_LDAC       0x1000

#define AD5304_DATA_MASK  0x0FF0
#define AD5314_DATA_MASK  0x0FFC
#define AD5324_DATA_MASK  0x0FFF

#endif
