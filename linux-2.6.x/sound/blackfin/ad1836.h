/*
 * File:         sound/blackfin/ad1836.h
 * Based on:
 * Author:       Luuk van Dijk <blackfin@mdnmttr.nl>
 *
 * Created:      Tue Sep 21 10:52:42 CEST 2004
 * Description:  definitions for AD1836A registers
 *
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright (C) 2004 Luuk van Dijk, Mind over Matter B.V.
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

#ifndef __AD1836_H__
#define __AD1836_H__

#define DAC_CTRL_1  0x0
#define DAC_CTRL_2  0x1
#define DAC_VOL_1L  0x2
#define DAC_VOL_1R  0x3
#define DAC_VOL_2L  0x4
#define DAC_VOL_2R  0x5
#define DAC_VOL_3L  0x6
#define DAC_VOL_3R  0x7
#define ADC_PEAK_1L 0x8
#define ADC_PEAK_1R 0x9
#define ADC_PEAK_2L 0xA
#define ADC_PEAK_2R 0xB
#define ADC_CTRL_1  0xC
#define ADC_CTRL_2  0xD
#define ADC_CTRL_3  0xE

#define ADC_READ    0x0800

/* DAC_CTRL1 */
#define DAC_DEEMPH_MASK  0x0300
#define DAC_DEEMPH_SHIFT 8
#define DAC_DEEMPH_44    0x0100
#define DAC_DEEMPH_32    0x0200
#define DAC_DEEMPH_48    0x0300

#define DAC_DEEMPH_VALUE(x) (((x) & DAC_DEEMPH_MASK) >> DAC_DEEMPH_SHIFT)

#define DAC_SERMOD_MASK  0x00e0
#define DAC_SERMOD_I2S   0x0000
#define DAC_SERMOD_RJ    0x0020
#define DAC_SERMOD_DSP   0x0040
#define DAC_SERMOD_LJ    0x0060
#define DAC_SERMOD_PM256 0x0080
#define DAC_SERMOD_PM128 0x00A0

#define DAC_DATA_MASK    0x0018
#define DAC_DATA_24      0x0000
#define DAC_DATA_20      0x0008
#define DAC_DATA_16      0x0010

#define DAC_PWRDWN       0x0004
#define DAC_96KHZ        0x0002

/* DAC CTRL 2 */

#define DAC_MUTE_MASK    0x003f
#define DAC_MUTE_DAC1	 0x0003
#define DAC_MUTE_DAC2	 0x000c
#define DAC_MUTE_DAC3	 0x0030

/* DAC VOL x */
#define DAC_VOL_MASK     0x03ff

/* ADC_PEAK */
#define ADC_PEAK_MASK    0x03f0
#define ADC_PEAK_VALUE(reg)   ( -( ((reg) & ADC_PEAK_MASK) >> 4) )


/* ADC CTRL 1 */

#define ADC_HIGHPASS        0x0100
#define ADC_PWRDWN          0x0080
#define ADC_SAMPLE_96KHZ    0x0040
#define ADC_GAIN_LEFT_MASK  0x0038
#define ADC_GAIN_LEFT_SHIFT 3
#define ADC_GAIN_RIGHT_MASK 0x0007

#define ADC_GAIN_LEFT(x)  (((x)&ADC_GAIN_LEFT_MASK ) >> ADC_GAIN_LEFT_SHIFT)
#define ADC_GAIN_RIGHT(x) (((x)&ADC_GAIN_RIGHT_MASK) /* >>ADC_GAIN_RIGHT_SHIFT */)

/* ADC CTRL 2 */
#define ADC_AUX_MASTER      0x0200

#define ADC_SOUT_MASK       0x01C0
#define ADC_SOUT_I2S        0x0000
#define ADC_SOUT_RJ         0x0040
#define ADC_SOUT_DSP        0x0080
#define ADC_SOUT_LJ         0x00C0
#define ADC_SOUT_PM256      0x0100
#define ADC_SOUT_PM128      0x0140
#define ADC_SOUT_PMAUX      0x0180

#define ADC_DATA_MASK       0x0030
#define ADC_DATA_24         0x0000
#define ADC_DATA_20         0x0010
#define ADC_DATA_16         0x0020

#define ADC_MUTE_MASK       0x000f
#define ADC_MUTE_ADC1	    0x0003
#define ADC_MUTE_ADC2	    0x000c

/* ADC CTRL 3 */

#define ADC_CLOCK_MASK      0x00C0
#define ADC_CLOCK_256       0x0000
#define ADC_CLOCK_512       0x0040
#define ADC_CLOCK_768       0x0080

#define ADC_MODE_MASK	    0x003F
#define ADC_LEFT_SE         0x0020
#define ADC_RIGHT_SE        0x0010
#define ADC_LEFT_MUX        0x0008
#define ADC_LEFT_SEL        0x0004
#define ADC_RIGHT_MUX       0x0002
#define ADC_RIGHT_SEL       0x0001

/* Channel Location */
#define DAC0_LEFT	0x0001
#define DAC1_LEFT	0x0002
#define DAC2_LEFT	0x0004
#define DAC0_RIGHT	0x0010
#define DAC1_RIGHT	0x0020
#define DAC2_RIGHT	0x0040
#define SPDIF_OUT_LEFT	0x0008
#define SPDIF_OUT_RIGHT	0x0080

/* Speaker location */
#define SP_FL		DAC0_LEFT
#define SP_FR		DAC0_RIGHT
#define SP_FC		DAC1_LEFT
#define SP_LFE		DAC1_RIGHT
#define SP_BL		DAC2_LEFT
#define SP_BR		DAC2_RIGHT

#define SP_STEREO	(SP_FL | SP_FR)
#define SP_2DOT1	(SP_FL | SP_FR | SP_LFE)
#define SP_QUAD		(SP_FL | SP_FR | SP_BL | SP_BR)
#define SP_5DOT1	(SP_FL | SP_FR | SP_FC | SP_LFE | SP_BL | SP_BR)

/* In channels */
#define ADC0_LEFT	0x0001
#define ADC0_RIGHT	0x0010
#define ADC1_LEFT	0x0002
#define ADC1_RIGHT	0x0020
#define SPDIF_IN_LEFT	0x0004
#define SPDIF_IN_RIGHT	0x0040

#define CAP_LINE	(ADC0_LEFT | ADC0_RIGHT)
#define CAP_MIC		(ADC1_LEFT | ADC1_RIGHT)
#define CAP_SPDIF	(SPDIF_IN_LEFT | SPDIF_IN_RIGHT)

#endif
