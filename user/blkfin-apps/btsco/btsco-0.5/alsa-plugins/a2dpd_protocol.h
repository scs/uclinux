/*
*
*  A2DPD - Bluetooth A2DP daemon for Linux
*
*  Copyright (C) 2006  Frédéric DALLEAU <frederic.dalleau@palmsource.com>
*
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software
*  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifndef __A2DPD_PROTOCOL_H__
#define __A2DPD_PROTOCOL_H__

#include <stdint.h>

// parameters used to describe device state
typedef struct {
	int16_t volume_speaker_right;
	int16_t volume_speaker_left;
	int16_t volume_micro_right;
	int16_t volume_micro_left;
} __attribute__ ((packed)) AUDIOMIXERDATA;

#define INVALIDAUDIOMIXERDATA   { -1, -1, -1, -1 }

// PCM formats defined in alsa, we will restrict our selves to 8 and 16 bits
#define A2DPD_PCM_FORMAT_UNKNOWN 0x00000000
#define A2DPD_PCM_FORMAT_S8      0x00000001
#define A2DPD_PCM_FORMAT_U8      0x00000002
#define A2DPD_PCM_FORMAT_S16_LE  0x00000003
//#define A2DPD_FORMAT_S16_BE        0x00000004
//#define A2DPD_FORMAT_U16_LE        0x00000005
//#define A2DPD_FORMAT_U16_BE        0x00000006

// parameters used to describe device state
typedef struct {
	uint32_t format;
	uint16_t rate;
	uint8_t channels;
	uint16_t bitspersample;
} __attribute__ ((packed)) AUDIOSTREAMINFOS;

#define INVALIDAUDIOSTREAMINFOS   { 0, 0, 0 }

// Different types of client plugin for the daemon
#define INVALID_CLIENT_TYPE     0xFFFFFFFF
#define A2DPD_PLUGIN_CTL_WRITE  0x00000001
#define A2DPD_PLUGIN_CTL_READ   0x00000002
#define A2DPD_PLUGIN_PCM_WRITE  0x00000003
#define A2DPD_VOLUME_MIN        0
#define A2DPD_VOLUME_MAX        15

#define A2DPD_FRAME_BYTES       4	// 16bits * 2 channels
#define A2DPD_FRAME_RATE        44100	// Can be 32000, tested with HP, iPhono and needed Sonorix, but quality decreases, 48000 nearly never works
// a2dp->sbc.channels*44100*2/(size*a2dp->frame_bytes);
// 344.53125=channels*freq*16 bits/sizeof(buf)
#define A2DPD_BLOCK_SIZE        (512*1)

#endif
