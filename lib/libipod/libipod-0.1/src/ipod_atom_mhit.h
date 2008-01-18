/*
 * ipod_atom_mhit.h
 *
 * Duane Maxwell
 * (c) 2005 by Linspire Inc
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTIBILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#ifndef __IPOD_ATOM_MHIT_H__
#define __IPOD_ATOM_MHIT_H__

#include "ipod_atom.h"
#include "ipod_atom_mhod.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint32_t trackID;
	uint32_t visible;
	uint32_t fileType; // typically 0 of HD-based ipods
	uint16_t vbr; // CBR MP3=0x0100, VBR MP3=0x0101, AAC=0x0000
	uint8_t compilation;
	uint8_t rating; // rating*20
	uint32_t lastPlayedTime;
	uint32_t size;
	uint32_t duration; // in milliseconds
	uint32_t trackNumber;
	uint32_t trackCount;
	uint32_t year;
	uint32_t bitRate;
	uint16_t unk8;
	uint16_t sampleRate;
	uint32_t volume;
	uint32_t startTime; // in milliseconds
	uint32_t endTime; // in milliseconds
	uint32_t soundCheck; // = 1000*10^(-0.1*y) where Y is adjustment in dB
	uint32_t playCount;
	uint32_t playCount2; // typically same as playCount
	uint32_t addedTime;
	uint32_t discNumber;
	uint32_t discCount;
	uint32_t userID; // Applestore ID for m4p, 0 otherwise
	uint32_t lastModificationTime;
	uint32_t bookmarkTime;
	uint32_t dbidlo;
	uint32_t dbidhi;
	uint8_t checked;
	uint8_t appRating;
	uint16_t BPM;
	uint16_t artworkCount;
	uint16_t unk9; // 0xffff for AAC and MP3, 0x0 for WAV, 0x1 for Audible
	uint32_t artworkSize;
	uint32_t unk11;
	float sampleRate2; // float version of sampleRate
	uint32_t unk13; // some sort of timeStamp
	uint32_t unk14; // 0x0000000c or 0x0100000c for MP3, 0x10000033 for AAC, 0x01000028 for Audible, 0 for WAV
	uint32_t unk15; // used by iTMS
	uint32_t unk16; 
	uint32_t unk17; 
	uint32_t unk18; 
	uint32_t unk19;
	uint32_t dbid2lo;
	uint32_t dbid2hi;
	uint32_t unk20; 
	uint32_t unk21; 
	uint32_t unk22; 
	uint32_t sampleCount; 
	uint32_t unk24; 
	uint32_t unk25; 
	uint32_t unk26; 
	uint32_t unk27; 
	uint32_t unk28; 
	uint32_t unk29; 
	uint32_t unk30; 
	uint32_t unk31; 
	uint32_t unk32; 
	uint32_t unk33; 
	uint32_t unk34; 
	uint32_t unk35; 
	uint32_t unk36; 
	
	ipod_atom_list children;
} ipod_atom_mhit_struct, *ipod_atom_mhit;

extern ipod_atom ipod_atom_new_mhit(void);

extern char *ipod_atom_mhit_get_text_utf8(ipod_atom atom, int tag, char *s);
extern void ipod_atom_mhit_set_text_utf8(ipod_atom atom, int tag, const char *s);
extern int ipod_atom_mhit_has_text(ipod_atom atom, int tag);

extern uint32_t ipod_atom_mhit_get_attribute(ipod_atom atom, int tag);
extern void ipod_atom_mhit_set_attribute(ipod_atom atom, int tag, uint32_t value);

//
// these are used by the Library Index mhods to pre-sort tracks
//
extern ipod_atom_mhod_string_struct *ipod_atom_mhit_title_struct(ipod_atom atom);
extern ipod_atom_mhod_string_struct *ipod_atom_mhit_album_struct(ipod_atom atom);
extern ipod_atom_mhod_string_struct *ipod_atom_mhit_artist_struct(ipod_atom atom);
extern ipod_atom_mhod_string_struct *ipod_atom_mhit_genre_struct(ipod_atom atom);
extern ipod_atom_mhod_string_struct *ipod_atom_mhit_composer_struct(ipod_atom atom);


#ifdef __cplusplus
};
#endif

#endif
