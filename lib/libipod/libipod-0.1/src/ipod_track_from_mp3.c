/*
 * ipod_track_from_mp3.c
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

#include <ipod/ipod.h>
#include <ipod/ipod_file_utils.h>
#include <ipod/ipod_io.h>
#include <ipod/ipod_constants.h>
#include <ipod/ipod_string.h>
#include <ipod/ipod_error.h>
#include <stdio.h>

#define IPOD_MPEG_VERSION_1		3
#define IPOD_MPEG_VERSION_2		2
#define IPOD_MPEG_VERSION_2_5	0

#define IPOD_MPEG_LAYER_1		3
#define IPOD_MPEG_LAYER_2		2
#define IPOD_MPEG_LAYER_3		1

#define IPOD_ATOM_TAG			0x544147

#define IPOD_ATOM_TP1			0x545031
#define IPOD_ATOM_TPE1			0x54504531
#define IPOD_ATOM_TT2			0x545432
#define IPOD_ATOM_TIT2			0x54495432
#define IPOD_ATOM_TAL			0x54414c
#define IPOD_ATOM_TALB			0x54414c42
#define IPOD_ATOM_TYE			0x545945
#define IPOD_ATOM_TYER			0x54594552
#define IPOD_ATOM_TCM			0x54434d
#define IPOD_ATOM_TCOM			0x54434f4d
#define IPOD_ATOM_TCO			0x54434f
#define IPOD_ATOM_TCON			0x54434f4e
#define IPOD_ATOM_TRK			0x54524b
#define IPOD_ATOM_TRCK			0x5452434b
#define IPOD_ATOM_TPA			0x545041
#define IPOD_ATOM_TPOS			0x54504f53

#define IPOD_ID3_ENCODING_ISO_8859		0
#define IPOD_ID3_ENCODING_UTF_16_BOM	1
#define IPOD_ID3_ENCODING_UTF_16_BE		2
#define IPOD_ID3_ENCODING_UTF_8			3

extern char *ipod_music_genres[];

static char *ipod_version_name[] = {"MPEG 2.5","reserved","MPEG 2","MPEG 1"};
static char *ipod_layer_name[] = {"reserved","Layer III","Layer II","Layer I"};
//
// sample rates, index by version, sample_rate_index
//
static unsigned long ipod_mp3_sample_rates[4][4] = {
	{11025,12000,8000,50000},	// MPEG 2.5
	{0,0,0,0},					// reserved
	{22050,24000,16000,50000},	// MPEG 2
	{44100,48000,32000,50000}	// MPEG 1
};

//
// bit rates, indexed by version, layer, bit_rate_index
//
static int ipod_mp3_bit_rates[4][3][16] = {
	{ // MPEG 2.5
		{0,32,48,56,64,80,96,112,128,144,160,176,192,224,256,0},	// layer 1
		{0,8,16,24,32,40,48,56,64,80,96,112,128,144,160,0},			// layer 2
		{0,8,16,24,32,40,48,56,64,80,96,112,128,144,160,0}			// layer 3
	},
	{ // reserved
		{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
		{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0},
		{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
	},
	{ // MPEG 2.0
		{0,32,48,56,64,80,96,112,128,144,160,176,192,224,256,0},	// layer 1
		{0,8,16,24,32,40,48,56,64,80,96,112,128,144,160,0},			// layer 2
		{0,8,16,24,32,40,48,56,64,80,96,112,128,144,160,0}			// layer 3
	},
	{ // MPEG 1.0
		{0,32,64,96,128,160,192,224,256,288,320,352,384,416,448,0},	// layer 1
		{0,32,48,56,64,80,96,112,128,160,192,224,256,320,384,0},	// layer 2
		{0,32,40,48,56,64,80,96,112,128,160,192,224,256,320,0}		// layer 3
	}
};

static char *ipod_mp3_scan_id3v1_text(ipod_io io,int count)
{
	int i;
	char *result,*raw = (char *)ipod_memory_alloc(count*2);
	for (i=0;i<count;i++) {
		raw[i*2] = ipod_io_getub(io);
		raw[i*2+1] = 0;
	}
	result = ipod_string_utf8_from_utf16(raw,count);
	ipod_memory_free(raw);
	//printf("id3v1: %s\n",result);
	return result;
}

static void ipod_mp3_scan_id3v1(ipod_io io,ipod_track_t track)
{
	uint32_t tag;
	ipod_io_seek(io,ipod_io_length(io)-128);
	tag = ipod_io_getul3(io);
	if (tag==IPOD_ATOM_TAG) { // got ID3v1 tags!
		uint32_t year;
		int trackNum,genre;
		char *text;
		//printf("ipod_mp3_scan_id3v1(): got id3v1 tags\n");
		text = ipod_mp3_scan_id3v1_text(io,30);
		ipod_track_set_text(track,IPOD_TITLE,text);
		ipod_string_free(text);
		text = ipod_mp3_scan_id3v1_text(io,30);
		ipod_track_set_text(track,IPOD_ARTIST,text);
		ipod_string_free(text);
		text = ipod_mp3_scan_id3v1_text(io,30);
		ipod_track_set_text(track,IPOD_ALBUM,text);
		ipod_string_free(text);
		year = ipod_io_getul_be(io);
		if (year) {
			int i,yearVal = 0;
			for (i=0;i<4;i++)
				yearVal = yearVal*10+((year>>((3-i)*8)) & 0xff)-'0';
			ipod_track_set_attribute(track,IPOD_TRACK_YEAR,yearVal);
			//printf("year %d\n",yearVal);
		}
		text = ipod_mp3_scan_id3v1_text(io,28);
		ipod_track_set_text(track,IPOD_COMMENT,text);
		ipod_string_free(text);
		trackNum = ipod_io_getub(io);
		ipod_track_set_attribute(track,IPOD_TRACK_TRACK_NUMBER,trackNum);
		genre = ipod_io_getub(io);
		ipod_track_set_text(track,IPOD_GENRE,ipod_music_genres[genre]);
	}
	ipod_io_seek(io,0);
}

//
// process a single text tag, normalizing the encodings to utf-8
//
static char *ipod_mp3_scan_id3v2_text(ipod_io io,int version,size_t size)
{
	char *result;
	int encoding = ipod_io_getb(io);
	switch (encoding) {
		case IPOD_ID3_ENCODING_ISO_8859: {
			// convert ISO-8850 to UTF-16LE, then to UTF-8
			int i,count = size-1;
			char *raw;
			raw = (char *)ipod_memory_alloc(count*2);
			for (i=0;i<count;i++) {
				raw[i*2] = ipod_io_getub(io);
				raw[i*2+1] = 0;
			}
			result = ipod_string_utf8_from_utf16(raw,count);
			ipod_memory_free(raw);
			}
			break;
		case IPOD_ID3_ENCODING_UTF_16_BOM: {
			uint8_t bom0,bom1;
			int i,count;
			char *raw;
			bom0 = ipod_io_getub(io);
			bom1 = ipod_io_getub(io);
			count = (size-3)/2;
			raw = (char *)ipod_memory_alloc(count*2);
			for (i=0;i<count;i++) {
				if (bom0==0xfe) {
					raw[i*2+1] = ipod_io_getub(io);
					raw[i*2] = ipod_io_getub(io);
				} else {
					raw[i*2] = ipod_io_getub(io);
					raw[i*2+1] = ipod_io_getub(io);
				}
			}
			result = ipod_string_utf8_from_utf16(raw,count);
			ipod_memory_free(raw);
			}
			break;
		case IPOD_ID3_ENCODING_UTF_16_BE: {
			int i,count = (size-1)/2;
			char *raw = (char *)ipod_memory_alloc(count*2);
			for (i=0;i<count;i++) {
				raw[i*2+1] = ipod_io_getub(io);
				raw[i*2] = ipod_io_getub(io);
			}
			result = ipod_string_utf8_from_utf16(raw,count);
			ipod_memory_free(raw);
			}
			break;
		case IPOD_ID3_ENCODING_UTF_8: {
			size_t dataRead;
			char *raw = (char *)ipod_memory_alloc(size);
			ipod_io_read(io,raw,size-1,&dataRead);
			raw[size-1] = '\0';
			result = ipod_string_new_from_array(raw,size-1);
			ipod_memory_free(raw);
			}
			break;
		default:
			ipod_error("ipod_mp3_scan_text(): Invalid text encoding %d\n",encoding);
	}
	//printf("id3v2: %s\n",result);
	return result;
}

//
// process a set of ID3v2 frames
//
static void ipod_mp3_scan_id3v2(ipod_io io,ipod_track_t track)
{
	int version, revision, flags;
	size_t  size,mark;
	version = ipod_io_getub(io);
	revision = ipod_io_getub(io);
	flags = ipod_io_getub(io);
	size = ipod_io_getul_ss(io);
	mark = ipod_io_tell(io); // save this spot
	//printf("ipod_mp3_scan_frames(): got ID3 (%d.%d) flags %x at %lx (size %d (0x%lx))\n",
	//	version,revision,flags,ipod_io_tell(io)-10,size,size);
	if (version>=2 && version<=4) {
		int unsync,extended,experimental,footer;
		unsync = (flags >> 7) & 1;
		extended = (flags >> 6) & 1;
		experimental = (flags >> 5) & 1;
		footer = (flags >> 4) & 1;
		if (extended) {
			size_t ext_size;
			int ext_flags,update,crc,restrictions;
			ext_size = ipod_io_getul_ss(io);
			ext_flags = ipod_io_getub(io);
			update = (ext_flags >> 6) & 1;
			crc = (ext_flags >>5 ) & 1;
			restrictions = (ext_flags >> 4) & 1;
			//ipod_error("ipod_mp3_scan_id3v2(): extended tags update %d, crc %d restrictions %d, total size  %d (0x%lx)\n",
			//	update,extended,restrictions,ext_size,ext_size);
			ipod_io_seek(io,mark+ext_size);
		}
		while (ipod_io_tell(io)<mark+size) {
			size_t frame_mark;
			uint32_t frame_id;
			size_t frame_size;
			uint16_t frame_flags;
			if (version==2) {
				frame_id = ipod_io_getul3(io);
				if (frame_id==0)
					break;
				frame_size = ipod_io_getul3(io);
				frame_flags = 0;
			} else {
				frame_id = ipod_io_getul_be(io);
				if (frame_id==0)
					break;
				if (version==4)
					frame_size = ipod_io_getul_ss(io);
				else
					frame_size = ipod_io_getul_be(io);
				frame_flags = ipod_io_getuw_be(io);
			}
			frame_mark = ipod_io_tell(io);
			//printf("ipod_mp3_scan_id3v2(): got frame %s (0x%lx)\n",ipod_tag_str(frame_id),frame_id);
			switch(frame_id) {
				case IPOD_ATOM_TT2:
				case IPOD_ATOM_TIT2: {
					char *title = ipod_mp3_scan_id3v2_text(io,version,frame_size);
					ipod_track_set_text(track,IPOD_TITLE,title);
					ipod_string_free(title);
					}
					break;
				case IPOD_ATOM_TP1:
				case IPOD_ATOM_TPE1: {
					char *artist =  ipod_mp3_scan_id3v2_text(io,version,frame_size);
					ipod_track_set_text(track,IPOD_ARTIST,artist);
					ipod_string_free(artist);
					}
					break;
				case IPOD_ATOM_TAL:
				case IPOD_ATOM_TALB: {
					char *album =  ipod_mp3_scan_id3v2_text(io,version,frame_size);
					ipod_track_set_text(track,IPOD_ALBUM,album);
					ipod_string_free(album);
					}
					break;
				case IPOD_ATOM_TYE:
				case IPOD_ATOM_TYER: {
					int i,yearVal = 0;
					char *year =  ipod_mp3_scan_id3v2_text(io,version,frame_size);
					for (i=0;i<4;i++)
						yearVal = yearVal*10+year[i]-'0';
					ipod_track_set_attribute(track,IPOD_TRACK_YEAR,yearVal);
					ipod_string_free(year);
					}
					break;
				case IPOD_ATOM_TCM:
				case IPOD_ATOM_TCOM: {
					char *composer =  ipod_mp3_scan_id3v2_text(io,version,frame_size);
					ipod_track_set_text(track,IPOD_COMPOSER,composer);
					ipod_string_free(composer);
					}
					break;
				case IPOD_ATOM_TCO:
				case IPOD_ATOM_TCON: {
					int genreVal = 0;
					char *genre =  ipod_mp3_scan_id3v2_text(io,version,frame_size);
					sscanf(genre,"(%d)",&genreVal);
					//printf("got genre %d\n",genreVal);
					ipod_track_set_text(track,IPOD_GENRE,ipod_music_genres[genreVal]);
					ipod_string_free(genre);
					}
					break;
				case IPOD_ATOM_TRK:
				case IPOD_ATOM_TRCK: {
					int track_num = 0,track_count = 0;
					char *track_info = ipod_mp3_scan_id3v2_text(io,version,frame_size);
					//printf("got track info %s\n",track_info);
					sscanf(track_info,"%d/%d",&track_num,&track_count);
					ipod_track_set_attribute(track,IPOD_TRACK_TRACK_NUMBER,track_num);
					ipod_track_set_attribute(track,IPOD_TRACK_TRACK_COUNT,track_count);
					ipod_string_free(track_info);
					}
					break;
				case IPOD_ATOM_TPA:
				case IPOD_ATOM_TPOS: {
					int disc_num = 0,disc_count = 0;
					char *disc_info = ipod_mp3_scan_id3v2_text(io,version,frame_size);
					//printf("got disk info %s\n",disc_info);
					sscanf(disc_info,"%d/%d",&disc_num,&disc_count);
					ipod_track_set_attribute(track,IPOD_TRACK_DISC_NUMBER,disc_num);
					ipod_track_set_attribute(track,IPOD_TRACK_DISC_COUNT,disc_count);
					ipod_string_free(disc_info);
					}
					break;
			}
			ipod_io_seek(io,frame_mark+frame_size);
		}
	} else {
		ipod_error("ipod_mp3_scan_id3v3(): Unsupported ID3v2 version (%d.%d)\n",version,revision);
	}
	ipod_io_seek(io,mark+size);
}

//
// We read the entire MP3 file, building a histogram of the bitrates, and extracting any
// ID3v2 tags we find along the way.
//
static void ipod_mp3_scan_frames(ipod_io io,ipod_track_t track)
{
	size_t total_length;
	uint8_t b;
	unsigned long frame_types[16];
	unsigned long frame_count;
	int i,frame_type_count,total_rate;
	int version,layer,skipcrc,bit_rate_index,sample_rate_index,padding;
	int channel_mode,channel_mode_extension,copyright,original,emphasis;
	unsigned long frame_length,bit_rate,sample_rate,duration;
	
	for (i=0;i<16;i++)
		frame_types[i] = 0;
	total_length = ipod_io_length(io);
	while (ipod_io_tell(io)<total_length) {
		do { // find the next frame sync
			b = ipod_io_getub(io);
			if (b=='I') { // possible ID3 tag!
				b = ipod_io_getub(io);
				if (b=='D') { // looking good so far...
					b = ipod_io_getub(io);
					if (b=='3') { // ...got one!
						ipod_mp3_scan_id3v2(io,track);
					} else {
						ipod_io_seek(io,ipod_io_tell(io)-2); // back up
					}
				} else {
					ipod_io_seek(io,ipod_io_tell(io)-1); // back up
				}
			}
		} while (b!=0xff && ipod_io_tell(io)<total_length);
		if (b==0xff) {
			b = ipod_io_getub(io);
			if ((b & 0xe0) == 0xe0) { // good frame
				version = (b >> 3) & 3; // 0==Version 2.5, 1==reserved, 2==Version 2, 3==Version 1
				layer = (b >> 1) & 3; // 1==Layer 3, 2==Layer 2, 3==Layer 1
				skipcrc = b & 1; // 0 = has crc, 1 = no crc
				b = ipod_io_getub(io);
				bit_rate_index = (b >> 4) & 0xf;
				sample_rate_index = (b >> 2) & 3;
				padding = (b >> 1) & 1;
				b = ipod_io_getub(io);
				channel_mode = (b >> 6) & 3; // 0==stereo 1==joint stereo,2==dual channel,3==mono
				channel_mode_extension = (b >> 4) & 1;
				copyright = (b >> 3) & 1;
				original = (b >> 2) & 1;
				emphasis = b & 3;
				frame_types[bit_rate_index]++;
				bit_rate = ipod_mp3_bit_rates[version][3-layer][bit_rate_index]*1000;
				sample_rate = ipod_mp3_sample_rates[version][sample_rate_index];
				if (layer==IPOD_MPEG_LAYER_1)
					frame_length = (12*bit_rate/sample_rate+padding)*4;
				else
					frame_length = 144*bit_rate/sample_rate+padding;
				ipod_io_seek(io,ipod_io_tell(io)+frame_length-4);
				if (!skipcrc)
					ipod_io_seek(io,ipod_io_tell(io)+2);
			} else { // back up in case this is a framesync
				ipod_io_seek(io,ipod_io_tell(io)-1);
			}
		}
	}
	frame_count = 0;
	frame_type_count = 0;
	total_rate = 0;
	duration = 0;
	for (i=0;i<16;i++) {
		if (frame_types[i]) {
			frame_count += frame_types[i];
			frame_type_count++;
			bit_rate = ipod_mp3_bit_rates[version][3-layer][i];
			total_rate += frame_types[i]*bit_rate;
			if (layer==IPOD_MPEG_LAYER_1)
				duration += 384*frame_types[i];
			else
				duration += 1152*frame_types[i];
		}
	}
	bit_rate = total_rate/frame_count;
	//printf("bit_rate %d\n",bit_rate);
	duration = duration/sample_rate*1000;
	//printf("duration %d\n",duration);
	ipod_track_set_attribute(track,IPOD_TRACK_SIZE,total_length);
	ipod_track_set_attribute(track,IPOD_TRACK_BIT_RATE,bit_rate);
	ipod_track_set_attribute(track,IPOD_TRACK_SAMPLE_RATE,sample_rate);
	ipod_track_set_attribute(track,IPOD_TRACK_DURATION,duration);
	ipod_track_set_attribute(track,IPOD_TRACK_VBR,(frame_type_count>1)?0x0101:0x0100);
}

static void ipod_mp3_scan(ipod_io io,ipod_track_t track)
{
	ipod_mp3_scan_id3v1(io,track);
	ipod_io_seek(io,0);
	ipod_mp3_scan_frames(io,track);
}

ipod_track_t ipod_track_from_mp3(ipod_t ipod,ipod_io io) {
	ipod_track_t track = ipod_track_add(ipod);
	//printf("ipod_track_from_mp3()\n");
	ipod_mp3_scan(io,track);
	ipod_track_set_text(track,IPOD_FILETYPE,"MPEG audio file");
	return track;
}
