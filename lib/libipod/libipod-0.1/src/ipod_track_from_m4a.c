/*
 * ipod_track_from_m4a.c
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
#include <stdio.h>

//
// types of tags that we care about in an m4a file
//
#define IPOD_ATOM_MOOV 0x6d6f6f76
#define IPOD_ATOM_MDAT 0x6d646174
#define IPOD_ATOM_MVHD 0x6d766864
#define IPOD_ATOM_UDTA 0x75647461
#define IPOD_ATOM_TRAK 0x7472616b
#define IPOD_ATOM_META 0x6d657461
#define IPOD_ATOM_ILST 0x696c7374
#define IPOD_ATOM_DATA 0x64617461
#define IPOD_ATOM_TRKN 0x74726b6e
#define IPOD_ATOM_DISK 0x6469736b
#define IPOD_ATOM_CPIL 0x6370696c
#define IPOD_ATOM_TMPO 0x746d706f
#define IPOD_ATOM_GNRE 0x676e7265
#define IPOD_ATOM_RTNG 0x72746e67
#define IPOD_ATOM_COVR 0x636f7672
#define IPOD_ATOM_DAY 0xa9646179
#define IPOD_ATOM_MDIA 0x6d646961
#define IPOD_ATOM_MINF 0x6d696e66
#define IPOD_ATOM_STBL 0x7374626c
#define IPOD_ATOM_STSD 0x73747364
#define IPOD_ATOM_MP4A 0x6d703461
#define IPOD_ATOM_DRMS 0x64726d73
#define IPOD_ATOM_SAMR 0x73616d72
#define IPOD_ATOM_GEN 0xa967656e
#define IPOD_ATOM_NAM 0xa96e616d
#define IPOD_ATOM_ART 0xa9415254
#define IPOD_ATOM_ALB 0xa9616c62
#define IPOD_ATOM_WRT 0xa9777274
#define IPOD_ATOM_TOO 0xa9746f6f
#define IPOD_ATOM_CMT 0xa9636d74
#define IPOD_ATOM_GRP 0xa9677270
#define IPOD_ATOM_APID 0x61706964
#define IPOD_ATOM_CPRT 0x63707274

char *ipod_music_genres[] = {
	"Blues","Classic Rock","Country","Dance","Disco","Funk","Grunge","Hip-Hop","Jazz","Metal",
	"New Age","Oldies","Other","Pop","R&B","Rap","Reggae","Rock","Techno","Industrial",
	"Alternative","Ska","Death Metal","Pranks","Soundtrack","Euro-Techno","Ambient","Trip-Hop","Vocal","Jazz+Funk",
	"Fusion","Trance","Classical","Instrumental","Acid","House","Game","Sound Clip","Gospel","Noise",
	"AlternRock","Bass","Soul","Punk","Space","Meditative","Instrumental Pop","Instrumental Rock","Ethnic","Gothic",
	"Darkwave","Techno-Industrial","Electronic","Pop-Folk","Eurodance","Dream","Southern Rock","Comedy","Cult","Gangsta",\
	"Top 40","Christian Rap","Pop/Funk","Jungle","Native American","Cabaret","New Wave","Psychedelic","Rave","Showtunes",
	"Trailer","Lo-Fi","Tribal","Acid Punk","Acid Jazz","Polka","Retro","Musical","Rock & Roll","Hard Rock",
	"Folk","Folk-Rock","National Folk","Swing","Fast Fusion","Bebob","Latin","Revival","Celtic","Bluegrass",
	"Avantgarde","Gothic Rock","Progressive Rock","Psychedelic Rock","Symphonic Rock","Slow Rock","Big Band","Chorus",
	"Easy Listening","Acoustic",
	"Humor","Speech","Chanson","Opera","Chamber Music","Sonata","Symphony","Booty Bass","Primus","Porn Groove",
	"Satire","Slow Jam","Club","Tango","Samba","Folklore","Ballad","Power Ballad","Rhythmic Soul","Freestyle",
	"Duet","Punk Rock","Drum Solo","A capella","Euro-House","Dance Hall","Goa","Drum & Bass","Club-House","Hardcore",
	"Terror","Indie","Britpop","Negerpunk","Polsk Punk","Beat","Christian Gangsta Rap","Heavy Metal","Black Metal","Crossover",
	"Contemporary Christian","Christian Rock","Merengue","Salsa","Trash Metal","Anime","JPop","Synthpop"};

static uint64_t g_size;

static void ipod_m4a_atom(ipod_io io,uint32_t *tag,size_t *nextAtom)
{
	*nextAtom = ipod_io_getul_be(io);
	*tag = ipod_io_getul_be(io);
	*nextAtom += ipod_io_tell(io)-8;
}

static void ipod_m4a_scan_mvhd(ipod_io io,ipod_track_t track,size_t mvhdEnds)
{
	size_t size = mvhdEnds-ipod_io_tell(io);
	uint32_t creationTime,modificationTime,timeScale,duration,rate;
	ipod_io_getul_be(io); // skip version and flags
	creationTime = ipod_io_getul_be(io);
	modificationTime = ipod_io_getul_be(io);
	timeScale = ipod_io_getul_be(io);
	duration = (ipod_io_getul_be(io)*1000)/timeScale;
	rate = ipod_io_getul_be(io);
	ipod_track_set_attribute(track,IPOD_TRACK_LAST_MODIFICATION_TIME,modificationTime);
	ipod_track_set_attribute(track,IPOD_TRACK_DURATION,duration);
}

static void ipod_m4a_scan_data(ipod_io io,ipod_track_t track,uint32_t tag,size_t dataEnds)
{
	size_t size = dataEnds-ipod_io_tell(io)-8;
	ipod_io_getul_be(io); // skip
	ipod_io_getul_be(io); // skip
	switch (tag) {
		case IPOD_ATOM_TRKN:
			ipod_track_set_attribute(track,IPOD_TRACK_TRACK_NUMBER,ipod_io_getul_be(io));
			ipod_track_set_attribute(track,IPOD_TRACK_TRACK_COUNT,ipod_io_getuw_be(io));
			break;
		case IPOD_ATOM_DISK:
			ipod_track_set_attribute(track,IPOD_TRACK_DISC_NUMBER,ipod_io_getul_be(io));
			ipod_track_set_attribute(track,IPOD_TRACK_DISC_COUNT,ipod_io_getuw_be(io));
			break;
		case IPOD_ATOM_CPIL:
			ipod_track_set_attribute(track,IPOD_TRACK_COMPILATION,ipod_io_getub(io)!=0);
			break;
		case IPOD_ATOM_GNRE:
			ipod_track_set_text(track,IPOD_GENRE,ipod_music_genres[ipod_io_getuw_be(io)]);
			break;
		case IPOD_ATOM_RTNG:
			ipod_track_set_attribute(track,IPOD_TRACK_RATING,ipod_io_getuw_be(io));
			break;
		case IPOD_ATOM_DAY:
			ipod_track_set_attribute(track,IPOD_TRACK_YEAR,ipod_io_getuw_be(io));
			break;
		case IPOD_ATOM_NAM:
		case IPOD_ATOM_GEN:
		case IPOD_ATOM_ART:
		case IPOD_ATOM_ALB:
		case IPOD_ATOM_WRT:
		case IPOD_ATOM_CMT:
		case IPOD_ATOM_GRP: {
				size_t dataRead;
				char *s = ipod_string_new();
				s = ipod_string_realloc(s,size);
				ipod_io_read(io,s,size,&dataRead);
				s[size] = '\0';
				switch (tag) {
					case IPOD_ATOM_NAM: ipod_track_set_text(track,IPOD_TITLE,s); break;
					case IPOD_ATOM_GEN: ipod_track_set_text(track,IPOD_GENRE,s); break;
					case IPOD_ATOM_ART: ipod_track_set_text(track,IPOD_ARTIST,s); break;
					case IPOD_ATOM_ALB: ipod_track_set_text(track,IPOD_ALBUM,s); break;
					case IPOD_ATOM_WRT: ipod_track_set_text(track,IPOD_COMPOSER,s); break;
					case IPOD_ATOM_CMT: ipod_track_set_text(track,IPOD_COMMENT,s); break;
					case IPOD_ATOM_GRP: ipod_track_set_text(track,IPOD_GROUPING,s); break;
				}
				ipod_string_free(s);
			}
			break;
	}
}

static void ipod_m4a_scan_ilst(ipod_io io,ipod_track_t track,size_t ilstEnds)
{
	uint32_t tag;
	size_t ends;
	uint32_t payloadTag;
	size_t payloadEnds;
	for (;;) {
		ipod_m4a_atom(io,&tag,&ends);
		ipod_m4a_atom(io,&payloadTag,&payloadEnds);
		if (payloadTag==IPOD_ATOM_DATA)
			ipod_m4a_scan_data(io,track,tag,ends);
		ipod_io_seek(io,ends);
		if (ends>=ilstEnds) break;
	}
}

static void ipod_m4a_scan_meta(ipod_io io,ipod_track_t track,size_t metaEnds)
{
	uint32_t tag;
	size_t ends;
	ipod_io_getul_be(io); // skip
	for (;;) {
		ipod_m4a_atom(io,&tag,&ends);
		if (tag==IPOD_ATOM_ILST)
			ipod_m4a_scan_ilst(io,track,ends);
		ipod_io_seek(io,ends);
		if (ends>=metaEnds) break;
	}
}

static void ipod_m4a_scan_udta(ipod_io io,ipod_track_t track,size_t udtaEnds)
{
	uint32_t tag;
	size_t ends;
	for (;;) {
		ipod_m4a_atom(io,&tag,&ends);
		if (tag==IPOD_ATOM_META)
			ipod_m4a_scan_meta(io,track,ends);
		ipod_io_seek(io,ends);
		if (ends>=udtaEnds) break;
	}
}

static void ipod_m4a_scan_stsd(ipod_io io,ipod_track_t track,size_t stsdEnds)
{
	uint32_t tag;
	size_t size = stsdEnds-ipod_io_tell(io);
	ipod_io_getul_be(io); // skip
	ipod_io_getul_be(io); // skip
	ipod_io_getul_be(io); // skip
	tag = ipod_io_getul_be(io);
	if (tag==IPOD_ATOM_MP4A || tag==IPOD_ATOM_DRMS || tag==IPOD_ATOM_SAMR) {
		uint16_t bps;
		uint16_t channels;
		uint16_t vbr;
		uint32_t sampleRate;
		ipod_io_getul_be(io); // skip
		ipod_io_getul_be(io); // skip
		ipod_io_getul_be(io); // skip
		ipod_io_getul_be(io); // skip
		channels = ipod_io_getuw_be(io);
		bps = ipod_io_getuw_be(io);
		vbr = ipod_io_getuw_be(io);
		ipod_io_getuw_be(io); // skip
		sampleRate = ipod_io_getul_be(io)>>16;
		ipod_track_set_attribute(track,IPOD_TRACK_SAMPLE_RATE,sampleRate);
		ipod_track_set_attribute(track,IPOD_TRACK_VBR,0);
	}
}

static void ipod_m4a_scan_stbl(ipod_io io,ipod_track_t track,size_t stblEnds)
{
	uint32_t tag;
	size_t ends;
	for (;;) {
		ipod_m4a_atom(io,&tag,&ends);
		if (tag==IPOD_ATOM_STSD)
			ipod_m4a_scan_stsd(io,track,ends);
		ipod_io_seek(io,ends);
		if (ends>=stblEnds) break;
	}
}

static void ipod_m4a_scan_minf(ipod_io io,ipod_track_t track,size_t minfEnds)
{
	uint32_t tag;
	size_t ends;
	for (;;) {
		ipod_m4a_atom(io,&tag,&ends);
		if (tag==IPOD_ATOM_STBL)
			ipod_m4a_scan_stbl(io,track,ends);
		ipod_io_seek(io,ends);
		if (ends>=minfEnds) break;
	}
}

static void ipod_m4a_scan_mdia(ipod_io io,ipod_track_t track,size_t mdiaEnds)
{
	uint32_t tag;
	size_t ends;
	for (;;) {
		ipod_m4a_atom(io,&tag,&ends);
		if (tag==IPOD_ATOM_MINF)
			ipod_m4a_scan_minf(io,track,ends);
		ipod_io_seek(io,ends);
		if (ends>=mdiaEnds) break;
	}
}

static void ipod_m4a_scan_trak(ipod_io io,ipod_track_t track,size_t trakEnds)
{
	uint32_t tag;
	size_t ends;
	for (;;) {
		ipod_m4a_atom(io,&tag,&ends);
		if (tag==IPOD_ATOM_MDIA)
			ipod_m4a_scan_mdia(io,track,ends);
		ipod_io_seek(io,ends);
		if (ends>=trakEnds) break;
	}
}

static void ipod_m4a_scan_moov(ipod_io io,ipod_track_t track,size_t moovEnds)
{
	uint32_t tag;
	size_t ends;
	for (;;) {
		ipod_m4a_atom(io,&tag,&ends);
		if (tag==IPOD_ATOM_MVHD)
			ipod_m4a_scan_mvhd(io,track,ends);
		else if (tag==IPOD_ATOM_UDTA)
			ipod_m4a_scan_udta(io,track,ends);
		else if (tag==IPOD_ATOM_TRAK)
			ipod_m4a_scan_trak(io,track,ends);
		ipod_io_seek(io,ends);
		if (ends>=moovEnds) break;
	}
}

static void ipod_m4a_scan_mdat(ipod_io io,ipod_track_t track,size_t mdatEnds)
{
	g_size += mdatEnds-ipod_io_tell(io);
}

static void ipod_m4a_scan(ipod_io io,ipod_track_t track)
{
	uint32_t tag;
	size_t ends;
	size_t total_length;
	total_length = ipod_io_length(io);
	for (;;) {
		ipod_m4a_atom(io,&tag,&ends);
		if (tag==IPOD_ATOM_MOOV)
			ipod_m4a_scan_moov(io,track,ends);
		if (tag==IPOD_ATOM_MDAT)
			ipod_m4a_scan_mdat(io,track,ends);
		ipod_io_seek(io,ends);
		if (ends>=total_length) break;
	}
	ipod_track_set_attribute(track,IPOD_TRACK_SIZE,total_length);
}

ipod_track_t ipod_track_from_m4a(ipod_t ipod,ipod_io io) {
	ipod_track_t track = ipod_track_add(ipod);
	//printf("ipod_track_from_m4a()\n");
	g_size = 0;
	ipod_m4a_scan(io,track);
	uint32_t bitRate;
	
	bitRate = g_size/(ipod_track_get_attribute(track,IPOD_TRACK_DURATION)/1000.0)/128.0;
	ipod_track_set_attribute(track,IPOD_TRACK_BIT_RATE,bitRate);
	ipod_track_set_text(track,IPOD_FILETYPE,"AAC audio file");
	return track;
}
