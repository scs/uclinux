/*
 * ipod_track_add.c
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
#include <ipod/ipod_io_file.h>
#include <ipod/ipod_constants.h>
#include <ipod/ipod_error.h>
#include <stdio.h>

extern ipod_track_t ipod_track_from_m4a(ipod_t ipod,ipod_io io);
extern ipod_track_t ipod_track_from_mp3(ipod_t ipod,ipod_io io);
//extern ipod_track_t ipod_track_from_wav(ipod_t ipod,ipod_io io);


static ipod_track_t ipod_track_add_from_mp3(ipod_t ipod, const char *filePath)
{
	FILE *f;
	f = fopen(filePath,"rb");
	if (f) {
		ipod_track_t t = NULL;
		ipod_io io = ipod_io_file_new(f);
		t = ipod_track_from_mp3(ipod,io);
		fclose(f);
		if (t) {
			if (!ipod_track_has_text(t,IPOD_TITLE))
				ipod_track_set_text(t,IPOD_TITLE,ipod_file_name_of(filePath));
			ipod_track_upload(t,filePath,NULL,NULL);
		}
		return t;
	}
	ipod_error("ipod_track_add_from_mp3(): Cannot open file %s\n",filePath);
	return NULL;
}

static ipod_track_t ipod_track_add_from_m4a(ipod_t ipod, const char *filePath)
{
	FILE *f;
	f = fopen(filePath,"rb");
	if (f) {
		ipod_track_t t = NULL;
		ipod_io io = ipod_io_file_new(f);
		t = ipod_track_from_m4a(ipod,io);
		fclose(f);
		if (t) {
			if (!ipod_track_has_text(t,IPOD_TITLE))
				ipod_track_set_text(t,IPOD_TITLE,ipod_file_name_of(filePath));
			ipod_track_upload(t,filePath,NULL,NULL);
		}
		return t;
	}
	ipod_error("ipod_track_add_from_m4a(): Cannot open file %s\n",filePath);
	return NULL;
}

static ipod_track_t ipod_track_add_from_wav(ipod_t ipod, const char *filePath)
{
	FILE *f;
	f = fopen(filePath,"rb");
	if (f) {
		ipod_track_t t = NULL;
		ipod_io io = ipod_io_file_new(f);
		//t = ipod_track_from_wav(ipod,io);
		fclose(f);
		if (t) {
			if (!ipod_track_has_text(t,IPOD_TITLE))
				ipod_track_set_text(t,IPOD_TITLE,ipod_file_name_of(filePath));
			ipod_track_upload(t,filePath,NULL,NULL);
		}
		return t;
	}
	ipod_error("ipod_track_add_from_wav(): Cannot open file %s\n",filePath);
	return NULL;
}

ipod_track_t ipod_track_add_from(ipod_t ipod, const char *filePath)
{
	const char *extension = ipod_extension_of(filePath,".mp3");
	if (!strcmp(extension,".mp3"))
		return ipod_track_add_from_mp3(ipod,filePath);
	else if (!strcmp(extension,".m4a"))
		return ipod_track_add_from_m4a(ipod,filePath);
	else if (!strcmp(extension,".wav"))
		return ipod_track_add_from_wav(ipod,filePath);
	else {
		ipod_error("ipod_track_add_from(): Unrecognized file extension for %s\n",filePath);
		return NULL;
	}
}

