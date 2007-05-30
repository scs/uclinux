/*
 * ipod_atom_mhit.c
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

#include <ipod/ipod_error.h>
#include <ipod/ipod_constants.h>
#include <ipod/ipod_memory.h>
#include <ipod/ipod_string.h>
#include "ipod_atom_mhit.h"
#include "ipod_private_constants.h"

static void ipod_atom_init_mhit(uint32_t version,void *data)
{
	if (data) {
		ipod_atom_mhit mhit = (ipod_atom_mhit)data;
		mhit->children = ipod_atom_list_new();
		mhit->trackID = 0;
		mhit->visible = 1;
		mhit->fileType = 0;
		mhit->vbr = 0;
		mhit->compilation = 0;
		mhit->rating = 0;
		mhit->lastPlayedTime = 0;
		mhit->size = 0;
		mhit->duration = 0;
		mhit->trackNumber = 0;
		mhit->trackCount = 0;
		mhit->year = 0;
		mhit->bitRate = 0;
		mhit->unk8 = 0;
		mhit->sampleRate = 0;
		mhit->volume = 0;
		mhit->startTime = 0;
		mhit->endTime = 0;
		mhit->soundCheck = 0;
		mhit->playCount = 0;
		mhit->playCount2 = 0;
		mhit->addedTime = 0;
		mhit->discNumber = 0;
		mhit->discCount = 0;
		mhit->userID = 0;
		mhit->lastModificationTime = 0;
		mhit->bookmarkTime = 0;
		mhit->dbidlo = 0;
		mhit->dbidhi = 0;
		mhit->checked = 0;
		mhit->appRating = 0;
		mhit->BPM = 0;
		mhit->artworkCount = 0;
		mhit->unk9 = 0xffff;
		mhit->artworkSize = 0;
		mhit->unk11 = 0;
		mhit->sampleRate2 = 0;
		mhit->unk13= 0;
		mhit->unk14 = 0x0000000c;
		mhit->unk15 = 0;
		mhit->unk16 = 0;
		mhit->unk17 = 0;
		mhit->unk18 = 0;
		mhit->unk19 = 2;
		mhit->dbid2lo = 0;
		mhit->dbid2hi = 0;
		mhit->unk20 = 0x00010000;
		mhit->unk21 = 0;
		mhit->unk22 = 0;
		mhit->sampleCount = 0;
		mhit->unk24 = 0;
		mhit->unk25 = 0;
		mhit->unk26 = 0;
		mhit->unk27 = 0;
		mhit->unk28 = 0;
		mhit->unk29 = 0;
		mhit->unk30 = 0;
		mhit->unk31 = 0;
		mhit->unk32 = 0;
		mhit->unk33 = 0;
		mhit->unk34 = 0;
		mhit->unk35 = 0;
		mhit->unk36 = 0;
	}
}

static void ipod_atom_free_mhit(void *data)
{
	if (data) {
		ipod_atom_mhit mhit = (ipod_atom_mhit)data;
		ipod_atom_list_remove_and_free_all(mhit->children);
		ipod_atom_list_free(mhit->children);
		ipod_memory_free(data);
	}
}

static void ipod_atom_read_mhit(ipod_io io,uint32_t version,void *data)
{
	if (data) {
		size_t h1,h2,count,i;
		ipod_atom_mhit mhit = (ipod_atom_mhit)data;
		ipod_io_get_simple_header(io,&h1,&h2);
		count = ipod_io_getul(io);
		mhit->trackID = ipod_io_getul(io);
		mhit->visible = ipod_io_getul(io);
		mhit->fileType = ipod_io_getul(io);
		mhit->vbr = ipod_io_getuw(io);
		mhit->compilation = ipod_io_getub(io);
		mhit->rating = ipod_io_getub(io);
		mhit->lastPlayedTime = ipod_io_getul(io);
		mhit->size = ipod_io_getul(io);
		mhit->duration = ipod_io_getul(io);
		mhit->trackNumber = ipod_io_getul(io);
		mhit->trackCount = ipod_io_getul(io);
		mhit->year = ipod_io_getul(io);
		mhit->bitRate = ipod_io_getul(io);
		mhit->unk8 = ipod_io_getuw(io);
		mhit->sampleRate = ipod_io_getuw(io);
		mhit->volume = ipod_io_getul(io);
		mhit->startTime = ipod_io_getul(io);
		mhit->endTime = ipod_io_getul(io);
		mhit->soundCheck = ipod_io_getul(io);
		mhit->playCount = ipod_io_getul(io);
		mhit->playCount2 = ipod_io_getul(io);
		mhit->addedTime = ipod_io_getul(io);
		mhit->discNumber = ipod_io_getul(io);
		mhit->discCount = ipod_io_getul(io);
		mhit->userID = ipod_io_getul(io);
		mhit->lastModificationTime = ipod_io_getul(io);
		mhit->bookmarkTime = ipod_io_getul(io);
		mhit->dbidlo = ipod_io_getul(io);
		mhit->dbidhi = ipod_io_getul(io);
		mhit->checked = ipod_io_getub(io);
		mhit->appRating = ipod_io_getub(io);
		mhit->BPM = ipod_io_getuw(io);
		mhit->artworkCount = ipod_io_getuw(io);
		mhit->unk9 = ipod_io_getuw(io);
		mhit->artworkSize = ipod_io_getul(io);
		mhit->unk11 = ipod_io_getul(io);
		mhit->sampleRate2 = ipod_io_getf(io);
		mhit->unk13= ipod_io_getul(io);
		mhit->unk14 = ipod_io_getul(io);
		mhit->unk15 = ipod_io_getul(io);
		mhit->unk16 = ipod_io_getul(io);
		if (version >= IPOD_VERSION4_8) {
			mhit->unk17 = ipod_io_getul(io);
			mhit->unk18 = ipod_io_getul(io);
			mhit->unk19 = ipod_io_getul(io);
			mhit->dbid2lo = ipod_io_getul(io);
			mhit->dbid2hi = ipod_io_getul(io);
			mhit->unk20 = ipod_io_getul(io);
			mhit->unk21 = ipod_io_getul(io);
			mhit->unk22 = ipod_io_getul(io);
			mhit->sampleCount = ipod_io_getul(io);
			mhit->unk24 = ipod_io_getul(io);
			mhit->unk25 = ipod_io_getul(io);
			mhit->unk26 = ipod_io_getul(io);
			mhit->unk27 = ipod_io_getul(io);
			mhit->unk28 = ipod_io_getul(io);
			mhit->unk29 = ipod_io_getul(io);
			mhit->unk30 = ipod_io_getul(io);
			mhit->unk31 = ipod_io_getul(io);
			mhit->unk32 = ipod_io_getul(io);
			mhit->unk33 = ipod_io_getul(io);
			mhit->unk34 = ipod_io_getul(io);
			mhit->unk35 = ipod_io_getul(io);
			mhit->unk36 = ipod_io_getul(io);
		}
		ipod_io_seek(io,h1);
		ipod_atom_list_remove_and_free_all(mhit->children);
		for (i=0;i<count;i++) {
			ipod_atom atom = ipod_atom_read_next(io,version);
			if (atom)
				ipod_atom_list_append(mhit->children,atom);
		}
		ipod_io_seek(io,h2);
	}		
}

static void ipod_atom_prepare_to_write_mhit(ipod_atom root,uint32_t version,void *data)
{
	if (data) {
		ipod_atom_mhit mhit = (ipod_atom_mhit)data;
		mhit->playCount2 = mhit->playCount;
		mhit->sampleRate2 = (float)mhit->sampleRate;
		mhit->dbid2lo = mhit->dbidlo;
		mhit->dbid2hi = mhit->dbidhi;
		ipod_atom_list_prepare_to_write(mhit->children,root,version);
	}
}

static void ipod_atom_write_mhit(ipod_io io, uint32_t version,void *data)
{
	if (data) {
		size_t mark;
		unsigned int i;
		int headerSize;
		ipod_atom_mhit mhit = (ipod_atom_mhit)data;
	
		headerSize = (version>=IPOD_VERSION4_8)?0xf4:0x9c;
		mark = ipod_io_put_simple_header(io,IPOD_ATOM_MHIT,headerSize);
		ipod_io_putul(io,ipod_atom_list_length(mhit->children));
		ipod_io_putul(io,mhit->trackID);
		ipod_io_putul(io,mhit->visible);
		ipod_io_putul(io,mhit->fileType);
		ipod_io_putuw(io,mhit->vbr);
		ipod_io_putub(io,mhit->compilation);
		ipod_io_putub(io,mhit->rating);
		ipod_io_putul(io,mhit->lastPlayedTime);
		ipod_io_putul(io,mhit->size);
		ipod_io_putul(io,mhit->duration);
		ipod_io_putul(io,mhit->trackNumber);
		ipod_io_putul(io,mhit->trackCount);
		ipod_io_putul(io,mhit->year);
		ipod_io_putul(io,mhit->bitRate);
		ipod_io_putuw(io,mhit->unk8);
		ipod_io_putuw(io,mhit->sampleRate);
		ipod_io_putul(io,mhit->volume);
		ipod_io_putul(io,mhit->startTime);
		ipod_io_putul(io,mhit->endTime);
		ipod_io_putul(io,mhit->soundCheck);
		ipod_io_putul(io,mhit->playCount);
		ipod_io_putul(io,mhit->playCount2);
		ipod_io_putul(io,mhit->addedTime);
		ipod_io_putul(io,mhit->discNumber);
		ipod_io_putul(io,mhit->discCount);
		ipod_io_putul(io,mhit->userID);
		ipod_io_putul(io,mhit->lastModificationTime);
		ipod_io_putul(io,mhit->bookmarkTime);
		ipod_io_putul(io,mhit->dbidlo);
		ipod_io_putul(io,mhit->dbidhi);
		ipod_io_putub(io,mhit->checked);
		ipod_io_putub(io,mhit->appRating);
		ipod_io_putuw(io,mhit->BPM);
		ipod_io_putuw(io,mhit->artworkCount);
		ipod_io_putuw(io,mhit->unk9);
		ipod_io_putul(io,mhit->artworkSize);
		ipod_io_putul(io,mhit->unk11);
		ipod_io_putf(io,mhit->sampleRate2);
		ipod_io_putul(io,mhit->unk13);
		ipod_io_putul(io,mhit->unk14);
		ipod_io_putul(io,mhit->unk15);
		ipod_io_putul(io,mhit->unk16);
		if (version>=IPOD_VERSION4_8) {
			ipod_io_putul(io,mhit->unk17);
			ipod_io_putul(io,mhit->unk18);
			ipod_io_putul(io,mhit->unk19);
			ipod_io_putul(io,mhit->dbid2lo);
			ipod_io_putul(io,mhit->dbid2hi);
			ipod_io_putul(io,mhit->unk20);
			ipod_io_putul(io,mhit->unk21);
			ipod_io_putul(io,mhit->unk22);
			ipod_io_putul(io,mhit->sampleCount);
			ipod_io_putul(io,mhit->unk24);
			ipod_io_putul(io,mhit->unk25);
			ipod_io_putul(io,mhit->unk26);
			ipod_io_putul(io,mhit->unk27);
			ipod_io_putul(io,mhit->unk28);
			ipod_io_putul(io,mhit->unk29);
			ipod_io_putul(io,mhit->unk30);
			ipod_io_putul(io,mhit->unk31);
			ipod_io_putul(io,mhit->unk32);
			ipod_io_putul(io,mhit->unk33);
			ipod_io_putul(io,mhit->unk34);
			ipod_io_putul(io,mhit->unk35);
			ipod_io_putul(io,mhit->unk36);
		}
		ipod_io_put_pad(io,mark,headerSize);
		for (i=0;i<ipod_atom_list_length(mhit->children);i++) {
			ipod_atom atom = ipod_atom_list_get(mhit->children,i);
			if (atom)
				ipod_atom_write(atom,io,version);
		}
		ipod_io_backpatch(io,mark);
	}
}

static void *ipod_atom_copy_mhit(void *data) {
	if (data) {
		ipod_atom_mhit mhit = (ipod_atom_mhit)data;
		ipod_atom_mhit copy = (ipod_atom_mhit)ipod_memory_alloc(sizeof(ipod_atom_mhit_struct));
		copy->trackID = mhit->trackID;
		copy->visible = mhit->visible;
		copy->fileType = mhit->fileType;
		copy->vbr = mhit->vbr;
		copy->compilation = mhit->compilation;
		copy->rating = mhit->rating;
		copy->lastPlayedTime = mhit->lastPlayedTime;
		copy->size = mhit->size;
		copy->duration = mhit->duration;
		copy->trackNumber = mhit->trackNumber;
		copy->trackCount = mhit->trackCount;
		copy->year = mhit->year;
		copy->bitRate = mhit->bitRate;
		copy->unk8 = mhit->unk8;
		copy->sampleRate = mhit->sampleRate;
		copy->volume = mhit->volume;
		copy->startTime = mhit->startTime;
		copy->endTime = mhit->endTime;
		copy->soundCheck = mhit->soundCheck;
		copy->playCount = mhit->playCount;
		copy->playCount2 = mhit->playCount2;
		copy->addedTime = mhit->addedTime;
		copy->discNumber = mhit->discNumber;
		copy->discCount = mhit->discCount;
		copy->userID = mhit->userID;
		copy->lastModificationTime = mhit->lastModificationTime;
		copy->bookmarkTime = mhit->bookmarkTime;
		copy->dbidlo = mhit->dbidlo;
		copy->dbidhi = mhit->dbidhi;
		copy->checked = mhit->checked;
		copy->appRating = mhit->appRating;
		copy->BPM = mhit->BPM;
		copy->artworkCount = mhit->artworkCount;
		copy->unk9 = mhit->unk9;
		copy->artworkSize = mhit->artworkSize;
		copy->unk11 = mhit->unk11;
		copy->sampleRate2 = mhit->sampleRate2;
		copy->unk13 = mhit->unk13;
		copy->unk14 = mhit->unk14;
		copy->unk15 = mhit->unk15;
		copy->unk16 = mhit->unk16;
		copy->unk17 = mhit->unk17;
		copy->unk18 = mhit->unk18;
		copy->unk19 = mhit->unk19;
		copy->dbid2lo = mhit->dbid2lo;
		copy->dbid2hi = mhit->dbid2hi;
		copy->unk20 = mhit->unk20;
		copy->unk21 = mhit->unk21;
		copy->unk22 = mhit->unk22;
		copy->sampleCount = mhit->sampleCount;
		copy->unk24 = mhit->unk24;
		copy->unk25 = mhit->unk25;
		copy->unk26 = mhit->unk26;
		copy->unk27 = mhit->unk27;
		copy->unk28 = mhit->unk28;
		copy->unk29 = mhit->unk29;
		copy->unk30 = mhit->unk30;
		copy->unk31 = mhit->unk31;
		copy->unk32 = mhit->unk32;
		copy->unk33 = mhit->unk33;
		copy->unk34 = mhit->unk34;
		copy->unk35 = mhit->unk35;
		copy->unk36 = mhit->unk36;
		copy->children = ipod_atom_list_copy(mhit->children);
		return (void *)copy;
	}
	return NULL;
}

#ifdef PLIST
plist_item *ipod_atom_get_plist_mhit(void *data)
{
	plist_item *p = plist_item_new_dict();
	if (data) {
		ipod_atom_mhit mhit = (ipod_atom_mhit)data;
		plist_item_dict_at_key_put(p,"tag",plist_item_from_string("mhit"));
		plist_item_dict_at_key_put(p,"trackID",plist_item_from_integer(mhit->trackID));
		plist_item_dict_at_key_put(p,"visible",plist_item_from_integer(mhit->visible));
		plist_item_dict_at_key_put(p,"fileType",plist_item_from_integer(mhit->fileType));
		plist_item_dict_at_key_put(p,"vbr",plist_item_from_integer(mhit->vbr));
		plist_item_dict_at_key_put(p,"compilation",plist_item_from_integer(mhit->compilation));
		plist_item_dict_at_key_put(p,"rating",plist_item_from_integer(mhit->rating));
		plist_item_dict_at_key_put(p,"lastPlayedTime",plist_item_from_integer(mhit->lastPlayedTime));
		plist_item_dict_at_key_put(p,"size",plist_item_from_integer(mhit->size));
		plist_item_dict_at_key_put(p,"duration",plist_item_from_integer(mhit->duration));
		plist_item_dict_at_key_put(p,"trackNumber",plist_item_from_integer(mhit->trackNumber));
		plist_item_dict_at_key_put(p,"trackCount",plist_item_from_integer(mhit->trackCount));
		plist_item_dict_at_key_put(p,"year",plist_item_from_integer(mhit->year));
		plist_item_dict_at_key_put(p,"bitRate",plist_item_from_integer(mhit->bitRate));
		plist_item_dict_at_key_put(p,"unk8",plist_item_from_integer(mhit->unk8));
		plist_item_dict_at_key_put(p,"sampleRate",plist_item_from_integer(mhit->sampleRate));
		plist_item_dict_at_key_put(p,"volume",plist_item_from_integer(mhit->volume));
		plist_item_dict_at_key_put(p,"startTime",plist_item_from_integer(mhit->startTime));
		plist_item_dict_at_key_put(p,"endTime",plist_item_from_integer(mhit->endTime));
		plist_item_dict_at_key_put(p,"soundCheck",plist_item_from_integer(mhit->soundCheck));
		plist_item_dict_at_key_put(p,"playCount",plist_item_from_integer(mhit->playCount));
		plist_item_dict_at_key_put(p,"playCount2",plist_item_from_integer(mhit->playCount2));
		plist_item_dict_at_key_put(p,"addedTime",plist_item_from_integer(mhit->addedTime));
		plist_item_dict_at_key_put(p,"discNumber",plist_item_from_integer(mhit->discNumber));
		plist_item_dict_at_key_put(p,"discCount",plist_item_from_integer(mhit->discCount));
		plist_item_dict_at_key_put(p,"userID",plist_item_from_integer(mhit->userID));
		plist_item_dict_at_key_put(p,"lastModificationTime",plist_item_from_integer(mhit->lastModificationTime));
		plist_item_dict_at_key_put(p,"bookmarkTime",plist_item_from_integer(mhit->bookmarkTime));
		plist_item_dict_at_key_put(p,"dbidlo",plist_item_from_integer(mhit->dbidlo));
		plist_item_dict_at_key_put(p,"dbidhi",plist_item_from_integer(mhit->dbidhi));
		plist_item_dict_at_key_put(p,"checked",plist_item_from_integer(mhit->checked));
		plist_item_dict_at_key_put(p,"appRating",plist_item_from_integer(mhit->appRating));
		plist_item_dict_at_key_put(p,"BPM",plist_item_from_integer(mhit->BPM));
		plist_item_dict_at_key_put(p,"artworkCount",plist_item_from_integer(mhit->artworkCount));
		plist_item_dict_at_key_put(p,"unk9",plist_item_from_integer(mhit->unk9));
		plist_item_dict_at_key_put(p,"artworkSize",plist_item_from_integer(mhit->artworkSize));
		plist_item_dict_at_key_put(p,"unk11",plist_item_from_integer(mhit->unk11));
		plist_item_dict_at_key_put(p,"sampleRate2",plist_item_from_real(mhit->sampleRate2));
		plist_item_dict_at_key_put(p,"unk13",plist_item_from_integer(mhit->unk13));
		plist_item_dict_at_key_put(p,"unk14",plist_item_from_integer(mhit->unk14));
		plist_item_dict_at_key_put(p,"unk15",plist_item_from_integer(mhit->unk15));
		plist_item_dict_at_key_put(p,"unk16",plist_item_from_integer(mhit->unk16));
		plist_item_dict_at_key_put(p,"unk17",plist_item_from_integer(mhit->unk17));
		plist_item_dict_at_key_put(p,"unk18",plist_item_from_integer(mhit->unk18));
		plist_item_dict_at_key_put(p,"unk19",plist_item_from_integer(mhit->unk19));
		plist_item_dict_at_key_put(p,"dbid2lo",plist_item_from_integer(mhit->dbid2lo));
		plist_item_dict_at_key_put(p,"dbid2hi",plist_item_from_integer(mhit->dbid2hi));
		plist_item_dict_at_key_put(p,"unk20",plist_item_from_integer(mhit->unk20));
		plist_item_dict_at_key_put(p,"unk21",plist_item_from_integer(mhit->unk21));
		plist_item_dict_at_key_put(p,"unk22",plist_item_from_integer(mhit->unk22));
		plist_item_dict_at_key_put(p,"sampleCount",plist_item_from_integer(mhit->sampleCount));
		plist_item_dict_at_key_put(p,"unk24",plist_item_from_integer(mhit->unk24));
		plist_item_dict_at_key_put(p,"unk25",plist_item_from_integer(mhit->unk25));
		plist_item_dict_at_key_put(p,"unk26",plist_item_from_integer(mhit->unk26));
		plist_item_dict_at_key_put(p,"unk27",plist_item_from_integer(mhit->unk27));
		plist_item_dict_at_key_put(p,"unk28",plist_item_from_integer(mhit->unk28));
		plist_item_dict_at_key_put(p,"unk29",plist_item_from_integer(mhit->unk29));
		plist_item_dict_at_key_put(p,"unk30",plist_item_from_integer(mhit->unk30));
		plist_item_dict_at_key_put(p,"unk31",plist_item_from_integer(mhit->unk31));
		plist_item_dict_at_key_put(p,"unk32",plist_item_from_integer(mhit->unk32));
		plist_item_dict_at_key_put(p,"unk33",plist_item_from_integer(mhit->unk33));
		plist_item_dict_at_key_put(p,"unk34",plist_item_from_integer(mhit->unk34));
		plist_item_dict_at_key_put(p,"unk35",plist_item_from_integer(mhit->unk35));
		plist_item_dict_at_key_put(p,"unk36",plist_item_from_integer(mhit->unk36));
		plist_item_dict_at_key_put(p,"children",ipod_atom_list_get_plist(mhit->children));
	}
	return p;
}

void ipod_atom_set_plist_mhit(plist_item *plist,void *data)
{
}
#endif

ipod_atom ipod_atom_new_mhit(void) {
	ipod_atom atom = ipod_atom_new();
	if (atom) {
		atom->tag = IPOD_ATOM_MHIT;
		atom->init = ipod_atom_init_mhit;
		atom->free = ipod_atom_free_mhit;
		atom->read = ipod_atom_read_mhit;
		atom->prepare_to_write = ipod_atom_prepare_to_write_mhit;
		atom->write = ipod_atom_write_mhit;
		atom->copy = ipod_atom_copy_mhit;
#ifdef PLIST
		atom->get_plist = ipod_atom_get_plist_mhit;
		atom->set_plist = ipod_atom_set_plist_mhit;
#endif
		atom->data = (void *)ipod_memory_alloc(sizeof(ipod_atom_mhit_struct));
	}
	return atom;
}

static ipod_atom ipod_atom_mhit_string_atom(ipod_atom atom,int tag)
{
	if (atom && atom->data) {
		int i;
		ipod_atom_mhit mhit = (ipod_atom_mhit)atom->data;
		for (i=0;i<ipod_atom_list_length(mhit->children);i++) {
			ipod_atom mhod_atom = ipod_atom_list_get(mhit->children,i);
			if (atom && atom->data) {
				ipod_atom_mhod mhod = (ipod_atom_mhod)mhod_atom->data;
				if (mhod->type==tag)
					return mhod_atom;
			}
		}
	}
	return NULL;
}

static ipod_atom_mhod_string_struct *ipod_atom_mhit_string_struct(ipod_atom atom, int tag)
{
	atom = ipod_atom_mhit_string_atom(atom,tag);
	if (atom) {
		ipod_atom_mhod mhod = (ipod_atom_mhod)atom->data;
		return &mhod->data.ipod_atom_mhod_string;
	}
	return NULL;
}

char *ipod_atom_mhit_get_text_utf8(ipod_atom atom, int tag, char *s)
{
	ipod_atom mhod_atom = ipod_atom_mhit_string_atom(atom,tag);
	if (s) s = ipod_string_zero(s);
	else s = ipod_string_new();
	if (mhod_atom)
		if (tag>=IPOD_TITLE && tag<=IPOD_DESCRIPTION)
			return ipod_atom_mhod_string_get(mhod_atom,s);
		else if (tag==IPOD_ENCLOSUREURL || tag==IPOD_RSSURL)
			return ipod_atom_mhod_url_get(mhod_atom,s);
		else
			ipod_error("ipod_atom_mhit_get_text_utf8(): Non-string type %d\n",tag);
	return s;
}

void ipod_atom_mhit_set_text_utf8(ipod_atom atom, int tag, const char *s)
{
	ipod_atom mhod_atom = ipod_atom_mhit_string_atom(atom,tag);
	if (mhod_atom) {
		//printf("ipod_atom_mhit_set_text_utf8(): item found\n");
		if (tag>=IPOD_TITLE && tag<=IPOD_DESCRIPTION)
			ipod_atom_mhod_string_set(mhod_atom,s);
		else if (tag==IPOD_ENCLOSUREURL || tag==IPOD_RSSURL)
			ipod_atom_mhod_url_set(mhod_atom,s);
		else
			ipod_error("ipod_atom_mhit_set_text_utf8(): Non-string type %d\n",tag);
	} else {
		if (tag>=IPOD_TITLE && tag<=IPOD_DESCRIPTION)
			mhod_atom = ipod_atom_new_mhod_string(tag,s);
		else if (tag==IPOD_ENCLOSUREURL || tag==IPOD_RSSURL)
			mhod_atom = ipod_atom_new_mhod_url(tag,s);
		else
			ipod_error("ipod_atom_mhit_set_text_utf8(): Non-string type %d\n",tag);
		if (mhod_atom) {
			ipod_atom_mhit mhit = (ipod_atom_mhit)atom->data;
			ipod_atom_list_append(mhit->children,mhod_atom);
		}
	}
}

int ipod_atom_mhit_has_text(ipod_atom atom, int tag)
{
	return ipod_atom_mhit_string_atom(atom,tag)!=NULL;
}

uint32_t ipod_atom_mhit_get_attribute(ipod_atom atom, int tag)
{
	if (atom && atom->data) {
		ipod_atom_mhit mhit = (ipod_atom_mhit)atom->data;
		switch (tag) {
			case IPOD_TRACK_ID: return mhit->trackID;
			case IPOD_TRACK_VISIBLE: return mhit->visible;
			case IPOD_TRACK_FILETYPE: return mhit->fileType;
			case IPOD_TRACK_VBR: return mhit->vbr;
			case IPOD_TRACK_COMPILATION: return mhit->compilation;
			case IPOD_TRACK_RATING: return mhit->rating;
			case IPOD_TRACK_LAST_PLAYED_TIME: return mhit->lastPlayedTime;
			case IPOD_TRACK_SIZE: return mhit->size;
			case IPOD_TRACK_DURATION: return mhit->duration;
			case IPOD_TRACK_TRACK_NUMBER: return mhit->trackNumber;
			case IPOD_TRACK_TRACK_COUNT: return mhit->trackCount;
			case IPOD_TRACK_YEAR: return mhit->year;
			case IPOD_TRACK_BIT_RATE: return mhit->bitRate;
			case IPOD_TRACK_SAMPLE_RATE: return mhit->sampleRate;
			case IPOD_TRACK_VOLUME: return mhit->volume;
			case IPOD_TRACK_START_TIME: return mhit->startTime;
			case IPOD_TRACK_END_TIME: return mhit->endTime;
			case IPOD_TRACK_SOUND_CHECK: return mhit->soundCheck;
			case IPOD_TRACK_PLAY_COUNT: return mhit->playCount;
			case IPOD_TRACK_ADDED_TIME: return mhit->addedTime;
			case IPOD_TRACK_DISC_NUMBER: return mhit->discNumber;
			case IPOD_TRACK_DISC_COUNT: return mhit->discCount;
			case IPOD_TRACK_USER_ID: return mhit->userID;
			case IPOD_TRACK_LAST_MODIFICATION_TIME: return mhit->lastModificationTime;
			case IPOD_TRACK_BOOKMARK_TIME: return mhit->bookmarkTime;
			case IPOD_TRACK_DBIDLO: return mhit->dbidlo;
			case IPOD_TRACK_DBIDHI: return mhit->dbidhi;
			case IPOD_TRACK_CHECKED: return mhit->checked;
			case IPOD_TRACK_APPLICATION_RATING: return mhit->appRating;
			case IPOD_TRACK_BEATS_PER_MINUTE: return mhit->BPM;
			case IPOD_TRACK_ARTWORK_COUNT: return mhit->artworkCount;
			case IPOD_TRACK_ARTWORK_SIZE: return mhit->artworkSize;
			case IPOD_TRACK_DBID2LO: return mhit->dbid2lo;
			case IPOD_TRACK_DBID2HI: return mhit->dbid2hi;
			case IPOD_TRACK_SAMPLE_COUNT: return mhit->sampleCount;
			
			case IPOD_TRACK_LAST_PLAYED_TIME_NATIVE: return mhit->lastPlayedTime-IPOD_MAC_EPOCH_OFFSET;
			case IPOD_TRACK_ADDED_TIME_NATIVE: return mhit->addedTime-IPOD_MAC_EPOCH_OFFSET;
			case IPOD_TRACK_LAST_MODIFICATION_TIME_NATIVE: return mhit->lastModificationTime-IPOD_MAC_EPOCH_OFFSET;

			default:
				ipod_error("ipod_atom_mhit_get_attribute(): Invalid tag %d\n",tag);
		}
			
	} else {
		ipod_error("ipod_atom_mhit_get_attribute(): Invalid track atom\n");
	}
	return 0;
}

void ipod_atom_mhit_set_attribute(ipod_atom atom, int tag, uint32_t value)
{
	if (atom && atom->data) {
		ipod_atom_mhit mhit = (ipod_atom_mhit)atom->data;
		switch (tag) {
			case IPOD_TRACK_ID: mhit->trackID = value; break;
			case IPOD_TRACK_VISIBLE: mhit->visible = value; break;
			case IPOD_TRACK_FILETYPE: mhit->fileType = value; break;
			case IPOD_TRACK_VBR: mhit->vbr = value; break;
			case IPOD_TRACK_COMPILATION: mhit->compilation = value; break;
			case IPOD_TRACK_RATING: mhit->rating = value; break;
			case IPOD_TRACK_LAST_PLAYED_TIME: mhit->lastPlayedTime = value; break;
			case IPOD_TRACK_SIZE: mhit->size = value; break;
			case IPOD_TRACK_DURATION: mhit->duration = value; break;
			case IPOD_TRACK_TRACK_NUMBER: mhit->trackNumber = value; break;
			case IPOD_TRACK_TRACK_COUNT: mhit->trackCount = value; break;
			case IPOD_TRACK_YEAR: mhit->year = value; break;
			case IPOD_TRACK_BIT_RATE: mhit->bitRate = value; break;
			case IPOD_TRACK_SAMPLE_RATE: mhit->sampleRate = value; break;
			case IPOD_TRACK_VOLUME: mhit->volume = value; break;
			case IPOD_TRACK_START_TIME: mhit->startTime = value; break;
			case IPOD_TRACK_END_TIME: mhit->endTime = value; break;
			case IPOD_TRACK_SOUND_CHECK: mhit->soundCheck = value; break;
			case IPOD_TRACK_PLAY_COUNT: mhit->playCount = value; break;
			case IPOD_TRACK_ADDED_TIME: mhit->addedTime = value; break;
			case IPOD_TRACK_DISC_NUMBER: mhit->discNumber = value; break;
			case IPOD_TRACK_DISC_COUNT: mhit->discCount = value; break;
			case IPOD_TRACK_USER_ID: mhit->userID = value; break;
			case IPOD_TRACK_LAST_MODIFICATION_TIME: mhit->lastModificationTime = value; break;
			case IPOD_TRACK_BOOKMARK_TIME: mhit->bookmarkTime = value; break;
			case IPOD_TRACK_DBIDLO: mhit->dbidlo = value; break;
			case IPOD_TRACK_DBIDHI: mhit->dbidhi = value; break;
			case IPOD_TRACK_CHECKED: mhit->checked = value; break;
			case IPOD_TRACK_APPLICATION_RATING: mhit->appRating = value; break;
			case IPOD_TRACK_BEATS_PER_MINUTE: mhit->BPM = value; break;
			case IPOD_TRACK_ARTWORK_COUNT: mhit->artworkCount = value; break;
			case IPOD_TRACK_ARTWORK_SIZE: mhit->artworkSize = value; break;
			case IPOD_TRACK_DBID2LO: mhit->dbid2lo = value; break;
			case IPOD_TRACK_DBID2HI: mhit->dbid2hi = value; break;
			case IPOD_TRACK_SAMPLE_COUNT: mhit->sampleCount = value; break;
			
			case IPOD_TRACK_LAST_PLAYED_TIME_NATIVE: mhit->lastPlayedTime = value+IPOD_MAC_EPOCH_OFFSET; break;
			case IPOD_TRACK_ADDED_TIME_NATIVE: mhit->addedTime = value+IPOD_MAC_EPOCH_OFFSET; break;
			case IPOD_TRACK_LAST_MODIFICATION_TIME_NATIVE: mhit->lastModificationTime = value+IPOD_MAC_EPOCH_OFFSET; break;
default:
				ipod_error("ipod_atom_mhit_set_attribute(): Invalid tag %d\n",tag);
		}
			
	} else {
		ipod_error("ipod_atom_mhit_set_attribute(): Invalid track atom\n");
	}
}

ipod_atom_mhod_string_struct *ipod_atom_mhit_title_struct(ipod_atom atom)
{
	return ipod_atom_mhit_string_struct(atom,IPOD_TITLE);
}

ipod_atom_mhod_string_struct *ipod_atom_mhit_album_struct(ipod_atom atom)
{
	return ipod_atom_mhit_string_struct(atom,IPOD_ALBUM);
}

ipod_atom_mhod_string_struct *ipod_atom_mhit_artist_struct(ipod_atom atom)
{
	return ipod_atom_mhit_string_struct(atom,IPOD_ARTIST);
}

ipod_atom_mhod_string_struct *ipod_atom_mhit_genre_struct(ipod_atom atom)
{
	return ipod_atom_mhit_string_struct(atom,IPOD_GENRE);
}

ipod_atom_mhod_string_struct *ipod_atom_mhit_composer_struct(ipod_atom atom)
{
	return ipod_atom_mhit_string_struct(atom,IPOD_COMPOSER);
}

