/*
 * ipod_atom_mhyp.c
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
#include "ipod_atom_mhyp.h"
#include "ipod_atom_mhip.h"
#include "ipod_atom_mhod.h"
#include "ipod_atom_mhsd.h"
#include "ipod_atom_mhbd.h"
#include "ipod_atom_mhlt.h"
#include "ipod_private_constants.h"

static void ipod_atom_init_mhyp(uint32_t version,void *data)
{
	if (data) {
		ipod_atom_mhyp mhyp = (ipod_atom_mhyp)data;
		mhyp->hidden = 0;
		mhyp->timeStamp = 0;
		mhyp->playlistIDLo = 0;
		mhyp->playlistIDHi = 0;
		mhyp->stringMhodCount = 1;
		mhyp->libraryMhodCount = 0;
		mhyp->sortOrder = 0;
		mhyp->mhip_children = ipod_atom_list_new();
		mhyp->mhod_children = ipod_atom_list_new();
	}
}

static void ipod_atom_free_mhyp(void *data)
{
	if (data) {
		ipod_atom_mhyp mhyp = (ipod_atom_mhyp)data;
		ipod_atom_list_remove_and_free_all(mhyp->mhod_children);
		ipod_atom_list_free(mhyp->mhod_children);
		ipod_atom_list_remove_and_free_all(mhyp->mhip_children);
		ipod_atom_list_free(mhyp->mhip_children);
		ipod_memory_free(data);
	}
}

static void ipod_atom_read_mhyp(ipod_io io,uint32_t version,void *data)
{
	if (data) {
		size_t h1,h2,mhod_count,mhip_count,i;
		ipod_atom_mhyp mhyp = (ipod_atom_mhyp)data;
		ipod_io_get_simple_header(io,&h1,&h2);
		mhod_count = ipod_io_getul(io);
		mhip_count = ipod_io_getul(io);
		mhyp->hidden = ipod_io_getul(io);
		mhyp->timeStamp = ipod_io_getul(io);
		mhyp->playlistIDLo = ipod_io_getul(io);
		mhyp->playlistIDHi = ipod_io_getul(io);
		mhyp->stringMhodCount = ipod_io_getul(io);
		mhyp->libraryMhodCount = ipod_io_getul(io);
		mhyp->sortOrder = ipod_io_getul(io);
		ipod_io_seek(io,h1);
		//printf("reading %d mhod_children\n",mhod_count);
		ipod_atom_list_read(mhyp->mhod_children,mhod_count,io,version);
		//printf("reading %d mhip_children\n",mhip_count);
		ipod_atom_list_remove_and_free_all(mhyp->mhip_children);
		for (i=0;i<mhip_count;i++) {
			ipod_atom atom = ipod_atom_read_next(io,version);
			//printf("atom tag %s\n",ipod_tag_str(atom->tag));
			if (atom)
				ipod_atom_list_append(mhyp->mhip_children,atom);
			{
				uint32_t tag;
				size_t mark = ipod_io_tell(io);
				tag = ipod_io_get4cc(io);
				ipod_io_seek(io,mark);
				if (tag==IPOD_ATOM_MHOD) {
					//static int junk_counter;
					ipod_atom junk = ipod_atom_read_next(io,version);
					//if (junk)
					//	ipod_atom_free(junk);
					//ipod_error("ipod_atom_read_mhyp(): junk %d\n",++junk_counter);
				}
			}
		}
		ipod_io_seek(io,h2);
	}		
}

static ipod_atom_list ipod_tracks(ipod_atom root)
{
	if (root) {
		ipod_atom mhsd, mhlt;
		ipod_atom_list mhits;
		mhsd = ipod_atom_mhbd_tracks(root);
		mhlt = ipod_atom_mhsd_tracks(mhsd);
		return ipod_atom_mhlt_tracks(mhlt);
	}
}

//
// make sure all tracks are represented in the master playlist
//
static void ipod_atom_mhyp_check_master_playlist(ipod_atom root,uint32_t version,ipod_atom_mhyp mhyp)
{
	unsigned int i;
	ipod_atom_list tracks = ipod_tracks(root);
	for (i=0;i<ipod_atom_list_length(tracks);i++) {
		int found;
		unsigned int j;
		uint32_t mhit_track_id;
		ipod_atom mhit = ipod_atom_list_get(tracks,i);
		mhit_track_id = ipod_atom_mhit_get_attribute(mhit,IPOD_TRACK_ID);
		found = 0;
		for (j=0;j<ipod_atom_list_length(mhyp->mhip_children);j++) {
			uint32_t mhip_track_id;
			ipod_atom mhip = ipod_atom_list_get(mhyp->mhip_children,j);
			mhip_track_id = ipod_atom_mhip_get_attribute(mhip,IPOD_TRACK_ITEM_TRACK_ID);
			if (mhit_track_id==mhip_track_id) {
				found = 1;
				break;
			}
		}
		if (!found) { // track not found, add it to the playlist
			ipod_atom mhip = ipod_atom_new_mhip();
			ipod_error("ipod_atom_mhyp_check_master_playlist(): Adding missing track %d to master playlist\n",
				mhit_track_id);
			ipod_atom_init(mhip,version);
			ipod_atom_mhip_set_attribute(mhip,IPOD_TRACK_ITEM_TRACK_ID,mhit_track_id);
			ipod_atom_list_append(mhyp->mhip_children,mhip);
		}
	}
}

//
// make sure all tracks in the playlist are in the track list
//
void ipod_atom_mhyp_check_playlist(ipod_atom root,uint32_t version,ipod_atom_mhyp mhyp)
{
	unsigned long i;
	ipod_atom_list tracks = ipod_tracks(root);
	for (i=0;i<ipod_atom_list_length(mhyp->mhip_children);i++) {
		int found;
		unsigned long j;
		uint32_t mhip_track_id;
		ipod_atom mhip = ipod_atom_list_get(mhyp->mhip_children,i);
		mhip_track_id = ipod_atom_mhip_get_attribute(mhip,IPOD_TRACK_ITEM_TRACK_ID);
		found = 0;
		for (j=0;j<ipod_atom_list_length(tracks);j++) {
			uint32_t mhit_track_id;
			ipod_atom mhit = ipod_atom_list_get(tracks,j);
			mhit_track_id = ipod_atom_mhit_get_attribute(mhit,IPOD_TRACK_ID);
			if (mhit_track_id==mhip_track_id) {
				found = 1;
				break;
			}
		}
		if (!found) { // track not found, remove it from the playlist
			ipod_error("ipod_atom_mhyp_check_playlist(): Removing missing track %d from playlist\n",mhip_track_id);
			ipod_atom_list_remove(mhyp->mhip_children,mhip);
			ipod_atom_free(mhip);
			i--;
		}
	}
}

static void ipod_atom_prepare_to_write_mhyp(ipod_atom root,uint32_t version,void *data)
{
	if (data) {
		ipod_atom_mhyp mhyp = (ipod_atom_mhyp)data;
		ipod_atom_list_prepare_to_write(mhyp->mhod_children,root,version);
		ipod_atom_list_prepare_to_write(mhyp->mhip_children,root,version);
		if (mhyp->hidden)
			ipod_atom_mhyp_check_master_playlist(root,version,mhyp);
		ipod_atom_mhyp_check_playlist(root,version,mhyp);
	}
}

static void write_fake_mhod(ipod_io io,uint32_t i)
{
	ipod_io_put4cc(io,IPOD_ATOM_MHOD);
	ipod_io_putul(io,0x18);
	ipod_io_putul(io,0x2c);
	ipod_io_putul(io,IPOD_PLAYLIST_SETTINGS);
	ipod_io_putul(io,0x0);
	ipod_io_putul(io,0x0);
	ipod_io_putul(io,i);
	ipod_io_putul(io,0x0);
	ipod_io_putul(io,0x0);
	ipod_io_putul(io,0x0);
	ipod_io_putul(io,0x0);
}

static void ipod_atom_write_mhyp(ipod_io io, uint32_t version,void *data)
{
	if (data) {
		size_t mark;
		int i;
		ipod_atom_mhyp mhyp = (ipod_atom_mhyp)data;
	
		mark = ipod_io_put_simple_header(io,IPOD_ATOM_MHYP,0x6c);
		ipod_io_putul(io,ipod_atom_list_length(mhyp->mhod_children));
		ipod_io_putul(io,ipod_atom_list_length(mhyp->mhip_children));
		ipod_io_putul(io,mhyp->hidden);
		ipod_io_putul(io,mhyp->timeStamp);
		ipod_io_putul(io,mhyp->playlistIDLo);
		ipod_io_putul(io,mhyp->playlistIDHi);
		ipod_io_putul(io,mhyp->stringMhodCount);
		ipod_io_putul(io,mhyp->libraryMhodCount);
		ipod_io_putul(io,mhyp->sortOrder);
		ipod_io_put_pad(io,mark,0x6c);
		ipod_atom_list_write(mhyp->mhod_children,io,version);
		for (i=0;i<ipod_atom_list_length(mhyp->mhip_children);i++) {
			ipod_atom atom = ipod_atom_list_get(mhyp->mhip_children,i);
			if (atom)
				ipod_atom_write(atom,io,version);
			if (version<IPOD_VERSION4_9)
				write_fake_mhod(io,i);
		}
		ipod_io_backpatch(io,mark);
	}
}

static void *ipod_atom_copy_mhyp(void *data) {
	if (data) {
		ipod_atom_mhyp mhyp = (ipod_atom_mhyp)data;
		ipod_atom_mhyp copy = (ipod_atom_mhyp)ipod_memory_alloc(sizeof(ipod_atom_mhyp_struct));
		copy->hidden = mhyp->hidden;
		copy->timeStamp = mhyp->timeStamp;
		copy->playlistIDLo = mhyp->playlistIDLo;
		copy->playlistIDHi = mhyp->playlistIDHi;
		copy->stringMhodCount = mhyp->stringMhodCount;
		copy->libraryMhodCount = mhyp->libraryMhodCount;
		copy->sortOrder = mhyp->sortOrder;
		copy->mhod_children = ipod_atom_list_copy(mhyp->mhod_children);
		copy->mhip_children = ipod_atom_list_copy(mhyp->mhip_children);
		return (void *)copy;
	}
	return NULL;
}

#ifdef PLIST
plist_item *ipod_atom_get_plist_mhyp(void *data)
{
	plist_item *p = plist_item_new_dict();
	if (data) {
		ipod_atom_mhyp mhyp = (ipod_atom_mhyp)data;
		plist_item_dict_at_key_put(p,"tag",plist_item_from_string("mhyp"));
		plist_item_dict_at_key_put(p,"hidden",plist_item_from_integer(mhyp->hidden));
		plist_item_dict_at_key_put(p,"timeStamp",plist_item_from_integer(mhyp->timeStamp));
		plist_item_dict_at_key_put(p,"playlistIDLo",plist_item_from_integer(mhyp->playlistIDLo));
		plist_item_dict_at_key_put(p,"playlistIDHi",plist_item_from_integer(mhyp->playlistIDHi));
		plist_item_dict_at_key_put(p,"stringMhodCount",plist_item_from_integer(mhyp->stringMhodCount));
		plist_item_dict_at_key_put(p,"libraryMhodCount",plist_item_from_integer(mhyp->libraryMhodCount));
		plist_item_dict_at_key_put(p,"sortOrder",plist_item_from_integer(mhyp->sortOrder));
		plist_item_dict_at_key_put(p,"mhod_children",ipod_atom_list_get_plist(mhyp->mhod_children));
		plist_item_dict_at_key_put(p,"mhip_children",ipod_atom_list_get_plist(mhyp->mhip_children));
	}
	return p;
}

void ipod_atom_set_plist_mhyp(plist_item *plist,void *data)
{
}
#endif

unsigned long ipod_atom_mhyp_track_item_count(ipod_atom atom)
{
	if (atom && atom->data) {
		ipod_atom_mhyp mhyp = (ipod_atom_mhyp)atom->data;
		return ipod_atom_list_length(mhyp->mhip_children);
	}
	return 0;
}

ipod_atom ipod_atom_mhyp_get_track_item_by_index(ipod_atom atom,unsigned long index)
{
	if (atom && atom->data) {
		ipod_atom_mhyp mhyp = (ipod_atom_mhyp)atom->data;
		if (index>=0 && index<ipod_atom_list_length(mhyp->mhip_children)) {
			return ipod_atom_list_get(mhyp->mhip_children,index);
		} else {
			ipod_error("ipod_atom_mhyp_get_track_item_by_index(): Index %d out of range\n",index);
		}
	} else {
		ipod_error("ipod_atom_mhyp_get_track_item_by_index(): Invalid playlist atom\n");
	}
	return NULL;
}

ipod_atom ipod_atom_mhyp_new_track_item(ipod_atom atom)
{
	if (atom && atom->data) {
		ipod_atom_mhyp mhyp = (ipod_atom_mhyp)atom->data;
		ipod_atom a = ipod_atom_new_mhip();
		ipod_atom_init(a,IPOD_VERSION_ANY);
		ipod_atom_list_append(mhyp->mhip_children,a);
		return a;
	} else {
		ipod_error("ipod_atom_mhyp_new_track_item(): Invalid playlist atom\n");
	}
	return NULL;	
}

void ipod_atom_mhyp_remove_track_item(ipod_atom atom, ipod_atom item)
{
	if (atom && atom->data) {
		ipod_atom_mhyp mhyp = (ipod_atom_mhyp)atom->data;
		ipod_atom_list_remove(mhyp->mhip_children,item);
	} else {
		ipod_error("ipod_atom_mhyp_remove_track_item(): Invalid playlist atom\n");
	}
}

static ipod_atom ipod_atom_mhyp_string_atom(ipod_atom atom,int tag)
{
	if (atom && atom->data) {
		int i;
		ipod_atom_mhyp mhyp = (ipod_atom_mhyp)atom->data;
		for (i=0;i<ipod_atom_list_length(mhyp->mhod_children);i++) {
			ipod_atom mhod_atom = ipod_atom_list_get(mhyp->mhod_children,i);
			if (atom && atom->data) {
				ipod_atom_mhod mhod = (ipod_atom_mhod)mhod_atom->data;
				if (mhod->type==tag)
					return mhod_atom;
			}
		}
	}
	return NULL;
}

char *ipod_atom_mhyp_get_text_utf8(ipod_atom atom, int tag, char *s)
{
	ipod_atom mhod_atom = ipod_atom_mhyp_string_atom(atom,tag);
	if (s) s = ipod_string_zero(s);
	else s = ipod_string_new();
	if (mhod_atom)
		if (tag==IPOD_TITLE)
			return ipod_atom_mhod_string_get(mhod_atom,s);
		else
			ipod_error("ipod_atom_mhyp_get_text_utf8(): Non-string type %d\n",tag);
	return s;
}

void ipod_atom_mhyp_set_text_utf8(ipod_atom atom, int tag, const char *s)
{
	ipod_atom mhod_atom = ipod_atom_mhyp_string_atom(atom,tag);
	if (mhod_atom) {
		if (tag==IPOD_TITLE)
			ipod_atom_mhod_string_set(mhod_atom,s);
		else
			ipod_error("ipod_atom_mhyp_set_text_utf8(): Non-string type %d\n",tag);
	} else {
		ipod_atom_mhyp mhyp = (ipod_atom_mhyp)atom->data;
		if (tag==IPOD_TITLE)
			mhod_atom = ipod_atom_new_mhod_string(tag,s);
		else
			ipod_error("ipod_atom_mhyp_set_text_utf8(): Non-string type %d\n",tag);
		if (mhod_atom)
			ipod_atom_list_append(mhyp->mhod_children,mhod_atom);
	}
}

int ipod_atom_mhyp_has_text(ipod_atom atom, int tag)
{
	return ipod_atom_mhyp_string_atom(atom,tag)!=NULL;
}

uint32_t ipod_atom_mhyp_get_attribute(ipod_atom atom, int tag)
{
	if (atom && atom->data) {
		ipod_atom_mhyp mhyp = (ipod_atom_mhyp)atom->data;
		switch (tag) {
			case IPOD_PLAYLIST_HIDDEN: return mhyp->hidden;
			case IPOD_PLAYLIST_TIMESTAMP: return mhyp->timeStamp;
			case IPOD_PLAYLIST_PLAYLIST_ID_LO: return mhyp->playlistIDLo;
			case IPOD_PLAYLIST_PLAYLIST_ID_HI: return mhyp->playlistIDHi;
			case IPOD_PLAYLIST_SORT_ORDER: return mhyp->sortOrder;
			case IPOD_PLAYLIST_TIMESTAMP_NATIVE: return mhyp->timeStamp-IPOD_MAC_EPOCH_OFFSET;
			default:
				ipod_error("ipod_atom_mhyp_get_attribute(): Invalid tag %d\n",tag);
		}
			
	} else {
		ipod_error("ipod_atom_mhyp_get_attribute(): Invalid playlist atom\n");
	}
	return 0;
}

void ipod_atom_mhyp_set_attribute(ipod_atom atom, int tag, uint32_t value)
{
	if (atom && atom->data) {
		ipod_atom_mhyp mhyp = (ipod_atom_mhyp)atom->data;
		switch (tag) {
			case IPOD_PLAYLIST_HIDDEN: mhyp->hidden = value; break;
			case IPOD_PLAYLIST_TIMESTAMP: mhyp->timeStamp = value; break;
			case IPOD_PLAYLIST_PLAYLIST_ID_LO: mhyp->playlistIDLo = value; break;
			case IPOD_PLAYLIST_PLAYLIST_ID_HI: mhyp->playlistIDHi = value; break;
			case IPOD_PLAYLIST_SORT_ORDER: mhyp->sortOrder = value; break;
			
			case IPOD_PLAYLIST_TIMESTAMP_NATIVE: mhyp->timeStamp = value+IPOD_MAC_EPOCH_OFFSET; break;
			default:
				ipod_error("ipod_atom_mhyp_set_attribute(): Invalid tag %d\n",tag);
		}
			
	} else {
		ipod_error("ipod_atom_mhyp_set_attribute(): Invalid playlist atom\n");
	}
}

ipod_atom ipod_atom_new_mhyp(void) {
	ipod_atom atom = ipod_atom_new();
	if (atom) {
		atom->tag = IPOD_ATOM_MHYP;
		atom->init = ipod_atom_init_mhyp;
		atom->free = ipod_atom_free_mhyp;
		atom->read = ipod_atom_read_mhyp;
		atom->prepare_to_write = ipod_atom_prepare_to_write_mhyp;
		atom->write = ipod_atom_write_mhyp;
		atom->copy = ipod_atom_copy_mhyp;
#ifdef PLIST
		atom->get_plist = ipod_atom_get_plist_mhyp;
		atom->set_plist = ipod_atom_set_plist_mhyp;
#endif
		atom->data = (void *)ipod_memory_alloc(sizeof(ipod_atom_mhyp_struct));
	}
	return atom;
}
