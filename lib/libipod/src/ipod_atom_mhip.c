/*
 * ipod_atom_mhip.c
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
#include "ipod_atom_mhip.h"
#include "ipod_private_constants.h"

static void ipod_atom_init_mhip(uint32_t version,void *data)
{
	if (data) {
		ipod_atom_mhip mhip = (ipod_atom_mhip)data;
		mhip->dataObjectChildCount = 1;
		mhip->podcastGroupingFlag = 0;
		mhip->groupID = 0;
		mhip->trackID = 0;
		mhip->timeStamp = 0;
		mhip->podcastGroupingReference = 0;
	}
}

static void ipod_atom_free_mhip(void *data)
{
	if (data) {
		ipod_memory_free(data);
	}
}

static void ipod_atom_read_mhip(ipod_io io,uint32_t version,void *data)
{
	if (data) {
		size_t h1,h2;
		ipod_atom_mhip mhip = (ipod_atom_mhip)data;
		ipod_io_get_simple_header(io,&h1,&h2);
		mhip->dataObjectChildCount = ipod_io_getul(io);
		mhip->podcastGroupingFlag = ipod_io_getul(io);
		mhip->groupID = ipod_io_getul(io);
		mhip->trackID = ipod_io_getul(io);
		mhip->timeStamp = ipod_io_getul(io);
		mhip->podcastGroupingReference = ipod_io_getul(io);
		ipod_io_seek(io,h2);
	}		
}

static void ipod_atom_prepare_to_write_mhip(ipod_atom root,uint32_t version,void *data)
{
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

static void ipod_atom_write_mhip(ipod_io io, uint32_t version,void *data)
{
	if (data) {
		size_t mark;
		ipod_atom_mhip mhip = (ipod_atom_mhip)data;
	
		mark = ipod_io_put_simple_header(io,IPOD_ATOM_MHIP,0x4c);
		ipod_io_putul(io,mhip->dataObjectChildCount);
		ipod_io_putul(io,mhip->podcastGroupingFlag);
		ipod_io_putul(io,mhip->groupID);
		ipod_io_putul(io,mhip->trackID);
		ipod_io_putul(io,mhip->timeStamp);
		ipod_io_putul(io,mhip->podcastGroupingReference);
		ipod_io_put_pad(io,mark,0x4c);
		if (version>=IPOD_VERSION4_9)
			write_fake_mhod(io,mhip->groupID);
		ipod_io_backpatch(io,mark);
	}
}

static void *ipod_atom_copy_mhip(void *data)
{
	if (data) {
		ipod_atom_mhip mhip = (ipod_atom_mhip)data;
		ipod_atom_mhip copy = (ipod_atom_mhip)ipod_memory_alloc(sizeof(ipod_atom_mhip_struct));
		copy->dataObjectChildCount = mhip->dataObjectChildCount;
		copy->podcastGroupingFlag = mhip->podcastGroupingFlag;
		copy->groupID = mhip->groupID;
		copy->trackID = mhip->trackID;
		copy->timeStamp = mhip->timeStamp;
		copy->podcastGroupingReference = mhip->podcastGroupingReference;
		return (void *)copy;
	}
	return NULL;
}

#ifdef PLIST
static plist_item *ipod_atom_get_plist_mhip(void *data)
{
	plist_item *p = plist_item_new_dict();
	if (data) {
		ipod_atom_mhip mhip = (ipod_atom_mhip)data;
		plist_item_dict_at_key_put(p,"tag",plist_item_from_string("mhip"));
		plist_item_dict_at_key_put(p,"dataObjectChildCount",plist_item_from_integer(mhip->dataObjectChildCount));
		plist_item_dict_at_key_put(p,"podcastGroupingFlag",plist_item_from_integer(mhip->podcastGroupingFlag));
		plist_item_dict_at_key_put(p,"groupID",plist_item_from_integer(mhip->groupID));
		plist_item_dict_at_key_put(p,"trackID",plist_item_from_integer(mhip->trackID));
		plist_item_dict_at_key_put(p,"timeStamp",plist_item_from_integer(mhip->timeStamp));
		plist_item_dict_at_key_put(p,"podcastGroupingReference",plist_item_from_integer(mhip->podcastGroupingReference));
	}
	return p;
}

static void ipod_atom_set_plist_mhip(plist_item *plist,void *data)
{
}
#endif

uint32_t ipod_atom_mhip_get_attribute(ipod_atom atom, int tag)
{
	if (atom && atom->data) {
		ipod_atom_mhip mhip = (ipod_atom_mhip)atom->data;
		switch (tag) {
			case IPOD_TRACK_ITEM_PODCAST_GROUPING_FLAG: return mhip->podcastGroupingFlag;
			case IPOD_TRACK_ITEM_GROUP_ID: return mhip->groupID;
			case IPOD_TRACK_ITEM_TRACK_ID: return mhip->trackID;
			case IPOD_TRACK_ITEM_TIMESTAMP: return mhip->timeStamp;
			case IPOD_TRACK_ITEM_PODCAST_GROUPING_REFERENCE: return mhip->podcastGroupingReference;
			case IPOD_TRACK_ITEM_TIMESTAMP_NATIVE: return mhip->timeStamp-IPOD_MAC_EPOCH_OFFSET;
			default:
				ipod_error("ipod_atom_mhip_get_attribute(): Invalid tag %d\n",tag);
		}
			
	} else {
		ipod_error("ipod_atom_mhip_get_attribute(): Invalid playlist atom\n");
	}
	return 0;
}

void ipod_atom_mhip_set_attribute(ipod_atom atom, int tag, uint32_t value)
{
	if (atom && atom->data) {
		ipod_atom_mhip mhip = (ipod_atom_mhip)atom->data;
		switch (tag) {
			case IPOD_TRACK_ITEM_PODCAST_GROUPING_FLAG: mhip->podcastGroupingFlag = value; break;
			case IPOD_TRACK_ITEM_GROUP_ID: mhip->groupID = value; break;
			case IPOD_TRACK_ITEM_TRACK_ID: mhip->trackID = value; break;
			case IPOD_TRACK_ITEM_TIMESTAMP: mhip->timeStamp = value; break;
			case IPOD_TRACK_ITEM_PODCAST_GROUPING_REFERENCE: mhip->podcastGroupingReference = value; break;
			case IPOD_TRACK_ITEM_TIMESTAMP_NATIVE: mhip->timeStamp = value+IPOD_MAC_EPOCH_OFFSET; break;
			default:
				ipod_error("ipod_atom_mhip_set_attribute(): Invalid tag %d\n",tag);
		}
			
	} else {
		ipod_error("ipod_atom_mhip_set_attribute(): Invalid playlist atom\n");
	}
}

ipod_atom ipod_atom_new_mhip(void) {
	ipod_atom atom = ipod_atom_new();
	if (atom) {
		atom->tag = IPOD_ATOM_MHIP;
		atom->init = ipod_atom_init_mhip;
		atom->free = ipod_atom_free_mhip;
		atom->read = ipod_atom_read_mhip;
		atom->prepare_to_write = ipod_atom_prepare_to_write_mhip;
		atom->write = ipod_atom_write_mhip;
		atom->copy = ipod_atom_copy_mhip;
#ifdef PLIST
		atom->get_plist = ipod_atom_get_plist_mhip;
		atom->set_plist = ipod_atom_set_plist_mhip;
#endif
		atom->data = (void *)ipod_memory_alloc(sizeof(ipod_atom_mhip_struct));
	}
	return atom;
}
