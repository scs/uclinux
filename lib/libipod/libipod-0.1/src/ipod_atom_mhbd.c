/*
 * ipod_atom_mhbd.c
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

#include <ipod/ipod_constants.h>
#include <ipod/ipod_memory.h>
#include "ipod_atom_mhbd.h"
#include "ipod_atom_mhsd.h"
#include "ipod_atom_mhlt.h"
#include "ipod_atom_mhlp.h"
#include "ipod_atom_mhyp.h"
#include "ipod_atom_mhod.h"
#include "ipod_private_constants.h"

static ipod_atom_mhsd_create_new_db(ipod_atom_mhbd mhbd,uint32_t version)
{
	ipod_atom mhsd_atom;
	ipod_atom_mhsd mhsd;
	ipod_atom mhlt_atom;
	ipod_atom_mhlt mhlt;
	ipod_atom mhlp_atom;
	ipod_atom_mhlp mhlp;
	ipod_atom mhyp_atom;
	ipod_atom_mhyp mhyp;
	unsigned int i,count;

	if (version==IPOD_VERSION_ANY)
		version = IPOD_VERSION5_0; // build something relatively modern

	// build track list
	mhsd_atom = ipod_atom_new_mhsd();
	ipod_atom_init(mhsd_atom,version);
	mhsd = (ipod_atom_mhsd)mhsd_atom->data;
	mhsd->index = 1; // tracks
	mhlt_atom = ipod_atom_new_mhlt();
	ipod_atom_init(mhlt_atom,version);
	mhlt = (ipod_atom_mhlt)mhlt_atom->data;
	mhsd->child = mhlt_atom;
	ipod_atom_list_append(mhbd->children,mhsd_atom);
	
	//
	// build lists of playlists (1 or 2 depending upon on version)
	// each with a single master playlist.  Each master playlist also
	// has 5 sorted library index objects to support the iPod UI - they are
	// automatically populated and sorted when the database is written
	//
	count = (version<IPOD_VERSION4_9)?1:2;
	for (i=0;i<count;i++) {
		// create data store
		mhsd_atom = ipod_atom_new_mhsd();
		ipod_atom_init(mhsd_atom,version);
		ipod_atom_list_append(mhbd->children,mhsd_atom);
		mhsd = (ipod_atom_mhsd)mhsd_atom->data;
		mhsd->index = count-i+1; // we want either 2, or 3,2
		// create list of playlists
		mhlp_atom = ipod_atom_new_mhlp();
		ipod_atom_init(mhlp_atom,version);
		mhsd->child = mhlp_atom;
		mhlp = (ipod_atom_mhlp)mhlp_atom->data;
		// create playlist
		mhyp_atom = ipod_atom_new_mhyp();
		ipod_atom_init(mhyp_atom,version);
		ipod_atom_list_append(mhlp->children,mhyp_atom);
		mhyp = (ipod_atom_mhyp)mhyp_atom->data;
		ipod_atom_mhyp_set_attribute(mhyp_atom,IPOD_PLAYLIST_HIDDEN,1);
		ipod_atom_mhyp_set_attribute(mhyp_atom,IPOD_PLAYLIST_SORT_ORDER,IPOD_SORT_ORDER_MANUAL);
		ipod_atom_mhyp_set_attribute(mhyp_atom,IPOD_PLAYLIST_PLAYLIST_ID_LO,500);
		// add title
		ipod_atom_mhyp_set_text_utf8(mhyp_atom,IPOD_TITLE,"iPod");
		// add library indices
		ipod_atom_list_append(mhyp->mhod_children,ipod_atom_new_mhod_library_index(IPOD_SORT_ORDER_TITLE));
		ipod_atom_list_append(mhyp->mhod_children,ipod_atom_new_mhod_library_index(IPOD_SORT_ORDER_ALBUM));
		ipod_atom_list_append(mhyp->mhod_children,ipod_atom_new_mhod_library_index(IPOD_SORT_ORDER_ARTIST));
		ipod_atom_list_append(mhyp->mhod_children,ipod_atom_new_mhod_library_index(IPOD_SORT_ORDER_GENRE));
		ipod_atom_list_append(mhyp->mhod_children,ipod_atom_new_mhod_library_index(IPOD_SORT_ORDER_COMPOSER));
	}
	
}

static void ipod_atom_init_mhbd(uint32_t version,void *data)
{
	if (data) {
		ipod_atom_mhbd mhbd = (ipod_atom_mhbd)data;
		mhbd->res0 = 1;
		mhbd->version = version?version:IPOD_VERSION5_0;
		mhbd->res1 = 0;
		mhbd->res2 = 0;
		mhbd->res3 = 2;
		mhbd->children = ipod_atom_list_new();
		ipod_atom_mhsd_create_new_db(mhbd,version);
	}
}

static void ipod_atom_free_mhbd(void *data)
{
	if (data) {
		ipod_atom_mhbd mhbd = (ipod_atom_mhbd)data;
		ipod_atom_list_remove_and_free_all(mhbd->children);
		ipod_atom_list_free(mhbd->children);
		ipod_memory_free(data);
	}
}

static void ipod_atom_read_mhbd(ipod_io io,uint32_t version,void *data)
{
	if (data) {
		size_t h1,h2,count;
		ipod_atom_mhbd mhbd = (ipod_atom_mhbd)data;
		ipod_io_get_simple_header(io,&h1,&h2);
		mhbd->res0 = ipod_io_getul(io);
		mhbd->version = ipod_io_getul(io);
		count = ipod_io_getul(io);
		mhbd->res1 = ipod_io_getul(io);
		mhbd->res2 = ipod_io_getul(io);
		mhbd->res3 = ipod_io_getul(io);
		ipod_io_seek(io,h1);
		ipod_atom_list_read(mhbd->children,count,io,version?version:mhbd->version);
		ipod_io_seek(io,h2);
	}		
}

//
// Duplicate the "playlists" mhsd and replace the "podcasts" mhsd with it
// until we figure out what the actual differences are
//
static void ipod_atom_prepare_to_write_mhbd(ipod_atom root,uint32_t version,void *data)
{
	if (data) {
		int i;
		ipod_atom_mhbd mhbd = (ipod_atom_mhbd)data;
		// begin weird code
		if (ipod_atom_list_length(mhbd->children)>2) {
			int i;
			for (i=0;i<ipod_atom_list_length(mhbd->children);i++) {
				ipod_atom playlists = ipod_atom_list_get(mhbd->children,i);
				if (((ipod_atom_mhsd)playlists->data)->index==2) {
					int j;
					for (j=0;j<ipod_atom_list_length(mhbd->children);j++) {
						ipod_atom podcasts = ipod_atom_list_get(mhbd->children,j);
						if (((ipod_atom_mhsd)podcasts->data)->index==3) {
							ipod_atom_free(podcasts);
							podcasts = ipod_atom_copy(playlists);
							((ipod_atom_mhsd)podcasts->data)->index=3;
							ipod_atom_list_put(mhbd->children,j,podcasts);
							break;
						}
					}
					break;
				}
			}
		}
		// end weird code
		ipod_atom_list_prepare_to_write(mhbd->children,root,version?version:mhbd->version);
	}
}

static void ipod_atom_write_mhbd(ipod_io io, uint32_t version,void *data)
{
	if (data) {
		size_t mark;
		ipod_atom_mhbd mhbd = (ipod_atom_mhbd)data;
	
		mark = ipod_io_put_simple_header(io,IPOD_ATOM_MHBD,0x68);
		ipod_io_putul(io,mhbd->res0);
		ipod_io_putul(io,version?version:mhbd->version);
		ipod_io_putul(io,ipod_atom_list_length(mhbd->children));
		ipod_io_putul(io,mhbd->res1);
		ipod_io_putul(io,mhbd->res2);
		ipod_io_putul(io,mhbd->res3);
		ipod_io_put_pad(io,mark,0x68);
		ipod_atom_list_write(mhbd->children,io,version?version:mhbd->version);
		ipod_io_backpatch(io,mark);
	}
}

static void *ipod_atom_copy_mhbd(void *data) {
	if (data) {
		ipod_atom_mhbd mhbd = (ipod_atom_mhbd)data;
		ipod_atom_mhbd copy = (ipod_atom_mhbd)ipod_memory_alloc(sizeof(ipod_atom_mhbd_struct));
		copy->res0 = mhbd->res0;
		copy->version = mhbd->version;
		copy->res1 = mhbd->res1;
		copy->res2 = mhbd->res2;
		copy->res3 = mhbd->res3;
		copy->children = ipod_atom_list_copy(mhbd->children);
		return (void *)copy;
	}
	return NULL;
}

#ifdef PLIST
plist_item *ipod_atom_get_plist_mhbd(void *data)
{
	plist_item *p = plist_item_new_dict();
	if (data) {
		ipod_atom_mhbd mhbd = (ipod_atom_mhbd)data;
		plist_item_dict_at_key_put(p,"tag",plist_item_from_string("mhbd"));
		plist_item_dict_at_key_put(p,"res0",plist_item_from_integer(mhbd->res0));
		plist_item_dict_at_key_put(p,"version",plist_item_from_integer(mhbd->version));
		plist_item_dict_at_key_put(p,"res1",plist_item_from_integer(mhbd->res1));
		plist_item_dict_at_key_put(p,"res2",plist_item_from_integer(mhbd->res2));
		plist_item_dict_at_key_put(p,"res3",plist_item_from_integer(mhbd->res3));
		plist_item_dict_at_key_put(p,"children",ipod_atom_list_get_plist(mhbd->children));
	}
	return p;
}

void ipod_atom_set_plist_mhbd(plist_item *plist,void *data)
{
}
#endif

ipod_atom ipod_atom_new_mhbd(void) {
	ipod_atom atom = ipod_atom_new();
	if (atom) {
		atom->tag = IPOD_ATOM_MHBD;
		atom->init = ipod_atom_init_mhbd;
		atom->free = ipod_atom_free_mhbd;
		atom->read = ipod_atom_read_mhbd;
		atom->prepare_to_write = ipod_atom_prepare_to_write_mhbd;
		atom->write = ipod_atom_write_mhbd;
		atom->copy = ipod_atom_copy_mhbd;
#ifdef PLIST
		atom->get_plist = ipod_atom_get_plist_mhbd;
		atom->set_plist = ipod_atom_set_plist_mhbd;
#endif
		atom->data = (void *)ipod_memory_alloc(sizeof(ipod_atom_mhbd_struct));
	}
	return atom;
}

static ipod_atom ipod_atom_mhbd_child(ipod_atom atom,unsigned int index)
{
	if (atom && atom->data) {
		unsigned int i;
		ipod_atom_mhbd mhbd = (ipod_atom_mhbd)(atom->data);
		for (i=0;i<ipod_atom_list_length(mhbd->children);i++) {
			ipod_atom mhsd_atom = ipod_atom_list_get(mhbd->children,i);
			if (mhsd_atom) {
				ipod_atom_mhsd mhsd = (ipod_atom_mhsd)(mhsd_atom->data);
				if (mhsd->index==index)
					return mhsd_atom;
			}
		}
	}
	return NULL;
}

uint32_t ipod_atom_mhbd_get_version(ipod_atom atom)
{
	if (atom && atom->data) {
		ipod_atom_mhbd mhbd = (ipod_atom_mhbd)(atom->data);
		return mhbd->version;	
	}
	return IPOD_VERSION_ANY;
}

ipod_atom ipod_atom_mhbd_tracks(ipod_atom atom)
{
	return ipod_atom_mhbd_child(atom,1);
}

ipod_atom ipod_atom_mhbd_playlists(ipod_atom atom)
{
	return ipod_atom_mhbd_child(atom,2); // XXX DSM weirdness
}

ipod_atom ipod_atom_mhbd_podcasts(ipod_atom atom)
{
	return ipod_atom_mhbd_child(atom,3); // XXX DSM  weirdness
}

