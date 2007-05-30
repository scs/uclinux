/*
 * ipod_atom_mhsd.c
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
#include "ipod_atom_mhsd.h"
#include "ipod_private_constants.h"

static void ipod_atom_init_mhsd(uint32_t version,void *data)
{
	if (data) {
		ipod_atom_mhsd mhsd = (ipod_atom_mhsd)data;
		mhsd->index = 0;
		mhsd->child = NULL;
	}
}

static void ipod_atom_free_mhsd(void *data)
{
	if (data) {
		ipod_atom_mhsd mhsd = (ipod_atom_mhsd)data;
		if (mhsd->child)
			ipod_atom_free(mhsd->child);
		ipod_memory_free(data);
	}
}

static void ipod_atom_read_mhsd(ipod_io io,uint32_t version,void *data)
{
	if (data) {
		size_t h1,h2,count,i;
		ipod_atom_mhsd mhsd = (ipod_atom_mhsd)data;
		ipod_io_get_simple_header(io,&h1,&h2);
		mhsd->index = ipod_io_getul(io);
		ipod_io_seek(io,h1);
		mhsd->child = ipod_atom_read_next(io,version);
		ipod_io_seek(io,h2);
	}		
}

static void ipod_atom_prepare_to_write_mhsd(ipod_atom root,uint32_t version,void *data)
{
	if (data) {
		ipod_atom_mhsd mhsd = (ipod_atom_mhsd)data;
		if (mhsd->child)
			ipod_atom_prepare_to_write(mhsd->child,root,version);
	}
}

static void ipod_atom_write_mhsd(ipod_io io, uint32_t version,void *data)
{
	if (data) {
		size_t mark;
		int i;
		ipod_atom_mhsd mhsd = (ipod_atom_mhsd)data;
	
		mark = ipod_io_put_simple_header(io,IPOD_ATOM_MHSD,0x60);
		ipod_io_putul(io,mhsd->index);
		ipod_io_put_pad(io,mark,0x60);
		if (mhsd->child)
			ipod_atom_write(mhsd->child,io,version);
		ipod_io_backpatch(io,mark);
	}
}

static void *ipod_atom_copy_mhsd(void *data) {
	if (data) {
		ipod_atom_mhsd mhsd = (ipod_atom_mhsd)data;
		ipod_atom_mhsd copy = (ipod_atom_mhsd)ipod_memory_alloc(sizeof(ipod_atom_mhsd_struct));
		copy->index = mhsd->index;
		copy->child = ipod_atom_copy(mhsd->child);
		return (void *)copy;
	}
	return NULL;
}

#ifdef PLIST
plist_item *ipod_atom_get_plist_mhsd(void *data)
{
	plist_item *p = plist_item_new_dict();
	if (data) {
		int i;
		ipod_atom_mhsd mhsd = (ipod_atom_mhsd)data;
		plist_item_dict_at_key_put(p,"tag",plist_item_from_string("mhsd"));
		plist_item_dict_at_key_put(p,"index",plist_item_from_integer(mhsd->index));
		plist_item_dict_at_key_put(p,"child",ipod_atom_get_plist(mhsd->child));
	}
	return p;
}

void ipod_atom_set_plist_mhsd(plist_item *plist,void *data)
{
}
#endif

ipod_atom ipod_atom_mhsd_tracks(ipod_atom atom)
{
	if (atom && atom->data)
		return ((ipod_atom_mhsd)(atom->data))->child;
	return NULL;
}

ipod_atom ipod_atom_mhsd_playlists(ipod_atom atom)
{
	if (atom && atom->data)
		return ((ipod_atom_mhsd)(atom->data))->child;
	return NULL;
}

ipod_atom ipod_atom_mhsd_podcasts(ipod_atom atom)
{
	if (atom && atom->data)
		return ((ipod_atom_mhsd)(atom->data))->child;
	return NULL;
}

ipod_atom ipod_atom_new_mhsd(void) {
	ipod_atom atom = ipod_atom_new();
	if (atom) {
		atom->tag = IPOD_ATOM_MHSD;
		atom->init = ipod_atom_init_mhsd;
		atom->free = ipod_atom_free_mhsd;
		atom->read = ipod_atom_read_mhsd;
		atom->prepare_to_write = ipod_atom_prepare_to_write_mhsd;
		atom->write = ipod_atom_write_mhsd;
		atom->copy = ipod_atom_copy_mhsd;
#ifdef PLIST
		atom->get_plist = ipod_atom_get_plist_mhsd;
		atom->set_plist = ipod_atom_set_plist_mhsd;
#endif
		atom->data = (void *)ipod_memory_alloc(sizeof(ipod_atom_mhsd_struct));
	}
	return atom;
}
