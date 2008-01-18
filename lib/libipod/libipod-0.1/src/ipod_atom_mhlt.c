/*
 * ipod_atom_mhlt.c
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
#include "ipod_atom_mhlt.h"
#include "ipod_private_constants.h"

static void ipod_atom_init_mhlt(uint32_t version,void *data)
{
	if (data) {
		ipod_atom_mhlt mhlt = (ipod_atom_mhlt)data;
		mhlt->children = ipod_atom_list_new();
	}
}

static void ipod_atom_free_mhlt(void *data)
{
	if (data) {
		ipod_atom_mhlt mhlt = (ipod_atom_mhlt)data;
		ipod_atom_list_remove_and_free_all(mhlt->children);
		ipod_atom_list_free(mhlt->children);
		ipod_memory_free(data);
	}
}

static void ipod_atom_read_mhlt(ipod_io io,uint32_t version,void *data)
{
	if (data) {
		size_t h1,count;
		ipod_atom_mhlt mhlt = (ipod_atom_mhlt)data;
		h1 = ipod_io_get_list_header(io);
		count = ipod_io_getul(io);
		ipod_io_seek(io,h1);
		ipod_atom_list_read(mhlt->children,count,io,version);
	}		
}

static void ipod_atom_prepare_to_write_mhlt(ipod_atom root,uint32_t version,void *data)
{
	if (data) {
		ipod_atom_mhlt mhlt = (ipod_atom_mhlt)data;
		ipod_atom_list_prepare_to_write(mhlt->children,root,version);
	}
}

static void ipod_atom_write_mhlt(ipod_io io, uint32_t version,void *data)
{
	if (data) {
		size_t mark;
		ipod_atom_mhlt mhlt = (ipod_atom_mhlt)data;
	
		mark = ipod_io_put_list_header(io,IPOD_ATOM_MHLT,0x5c);
		ipod_io_putul(io,ipod_atom_list_length(mhlt->children));
		ipod_io_put_pad(io,mark,0x5c);
		ipod_atom_list_write(mhlt->children,io,version);
	}
}

static void *ipod_atom_copy_mhlt(void *data) {
	if (data) {
		ipod_atom_mhlt mhlt = (ipod_atom_mhlt)data;
		ipod_atom_mhlt copy = (ipod_atom_mhlt)ipod_memory_alloc(sizeof(ipod_atom_mhlt_struct));
		copy->children = ipod_atom_list_copy(mhlt->children);
		return (void *)copy;
	}
	return NULL;
}

#ifdef PLIST
plist_item *ipod_atom_get_plist_mhlt(void *data)
{
	plist_item *p = plist_item_new_dict();
	if (data) {
		ipod_atom_mhlt mhlt = (ipod_atom_mhlt)data;
		plist_item_dict_at_key_put(p,"tag",plist_item_from_string("mhlt"));
		plist_item_dict_at_key_put(p,"children",ipod_atom_list_get_plist(mhlt->children));
	}
	return p;
}

void ipod_atom_set_plist_mhlt(plist_item *plist,void *data)
{
}
#endif

ipod_atom_list ipod_atom_mhlt_tracks(ipod_atom atom)
{
	if (atom && atom->data)
		return ((ipod_atom_mhlt)(atom->data))->children;
	return NULL;
}

ipod_atom ipod_atom_new_mhlt(void) {
	ipod_atom atom = ipod_atom_new();
	if (atom) {
		atom->tag = IPOD_ATOM_MHLT;
		atom->init = ipod_atom_init_mhlt;
		atom->free = ipod_atom_free_mhlt;
		atom->read = ipod_atom_read_mhlt;
		atom->prepare_to_write = ipod_atom_prepare_to_write_mhlt;
		atom->write = ipod_atom_write_mhlt;
		atom->copy = ipod_atom_copy_mhlt;
#ifdef PLIST
		atom->get_plist = ipod_atom_get_plist_mhlt;
		atom->set_plist = ipod_atom_set_plist_mhlt;
#endif
		atom->data = (void *)ipod_memory_alloc(sizeof(ipod_atom_mhlt_struct));
	}
	return atom;
}
