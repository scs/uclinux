/*
 * ipod_atom_list.c
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
#include <ipod/ipod_memory.h>
#include <ipod/ipod_constants.h>
#include "ipod_atom.h"
 
static long ipod_atom_list_allocs;
static long ipod_atom_list_frees;

ipod_atom_list ipod_atom_list_new(void)
{
	ipod_atom_list list = (ipod_atom_list)ipod_memory_alloc(sizeof(ipod_atom_list_struct));
	if (list) {
		list->atoms = (ipod_atom *)ipod_memory_alloc(0);
		list->count = 0;
	} else {
		ipod_error("ipod_atom_list_new(): Cannot create atom list\n");
	}
	ipod_atom_list_allocs++;
	return list;
}

void ipod_atom_list_free(ipod_atom_list list)
{
	if (list) {
		ipod_memory_free(list->atoms);
		ipod_memory_free(list);
	} else {
		ipod_error("ipod_atom_list_free(): Freeing invalid list\n");
	}
	ipod_atom_list_frees++;
}

ipod_atom_list ipod_atom_list_shallow_copy(ipod_atom_list list)
{
	if (list) {
		ipod_atom_list l = ipod_atom_list_new();
		l->atoms = (ipod_atom *)ipod_memory_realloc(l->atoms,list->count*sizeof(ipod_atom));
		memcpy(l->atoms,list->atoms,list->count*sizeof(ipod_atom));
		l->count = list->count;
		return l;
	} else {
		ipod_error("ipod_atom_list_shallow_copy(): Copying invalid list\n");
	}
	return NULL;
}


ipod_atom ipod_atom_list_get(ipod_atom_list list,int index)
{
	if (list) {
		if (index>=0 && index<list->count)
			return list->atoms[index];
		else
			ipod_error("ipod_atom_list_get(): Index out of range (%d)\n",index);
	} else {
		ipod_error("ipod_atom_list_get(): Getting item from invalid list\n");
	}
	return NULL;
}

void ipod_atom_list_put(ipod_atom_list list,int index,ipod_atom atom)
{
	if (list) {
		if (index>=0 && index<list->count)
			list->atoms[index] = atom;
		else
			ipod_error("ipod_atom_list_put(): Index out of range (%d)\n",index);
	} else {
		ipod_error("ipod_atom_list_put(): Getting item from invalid list\n");
	}
}


size_t ipod_atom_list_length(ipod_atom_list list)
{
	if (list)
		return list->count;
	return 0;
}

void ipod_atom_list_remove(ipod_atom_list list,ipod_atom atom)
{
	if (list) {
		if (atom) {
			int i = ipod_atom_list_index(list,atom);
			if (i>=0)
				ipod_atom_list_remove_index(list,i);
			else
				ipod_error("ipod_atom_list_remove(): Atom not found in list\n");
		} else {
			ipod_error("ipod_atom_list_remove(): Atom to remove is NULL\n");
		}
	} else {
		ipod_error("ipod_atom_list_remove(): Removing item from invalid list\n");
	}
}

void ipod_atom_list_remove_index(ipod_atom_list list,int index)
{
	if (list) {
		if (index>=0 && index<list->count) {
			ipod_atom *src,*dst;
			dst = &list->atoms[index];
			src = dst+1;
			memmove(dst,src,(list->count-index-1)*sizeof(ipod_atom));
			list->count--;
			list->atoms = (ipod_atom *)ipod_memory_realloc(list->atoms,list->count*sizeof(ipod_atom));
		} else {
			ipod_error("ipod_atom_list_remove_index(): Index out of range\n");
		}
	} else {
		ipod_error("ipod_atom_list_remove_index(): Removing item from invalid list\n");
	}
}

void ipod_atom_list_remove_and_free_all(ipod_atom_list list)
{
	if (list) {
		int i;
		for (i=0;i<list->count;i++)
			ipod_atom_free(list->atoms[i]);
		list->atoms = (ipod_atom *)ipod_memory_realloc(list->atoms,0);
		list->count = 0;
	} else {
		ipod_error("ipod_atom_list_remove_and_free_all(): Removing items from invalid list\n");
	}
}

long ipod_atom_list_index(ipod_atom_list list,ipod_atom atom)
{
	if (list) {
		if (atom) {
			long i;
			for (i=0;i<list->count;i++)
				if (list->atoms[i]==atom)
					return i;
		} else {
			ipod_error("ipod_atom_list_index(): Atom to search for is NULL\n");
		}
	} else {
		ipod_error("ipod_atom_list_index(): Searching in invalid list\n");
	}
	return -1;
}

void ipod_atom_list_append(ipod_atom_list list,ipod_atom atom)
{
	if (list) {
		if (atom) {
			list->atoms = (ipod_atom *)ipod_memory_realloc(list->atoms,(list->count+1)*sizeof(ipod_atom));
			list->atoms[list->count] = atom;
			list->count++;
		} else {
			ipod_error("ipod_atom_list_append(): Appending NULL atom\n");
		}	
	} else {
		ipod_error("ipod_atom_list_append(): Appending to invalid list\n");
	}
}

void ipod_atom_list_read(ipod_atom_list list,size_t count,ipod_io io,uint32_t version)
{
	int i;
	ipod_atom_list_remove_and_free_all(list);
	for (i=0;i<count;i++) {
		ipod_atom atom = ipod_atom_read_next(io,version);
		if (atom)
			ipod_atom_list_append(list,atom);
	}
}

void ipod_atom_list_prepare_to_write(ipod_atom_list list, ipod_atom root,uint32_t version)
{
	int i;
	for (i=0;i<ipod_atom_list_length(list);i++) {
		ipod_atom atom = ipod_atom_list_get(list,i);
		if (atom)
			ipod_atom_prepare_to_write(atom,root,version);
	}
}

void ipod_atom_list_write(ipod_atom_list list,ipod_io io,uint32_t version)
{
	int i;
	for (i=0;i<ipod_atom_list_length(list);i++) {
		ipod_atom atom = ipod_atom_list_get(list,i);
		if (atom)
			ipod_atom_write(atom,io,version);
	}
}

ipod_atom_list ipod_atom_list_copy(ipod_atom_list list)
{
	int i;
	ipod_atom_list copy = ipod_atom_list_new();
	for (i=0;i<ipod_atom_list_length(list);i++) {
		ipod_atom_list_append(copy,ipod_atom_copy(ipod_atom_list_get(list,i)));
	}
	return copy;
}

#ifdef PLIST
plist_item *ipod_atom_list_get_plist(ipod_atom_list list)
{
	int i;
	plist_item *p = plist_item_new_array();
	for (i=0;i<ipod_atom_list_length(list);i++) {
		ipod_atom atom = ipod_atom_list_get(list,i);
		if (atom)
			plist_item_array_append(p,ipod_atom_get_plist(atom));
	}
	return p;
}

void ipod_atom_list_set_plist(ipod_atom_list list,plist_item *items)
{
	int i;
	ipod_atom_list_remove_and_free_all(list);
	for (i=0;i<plist_item_array_length(items);i++) {
		plist_item *item = plist_item_array_at_index(items,i);
		ipod_atom_list_append(list,ipod_atom_from_plist(item,IPOD_VERSION_ANY)); 
	}
}
#endif

void ipod_atom_list_shuffle(ipod_atom_list list)
{
	// XXX DSM shuffle this list in place
}

void ipod_atom_list_report(void) {
	ipod_error("ipod_atom_list_report(): ipod_atom_list allocs %lu frees %lu delta %ld\n",
		ipod_atom_list_allocs,ipod_atom_list_frees,
		ipod_atom_list_allocs-ipod_atom_list_frees);
}
