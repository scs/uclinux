/*
 * ipod_atom.c
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
#include "ipod_private_constants.h"
#include "ipod_atom_mhbd.h"
#include "ipod_atom_mhsd.h"
#include "ipod_atom_mhlt.h"
#include "ipod_atom_mhit.h"
#include "ipod_atom_mhod.h"
#include "ipod_atom_mhlp.h"
#include "ipod_atom_mhyp.h"
#include "ipod_atom_mhip.h"
#include "ipod_atom_mqed.h"
#include "ipod_atom_pqed.h"

typedef struct {
	uint32_t tag;
	ipod_atom (*create)(void);
} ipod_atom_table_struct;

static ipod_atom_table_struct ipod_atom_table[] = {
	{ IPOD_ATOM_MHBD, ipod_atom_new_mhbd },
	{ IPOD_ATOM_MHSD, ipod_atom_new_mhsd },
	{ IPOD_ATOM_MHLT, ipod_atom_new_mhlt },
	{ IPOD_ATOM_MHIT, ipod_atom_new_mhit },
	{ IPOD_ATOM_MHOD, ipod_atom_new_mhod },
	{ IPOD_ATOM_MHLP, ipod_atom_new_mhlp },
	{ IPOD_ATOM_MHYP, ipod_atom_new_mhyp },
	{ IPOD_ATOM_MHIP, ipod_atom_new_mhip },
	{ IPOD_ATOM_MQED, ipod_atom_new_mqed },
	{ IPOD_ATOM_PQED, ipod_atom_new_pqed },
	0,0
};

static unsigned long ipod_atom_allocs;
static unsigned long ipod_atom_frees;

extern ipod_atom ipod_atom_new(void) {
	ipod_atom atom = (ipod_atom)ipod_memory_alloc(sizeof(ipod_atom_struct));
	if (atom) {
		atom->tag = 0;
		atom->init = ipod_atom_init_null;
		atom->free = ipod_atom_free_null;
		atom->read = ipod_atom_read_null;
		atom->prepare_to_write = ipod_atom_prepare_to_write_null;
		atom->write = ipod_atom_write_null;
		atom->copy = ipod_atom_copy_null;
#ifdef PLIST
		atom->get_plist = ipod_atom_get_plist_null;
		atom->set_plist = ipod_atom_set_plist_null;
#endif
		atom->data = NULL;
	} else {
		ipod_error("ipod_atom_new(): Cannot create new atom\n");
	}
	ipod_atom_allocs++;
	return atom;
}

char *ipod_tag_str(uint32_t tag)
{
	static char s[5];
	s[0] = tag>>24;
	s[1] = tag>>16;
	s[2] = tag>>8;
	s[3] = tag;
	s[4] = '\0';
	return s;
}

ipod_atom ipod_atom_new_for_tag(uint32_t tag,uint32_t version)
{
	ipod_atom_table_struct *item = ipod_atom_table;
	//printf("creating atom for tag %s\n",ipod_tag_str(tag));
	while (item->tag) {
		if (item->tag==tag) {
			ipod_atom atom = (item->create)();
			ipod_atom_init(atom,version);
			return atom;
		}
		item++;
	}
	ipod_error("ipod_atom_new_for_tag(): unknown tag 0x%x (%s)\n",tag,ipod_tag_str(tag));
	exit(1);
	return NULL;
}

void ipod_atom_init(ipod_atom atom,uint32_t version)
{
	if (atom && atom->init)
		(atom->init)(version,atom->data);
}

void ipod_atom_free(ipod_atom atom)
{
	if (atom) {
		if (atom->free)
			(atom->free)(atom->data);
		ipod_memory_free(atom);
		ipod_atom_frees++;
	} else {
		ipod_error("ipod_atom_free(): Freeing invalid atom\n");
	}
}

void ipod_atom_read(ipod_atom atom,ipod_io io, uint32_t version)
{
	if (atom && atom->read)
		(atom->read)(io,version,atom->data);
	else {
		ipod_error("ipod_atom_read(): Reading invalid atom\n");
	}
}

ipod_atom ipod_atom_read_next(ipod_io io, uint32_t version) {
	uint32_t tag;
	ipod_atom atom;
	tag = ipod_io_get4cc(io);
	atom = ipod_atom_new_for_tag(tag,version);
	if (atom)
		ipod_atom_read(atom,io,version);
	else
		ipod_error("ipod_atom_read_next(): Reading invalid atom\n");
	return atom;
}

void ipod_atom_prepare_to_write(ipod_atom atom, ipod_atom root, uint32_t version)
{
	if (atom && atom->prepare_to_write)
		(atom->prepare_to_write)(root,version,atom->data);
}

void ipod_atom_write(ipod_atom atom,ipod_io io, uint32_t version)
{
	if (atom && atom->write)
		(atom->write)(io,version,atom->data);
}

ipod_atom ipod_atom_copy(ipod_atom atom)
{
	if (atom && atom->copy) {
		ipod_atom copy = ipod_atom_new_for_tag(atom->tag,IPOD_VERSION_ANY); // make new one
		(copy->free)(copy->data); // delete the current newly created data
		copy->data = (atom->copy)(atom->data); // copy the data from the original
		return copy;
	}
	return NULL;
}

#ifdef PLIST
plist_item *ipod_atom_get_plist(ipod_atom atom)
{
	if (atom && atom->get_plist)
		return (atom->get_plist)(atom->data);
	return NULL;
}

void ipod_atom_set_plist(ipod_atom atom,plist_item *plist)
{
	if (atom && atom->set_plist)
		(atom->set_plist)(plist,atom->data);
}
#endif

uint32_t ipod_tag_from_str(char *t)
{
	return ((uint32_t)t[0]<<24)+((uint32_t)t[1]<<16)+((uint32_t)t[2]<<8)+(uint32_t)t[3];
}

#ifdef PLIST
ipod_atom ipod_atom_from_plist(plist_item *plist,uint32_t version) {
	plist_item *tagItem; 
	uint32_t tag;
	ipod_atom atom;
	tagItem = plist_item_dict_at_key(plist,"tag");
	tag = ipod_tag_from_str(plist_item_string_value(tagItem));
	atom = ipod_atom_new_for_tag(tag,version);
	ipod_atom_set_plist(atom,plist);
	return atom;
}
#endif

void ipod_atom_init_null(uint32_t version,void *data)
{
	ipod_error("ipod_atom_init_null()\n");
}

void ipod_atom_free_null(void *data)
{
	ipod_error("ipod_atom_free_null()\n");
}

void ipod_atom_read_null(ipod_io io,uint32_t version,void *data)
{
	ipod_error("ipod_atom_read_null()\n");
}

void ipod_atom_prepare_to_write_null(ipod_atom root,uint32_t version,void *data)
{
	ipod_error("ipod_atom_prepare_to_write_null()\n");
}

void ipod_atom_write_null(ipod_io io, uint32_t version,void *data)
{
	ipod_error("ipod_atom_write_null()\n");
}

void *ipod_atom_copy_null(void *data)
{
	return NULL;
}

#ifdef PLIST
plist_item *ipod_atom_get_plist_null(void *data)
{
	ipod_error("ipod_atom_get_plist_null()\n");
	return NULL;
}

void ipod_atom_set_plist_null(plist_item *plist,void *data)
{
	ipod_error("ipod_atom_set_plist_null()\n");
}
#endif

void ipod_atom_report(void) {
	ipod_error("ipod_atom_report(): ipod_atom allocs %lu frees %lu delta %ld\n",
		ipod_atom_allocs,ipod_atom_frees,
		ipod_atom_allocs-ipod_atom_frees);
}
