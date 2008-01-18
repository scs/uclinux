/*
 * ipod_atom.h
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

#ifndef __IPOD_ATOM_H__
#define __IPOD_ATOM_H__

#include <ipod/ipod_io.h>
#ifdef PLIST
#include "plist.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif


typedef struct ipod_atom_struct_t *ipod_atom;

//
// bottleneck functions
//
typedef void (*ipod_atom_init_func)(uint32_t version,void *data);
typedef void (*ipod_atom_free_func)(void *data);
typedef void (*ipod_atom_read_func)(ipod_io io,uint32_t version,void *data);
typedef void (*ipod_atom_prepare_to_write_func)(ipod_atom root, uint32_t version,void *data);
typedef void (*ipod_atom_write_func)(ipod_io io, uint32_t version,void *data);
typedef void *(*ipod_atom_copy_func)(void *data);

#ifdef PLIST
typedef plist_item *(*ipod_atom_get_plist_func)(void *data);
typedef void (*ipod_atom_set_plist_func)(plist_item *plist,void *data);
#endif

typedef struct ipod_atom_struct_t {
	uint32_t tag;
	ipod_atom_init_func init;
	ipod_atom_free_func free;
	ipod_atom_read_func read;
	ipod_atom_prepare_to_write_func prepare_to_write;
	ipod_atom_write_func write;
	ipod_atom_copy_func copy;
#ifdef PLIST
	ipod_atom_get_plist_func get_plist;
	ipod_atom_set_plist_func set_plist;
#endif
	void *data; // atom type-specific data
} ipod_atom_struct;

//
// standard routines
//
extern ipod_atom ipod_atom_new(void);
extern ipod_atom ipod_atom_new_for_tag(uint32_t tag,uint32_t version);
extern void ipod_atom_init(ipod_atom atom,uint32_t version);
extern void ipod_atom_free(ipod_atom atom);
extern void ipod_atom_read(ipod_atom atom,ipod_io io, uint32_t version);
extern ipod_atom ipod_atom_read_next(ipod_io io, uint32_t version);
extern void ipod_atom_prepare_to_write(ipod_atom atom, ipod_atom root, uint32_t version);
extern void ipod_atom_write(ipod_atom atom,ipod_io io, uint32_t version);
extern ipod_atom ipod_atom_copy(ipod_atom atom);

#ifdef PLIST
extern plist_item *ipod_atom_get_plist(ipod_atom atom);
extern void ipod_atom_set_plist(ipod_atom atom,plist_item *plist);
extern ipod_atom ipod_atom_from_plist(plist_item *plist,uint32_t version);
#endif

//
// stub bottlenecks
//
extern void ipod_atom_init_null(uint32_t version,void *data);
extern void ipod_atom_free_null(void *data);
extern void ipod_atom_read_null(ipod_io io,uint32_t version,void *data);
extern void ipod_atom_prepare_to_write_null(ipod_atom root,uint32_t version,void *data);
extern void ipod_atom_write_null(ipod_io io, uint32_t version,void *data);
extern void *ipod_atom_copy_null(void *data);

#ifdef PLIST
extern plist_item *ipod_atom_get_plist_null(void *data);
extern void ipod_atom_set_plist_null(plist_item *plist,void *data);
#endif

//
// lists of atoms
//
typedef struct {
	ipod_atom *atoms;
	size_t count;
} ipod_atom_list_struct, *ipod_atom_list;

extern ipod_atom_list ipod_atom_list_new(void);
extern void ipod_atom_list_free(ipod_atom_list list);
extern ipod_atom_list ipod_atom_list_shallow_copy(ipod_atom_list list);
extern ipod_atom ipod_atom_list_get(ipod_atom_list list,int index);
extern void ipod_atom_list_put(ipod_atom_list list,int index,ipod_atom atom);
extern size_t ipod_atom_list_length(ipod_atom_list list);
extern void ipod_atom_list_remove(ipod_atom_list list,ipod_atom atom);
extern void ipod_atom_list_remove_index(ipod_atom_list list,int index);
extern void ipod_atom_list_remove_and_free_all(ipod_atom_list list);
extern long ipod_atom_list_index(ipod_atom_list list,ipod_atom atom);
extern void ipod_atom_list_append(ipod_atom_list list,ipod_atom atom);
extern void ipod_atom_list_read(ipod_atom_list list,size_t count,ipod_io io,uint32_t version);
extern void ipod_atom_list_prepare_to_write(ipod_atom_list list,ipod_atom root, uint32_t version);
extern void ipod_atom_list_write(ipod_atom_list list,ipod_io io,uint32_t version);
extern ipod_atom_list ipod_atom_list_copy(ipod_atom_list list);

#ifdef PLIST
extern plist_item *ipod_atom_list_get_plist(ipod_atom_list list);
extern void ipod_atom_list_set_plist(ipod_atom_list list,plist_item *item);
#endif
extern void ipod_atom_list_shuffle(ipod_atom_list list);

//
// misc stuff
//
extern char *ipod_tag_str(uint32_t tag); // NOTE: uses shared static string buffer
extern uint32_t ipod_tag_from_str(char *t);

extern void ipod_atom_report(void);

#ifdef __cplusplus
};
#endif

#endif
