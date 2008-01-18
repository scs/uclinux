/*
 * ipod_atom_mhod.h
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

#ifndef __IPOD_ATOM_MHOD_H__
#define __IPOD_ATOM_MHOD_H__

#include "ipod_atom.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint32_t position;
	uint32_t unk3;
	uint32_t unk4;
	size_t length;
	char *string;
} ipod_atom_mhod_string_struct;

typedef struct {
	size_t length;
	char *string;
} ipod_atom_mhod_url_struct;

typedef struct {
	size_t length;
	char *data;
} ipod_atom_mhod_raw_struct;

typedef struct {
	uint32_t sortIndex;
	size_t count;
	uint32_t *indices;
} ipod_atom_mhod_library_index_struct;

typedef struct {
	uint32_t type;
	uint32_t unk1;
	uint32_t unk2;
	union {
		ipod_atom_mhod_string_struct ipod_atom_mhod_string;
		ipod_atom_mhod_url_struct ipod_atom_mhod_url;
		ipod_atom_mhod_raw_struct ipod_atom_mhod_raw;
		ipod_atom_mhod_library_index_struct ipod_atom_mhod_library_index;
	} data;
} ipod_atom_mhod_struct, *ipod_atom_mhod;

extern ipod_atom ipod_atom_new_mhod(void);

extern ipod_atom ipod_atom_new_mhod_string(int tag,const char *s);
extern char *ipod_atom_mhod_string_get(ipod_atom atom,char *s);
extern void ipod_atom_mhod_string_set(ipod_atom atom,const char *s);

extern ipod_atom ipod_atom_new_mhod_url(int tag,const char *s);
extern char *ipod_atom_mhod_url_get(ipod_atom atom,char *s);
extern void ipod_atom_mhod_url_set(ipod_atom atom,const char *s);

extern ipod_atom ipod_atom_new_mhod_library_index(int key);

#ifdef __cplusplus
};
#endif

#endif
