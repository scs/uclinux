/*
 * ipod_atom_mhyp.h
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

#ifndef __IPOD_ATOM_MHYP_H__
#define __IPOD_ATOM_MHYP_H__

#include "ipod_atom.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint32_t hidden;
	uint32_t timeStamp;
	uint32_t playlistIDLo;
	uint32_t playlistIDHi;
	uint32_t stringMhodCount;
	uint32_t libraryMhodCount;
	uint32_t sortOrder;
	ipod_atom_list mhod_children;
	ipod_atom_list mhip_children;
} ipod_atom_mhyp_struct, *ipod_atom_mhyp;

extern ipod_atom ipod_atom_new_mhyp(void);

extern unsigned long ipod_atom_mhyp_track_item_count(ipod_atom atom);
extern ipod_atom ipod_atom_mhyp_get_track_item_by_index(ipod_atom atom,unsigned long index);
extern ipod_atom ipod_atom_mhyp_new_track_item(ipod_atom atom);
extern void ipod_atom_mhyp_remove_track_item(ipod_atom atom, ipod_atom item);

extern char *ipod_atom_mhyp_get_text_utf8(ipod_atom atom, int tag, char *s);
extern void ipod_atom_mhyp_set_text_utf8(ipod_atom atom, int tag, const char *s);
extern int ipod_atom_mhyp_has_text(ipod_atom atom, int tag);

extern uint32_t ipod_atom_mhyp_get_attribute(ipod_atom atom, int tag);
extern void ipod_atom_mhyp_set_attribute(ipod_atom atom, int tag, uint32_t value);

#ifdef __cplusplus
};
#endif

#endif
