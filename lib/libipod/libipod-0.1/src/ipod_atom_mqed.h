 /*
 * ipod_atom_mqed.h
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

#ifndef __IPOD_ATOM_MQED_H__
#define __IPOD_ATOM_MQED_H__

#include "ipod_atom.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint32_t unk1;
	uint32_t unk2;
	ipod_atom_list children;
} ipod_atom_mqed_struct, *ipod_atom_mqed;

extern ipod_atom ipod_atom_new_mqed(void);

extern unsigned long ipod_atom_mqed_preset_count(ipod_atom atom);
extern ipod_atom ipod_atom_mqed_get_preset_by_index(ipod_atom atom,unsigned long index);
extern ipod_atom ipod_atom_mqed_new_preset(ipod_atom atom);
extern void ipod_atom_mqed_remove_preset(ipod_atom atom, ipod_atom item);

#ifdef __cplusplus
};
#endif

#endif
