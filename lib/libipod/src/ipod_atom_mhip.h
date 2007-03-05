/*
 * ipod_atom_mhip.h
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

#ifndef __IPOD_ATOM_MHIP_H__
#define __IPOD_ATOM_MHIP_H__

#include "ipod_atom.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint32_t dataObjectChildCount;
	uint32_t podcastGroupingFlag;
	uint32_t groupID;
	uint32_t trackID;
	uint32_t timeStamp;
	uint32_t podcastGroupingReference;
} ipod_atom_mhip_struct, *ipod_atom_mhip;

extern ipod_atom ipod_atom_new_mhip(void);

extern uint32_t ipod_atom_mhip_get_attribute(ipod_atom atom, int tag);
extern void ipod_atom_mhip_set_attribute(ipod_atom atom, int tag, uint32_t value);

#ifdef __cplusplus
};
#endif

#endif
