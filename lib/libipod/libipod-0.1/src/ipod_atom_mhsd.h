/*
 * ipod_atom_mhsd.h
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

#ifndef __IPOD_ATOM_MHSD_H__
#define __IPOD_ATOM_MHSD_H__

#include "ipod_atom.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	uint32_t index;
	ipod_atom child;
} ipod_atom_mhsd_struct, *ipod_atom_mhsd;

extern ipod_atom ipod_atom_new_mhsd(void);

extern ipod_atom ipod_atom_mhsd_tracks(ipod_atom atom);
extern ipod_atom ipod_atom_mhsd_playlists(ipod_atom atom);
extern ipod_atom ipod_atom_mhsd_podcasts(ipod_atom atom);

#ifdef __cplusplus
};
#endif

#endif
