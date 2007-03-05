/*
 * ipod_private.h
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

#ifndef __IPOD_PRIVATE_H__
#define __IPOD_PRIVATE_H__

#include "ipod_atom.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	char *basePath;
	char *dbPath;
	char *sdPath;
	char *eqPath;
	ipod_atom db;
	ipod_atom eq;
	int db_dirty;
	int eq_dirty;
} ipod_private_struct, *ipod_p;

typedef struct {
	ipod_atom track;
	ipod_p ipod;
} ipod_track_private_struct, *ipod_track_p;

typedef struct {
	ipod_atom playlist;
	ipod_p ipod;
} ipod_playlist_private_struct, *ipod_playlist_p;

typedef struct {
	ipod_atom track_item;
	ipod_playlist_p playlist;
	ipod_p ipod;
} ipod_track_item_private_struct, *ipod_track_item_p;

typedef struct {
	ipod_atom preset;
	ipod_p ipod;
} ipod_eq_preset_private_struct, *ipod_eq_preset_p;

#ifdef __cplusplus
};
#endif

#endif
