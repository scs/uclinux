/*
 * ipod_private_constants.h
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

#ifndef __IPOD_PRIVATE_CONSTANTS_H__
#define __IPOD_PRIVATE_CONSTANTS_H__

#ifdef __cplusplus
extern "C" {
#endif

//
// iTunesDB database atom types
//
#define IPOD_ATOM_MHBD 0x6d686264
#define IPOD_ATOM_MHSD 0x6d687364
#define IPOD_ATOM_MHLT 0x6d686c74
#define IPOD_ATOM_MHIT 0x6d686974
#define IPOD_ATOM_MHOD 0x6d686f64
#define IPOD_ATOM_MHLP 0x6d686c70
#define IPOD_ATOM_MHYP 0x6d687970
#define IPOD_ATOM_MHIP 0x6d686970

// iTunesEQPresets database atom types
#define IPOD_ATOM_MQED 0x6d716564
#define IPOD_ATOM_PQED 0x70716564

#ifdef __cplusplus
};
#endif

#endif
