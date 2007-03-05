/*
 * ipod_atom_pqed.h
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

#ifndef __IPOD_ATOM_PQED_H__
#define __IPOD_ATOM_PQED_H__

#include <ipod/ipod_string.h>
#include "ipod_atom.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	char *name; // stored as utf-8
	int32_t preamp; // -1200..1200 (dB*100)
	int32_t bands0[10]; // bands used in the client, -1200..1200 (dB*100)
	int32_t bands1[5]; // bands used in the device, -1200..1200 (dB*100)
} ipod_atom_pqed_struct, *ipod_atom_pqed;

extern ipod_atom ipod_atom_new_pqed(void);

extern char *ipod_atom_pqed_get_text_utf8(ipod_atom atom, int tag, char *s);
extern void ipod_atom_pqed_set_text_utf8(ipod_atom atom, int tag, const char *s);
extern int ipod_atom_pqed_has_text(ipod_atom atom, int tag);

extern int32_t ipod_atom_pqed_get_attribute(ipod_atom atom, int tag);
extern void ipod_atom_pqed_set_attribute(ipod_atom atom, int tag, int32_t value);

#ifdef __cplusplus
};
#endif

#endif
