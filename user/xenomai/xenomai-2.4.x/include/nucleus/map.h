/**
 * @file
 * @note Copyright (C) 2007 Philippe Gerum <rpm@xenomai.org>.
 *
 * Xenomai is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * \ingroup map
 */

#ifndef _XENO_NUCLEUS_MAP_H
#define _XENO_NUCLEUS_MAP_H

/*! \addtogroup map
 *@{*/

#include <nucleus/types.h>

#define XNMAP_MAX_KEYS	(BITS_PER_LONG * BITS_PER_LONG)

typedef struct xnmap {

    int nkeys;
    int ukeys;
    int offset;
    unsigned long himask;
    unsigned long himap;
#define __IDMAP_LONGS	((XNMAP_MAX_KEYS+BITS_PER_LONG-1)/BITS_PER_LONG)
    unsigned long lomap[__IDMAP_LONGS];
#undef __IDMAP_LONGS
    void *objarray[1];

} xnmap_t;

xnmap_t *xnmap_create(int nkeys,
		      int reserve,
		      int offset);

void xnmap_delete(xnmap_t *map);

int xnmap_enter(xnmap_t *map,
		int key,
		void *objaddr);

int xnmap_remove(xnmap_t *map,
		 int key);

void *xnmap_fetch(xnmap_t *map,
		  int key);

/*@}*/

#endif /* !_XENO_NUCLEUS_MAP_H */
