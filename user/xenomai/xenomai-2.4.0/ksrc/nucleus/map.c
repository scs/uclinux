/**
 * @file
 * @note Copyright (C) 2007 Philippe Gerum <rpm@xenomai.org>.
 *
 * Xenomai is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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

/*!
 * \ingroup nucleus
 * \defgroup map Lightweight key-to-object mapping service
 *
 * A map is a simple indexing structure which associates unique
 * integer keys with pointers to objects.  The current implementation
 * supports reservation, for naming/indexing the real-time objects
 * skins create, either on a fixed, user-provided integer (i.e. a
 * reserved key value), or by drawing the next available key
 * internally if the caller did not specify any fixed key. For
 * instance, in some given map, the key space ranging from 0 to 255
 * could be reserved for fixed keys, whilst the range from 256 to 511
 * could be available for drawing free keys dynamically.
 *
 * A maximum of 1024 unique keys per map is supported on 32bit
 * machines.
 *
 * (This implementation should not be confused with C++ STL maps,
 * which are dynamically expandable and allow arbitrary key types;
 * Xenomai maps don't).
 *
 *@{*/

#include <nucleus/heap.h>
#include <nucleus/pod.h>
#include <nucleus/map.h>

/*!
 * \fn void xnmap_create(int nkeys, int reserve, int offset)
 * \brief Create a map.
 *
 * Allocates a new map with the specified addressing capabilities. The
 * memory is obtained from the Xenomai system heap.
 *
 * @param nkeys The maximum number of unique keys the map will be able
 * to hold. This value cannot exceed the static limit represented by
 * XNMAP_MAX_KEYS, and must be a power of two.
 *
 * @param reserve The number of keys which should be kept for
 * reservation within the index space. Reserving a key means to
 * specify a valid key to the xnmap_enter() service, which will then
 * attempt to register this exact key, instead of drawing the next
 * available key from the unreserved index space. When reservation is
 * in effect, the unreserved index space will hold key values greater
 * than @a reserve, keeping the low key values for the reserved space.
 * For instance, passing @a reserve = 32 would cause the index range [
 * 0 .. 31 ] to be kept for reserved keys.  When non-zero, @a reserve
 * is rounded to the next multiple of BITS_PER_LONG. If @a reserve is
 * zero no reservation will be available from the map.
 *
 * @param offset The lowest key value xnmap_enter() will return to the
 * caller. Key values will be in the range [ 0 + offset .. @a nkeys +
 * offset - 1 ]. Negative offsets are valid.
 *
 * @return the address of the new map is returned on success;
 * otherwise, NULL is returned if @a nkeys is invalid.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 */

xnmap_t *xnmap_create(int nkeys, int reserve, int offset)
{
	xnmap_t *map;
	int mapsize;

	if (nkeys <= 0 || (nkeys & (nkeys - 1)) != 0)
		return NULL;

	mapsize = sizeof(*map) + (nkeys - 1) * sizeof(map->objarray[0]);
	map = (xnmap_t *) xnmalloc(mapsize);

	if (!map)
		return NULL;

	map->ukeys = 0;
	map->nkeys = nkeys;
	map->offset = offset;
	map->himask = (1 << ((reserve + BITS_PER_LONG - 1) / BITS_PER_LONG)) - 1;
	map->himap = ~0;
	memset(map->lomap, ~0, sizeof(map->lomap));
	memset(map->objarray, 0, sizeof(map->objarray[0]) * nkeys);

	return map;
}

/*!
 * \fn void xnmap_delete(xnmap_t *map)
 * \brief Delete a map.
 *
 * Deletes a map, freeing any associated memory back to the Xenomai
 * system heap.
 *
 * @param map The address of the map to delete.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 */

void xnmap_delete(xnmap_t *map)
{
	xnfree(map);
}

/*!
 * \fn void xnmap_enter(xnmap_t *map, int key, void *objaddr)
 * \brief Index an object into a map.
 *
 * Insert a new object into the given map.
 *
 * @param map The address of the map to insert into.
 *
 * @param key The key to index the object on. If this key is within
 * the valid index range [ 0 - offset .. nkeys - offset - 1 ], then an
 * attempt to reserve this exact key is made. If @a key has an
 * out-of-range value lower or equal to 0 - offset - 1, then an
 * attempt is made to draw a free key from the unreserved index space.
 *
 * @param objaddr The address of the object to index on the key. This
 * value will be returned by a successful call to xnmap_fetch() with
 * the same key.
 *
 * @return a valid key is returned on success, either @a key if
 * reserved, or the next free key. Otherwise:
 *
 * - -EEXIST is returned upon attempt to reserve a busy key.
 *
 * - -ENOSPC when no more free key is available.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 */

int xnmap_enter(xnmap_t *map, int key, void *objaddr)
{
	int hi, lo, ofkey = key - map->offset;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (ofkey >= 0 && ofkey < map->nkeys) {
		if (map->objarray[ofkey] != NULL) {
			key = -EEXIST;
			goto unlock_and_exit;
		}
	} else if (map->ukeys >= map->nkeys) {
		key = -ENOSPC;
		goto unlock_and_exit;
	}
	else {
		/* The himask implements a namespace reservation of
		   half of the bitmap space which cannot be used to
		   draw keys. */

		hi = ffnz(map->himap & ~map->himask);
		lo = ffnz(map->lomap[hi]);
		ofkey = hi * BITS_PER_LONG + lo;
		++map->ukeys;

		__clrbits(map->lomap[hi], 1UL << lo);

		if (map->lomap[hi] == 0)
			__clrbits(map->himap, 1UL << hi);
	}

	map->objarray[ofkey] = objaddr;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return ofkey + map->offset;
}

/*!
 * \fn void xnmap_remove(xnmap_t *map, int key)
 * \brief Remove an object reference from a map.
 *
 * Removes an object reference from the given map, releasing the
 * associated key.
 *
 * @param map The address of the map to remove from.
 *
 * @param key The key the object reference to be removed is indexed
 * on.
 *
 * @return 0 is returned on success. Otherwise:
 *
 * - -ESRCH is returned if @a key is invalid.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 */

int xnmap_remove(xnmap_t *map, int key)
{
	int ofkey = key - map->offset, hi, lo;
	spl_t s;

	if (ofkey < 0 || ofkey >= map->nkeys)
		return -ESRCH;

	hi = ofkey / BITS_PER_LONG;
	lo = ofkey % BITS_PER_LONG;
	xnlock_get_irqsave(&nklock, s);
	map->objarray[ofkey] = NULL;
	__setbits(map->himap, 1UL << hi);
	__setbits(map->lomap[hi], 1UL << lo);
	--map->ukeys;
	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/*!
 * \fn void xnmap_fetch(xnmap_t *map, int key)
 * \brief Search an object into a map.
 *
 * Retrieve an object reference from the given map by its index key.
 *
 * @param map The address of the map to retrieve from.
 *
 * @param key The key to be searched for in the map index.
 *
 * @return The indexed object address is returned on success,
 * otherwise NULL is returned when @a key is invalid or no object is
 * currently indexed on it.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 */

void *xnmap_fetch(xnmap_t *map, int key)
{
	int ofkey = key - map->offset;

	if (ofkey < 0 || ofkey >= map->nkeys)
		return NULL;

	return map->objarray[ofkey];
}

/*@}*/

EXPORT_SYMBOL(xnmap_create);
EXPORT_SYMBOL(xnmap_delete);
EXPORT_SYMBOL(xnmap_enter);
EXPORT_SYMBOL(xnmap_remove);
EXPORT_SYMBOL(xnmap_fetch);
