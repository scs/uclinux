/*
 * Copyright (C) 2006 Gilles Chanteperdrix <gilles.chanteperdrix@laposte.net>
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
 */

#ifndef _XENO_NUCLEUS_BHEAP_H
#define _XENO_NUCLEUS_BHEAP_H

#include <nucleus/compiler.h>

/* debug support */
#include <nucleus/assert.h>

#ifndef CONFIG_XENO_OPT_DEBUG_QUEUES
#define CONFIG_XENO_OPT_DEBUG_QUEUES 0
#endif

/* Priority queue implementation, using a binary heap. */

typedef unsigned long long bheap_key_t;

typedef struct bheaph {
	bheap_key_t key;
	unsigned prio;
	unsigned pos;
} bheaph_t;

#define bheaph_init(holder) do { } while (0)
#define bheaph_key(holder)  ((holder)->key)
#define bheaph_prio(holder) ((holder)->prio)
#define bheaph_pos(holder)  ((holder)->pos)
#define bheaph_lt(h1, h2)   ((long long) ((h1)->key - (h2)->key) < 0 ||	\
                             ((h1)->key == (h2)->key &&			\
                              (h1)->prio > (h2)->prio))

typedef struct bheap {
	unsigned sz;
	unsigned last;
	bheaph_t *elems[1]; /* only padding, indexing starts at 1 */
} bheap_t;

#define DECLARE_BHEAP_CONTAINER(name, sz)       \
	struct {				\
		bheap_t bheap;			\
		bheaph_t *elems[sz];		\
	} name

/* Check the binary heap invariant. */
static inline int bheap_ordered(bheap_t *heap)
{
	unsigned i;
	for (i = 2; i < heap->last; i++)
		if (bheaph_lt(heap->elems[i], heap->elems[i / 2]))
			return 0;
	return 1;
}

#define BHEAP_CHECK(heap)						\
	XENO_BUGON(QUEUES, ((heap)->sz == 0) || !bheap_ordered(heap))

#define bheap_gethead(heap)				\
	({                                              \
		bheap_t *_bheap = &(heap)->bheap;	\
		BHEAP_CHECK(_bheap);			\
		__internal_bheap_gethead(_bheap);	\
	})

static inline bheaph_t *__internal_bheap_gethead(bheap_t *heap)
{
	if (heap->last == 1)
		return NULL;

	return heap->elems[1];
}

#define bheap_next(heap, holder)			\
	({						\
		bheap_t *_bheap = &(heap)->bheap;	\
		BHEAP_CHECK(_bheap);			\
		__internal_bheap_next(_bheap, holder);	\
	})

static inline bheaph_t *__internal_bheap_next(bheap_t *heap, bheaph_t *holder)
{
	unsigned pos;

	if (unlikely(bheaph_pos(holder) >= heap->last
		     || heap->elems[bheaph_pos(holder)] != holder))
		return (bheaph_t *) ERR_PTR(-EINVAL);

	pos = bheaph_pos(holder) + 1;

	return likely(pos < heap->last) ? heap->elems[pos] : NULL;
}

static inline bheaph_t *bheaph_parent(bheap_t *heap, bheaph_t *holder)
{
	const unsigned pos = holder->pos;

	return likely(pos > 1) ? heap->elems[pos / 2] : NULL;
}

static inline bheaph_t *bheaph_child(bheap_t *heap, bheaph_t *holder, int side)
{
	const unsigned pos = 2 * holder->pos + side;

	return likely(pos < heap->last) ? heap->elems[pos] : NULL;
}

#define bheap_init(heap, sz) __internal_bheap_init(&(heap)->bheap, sz)

static inline void __internal_bheap_init(bheap_t *heap, unsigned sz)
{
	heap->sz = sz;
	heap->last = 1;
}

#define bheap_destroy(heap) __internal_bheap_destroy(&(heap)->bheap)

static inline void __internal_bheap_destroy(bheap_t *heap)
{
	heap->sz = 0;
	heap->last = 1;
}

static inline void bheap_swap(bheap_t *heap, bheaph_t *h1, bheaph_t *h2)
{
	const unsigned pos2 = bheaph_pos(h2);

	heap->elems[bheaph_pos(h1)] = h2;
	bheaph_pos(h2) = bheaph_pos(h1);
	heap->elems[pos2] = h1;
	bheaph_pos(h1) = pos2;
}

static inline void bheap_up(bheap_t *heap, bheaph_t *holder)
{
	bheaph_t *parent;

	while ((parent = bheaph_parent(heap, holder)) && bheaph_lt(holder, parent))
		bheap_swap(heap, holder, parent);
}

static inline void bheap_down(bheap_t *heap, bheaph_t *holder)
{
	bheaph_t *left, *right, *minchild;

	for (;;) {
		left = bheaph_child(heap, holder, 0);
		right = bheaph_child(heap, holder, 1);

		if (left && right)
			minchild = bheaph_lt(left, right) ? left : right;
		else
			minchild = left ?: right;

		if (!minchild || bheaph_lt(holder, minchild))
			break;

		bheap_swap(heap, minchild, holder);
	}
}

#define bheap_insert(heap, holder)				\
	({							\
		bheap_t *_bheap = &(heap)->bheap;		\
		BHEAP_CHECK(_bheap);				\
		__internal_bheap_insert(_bheap, holder);	\
	})

static inline int __internal_bheap_insert(bheap_t *heap, bheaph_t *holder)
{
	if (heap->last == heap->sz + 1)
		return EBUSY;

	heap->elems[heap->last] = holder;
	bheaph_pos(holder) = heap->last;
	++heap->last;
	bheap_up(heap, holder);
	return 0;
}

#define bheap_delete(heap, holder)				\
	({							\
		bheap_t *_bheap = &(heap)->bheap;		\
		BHEAP_CHECK(_bheap);				\
		__internal_bheap_delete(_bheap, holder);	\
	})

static inline int __internal_bheap_delete(bheap_t *heap, bheaph_t *holder)
{
	bheaph_t *lasth;

	if (unlikely(bheaph_pos(holder) >= heap->last
		     || heap->elems[bheaph_pos(holder)] != holder))
		return EINVAL;

	--heap->last;
	if (heap->last != bheaph_pos(holder)) {
		bheaph_t *parent;
		lasth = heap->elems[heap->last];
		heap->elems[bheaph_pos(holder)] = lasth;
		bheaph_pos(lasth) = bheaph_pos(holder);
		if ((parent = bheaph_parent(heap, lasth)) && bheaph_lt(lasth, parent))
			bheap_up(heap, lasth);
		else
			bheap_down(heap, lasth);
	}

	return 0;
}

#define bheap_get(heap)					\
	({                                              \
		bheap_t *_bheap = &(heap)->bheap;	\
		BHEAP_CHECK(_bheap);			\
		__internal_bheap_get(_bheap, holder);	\
	})

static inline bheaph_t *__internal_bheap_get(bheap_t *heap)
{
	bheaph_t *holder = __internal_bheap_gethead(heap);

	if (!holder)
		return NULL;

	__internal_bheap_delete(heap, holder);

	return holder;
}

#endif /* _XENO_NUCLEUS_BHEAP_H */
