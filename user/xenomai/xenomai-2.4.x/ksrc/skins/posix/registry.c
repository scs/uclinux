/*
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@laposte.net>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <posix/registry.h>
#include <posix/thread.h>

#define BITS_PER_INT 32

struct {
	pse51_node_t **node_buckets;
	unsigned buckets_count;

	pse51_desc_t **descs;
	unsigned maxfds;
	unsigned *fdsmap;
	unsigned mapsz;
} pse51_reg;

static unsigned pse51_reg_crunch(const char *key)
{
	unsigned h = 0, g;

#define HQON    24		/* Higher byte position */
#define HBYTE   0xf0000000	/* Higher nibble on */

	while (*key) {
		h = (h << 4) + *key++;
		if ((g = (h & HBYTE)) != 0)
			h = (h ^ (g >> HQON)) ^ g;
	}

	return h % pse51_reg.buckets_count;
}

static int pse51_node_lookup(pse51_node_t *** node_linkp,
			     const char *name, unsigned long magic)
{
	pse51_node_t **node_link;

	if (strnlen(name, sizeof((*node_link)->name)) ==
	    sizeof((*node_link)->name))
		return ENAMETOOLONG;

	node_link = &pse51_reg.node_buckets[pse51_reg_crunch(name)];

	while (*node_link) {
		pse51_node_t *node = *node_link;

		if (!strncmp(node->name, name, PSE51_MAXNAME)
		    && node->magic == magic)
			break;

		node_link = &node->next;
	}

	*node_linkp = node_link;
	return 0;
}

static void pse51_node_unbind(pse51_node_t * node)
{
	pse51_node_t **node_link;

	node_link = node->prev;
	*node_link = node->next;
	if (node->next)
		node->next->prev = node_link;
	node->prev = NULL;
	node->next = NULL;
}

int pse51_node_add(pse51_node_t * node, const char *name, unsigned magic)
{
	pse51_node_t **node_link;
	int err;

	err = pse51_node_lookup(&node_link, name, magic);

	if (err)
		return err;

	if (*node_link)
		return EEXIST;

	node->magic = magic;
	node->flags = 0;
	node->refcount = 1;

	/* Insertion in hash table. */
	node->next = NULL;
	node->prev = node_link;
	*node_link = node;
	strcpy(node->name, name);	/* name length is checked in
					   pse51_node_lookup. */

	return 0;
}

int pse51_node_put(pse51_node_t * node)
{
	if (!pse51_node_ref_p(node))
		return EINVAL;

	--node->refcount;
	return 0;
}

int pse51_node_remove(pse51_node_t ** nodep, const char *name, unsigned magic)
{
	pse51_node_t *node, **node_link;
	int err;

	err = pse51_node_lookup(&node_link, name, magic);

	if (err)
		return err;

	node = *node_link;

	if (!node)
		return ENOENT;

	*nodep = node;
	node->magic = ~node->magic;
	node->flags |= PSE51_NODE_REMOVED;
	pse51_node_unbind(node);
	return 0;
}

/* Look for a node and check the POSIX open flags. */
int pse51_node_get(pse51_node_t ** nodep,
		   const char *name, unsigned long magic, long oflags)
{
	pse51_node_t *node, **node_link;
	int err;

	err = pse51_node_lookup(&node_link, name, magic);
	if (err)
		return err;
	
	node = *node_link;
	if (node && (oflags & (O_CREAT | O_EXCL)) == (O_CREAT | O_EXCL))
		return EEXIST;

	if (!node && !(oflags & O_CREAT))
		return ENOENT;

	*nodep = node;
	if (!node)
		return 0;

	++node->refcount;

	return 0;
}

static int pse51_reg_fd_get(void)
{
	unsigned i;

	for (i = 0; i < pse51_reg.mapsz; i++)
		if (pse51_reg.fdsmap[i]) {
			int fd = ffnz(pse51_reg.fdsmap[i]);

			pse51_reg.fdsmap[i] &= ~(1 << fd);
			return fd + BITS_PER_INT * i;
		}

	return -1;
}

static void pse51_reg_fd_put(int fd)
{
	unsigned i, bit;

	i = fd / BITS_PER_INT;
	bit = 1 << (fd % BITS_PER_INT);

	pse51_reg.fdsmap[i] |= bit;
	pse51_reg.descs[fd] = NULL;
}

static int pse51_reg_fd_lookup(pse51_desc_t ** descp, int fd)
{
	unsigned i, bit;

	if (fd > pse51_reg.maxfds)
		return EBADF;

	i = fd / BITS_PER_INT;
	bit = 1 << (fd % BITS_PER_INT);

	if ((pse51_reg.fdsmap[i] & bit))
		return EBADF;

	*descp = pse51_reg.descs[fd];
	return 0;
}

int pse51_desc_create(pse51_desc_t ** descp, pse51_node_t * node, long flags)
{
	pse51_desc_t *desc;
	spl_t s;
	int fd;

	desc = (pse51_desc_t *) xnmalloc(sizeof(*desc));
	if (!desc)
		return ENOSPC;

	xnlock_get_irqsave(&nklock, s);
	fd = pse51_reg_fd_get();
	if (fd == -1) {
		xnlock_put_irqrestore(&nklock, s);
		xnfree(desc);
		return EMFILE;
	}

	pse51_reg.descs[fd] = desc;
	desc->node = node;
	desc->fd = fd;
	desc->flags = flags;
	xnlock_put_irqrestore(&nklock, s);

	*descp = desc;
	return 0;
}

int pse51_desc_destroy(pse51_desc_t * desc)
{
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	pse51_reg_fd_put(desc->fd);
	xnlock_put_irqrestore(&nklock, s);
	xnfree(desc);
	return 0;
}

int pse51_desc_get(pse51_desc_t ** descp, int fd, unsigned magic)
{
	pse51_desc_t *desc;
	int err;

	err = pse51_reg_fd_lookup(&desc, fd);

	if (err)
		return err;

	if (desc->node->magic != magic
	    /* In case the object has been unlinked. */
	    && desc->node->magic != ~magic)
		return EBADF;

	*descp = desc;
	return 0;
}

#ifdef CONFIG_XENO_OPT_PERVASIVE

DEFINE_XNLOCK(pse51_assoc_lock);

static int pse51_assoc_lookup_inner(pse51_assocq_t * q,
				    pse51_assoc_t ** passoc,
				    u_long key)
{
	pse51_assoc_t *assoc;
	xnholder_t *holder;

	holder = getheadq(q);

	if (!holder) {
		/* empty list. */
		*passoc = NULL;
		return 0;
	}

	do {
		assoc = link2assoc(holder);
		holder = nextq(q, holder);
	}
	while (holder && (assoc->key < key));

	if (assoc->key == key) {
		/* found */
		*passoc = assoc;
		return 1;
	}

	/* not found. */
	if (assoc->key < key)
		*passoc = holder ? link2assoc(holder) : NULL;
	else
		*passoc = assoc;

	return 0;
}

int pse51_assoc_insert(pse51_assocq_t * q, pse51_assoc_t * assoc, u_long key)
{
	pse51_assoc_t *next;
	spl_t s;

	xnlock_get_irqsave(&pse51_assoc_lock, s);

	if (pse51_assoc_lookup_inner(q, &next, key)) {
		xnlock_put_irqrestore(&pse51_assoc_lock, s);
		return -EBUSY;
	}

	assoc->key = key;
	inith(&assoc->link);
	if (next)
		insertq(q, &next->link, &assoc->link);
	else
		appendq(q, &assoc->link);

	xnlock_put_irqrestore(&pse51_assoc_lock, s);

	return 0;
}

pse51_assoc_t *pse51_assoc_lookup(pse51_assocq_t * q, u_long key)
{
	pse51_assoc_t *assoc;
	unsigned found;
	spl_t s;

	xnlock_get_irqsave(&pse51_assoc_lock, s);
	found = pse51_assoc_lookup_inner(q, &assoc, key);
	xnlock_put_irqrestore(&pse51_assoc_lock, s);

	return found ? assoc : NULL;
}

pse51_assoc_t *pse51_assoc_remove(pse51_assocq_t * q, u_long key)
{
	pse51_assoc_t *assoc;
	spl_t s;

	xnlock_get_irqsave(&pse51_assoc_lock, s);
	if (!pse51_assoc_lookup_inner(q, &assoc, key)) {
		xnlock_put_irqrestore(&pse51_assoc_lock, s);
		return NULL;
	}

	removeq(q, &assoc->link);
	xnlock_put_irqrestore(&pse51_assoc_lock, s);

	return assoc;
}

void pse51_assocq_destroy(pse51_assocq_t * q, void (*destroy) (pse51_assoc_t *))
{
	pse51_assoc_t *assoc;
	xnholder_t *holder;
	spl_t s;

	xnlock_get_irqsave(&pse51_assoc_lock, s);
	while ((holder = getq(q))) {
		assoc = link2assoc(holder);
		xnlock_put_irqrestore(&pse51_assoc_lock, s);
		if (destroy)
			destroy(assoc);
		xnlock_get_irqsave(&pse51_assoc_lock, s);
	}
	xnlock_put_irqrestore(&pse51_assoc_lock, s);
}

#endif /* CONFIG_XENO_OPT_PERVASIVE */

pse51_kqueues_t pse51_global_kqueues;

int pse51_reg_pkg_init(unsigned buckets_count, unsigned maxfds)
{
	size_t size, mapsize;
	char *chunk;
	unsigned i;

	mapsize = maxfds / BITS_PER_INT;
	if (maxfds % BITS_PER_INT)
		++mapsize;

	size = sizeof(pse51_node_t) * buckets_count +
		sizeof(pse51_desc_t) * maxfds + sizeof(unsigned) * mapsize;

	chunk = (char *)xnarch_alloc_host_mem(size);
	if (!chunk)
		return ENOMEM;

	pse51_reg.node_buckets = (pse51_node_t **) chunk;
	pse51_reg.buckets_count = buckets_count;
	for (i = 0; i < buckets_count; i++)
		pse51_reg.node_buckets[i] = NULL;

	chunk += sizeof(pse51_node_t) * buckets_count;
	pse51_reg.descs = (pse51_desc_t **) chunk;
	for (i = 0; i < maxfds; i++)
		pse51_reg.descs[i] = NULL;

	chunk += sizeof(pse51_desc_t) * maxfds;
	pse51_reg.fdsmap = (unsigned *)chunk;
	pse51_reg.maxfds = maxfds;
	pse51_reg.mapsz = mapsize;

	/* Initialize fds map. Bit set means "descriptor free". */
	for (i = 0; i < maxfds / BITS_PER_INT; i++)
		pse51_reg.fdsmap[i] = ~0;
	if (maxfds % BITS_PER_INT)
		pse51_reg.fdsmap[mapsize - 1] =
		    (1 << (maxfds % BITS_PER_INT)) - 1;

#ifdef CONFIG_XENO_OPT_PERVASIVE
	xnlock_init(&pse51_assoc_lock);
#endif /* CONFIG_XENO_OPT_PERVASIVE */
	return 0;
}

void pse51_reg_pkg_cleanup(void)
{
	size_t size;
	unsigned i;
	for (i = 0; i < pse51_reg.maxfds; i++)
		if (pse51_reg.descs[i]) {
#if XENO_DEBUG(POSIX)
			xnprintf("Posix: destroying descriptor %d.\n", i);
#endif /* XENO_DEBUG(POSIX) */
			pse51_desc_destroy(pse51_reg.descs[i]);
		}
#if XENO_DEBUG(POSIX)
	for (i = 0; i < pse51_reg.buckets_count; i++) {
		pse51_node_t *node;
		for (node = pse51_reg.node_buckets[i];
		     node;
		     node = node->next)
			xnprintf("Posix: node \"%s\" left aside.\n",
				 node->name);
	}
#endif /* XENO_DEBUG(POSIX) */

	size = sizeof(pse51_node_t) * pse51_reg.buckets_count
		+ sizeof(pse51_desc_t) * pse51_reg.maxfds
		+ sizeof(unsigned) * pse51_reg.mapsz;

	xnarch_free_host_mem(pse51_reg.node_buckets, size);
}
