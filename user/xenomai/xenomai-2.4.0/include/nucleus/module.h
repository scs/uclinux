/*
 * Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
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

#ifndef _XENO_NUCLEUS_MODULE_H
#define _XENO_NUCLEUS_MODULE_H

#include <nucleus/queue.h>
#include <nucleus/timebase.h>

#define XNMOD_GHOLDER_REALLOC   128 /* Realloc count */
#define XNMOD_GHOLDER_THRESHOLD 64  /* Safety threshold */

#ifdef __cplusplus
extern "C" {
#endif

void xnmod_alloc_glinks(xnqueue_t *freehq);

#ifdef __cplusplus
}
#endif

extern xnqueue_t xnmod_glink_queue;

extern u_long xnmod_sysheap_size;

#ifdef CONFIG_XENO_OPT_STATS
void xnpod_declare_tbase_proc(xntbase_t *base);
void xnpod_discard_tbase_proc(xntbase_t *base);
#else /* !CONFIG_XENO_OPT_STATS */
static inline void xnpod_declare_tbase_proc(xntbase_t *base) { }
static inline void xnpod_discard_tbase_proc(xntbase_t *base) { }
#endif /* !CONFIG_XENO_OPT_STATS */

#endif /* !_XENO_NUCLEUS_MODULE_H */
