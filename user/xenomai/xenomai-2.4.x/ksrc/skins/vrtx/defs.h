/*
 * Copyright (C) 2001,2002 IDEALX (http://www.idealx.com/).
 * Written by Julien Pinon <jpinon@idealx.com>.
 * Copyright (C) 2003,2006 Philippe Gerum <rpm@xenomai.org>.
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
 * along with Xenomai; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef _XENO_VRTX_DEFS_H
#define _XENO_VRTX_DEFS_H

#include <nucleus/xenomai.h>
#include <nucleus/registry.h>
#include <nucleus/map.h>
#include <vrtx/vrtx.h>

/* Those should be ^2s and even multiples of BITS_PER_LONG when
   reservation is applicable. */
#define VRTX_MAX_EVENTS  256
#define VRTX_MAX_HEAPS   256
#define VRTX_MAX_MUTEXES 256
#define VRTX_MAX_PTS     512
#define VRTX_MAX_SEMS    256
#define VRTX_MAX_QUEUES  512
#define VRTX_MAX_NTASKS  512	/* Named tasks -- anonymous ones aside. */

#define VRTX_MAX_IDS     512 /* # of available ids per object type. */

#if XNMAP_MAX_KEYS < VRTX_MAX_IDS
#error "Internal map cannot hold so many identifiers"
#endif

#define vrtx_h2obj_active(h,m,t) \
((h) && ((t *)(h))->magic == (m) ? ((t *)(h)) : NULL)

#define vrtx_mark_deleted(t) ((t)->magic = ~(t)->magic)

extern xntbase_t *vrtx_tbase;

#ifdef __cplusplus
extern "C" {
#endif

struct vrtxtask;

int sc_tecreate_inner(struct vrtxtask *task,
		      void (*entry)(void *),
		      int tid,
		      int prio,
		      int mode,
		      u_long user,
		      u_long sys,
		      char *paddr,
		      u_long psize,
		      int *errp);
#ifdef __cplusplus
}
#endif

#endif /* !_XENO_VRTX_DEFS_H */
