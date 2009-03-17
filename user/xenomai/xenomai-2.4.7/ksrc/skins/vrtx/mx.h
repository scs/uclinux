/*
 * Copyright (C) 2001,2002 IDEALX (http://www.idealx.com/).
 * Written by Julien Pinon <jpinon@idealx.com>.
 * Copyright (C) 2003 Philippe Gerum <rpm@xenomai.org>.
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

#ifndef _XENO_VRTX_MX_H
#define _XENO_VRTX_MX_H

#include <vrtx/defs.h>

typedef struct vrtxmx {

    xnholder_t link;

#define link2vrtxmx(ln) container_of(ln, vrtxmx_t, link)

    int mid;

    xnthread_t *owner;

    xnsynch_t synchbase;

#ifdef CONFIG_XENO_OPT_REGISTRY
    xnhandle_t handle;
    char name[XNOBJECT_NAME_LEN];
#endif /* CONFIG_XENO_OPT_REGISTRY */

} vrtxmx_t;

#ifdef __cplusplus
extern "C" {
#endif

int vrtxmx_init(void);

void vrtxmx_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* !_XENO_VRTX_MX_H */
