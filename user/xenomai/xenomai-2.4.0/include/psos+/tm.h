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

#ifndef _PSOS_TM_H
#define _PSOS_TM_H

#include <psos+/defs.h>
#include <psos+/psos.h>

#define PSOS_TM_MAGIC 0x81810505

struct psostask;

typedef struct psostm {

    unsigned magic;   /* Magic code - must be first */

    xnholder_t link;

#define link2psostm(ln)  container_of(ln, psostm_t, link)

    u_long data;	/* Event flags or signal */

#ifdef CONFIG_XENO_OPT_REGISTRY
    xnhandle_t handle;
    char name[XNOBJECT_NAME_LEN]; /* Name of timer */
#endif /* CONFIG_XENO_OPT_REGISTRY */

    struct psostask *owner;	/* Timer owner */

    xntimer_t timerbase;

} psostm_t;

extern xntbase_t *psos_tbase;

#ifdef __cplusplus
extern "C" {
#endif

void psostm_init(void);

void psostm_cleanup(void);

void tm_destroy_internal(psostm_t *tm);

u_long tm_start_signal_timer(u_long ticks,
			     u_long interval,
			     int signo,
			     u_long *tmid);
#ifdef __cplusplus
}
#endif

#endif /* !_PSOS_TM_H */
