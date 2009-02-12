/*
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


#ifndef _POSIX_INTR_H
#define _POSIX_INTR_H

#include <nucleus/synch.h>
#include <nucleus/intr.h>

#if defined(__KERNEL__) || defined(__XENO_SIM__)

#define PTHREAD_IDESC(xintr)  ((struct pse51_interrupt *)(xintr)->cookie)

struct pse51_interrupt {

    unsigned magic;   /* !< Magic code - must be first */

    xnintr_t intr_base; /* !< Base interrupt object. */

    xnholder_t link;	/* !< Link in pse51_intrq */

#define link2intr(ln) container_of(ln, struct pse51_interrupt, link)

#ifdef CONFIG_XENO_OPT_PERVASIVE

    int mode;		/* !< Interrupt control mode. */

    int pending;	/* !< Pending hits to process. */

    xnsynch_t synch_base; /* !< Base synchronization object. */

#endif /* CONFIG_XENO_OPT_PERVASIVE */
    pse51_kqueues_t *owningq;
};

#ifdef __cplusplus
extern "C" {
#endif

void pse51_intrq_cleanup(pse51_kqueues_t *q);

void pse51_intr_pkg_init(void);

void pse51_intr_pkg_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* __KERNEL__ || __XENO_SIM__ */

#endif /* !_POSIX_INTR_H */
