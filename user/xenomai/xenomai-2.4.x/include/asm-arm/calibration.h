/*
 * Copyright (C) 2001,2002,2003,2004,2005 Philippe Gerum <rpm@xenomai.org>.
 *
 * ARM port
 *   Copyright (C) 2005 Stelian Pop
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
 */

#ifndef _XENO_ASM_ARM_CALIBRATION_H
#define _XENO_ASM_ARM_CALIBRATION_H

#ifndef _XENO_ASM_ARM_BITS_INIT_H
#error "please don't include asm/calibration.h directly"
#endif

static inline unsigned long xnarch_get_sched_latency (void)
{
#if CONFIG_XENO_OPT_TIMING_SCHEDLAT != 0
	return CONFIG_XENO_OPT_TIMING_SCHEDLAT;
#else
	return 9500;	/* XXX sane ? */
#endif
}

#endif /* !_XENO_ASM_ARM_CALIBRATION_H */

// vim: ts=4 et sw=4 sts=4
