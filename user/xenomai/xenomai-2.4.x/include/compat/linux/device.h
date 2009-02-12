/*
 * Copyright (C) 2005 Philippe Gerum <rpm@xenomai.org>.
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
 */

#ifndef _XENO_COMPAT_LINUX_DEVICE_H
#define _XENO_COMPAT_LINUX_DEVICE_H

#define DECLARE_DEVCLASS(clname) void *clname /* Optimized out */
#define DECLARE_DEVHANDLE(devh)  void *devh /* Optimized out */
#define class_create(a,b)			NULL
#define wrap_device_create(a,b,c,d,e,args...)	NULL
#define wrap_device_destroy(a,b)
#define class_destroy(a)

#endif /* _XENO_COMPAT_LINUX_DEVICE_H */
