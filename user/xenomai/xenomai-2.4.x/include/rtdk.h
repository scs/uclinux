/*
 * Copyright (C) 2007 Jan Kiszka <jan.kiszka@web.de>.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
 */

#ifndef _RTUTILS_H
#define _RTUTILS_H

#ifdef __KERNEL__

#define rt_printf(format, ...)	printk(format __VA_ARGS__)

static inline int rt_print_init(size_t buffer_size, const char *buffer_name)
{
	return 0;
}

#define rt_print_cleanup()	do { } while (0)

static inline void rt_print_auto_init(int enable)
{
}

static inline const char *rt_print_buffer_name(void)
{
	return "<unknown>";
}

#else /* !__KERNEL__ */

#include <stdio.h>
#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

int rt_vfprintf(FILE *stream, const char *format, va_list args);
int rt_vprintf(const char *format, va_list args);
int rt_fprintf(FILE *stream, const char *format, ...);
int rt_printf(const char *format, ...);

int rt_print_init(size_t buffer_size, const char *name);
void rt_print_cleanup(void);
void rt_print_auto_init(int enable);
const char *rt_print_buffer_name(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* !KERNEL */

#endif /* !_RTUTILS_H */
