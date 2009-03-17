/*
 * Copyright (C) 2006 Wolfgang Grandegger <wg@grandegger.com>
 *
 * Derived from RTnet project file stack/include/rtnet_internal.h:
 *
 * Copyright (C) 1999       Lineo, Inc
 *               1999, 2002 David A. Schleef <ds@schleef.org>
 *               2002       Ulrich Marx <marx@kammer.uni-hannover.de>
 *               2003-2005  Jan Kiszka <jan.kiszka@web.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef __RTCAN_INTERNAL_H_
#define __RTCAN_INTERNAL_H_

#include <linux/module.h>
#include <rtdm/rtdm_driver.h>

#ifndef LIST_POISON1
/* 2.4 - 2.6 compatibility stuff */
#define LIST_POISON1  ((void *) 0x0)
#endif

#ifdef CONFIG_XENO_DRIVERS_CAN_DEBUG
#define RTCAN_ASSERT(expr, func) \
    if (!(expr)) { \
        rtdm_printk("Assertion failed! %s:%s:%d %s\n", \
        __FILE__, __FUNCTION__, __LINE__, (#expr)); \
        func \
    }
#else
#define RTCAN_ASSERT(expr, func)
#endif /* CONFIG_RTCAN_CHECKED */

#ifdef CONFIG_PROC_FS
#include <linux/proc_fs.h>

/* Derived from Erwin Rol's rtai_proc_fs.h.
   Standard version assumes that output fits into the provided buffer,
   extended version also deals with potential fragmentation. */

#define RTCAN_PROC_PRINT_VARS(MAX_BLOCK_LEN)                            \
    const int max_block_len = MAX_BLOCK_LEN;                            \
    off_t __limit           = count - MAX_BLOCK_LEN;                    \
    int   __len             = 0;                                        \
                                                                        \
    *eof = 1;                                                           \
    if (count < MAX_BLOCK_LEN)                                          \
        return 0

#define RTCAN_PROC_PRINT(fmt, args...)                                  \
    ({                                                                  \
        __len += snprintf(buf + __len, max_block_len, fmt, ##args);     \
        (__len <= __limit);                                             \
    })

#define RTCAN_PROC_PRINT_DONE                                           \
    return __len


#define RTCAN_PROC_PRINT_VARS_EX(MAX_BLOCK_LEN)                         \
    const int max_block_len = MAX_BLOCK_LEN;                            \
    off_t __limit           = offset + count - MAX_BLOCK_LEN;           \
    off_t __pos             = 0;                                        \
    off_t __begin           = 0;                                        \
    int   __len             = 0;                                        \
                                                                        \
    *eof = 1;                                                           \
    if (count < MAX_BLOCK_LEN)                                          \
        return 0

#define RTCAN_PROC_PRINT_EX(fmt, args...)                               \
    ({                                                                  \
        int len = snprintf(buf + __len, max_block_len, fmt, ##args);    \
        __len += len;                                                   \
        __pos += len;                                                   \
        if (__pos < offset) {                                           \
            __len = 0;                                                  \
            __begin = __pos;                                            \
        }                                                               \
        if (__pos > __limit)                                            \
            *eof = 0;                                                   \
        (__pos <= __limit);                                             \
    })

#define RTCAN_PROC_PRINT_DONE_EX                                        \
    *start = buf + (offset - __begin);                                  \
    __len -= (offset - __begin);                                        \
    if (__len > count)                                                  \
        __len = count;                                                  \
    if (__len < 0)                                                      \
        __len = 0;                                                      \
    return __len;

#endif /* CONFIG_PROC_FS */

#ifdef CONFIG_XENO_DRIVERS_CAN_DEBUG
# define RTCAN_DBG(fmt,args...) do { printk(fmt ,##args); } while (0)
# define RTCAN_RTDM_DBG(fmt,args...) do { rtdm_printk(fmt ,##args); } while (0)
#else
# define RTCAN_DBG(fmt,args...) do {} while (0)
# define RTCAN_RTDM_DBG(fmt,args...) do {} while (0)
#endif

#endif /* __RTCAN_INTERNAL_H_ */

