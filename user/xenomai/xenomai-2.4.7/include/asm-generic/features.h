/*
 * Copyright (C) 2005 Philippe Gerum <rpm@xenomai.org>.
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

#ifndef _XENO_ASM_GENERIC_FEATURES_H
#define _XENO_ASM_GENERIC_FEATURES_H

#ifdef __KERNEL__
#include <linux/version.h>
#else /* !__KERNEL__ */
#include <xeno_config.h>
#endif /* __KERNEL__ */

#define __xn_feat_smp     0x80000000

#ifdef CONFIG_SMP
#define __xn_feat_smp_mask __xn_feat_smp
#else
#define __xn_feat_smp_mask 0
#endif

#define __xn_feat_generic_mask  __xn_feat_smp_mask

static inline const char *get_generic_feature_label (unsigned feature)
{
    switch (feature) {
    	case __xn_feat_smp:
	    return "smp";
    	default:
	    return 0;
    }
}

#endif /* !_XENO_ASM_GENERIC_FEATURES_H */
