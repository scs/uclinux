/*
 * Copyright (C) 2004 Anton Blanchard <anton@au.ibm.com>, IBM
 *
 * Based on alpha version.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef OP_BLACKFIN_H
#define OP_BLACKFIN_H 1

#define OP_MAX_COUNTER 2

#include <asm/blackfin.h>

/* Per-counter configuration as set via oprofilefs.  */
struct op_counter_config {
	unsigned long valid;
	unsigned long enabled;
	unsigned long event;
	unsigned long count;
	unsigned long kernel;
	unsigned long user;
	unsigned long unit_mask;
};

/* System-wide configuration as set via oprofilefs.  */
struct op_system_config {
	unsigned long enable_kernel;
	unsigned long enable_user;
};

/* Per-arch configuration */
struct op_bfin533_model {
	int (*reg_setup) (struct op_counter_config *);
	int (*start) (struct op_counter_config *);
	void (*stop) (void);
	int num_counters;
	char *name;
};

static inline unsigned int ctr_read(void)
{
	unsigned int tmp;

	tmp = *pPFCTL;
	__builtin_bfin_csync();

	return tmp;
}

static inline void ctr_write(unsigned int val)
{
	*pPFCTL = val;
	__builtin_bfin_csync();
}

static inline void count_read(unsigned int *count)
{
	count[0] = *pPFCNTR0;
	count[1] = *pPFCNTR1;
	__builtin_bfin_csync();
}

static inline void count_write(unsigned int *count)
{
	*pPFCNTR0 = count[0];
	*pPFCNTR1 = count[1];
	__builtin_bfin_csync();
}

#endif
