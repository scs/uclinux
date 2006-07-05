#ifndef __MMU_H
#define __MMU_H

/* Copyright (C) 2002, David McCullough <davidm@snapgear.com> */

typedef struct {
	struct vm_list_struct *vmlist;
	unsigned long end_brk;
	unsigned long stack_start;

#ifdef CONFIG_BINFMT_ELF_FDPIC
	unsigned long	exec_fdpic_loadmap;
	unsigned long	interp_fdpic_loadmap;
#endif

} mm_context_t;

#endif
