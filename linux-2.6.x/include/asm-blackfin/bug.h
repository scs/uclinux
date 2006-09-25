#ifndef _BLACKFIN_BUG_H
#define _BLACKFIN_BUG_H

#ifdef CONFIG_BUG
#define HAVE_ARCH_BUG
#define BUG() do { \
	dump_stack(); \
	printk(KERN_WARNING "\nkernel BUG at %s:%d!\n",
		 __FILE__, __LINE__); \
	panic("BUG!"); \
} while (0)
#endif

#include <asm-generic/bug.h>
#endif
