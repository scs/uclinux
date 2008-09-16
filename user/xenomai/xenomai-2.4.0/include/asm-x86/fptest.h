#ifndef _XENO_ASM_X86_FPTEST_H
#define _XENO_ASM_X86_FPTEST_H

#ifdef __KERNEL__
#include <linux/module.h>
#else /* !__KERNEL__ */
#include <stdio.h>
#define printk printf
#endif /* !__KERNEL__ */

static inline void fp_regs_set(unsigned val)
{
	unsigned i;

	for (i = 0; i < 8; i++)
		__asm__ __volatile__("fildl %0": /* no output */ :"m"(val));
}

static inline unsigned fp_regs_check(unsigned val)
{
	unsigned i, result = val;
	unsigned e[8];

	for (i = 0; i < 8; i++)
		__asm__ __volatile__("fistpl %0":"=m"(e[7 - i]));

	for (i = 0; i < 8; i++)
		if (e[i] != val) {
			printk("r%d: %u != %u\n", i, e[i], val);
			result = e[i];
		}

	return result;
}

#endif /* _XENO_ASM_X86_FPTEST_H */
