#ifndef _XENO_ASM_POWERPC_FPTEST_H
#define _XENO_ASM_POWERPC_FPTEST_H

#ifdef __KERNEL__
#include <linux/module.h>
#else /* !__KERNEL__ */
#include <stdio.h>
#define printk printf
#endif /* !__KERNEL__ */

static inline void fp_regs_set(unsigned val)
{
	uint64_t fpval = val;
	__asm__ __volatile__("lfd	0, %0\n"
			     "	fmr	1, 0\n"
			     "	fmr	2, 0\n"
			     "	fmr	3, 0\n"
			     "	fmr	4, 0\n"
			     "	fmr	5, 0\n"
			     "	fmr	6, 0\n"
			     "	fmr	7, 0\n"
			     "	fmr	8, 0\n"
			     "	fmr	9, 0\n"
			     "	fmr	10, 0\n"
			     "	fmr	11, 0\n"
			     "	fmr	12, 0\n"
			     "	fmr	13, 0\n"
			     "	fmr	14, 0\n"
			     "	fmr	15, 0\n"
			     "	fmr	16, 0\n"
			     "	fmr	17, 0\n"
			     "	fmr	18, 0\n"
			     "	fmr	19, 0\n"
			     "	fmr	20, 0\n"
			     "	fmr	21, 0\n"
			     "	fmr	22, 0\n"
			     "	fmr	23, 0\n"
			     "	fmr	24, 0\n"
			     "	fmr	25, 0\n"
			     "	fmr	26, 0\n"
			     "	fmr	27, 0\n"
			     "	fmr	28, 0\n"
			     "	fmr	29, 0\n"
			     "	fmr	30, 0\n"
			     "	fmr	31, 0\n"::"m"(fpval));
}

#define FPTEST_REGVAL(n) {						\
	uint64_t t;							\
	__asm__ __volatile__("	stfd	" #n ", %0" : "=m" (t));	\
	e[n] = (unsigned)t;						\
	}

static inline unsigned fp_regs_check(unsigned val)
{
	unsigned i, result = val;
	uint32_t e[32];

	FPTEST_REGVAL(0);
	FPTEST_REGVAL(1);
	FPTEST_REGVAL(2);
	FPTEST_REGVAL(3);
	FPTEST_REGVAL(4);
	FPTEST_REGVAL(5);
	FPTEST_REGVAL(6);
	FPTEST_REGVAL(7);
	FPTEST_REGVAL(8);
	FPTEST_REGVAL(9);
	FPTEST_REGVAL(10);
	FPTEST_REGVAL(11);
	FPTEST_REGVAL(12);
	FPTEST_REGVAL(13);
	FPTEST_REGVAL(14);
	FPTEST_REGVAL(15);
	FPTEST_REGVAL(16);
	FPTEST_REGVAL(17);
	FPTEST_REGVAL(18);
	FPTEST_REGVAL(19);
	FPTEST_REGVAL(20);
	FPTEST_REGVAL(21);
	FPTEST_REGVAL(22);
	FPTEST_REGVAL(23);
	FPTEST_REGVAL(24);
	FPTEST_REGVAL(25);
	FPTEST_REGVAL(26);
	FPTEST_REGVAL(27);
	FPTEST_REGVAL(28);
	FPTEST_REGVAL(29);
	FPTEST_REGVAL(30);
	FPTEST_REGVAL(31);

	for (i = 0; i < 32; i++)
		if (e[i] != val) {
			printk("r%d: %u != %u\n", i, e[i], val);
			result = e[i];
		}

	return result;
}

#endif /* !_XENO_ASM_POWERPC_FPTEST_H */
