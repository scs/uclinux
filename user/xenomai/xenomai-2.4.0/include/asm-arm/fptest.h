#ifndef _XENO_ASM_ARM_FPTEST_H
#define _XENO_ASM_ARM_FPTEST_H

#ifdef __KERNEL__
#include <linux/module.h>
#else /* !__KERNEL__ */
#include <stdio.h>
#define printk printf
#endif /* !__KERNEL__ */

static inline void fp_regs_set(unsigned val)
{
}

static inline unsigned fp_regs_check(unsigned val)
{
    return val;
}

#endif /* _XENO_ASM_ARM_FPTEST_H */
