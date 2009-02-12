#ifndef _XENO_ASM_ARM_FPTEST_H
#define _XENO_ASM_ARM_FPTEST_H

#ifdef __KERNEL__
#include <linux/module.h>
#include <asm/hwcap.h>

#ifdef CONFIG_VFP
#define have_vfp (elf_hwcap & HWCAP_VFP)
#else /* !CONFIG_VFP */
#define have_vfp (0)
#endif /* !CONFIG_VFP */

#else /* !__KERNEL__ */
#include <stdio.h>
#include <string.h>
#define printk(fmt, args...) fprintf(stderr, fmt, ## args)

static int have_vfp;

static void __attribute__((constructor)) fp_init(void)
{
	char buffer[1024];
	FILE *f = fopen("/proc/cpuinfo", "r");
	if(!f)
		return;

	while(fgets(buffer, sizeof(buffer), f)) {
		if(strncmp(buffer, "Features", sizeof("Features") - 1))
			continue;

		if (strstr(buffer, "vfp")) {
			have_vfp = 1;
			break;
		}
	}

	fclose(f);
}

#endif /* !__KERNEL__ */

static inline void fp_regs_set(unsigned val)
{
	if (have_vfp) {
		unsigned long long e[16];
		unsigned i;

		for (i = 0; i < 16; i++)
			e[i] = val;

		/* vldm %0!, {d0-d15},
		   AKA fldmiax %0!, {d0-d15} */
		__asm__ __volatile__("ldc p11, cr0, [%0],#32*4": 
				     "=r"(i): "0"(&e[0]): "memory");
	}
}

static inline unsigned fp_regs_check(unsigned val)
{
	unsigned result = val;

	if (have_vfp) {
		unsigned long long e[16];
		unsigned i;

		/* vstm %0!, {d0-d15},
		   AKA fstmiax %0!, {d0-d15} */
		__asm__ __volatile__("stc p11, cr0, [%0],#32*4": 
				     "=r"(i): "0"(&e[0]): "memory");

		for (i = 0; i < 16; i++)
			if (e[i] != val) {
				printk("d%d: %llu != %u\n", i, e[i], val);
				result = e[i];
			}
	}

	return result;
}
#endif /* _XENO_ASM_ARM_FPTEST_H */

