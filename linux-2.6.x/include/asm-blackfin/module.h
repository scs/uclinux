/* changes origined from m68k.....   Lineo, Inc		May 2001  */

#ifndef _ASM_BFIN_MODULE_H
#define _ASM_BFIN_MODULE_H


/*
 * This file contains the bfin architecture specific module code.
 */
struct mod_arch_specific
{
	int foo;
};
#define Elf_Shdr	Elf32_Shdr
#define Elf_Sym		Elf32_Sym
#define Elf_Ehdr	Elf32_Ehdr



#define module_map(x)		vmalloc(x)
#define module_unmap(x)		vfree(x)
#define module_arch_init(x)	(0)

#endif /* _ASM_BFIN_MODULE_H */
