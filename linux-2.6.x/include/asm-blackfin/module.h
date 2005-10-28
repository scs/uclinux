#ifndef _ASM_BFIN_MODULE_H
#define _ASM_BFIN_MODULE_H

#define MODULE_SYMBOL_PREFIX "_"

struct mod_arch_specific {
};

#define Elf_Shdr	Elf32_Shdr
#define Elf_Sym		Elf32_Sym
#define Elf_Ehdr	Elf32_Ehdr

#endif				/* _ASM_BFIN_MODULE_H */
