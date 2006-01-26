/*
 * include/asm-blackfin/flat.h -- uClinux flat-format executables
 *
 * Copyright (C) 2003,
 *
 */

#ifndef __BLACKFIN_FLAT_H__
#define __BLACKFIN_FLAT_H__

#include <asm/unaligned.h>

#define	flat_stack_align(sp)	/* nothing needed */
#define	flat_argvp_envp_on_stack()		0
#define	flat_old_ram_flag(flags)		(flags)

/* The amount by which a relocation can exceed the program image limits
   without being regarded as an error.  */

#define	flat_reloc_valid(reloc, size)	((reloc) <= (size))

#define	flat_get_addr_from_rp(rp, relval, flags, persistent)	\
	bfin_get_addr_from_rp(rp, relval, persistent)
#define	flat_put_addr_at_rp(rp, val, relval)	\
	bfin_put_addr_at_rp(rp, val, relval)

#define FLAT_BFIN_RELOC_TYPE_16_BIT 0
#define FLAT_BFIN_RELOC_TYPE_16H_BIT 1
#define FLAT_BFIN_RELOC_TYPE_32_BIT 2

/* Convert a relocation entry into an address.  */
static inline unsigned long
flat_get_relocate_addr (unsigned long relval)
{
	return relval & 0x00ffffff; /* Mask out top 8 bits */
}

static inline int flat_set_persistent (unsigned long relval, unsigned long *persistent)
{
	int type = (relval >> 26) & 7;
	if (type == 3) {
		*persistent = relval << 16;
		return 1;
	}
	return 0;
}

static inline int flat_addr_absolute (unsigned long relval)
{
	return (relval & (1 << 29)) != 0;
}

static inline unsigned long bfin_get_addr_from_rp (unsigned long *ptr,
						   unsigned long relval,
						   unsigned long *persistent)
{
	unsigned short *usptr = (unsigned short *)ptr;
	int type = (relval >> 26) & 7;
	unsigned long val;

	switch (type) {
	case FLAT_BFIN_RELOC_TYPE_16_BIT:
	case FLAT_BFIN_RELOC_TYPE_16H_BIT:
		usptr = (unsigned short *) ptr;
#ifdef DEBUG_BFIN_RELOC
		printk(" *usptr = %x", get_unaligned (usptr));
#endif
		val = get_unaligned (usptr);
		val += *persistent;
		break;

	case FLAT_BFIN_RELOC_TYPE_32_BIT:
#ifdef DEBUG_BFIN_RELOC
		printk(" ptr =%x", get_unaligned ((unsigned short *)ptr));
#endif
		val = get_unaligned (ptr);
		break;

	default:
		printk("BINFMT_FLAT: Unknown relocation type %x\n",
		       type);
		return 0;
	}

	/* Stack-relative relocs contain the offset into the stack, we
	   have to add the stack's start address here and return 1 from
	   flat_addr_absolute to prevent the normal address calculations.  */
	if (relval & (1 << 29))
		return val + current->mm->context.end_brk;

	return htonl (val);
}

/* Insert the address ADDR into the symbol reference at RP;
   RELVAL is the raw relocation-table entry from which RP is derived.  */
static inline void bfin_put_addr_at_rp (unsigned long *ptr, unsigned long addr,
					unsigned long relval)
{
	unsigned short *usptr = (unsigned short *)ptr;
	int type = (relval >> 26) & 7;

	switch (type) {
	case FLAT_BFIN_RELOC_TYPE_16_BIT:
		put_unaligned (addr, usptr);
#ifdef DEBUG_BFIN_RELOC
		printk(" new value %x at %p", get_unaligned (usptr), usptr);
#endif
		break;

	case FLAT_BFIN_RELOC_TYPE_16H_BIT:
		put_unaligned (addr >> 16, usptr);
#ifdef DEBUG_BFIN_RELOC
		printk(" new value %x", get_unaligned (usptr));
#endif
		break;

	case FLAT_BFIN_RELOC_TYPE_32_BIT:
		put_unaligned (addr, ptr);
#ifdef DEBUG_BFIN_RELOC
		printk(" new ptr =%x", get_unaligned (ptr));
#endif
		break;
	}
}

#endif				/* __BLACKFIN_FLAT_H__ */
