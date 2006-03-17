/* Changes made by Lineo Inc.    May 2001
 *
 * Based on: include/asm-m68knommu/uaccess.h
 */

#ifndef __BLACKFIN_UACCESS_H
#define __BLACKFIN_UACCESS_H

/*
 * User space memory access functions
 */
#include <linux/mm.h>

#define VERIFY_READ	0
#define VERIFY_WRITE	1

#define access_ok(type,addr,size)	_access_ok((unsigned long)(addr),(size))

extern int is_in_rom(unsigned long);
static inline int _access_ok(unsigned long addr, unsigned long size)
{
	extern unsigned long memory_end;
	return (((addr >= memory_start) && (addr + size <= memory_end)) ||
		(is_in_rom(addr) && is_in_rom(addr + size)));

}

static inline int verify_area(int type, const void *addr, unsigned long size)
{
	return access_ok(type, addr, size) ? 0 : -EFAULT;
}

/*
 * The exception table consists of pairs of addresses: the first is the
 * address of an instruction that is allowed to fault, and the second is
 * the address at which the program should continue.  No registers are
 * modified, so it is entirely up to the continuation code to figure out
 * what to do.
 *
 * All the routines below use bits of fixup code that are out of line
 * with the main instruction path.  This means when everything is well,
 * we don't even have to jump over them.  Further, they do not intrude
 * on our cache or tlb entries.
 */

struct exception_table_entry {
	unsigned long insn, fixup;
};

/* Returns 0 if exception not found and fixup otherwise.  */
extern unsigned long search_exception_table(unsigned long);

/*
 * These are the main single-value transfer routines.  They automatically
 * use the right size if we just have the right pointer type.
 */

#define put_user(x, ptr)				\
({							\
    int __pu_err = 0;					\
    typeof(*(ptr)) __pu_val = (x);			\
    switch (sizeof (*(ptr))) {				\
    case 1:						\
	__put_user_asm(__pu_val, ptr, B);		\
	break;						\
    case 2:						\
	__put_user_asm(__pu_val, ptr, W);		\
	break;						\
    case 4:						\
	__put_user_asm(__pu_val, ptr,  );		\
	break;						\
    case 8: { long __pu_vall, __pu_valh;		\
         __pu_vall = ((long *)&__pu_val)[0]; \
        __pu_valh = ((long *)&__pu_val)[1]; \
	__put_user_asm(__pu_vall, ((long *)ptr)+0, );	\
	__put_user_asm(__pu_valh, ((long *)ptr)+1, );	\
    } break;						\
    default:						\
	__pu_err = __put_user_bad();			\
	break;						\
    }							\
    __pu_err;						\
})

#define __put_user(x, ptr) put_user(x, ptr)
static inline int bad_user_access_length(void)
{
	panic("bad_user_access_length");
	return -1;
}

#define __put_user_bad() (printk("put_user_bad %s:%d %s\n", __FILE__, __LINE__, __FUNCTION__), bad_user_access_length(), (-EFAULT))

/*
 * Tell gcc we read from memory instead of writing: this is because
 * we do not write to any memory gcc knows about, so there are no
 * aliasing issues.
 */

#define __ptr(x) ((unsigned long *)(x))

#define __put_user_asm(x,ptr,bhw)			\
	__asm__ (#bhw"[%1] = %0;\n\t"			\
		: /* no outputs */			\
		:"d" (x),"a" (__ptr(ptr)) : "memory")

#define get_user(x, ptr)				\
({							\
    int __gu_err = 0;					\
    switch (sizeof(*(ptr))) {				\
    case 1:						\
	__get_user_asm(x, ptr, B,(Z));			\
	break;						\
    case 2:						\
	__get_user_asm(x, ptr, W,(Z));			\
	break;						\
    case 4:						\
	__get_user_asm(x, ptr,  , );			\
	break;						\
    case 8: { unsigned long __gu_vall, __gu_valh;	\
	__get_user_asm(__gu_vall, ((unsigned long *)ptr)+0,  , );	\
	__get_user_asm(__gu_valh, ((unsigned long *)ptr)+1,  , );	\
        ((unsigned long *)&x)[0] = __gu_vall;		\
        ((unsigned long *)&x)[1] = __gu_valh;		\
    } break;						\
    default:						\
	x = 0;						\
        printk("get_user_bad: %s:%d %s\n", __FILE__, __LINE__, __FUNCTION__); \
	__gu_err = __get_user_bad();			\
	break;						\
    }							\
    __gu_err;						\
})

#define __get_user(x, ptr) get_user(x, ptr)

#define __get_user_bad() (bad_user_access_length(), (-EFAULT))

#define __get_user_asm(x,ptr,bhw,option)		\
{							\
	unsigned long __gu_tmp;				\
	__asm__ ("%0 =" #bhw "[%1]"#option";\n\t"	\
		 : "=d" (__gu_tmp)			\
		 : "a" (__ptr(ptr)));			\
	(x) = (__typeof__(*(ptr))) __gu_tmp;		\
}

#define copy_from_user(to, from, n)		(memcpy(to, from, n), 0)
#define copy_to_user(to, from, n)		(memcpy(to, from, n), 0)

#define __copy_from_user(to, from, n) copy_from_user(to, from, n)
#define __copy_to_user(to, from, n) copy_to_user(to, from, n)
#define __copy_to_user_inatomic __copy_to_user
#define __copy_from_user_inatomic __copy_from_user

#define copy_to_user_ret(to,from,n,retval) ({ if (copy_to_user(to,from,n)) return retval; })

#define copy_from_user_ret(to,from,n,retval) ({ if (copy_from_user(to,from,n)) return retval; })

/*
 * Copy a null terminated string from userspace.
 */

static inline long strncpy_from_user(char *dst, const char *src, long count)
{
	char *tmp;
	if ((unsigned long)src > memory_end || ((unsigned long)src < _stext)) {
		return -EFAULT;
	}
	strncpy(dst, src, count);
	for (tmp = dst; *tmp && count > 0; tmp++, count--) ;
	return (tmp - dst);
}

/*
 * Return the size of a string (including the ending 0)
 *
 * Return 0 on exception, a value greater than N if too long
 */
static inline long strnlen_user(const char *src, long n)
{
	return (strlen(src) + 1);
}

#define strlen_user(str) strnlen_user(str, 32767)

/*
 * Zero Userspace
 */

static inline unsigned long clear_user(void *to, unsigned long n)
{
	memset(to, 0, n);
	return (0);
}

#endif				/* _BLACKFIN_UACCESS_H */
