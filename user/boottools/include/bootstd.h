/* bootstd.h:  Bootloader system call interface
 *
 * (c) 1999, Rt-Control, Inc.
 * Copyright (C) 2000  Lineo, Inc.  (www.lineo.com) 
 */

#ifndef __BOOTSTD_H__
#define __BOOTSTD_H__

#define NR_BSC 11            /* last used bootloader system call */

#define __BN_reset        0  /* reset and start the bootloader */
#define __BN_test         1  /* tests the system call interface */
#define __BN_exec         2  /* executes a bootloader image */
#define __BN_exit         3  /* terminates a bootloader image */
#define __BN_program      4  /* program FLASH from a chain */
#define __BN_erase        5  /* erase sector(s) of FLASH */
#define __BN_open         6
#define __BN_write        7
#define __BN_read         8
#define __BN_close        9
#define __BN_mmap         10 /* map a file descriptor into memory */
#define __BN_munmap       11 /* remove a file to memory mapping */

/* Calling conventions compatible to (uC)linux/68k
 * We use simmilar macros to call into the bootloader as for uClinux
 */

#define __bsc_return(type, res) \
do { \
   if ((unsigned long)(res) >= (unsigned long)(-64)) { \
      /* let errno be a function, preserve res in %d0 */ \
      int __err = -(res); \
      errno = __err; \
      res = -1; \
   } \
   return (type)(res); \
} while (0)

#define _bsc0(type,name) \
type name(void) \
{ \
   register long __res __asm__ ("%d0") = __BN_##name; \
   __asm__ __volatile__ ("trap #2" \
                         : "=g" (__res) \
                         : "0" (__res) \
                         : "%d0"); \
   __bsc_return(type,__res); \
}

#define _bsc1(type,name,atype,a) \
type name(atype a) \
{ \
   register long __res __asm__ ("%d0") = __BN_##name; \
   register long __a __asm__ ("%d1") = (long)a; \
   __asm__ __volatile__ ("trap #2" \
                         : "=g" (__res) \
                         : "0" (__res), "d" (__a) \
                         : "%d0"); \
   __bsc_return(type,__res); \
}

#define _bsc2(type,name,atype,a,btype,b) \
type name(atype a, btype b) \
{ \
   register long __res __asm__ ("%d0") = __BN_##name; \
   register long __a __asm__ ("%d1") = (long)a; \
   register long __b __asm__ ("%d2") = (long)b; \
   __asm__ __volatile__ ("trap #2" \
                         : "=g" (__res) \
                         : "0" (__res), "d" (__a), "d" (__b) \
                         : "%d0"); \
   __bsc_return(type,__res); \
}

#define _bsc3(type,name,atype,a,btype,b,ctype,c) \
type name(atype a, btype b, ctype c) \
{ \
   register long __res __asm__ ("%d0") = __BN_##name; \
   register long __a __asm__ ("%d1") = (long)a; \
   register long __b __asm__ ("%d2") = (long)b; \
   register long __c __asm__ ("%d3") = (long)c; \
   __asm__ __volatile__ ("trap #2" \
                         : "=g" (__res) \
                         : "0" (__res), "d" (__a), "d" (__b), \
                           "d" (__c) \
                         : "%d0"); \
   __bsc_return(type,__res); \
}

#define _bsc4(type,name,atype,a,btype,b,ctype,c,dtype,d) \
type name(atype a, btype b, ctype c, dtype d) \
{ \
   register long __res __asm__ ("%d0") = __BN_##name; \
   register long __a __asm__ ("%d1") = (long)a; \
   register long __b __asm__ ("%d2") = (long)b; \
   register long __c __asm__ ("%d3") = (long)c; \
   register long __d __asm__ ("%d4") = (long)d; \
   __asm__ __volatile__ ("trap #2" \
                         : "=g" (__res) \
                         : "0" (__res), "d" (__a), "d" (__b), \
                           "d" (__c), "d" (__d) \
                         : "%d0"); \
   __bsc_return(type,__res); \
}

#define _bsc5(type,name,atype,a,btype,b,ctype,c,dtype,d,etype,e) \
type name(atype a, btype b, ctype c, dtype d, etype e) \
{ \
   register long __res __asm__ ("%d0") = __BN_##name; \
   register long __a __asm__ ("%d1") = (long)a; \
   register long __b __asm__ ("%d2") = (long)b; \
   register long __c __asm__ ("%d3") = (long)c; \
   register long __d __asm__ ("%d4") = (long)d; \
   register long __e __asm__ ("%d5") = (long)e; \
   __asm__ __volatile__ ("trap #2" \
                         : "=g" (__res) \
                         : "0" (__res), "d" (__a), "d" (__b), \
                           "d" (__c), "d" (__d), "d" (__e) \
                         : "%d0"); \
   __bsc_return(type,__res); \
}

#endif /* __BOOTSTD_H__ */
