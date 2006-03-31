#pragma once
#ifndef __NO_BUILTIN
#pragma GCC system_header /* ccblkfn.h */
#endif
/************************************************************************
 *
 * ccblkfn.h
 *
 * (c) Copyright 2001-2004 Analog Devices, Inc.
 * This file is subject to the terms and conditions of the GNU Library General
 * Public License. See the file "COPYING.LIB" in the main directory of this
 * archive for more details.
 *
 * Non-LGPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 *
 *
 ************************************************************************/

/* ccblkfn definitions */

#ifndef _CCBLKFN_H
#define _CCBLKFN_H

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define __builtin_bfin_lvitmax2x16(A,B,C,D,E) { \
  D=__builtin_bfin_lvitmax2x16res1(A,B,C); \
  E=__builtin_bfin_vitmaxres2x16(D); \
}
#define __builtin_bfin_rvitmax2x16(A,B,C,D,E) { \
  D=__builtin_bfin_rvitmax2x16res1(A,B,C); \
  E=__builtin_bfin_vitmaxres2x16(D); \
}
#define __builtin_bfin_lvitmax1x16(A,B,C,D) { \
  C=__builtin_bfin_lvitmax1x16res1(A,B); \
  D=__builtin_bfin_vitmaxres1x16(C); \
}
#define __builtin_bfin_rvitmax1x16(A,B,C,D) { \
  C=__builtin_bfin_rvitmax1x16res1(A,B); \
  D=__builtin_bfin_vitmaxres1x16(C); \
}

#ifndef __NO_BUILTIN

/* The following two builtin_bfins change data from big-endian to little-endian,
   or vice versa */
#define byteswap4(A) __builtin_bfin_byteswap4(A)
#define byteswap2(A) __builtin_bfin_byteswap2(A)

#define expadj1x32 __builtin_bfin_expadj1x32
#define expadj2x16 __builtin_bfin_expadj2x16
#define expadj1x16 __builtin_bfin_expadj1x16
#define divs __builtin_bfin_divs
#define divq __builtin_bfin_divq
#define rvitmax1x16(A,B,C,D) __builtin_bfin_rvitmax1x16(A,B,C,D)
#define lvitmax1x16(A,B,C,D) __builtin_bfin_lvitmax1x16(A,B,C,D)
#define rvitmax2x16(A,B,C,D,E) __builtin_bfin_rvitmax2x16(A,B,C,D,E)
#define rvitmax2x16(A,B,C,D,E) __builtin_bfin_rvitmax2x16(A,B,C,D,E)
#define idle() __builtin_bfin_idle()
/* halt() and abort() operations are no longer supported by the simulators;
   invoke the _Exit() system call, which circumvents exit()'s clean-up. */
#define sys_halt() _Exit()
#if !defined(abort)
#define sys_abort() _Exit()
#endif
#define ssync() __builtin_bfin_ssync()
#define csync() __builtin_bfin_csync()
#ifdef __AVOID_CLI_ANOMALY__
static __inline int cli(void) {
  int r, reti;
  __asm volatile("%0 = RETI; RETI = [SP++];\n" : "=d" (reti));
  r = __builtin_bfin_cli();
  __asm volatile("[--SP] = RETI; RETI = %0;\n" : : "d" (reti) : "reti");
   return r;
}
#else
#define cli() __builtin_bfin_cli()
#endif
#define sti(A) __builtin_bfin_sti(A)
#define raise_intr(A) __builtin_bfin_raise(A)
#define excpt(A) __builtin_bfin_excpt(A)
#define sysreg_read(A) __builtin_bfin_sysreg_read(A)
#define sysreg_write(A,B) __builtin_bfin_sysreg_write(A,B)
#define sysreg_read64(A) __builtin_bfin_sysreg_read64(A)
#define sysreg_write64(A,B) __builtin_bfin_sysreg_write64(A,B)
#define circindex(IDX,INC,ITMS) __builtin_bfin_circindex(IDX,INC,ITMS)
#define circptr(PTR,INCR,BASE,LEN) __builtin_bfin_circptr(PTR,INCR,BASE,LEN)
#define expected_true(_v) __builtin_bfin_expected_true(_v)
#define expected_false(_v) __builtin_bfin_expected_false(_v)
#define bitmux_shr(X,Y,A)  { \
	int _x = (X), _y = (Y); \
	long long _a = (A); \
	_a = __builtin_bfin_bitmux_shr_res1(_a,_x,_y); \
	_x = __builtin_bfin_bitmux_shr_res2(_a); \
	_y = __builtin_bfin_bitmux_shr_res3(_a); \
	X = _x ; \
	Y = _y ; \
	A = _a ; \
	} 
#define bitmux_shl(X,Y,A)  { \
	int _x = (X), _y = (Y); \
	long long _a = (A); \
	_a = __builtin_bfin_bitmux_shl_res1(_a,_x,_y); \
	_x = __builtin_bfin_bitmux_shl_res2(_a); \
	_y = __builtin_bfin_bitmux_shl_res3(_a); \
	X = _x ; \
	Y = _y ; \
	A = _a ; \
	} 
#define misaligned_load16(_a) __builtin_bfin_misaligned_load16(_a);
#define misaligned_load16_vol(_a) __builtin_bfin_misaligned_load16_vol(_a);
#define misaligned_store16(_a,_v) __builtin_bfin_misaligned_store16(_a, _v);
#define misaligned_store16_vol(_a,_v) __builtin_bfin_misaligned_store16_vol(_a, _v);

#define misaligned_load32(_a) __builtin_bfin_misaligned_load32(_a);
#define misaligned_load32_vol(_a) __builtin_bfin_misaligned_load32_vol(_a);
#define misaligned_store32(_a,_v) __builtin_bfin_misaligned_store32(_a, _v);
#define misaligned_store32_vol(_a,_v) __builtin_bfin_misaligned_store32_vol(_a, _v);

#define misaligned_load64(_a) __builtin_bfin_misaligned_load64(_a);
#define misaligned_load64_vol(_a) __builtin_bfin_misaligned_load64_vol(_a);
#define misaligned_store64(_a,_v) __builtin_bfin_misaligned_store64(_a, _v);
#define misaligned_store64_vol(_a,_v) __builtin_bfin_misaligned_store64_vol(_a, _v);

#endif /* !__NO_BUILTIN */

/* Copy from L1 Instuction memory */
void *_l1_memcpy(void *datap, const void *instrp, size_t n);
/* Copy to L1 Instruction memory */
void *_memcpy_l1(void *instrp, const void *datap, size_t n);

/* Routines for set/unseting atomic access bit in value pointed to.
   These routines use the TESTSET instruction to gain exclusive access to a
   flag variable.
   Obtaining the flag provides atomic access for the core that claims
   the flag that is passed in.
   NOTE: It is assumed that the routines will be called in a lock/unlock
         order. No checking is performed in the unlock routine to ensure
    that the current core has the lock. As long as the routines
    are used correctly there is no need for this functionality.
   For Multi-Core Processors Only */

#if defined(__ADSPBF535__) || defined(__AD6532__)
#define testset_t volatile unsigned char 
#elif defined(__WORKAROUND_TESTSET_ALIGN) /* require 32-bit aligned address */
#define testset_t volatile unsigned int 
#else
#define testset_t volatile unsigned short 
#endif

extern int __builtin_bfin_testset(char *);
extern void __builtin_bfin_untestset(char *);

static __inline void adi_acquire_lock(testset_t *t)
{
        int  tVal;

	__builtin_bfin_csync();
	tVal = __builtin_bfin_testset((char *)t);
	while ( tVal == 0 )
	{
		__builtin_bfin_csync();
		tVal = __builtin_bfin_testset((char *)t);
	}
}

static __inline int adi_try_lock(testset_t *t)
{
	__builtin_bfin_csync();
	return __builtin_bfin_testset((char *)t);
}

static __inline void adi_release_lock(testset_t *t)
{
	__builtin_bfin_untestset((char *)t);
	__builtin_bfin_ssync();
}

/* Legacy routines - will be depracated */
static __inline void claim_atomic_access(testset_t *t)
{
	adi_acquire_lock(t);
}

static __inline void release_atomic_access(testset_t *t)
{
	adi_release_lock(t);
}

#if defined(__ADSPBF561__) || defined(__ADSPBF566__)
#include <sys/platform.h>
static inline int adi_core_id(void)
{
	/*  Returns the Core ID: 0 for coreA, 1 for coreB
	 ** This method is actually quicker than extracting the relevant
	 ** From the DSPID register.
	 */
	return ( ((unsigned long)*(unsigned long *)SRAM_BASE_ADDRESS) == 0xFF800000  ? 0 : 1 );
}
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif  /* _CCBLKFN_H */
