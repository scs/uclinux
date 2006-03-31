/************************************************************************
 *
 * libetsi.h
 *
 * (c) Copyright 2001-2005 Analog Devices, Inc.
 * This file is subject to the terms and conditions of the GNU Library General
 * Public License. See the file "COPYING.LIB" in the main directory of this
 * archive for more details.
 *
 * Non-LGPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 *
 *
 ************************************************************************/

#ifndef _LIBETSI_H
#define _LIBETSI_H

#ifndef ETSI_SOURCE
# define ETSI_SOURCE
#endif

#ifdef ETSI_SOURCE
#include <fract.h>

#ifndef __SET_ETSI_FLAGS
#define __SET_ETSI_FLAGS 0
#endif

#define MAX_32	(fract32)0x7fffffffL
#define MIN_32	(fract32)0x80000000L
#define MAX_16	(fract16)0x7fff
#define MIN_16	(fract16)0x8000

#ifdef __cplusplus
	extern "C" {
#endif
		fract16 div_l (fract32,fract16);

		// Oper32 Routines
		fract32 Div_32(fract32,fract16,fract16);
#ifdef NO_ETSI_BUILTINS
		fract32 L_Comp(fract16,fract16);
		void    L_Extract(fract32,fract16 *,fract16 *);
		fract32 Mpy_32(fract16,fract16,fract16,fract16);
		fract32 Mpy_32_16(fract16,fract16,fract16);
#endif
		// 32 Bit returning routines
		
		fract32 L_add_c(fract32, fract32);
		fract32 L_mls(fract32, fract16);
		fract32 L_sub_c(fract32, fract32);
		fract32 L_sat(fract32);
#ifdef NO_ETSI_BUILTINS
		fract32 L_sub(fract32, fract32);
		fract32 L_abs(fract32);
		fract32 L_add(fract32, fract32);
#ifdef RENAME_ETSI_NEGATE
#pragma linkage_name _negate
		fract16 etsi_negate(fract16);
#else
		fract16 negate(fract16);
#endif
		fract32 L_mult(fract16, fract16);
		fract32 L_deposit_l(fract16);
		fract32 L_deposit_h(fract16);
		fract32 L_mac(fract32, fract16, fract16);
		fract32 L_msu(fract32, fract16, fract16);
		fract32 L_shl(fract32, fract16);
		fract32 L_shr(fract32, fract16);
#endif
		fract32 L_macNs(fract32,fract16, fract16);
		fract32 L_msuNs(fract32, fract16, fract16);
		fract32 L_shr_r(fract32, fract16);
#ifndef L_shift_r
#define L_shift_r(a,b) (L_shr_r((a),negate(b)))
#endif

#define i_mult(X,Y)  (((int)(X))*((int)(Y)))   /* integer multiply */

		// 16 bit returning routines
#ifdef NO_ETSI_BUILTINS
		fract16 abs_s(fract16);
		fract16 add(fract16, fract16);
		fract16 sub(fract16, fract16);
		fract16 div_s(fract16, fract16);
		fract16 mult(fract16, fract16);
		fract16 mult_r(fract16, fract16);
		fract16 round(fract32);
		fract16 saturate(fract32);
		fract16 extract_l(fract32);
		fract16 extract_h(fract32);
		int norm_l(fract32);
		int norm_s(fract32);
		fract16 shl(fract16, fract16);
		fract16 shr(fract16, fract16);
#endif
		fract16 mac_r(fract32, fract16, fract16);
		fract16 msu_r(fract32, fract16, fract16);
		fract16 shr_r(fract16, fract16);
#ifndef shift_r
#define shift_r(a,b) (shr_r((a),negate(b)))
#endif 

#if __SET_ETSI_FLAGS
		extern int Overflow;
		extern int Carry;
#endif
#ifdef __cplusplus
		}
#endif

#endif /* ETSI_SOURCE */

#endif
