#pragma once
#ifndef __NO_BUILTIN
#pragma GCC system_header /* video.h */
#endif
/************************************************************************
 *
 * video.h
 *
 * (c) Copyright 2002-2003 Analog Devices, Inc.
 * This file is subject to the terms and conditions of the GNU Library General
 * Public License. See the file "COPYING.LIB" in the main directory of this
 * archive for more details.
 *
 * Non-LGPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 *
 *
 ************************************************************************/

#ifndef _VIDEO_H
#define _VIDEO_H

#define align8		__builtin_bfin_align8
#define align16		__builtin_bfin_align16
#define align24		__builtin_bfin_align24
#define bytepack	__builtin_bfin_bytepack
#define compose_i64	__builtin_bfin_compose_i64
#define loadbytes	__builtin_bfin_loadbytes
#define addclip_lo	__builtin_bfin_addclip_lo
#define addclip_hi	__builtin_bfin_addclip_hi
#define addclip_lor	__builtin_bfin_addclip_lor
#define addclip_hir	__builtin_bfin_addclip_hir
#define avg_i4x8	__builtin_bfin_avg_i4x8
#define avg_i4x8_t	__builtin_bfin_avg_i4x8_t
#define avg_i4x8_r	__builtin_bfin_avg_i4x8_r
#define avg_i4x8_tr	__builtin_bfin_avg_i4x8_tr
#define avg_i2x8_lo	__builtin_bfin_avg_i2x8_lo
#define avg_i2x8_lot	__builtin_bfin_avg_i2x8_lot
#define avg_i2x8_lor	__builtin_bfin_avg_i2x8_lor
#define avg_i2x8_lotr	__builtin_bfin_avg_i2x8_lotr
#define avg_i2x8_hi	__builtin_bfin_avg_i2x8_hi
#define avg_i2x8_hit	__builtin_bfin_avg_i2x8_hit
#define avg_i2x8_hir	__builtin_bfin_avg_i2x8_hir
#define avg_i2x8_hitr	__builtin_bfin_avg_i2x8_hitr

#define byteunpack(_src,_ptr,_dst1,_dst2) \
	do { \
		int __t1 = __builtin_bfin_byteunpackres1(_src,_ptr); \
		int __t2 = __builtin_bfin_byteunpackres2(__t1); \
		_dst1 = __t1; \
		_dst2 = __t2; \
	} while (0)


#define byteunpackr(_src,_ptr,_dst1,_dst2) \
	do { \
		int __t1 = __builtin_bfin_byteunpackrres1(_src,_ptr); \
		int __t2 = __builtin_bfin_byteunpackrres2(__t1); \
		_dst1 = __t1; \
		_dst2 = __t2; \
	} while (0)


#define add_i4x8(_src1,_ptr1,_src2,_ptr2,_dst1,_dst2) \
	do { \
		int __t1 = __builtin_bfin_add_i4x8_res1(_src1,_ptr1,_src2,_ptr2); \
		int __t2 = __builtin_bfin_add_i4x8_res2(__t1); \
		_dst1 = __t1; \
		_dst2 = __t2; \
	} while (0)


#define add_i4x8r(_src1,_ptr1,_src2,_ptr2,_dst1,_dst2) \
	do { \
		int __t1 = __builtin_bfin_add_i4x8_rres1(_src1,_ptr1,_src2,_ptr2); \
		int __t2 = __builtin_bfin_add_i4x8_rres2(__t1); \
		_dst1 = __t1; \
		_dst2 = __t2; \
	} while (0)



#define sub_i4x8(_src1,_ptr1,_src2,_ptr2,_dst1,_dst2) \
	do { \
		int __t1 = __builtin_bfin_sub_i4x8_res1(_src1,_ptr1,_src2,_ptr2); \
		int __t2 = __builtin_bfin_sub_i4x8_res2(__t1); \
		_dst1 = __t1; \
		_dst2 = __t2; \
	} while (0)


#define sub_i4x8r(_src1,_ptr1,_src2,_ptr2,_dst1,_dst2) \
	do { \
		int __t1 = __builtin_bfin_sub_i4x8_rres1(_src1,_ptr1,_src2,_ptr2); \
		int __t2 = __builtin_bfin_sub_i4x8_rres2(__t1); \
		_dst1 = __t1; \
		_dst2 = __t2; \
	} while (0)


#define extract_and_add(_src1,_src2,_dst1,_dst2) \
	do { \
		int __t1 = __builtin_bfin_extract_and_add_res1(_src1,_src2); \
		int __t2 = __builtin_bfin_extract_and_add_res2(__t1); \
		_dst1 = __t1; \
		_dst2 = __t2; \
	} while (0)


#define saa(_src1,_ptr1,_src2,_ptr2,_sum1,_sum2,_dst1,_dst2) \
	do { \
		int __t1 = __builtin_bfin_saa_res1(_src1,_ptr1,_src2,_ptr2,_sum1,_sum2); \
		int __t2 = __builtin_bfin_saa_res2(__t1); \
		_dst1 = __t1; \
		_dst2 = __t2; \
	} while (0)

#define saar(_src1,_ptr1,_src2,_ptr2,_sum1,_sum2,_dst1,_dst2) \
	do { \
		int __t1 = __builtin_bfin_saa_rres1(_src1,_ptr1,_src2,_ptr2,_sum1,_sum2); \
		int __t2 = __builtin_bfin_saa_rres2(__t1); \
		_dst1 = __t1; \
		_dst2 = __t2; \
	} while (0)

#endif /* _VIDEO_H */
