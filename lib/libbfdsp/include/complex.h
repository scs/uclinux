/************************************************************************
 *
 * complex.h
 *
 * (c) Copyright 1996-2005 Analog Devices, Inc.
 * This file is subject to the terms and conditions of the GNU Library General
 * Public License. See the file "COPYING.LIB" in the main directory of this
 * archive for more details.
 *
 * Non-LGPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 *
 * $Revision$
 ************************************************************************/

#ifndef __NO_BUILTIN
#pragma GCC system_header /* complex.h */
#endif

#ifndef __COMPLEX_DEFINED
#define __COMPLEX_DEFINED

#include <complex_typedef.h>
#include <fr2x16_typedef.h>
#ifdef __cplusplus
  extern "C" {
#endif 

/* * * *        cabs      * * * *
 *
 *    Complex absolute value
 *
 */

        float cabsf (complex_float _a) asm("__cabsf");

        long double cabsd (complex_long_double _a) asm("__cabsd");


#ifdef __DOUBLES_ARE_FLOATS__
        double cabs (complex_double _a) asm("__cabsf");
#else
        double cabs (complex_double _a) asm("__cabsd");
#endif

        fract16 cabs_fr16 (complex_fract16 _a) asm("__cabs_fr16");
        complex_fract16 conj_fr16 (complex_fract16 _a);

#if defined(__ADSPBLACKFIN__) && !defined(__NO_BUILTIN)
#define COMPFRACT(X) __builtin_bfin_compose_2x16(X.im, X.re)
#define EXTRFRACT(R,X) \
  { \
    R.re = __builtin_bfin_extract_lo(X); \
    R.im = __builtin_bfin_extract_hi(X); \
  }
        static __inline complex_fract16
            cadd_fr16(complex_fract16 _a, complex_fract16 _b) {
              complex_fract16 r;
              fract2x16 i = __builtin_bfin_add_fr2x16(COMPFRACT(_a), COMPFRACT(_b));
              EXTRFRACT(r,i);
              return r;
         }
#else
        complex_fract16 cadd_fr16 (complex_fract16 _a, complex_fract16 _b) asm ("__cadd_fr16");
#endif


#if defined(__ADSPBLACKFIN__) && !defined(__NO_BUILTIN)
        static __inline complex_fract16
            csub_fr16(complex_fract16 _a, complex_fract16 _b) {
              complex_fract16 r;
              fract2x16 i = __builtin_bfin_sub_fr2x16(COMPFRACT(_a), COMPFRACT(_b));
              EXTRFRACT(r,i);
              return r;
         }
#else
        complex_fract16 csub_fr16 (complex_fract16 _a, complex_fract16 _b) asm ("__csub_fr16");
#endif




/* * * *        cmlt      * * * *
 *
 *    Complex multiplication
 * 
 */

#if defined(__ADSPBLACKFIN__) && !defined(__NO_BUILTIN)
        static __inline complex_fract16
            cmlt_fr16(complex_fract16 _a, complex_fract16 _b) {
              complex_fract16 r;
              fract2x16 i = __builtin_bfin_cmplx_mul(COMPFRACT(_a), COMPFRACT(_b));
              EXTRFRACT(r,i);
              return r;
         }
#else
        complex_fract16 cmlt_fr16 (complex_fract16 _a, complex_fract16 _b) asm ("__cmlt_fr16");
#endif

#if defined(__ADSPBLACKFIN__) && !defined(__NO_BUILTIN)
        static __inline complex_fract16 cmac_fr16(complex_fract16 _sum,
                                                  complex_fract16 _a, 
                                                  complex_fract16 _b){
              complex_fract16 r;
              fract2x16 i = __builtin_bfin_cmplx_mac(COMPFRACT(_sum),
						COMPFRACT(_a), COMPFRACT(_b));
              EXTRFRACT(r,i);
              return r;
         }

        static __inline complex_fract16 cmsu_fr16(complex_fract16 _sum,
                                                  complex_fract16 _a, 
                                                  complex_fract16 _b){
              complex_fract16 r;
              fract2x16 i = __builtin_bfin_cmplx_msu(COMPFRACT(_sum),
						COMPFRACT(_a), COMPFRACT(_b));
              EXTRFRACT(r,i);
              return r;
         }

         static __inline fract16 csqu_add_fr16(complex_fract16 _c) {
           return
             __builtin_bfin_add_fr1x16(__builtin_bfin_mult_fr1x16(_c.re, _c.re), 
                                  __builtin_bfin_mult_fr1x16(_c.im, _c.im));
         }

         static __inline fract32 csqu_add_fr32(complex_fract16 _c) {
           return
             __builtin_bfin_add_fr1x32(__builtin_bfin_mult_fr1x32(_c.re, _c.re), 
                                  __builtin_bfin_mult_fr1x32(_c.im,_c.im));
         }

         static __inline fract16 cdst_fr16(complex_fract16 _x, 
                                           complex_fract16 _y) {
           return __builtin_bfin_add_fr1x16(
                    __builtin_bfin_mult_fr1x16(__builtin_bfin_sub_fr1x16(_x.re,_y.re), 
                                          __builtin_bfin_sub_fr1x16(_x.re,_y.re)),
                    __builtin_bfin_mult_fr1x16(__builtin_bfin_sub_fr1x16(_x.im,_y.im), 
                                          __builtin_bfin_sub_fr1x16(_x.im,_y.im)));
         }

         static __inline fract32 cdst_fr32(complex_fract16 _x, 
                                           complex_fract16 _y) {
           return __builtin_bfin_add_fr1x32(
             __builtin_bfin_mult_fr1x32(__builtin_bfin_sub_fr1x16(_x.re,_y.re), 
                                   __builtin_bfin_sub_fr1x16(_x.re,_y.re)),
             __builtin_bfin_mult_fr1x32(__builtin_bfin_sub_fr1x16(_x.im,_y.im), 
                                   __builtin_bfin_sub_fr1x16(_x.im,_y.im)));
         }

#undef COMPFRACT
#undef EXTRFRACT
#endif /* __ADSPBLACKFIN__ */




/* * * *        cdiv      * * * *
 *
 *    Complex division
 * 
 */


        complex_fract16 cdiv_fr16 (complex_fract16 _a, complex_fract16 _b) asm("__cdiv_fr16");



	
/* * * *        arg      * * * *
 *
 *    Get phase of complex number
 *
 */
        float argf (complex_float _a) asm("__argf");

        fract16 arg_fr16 (complex_fract16 _a);
        complex_fract16 polar_fr16 (fract16 _magnitude, 
                                    fract16 _phase);

        fract16 cartesian_fr16 (complex_fract16 _a, fract16* _phase);


#if !defined(__NO_BUILTIN)

/* complex_fract32 support routines */

extern long long  __builtin_bfin_conj_fr32(long long);
extern int __builtin_bfin_csqu_fr16(int);

static __inline complex_fract32 ccompose_fr32(fract32 _real, fract32 _imag)
{
	complex_fract32 _x;
	_x.re = _real;
	_x.im = _imag;
	return _x;
}

static __inline fract32 real_fr32(complex_fract32 _a)
{
	return _a.re;
}

static __inline fract32 imag_fr32(complex_fract32 _a)
{
	return _a.im;
}

static __inline complex_fract32 cadd_fr32(complex_fract32 _a, 
                                          complex_fract32 _b)
{
	complex_fract32 _x;
	_x.re = __builtin_bfin_add_fr1x32 (_a.re, _b.re);
	_x.im = __builtin_bfin_add_fr1x32 (_a.im, _b.im);
	return _x;
}

static __inline complex_fract32 csub_fr32(complex_fract32 _a, 
					  complex_fract32 _b)
{
	complex_fract32 _x;
	_x.re = __builtin_bfin_sub_fr1x32 (_a.re, _b.re);
	_x.im = __builtin_bfin_sub_fr1x32 (_a.im, _b.im);
	return _x;
}

static __inline complex_fract32 conj_fr32(complex_fract32 _a)
{
	complex_fract32 _x;
	_x.im = __builtin_bfin_sub_fr1x32 (0, _a.im);
	_x.re = _a.re;
	return _x;
}

/* cmul_fr32 is not a builtin. It is declared in libdsp */
extern complex_fract32 cmul_fr32(complex_fract32, complex_fract32);

/* Other builtins */
static __inline complex_fract16 csqu_fr16(complex_fract16 _a)
{
	composite_complex_fract16 _x;
	_x.x.re = _a.re; _x.x.im = _a.im;
	_x.raw = __builtin_bfin_csqu_fr16(_x.raw);
	return _x.x;
}
	
#endif /* !__NO_BUILTIN */

#ifdef __cplusplus
}       /* end extern "C" */
#endif 

#endif   /* __COMPLEX_DEFINED  (include guard) */
