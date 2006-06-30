/************************************************************************
 *
 * math.h
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
 * Copyright (c) 1992-2001 by P.J. Plauger.  ALL RIGHTS RESERVED.

 * This file is subject to the terms and conditions of the GNU Library General
 * Public License. See the file "COPYING.LIB" in the main directory of this
 * archive for more details.
 *
 * Non-LGPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 *
 * Consult your license regarding permissions and restrictions.
 *
 ************************************************************************/
/* math.h - used only for the library itself standard header */

#ifndef _MATH
#define _MATH

#include <yvals.h>

#if !defined( __NO_ANSI_EXTENSIONS__ )
#if defined(__ADSPBLACKFIN__) 

#include <math_bf.h>

#endif  /* __ADSPBLACKFIN__ */
#endif  /* __NO_ANSI_EXTENSIONS__ */


_C_STD_BEGIN

/* MACROS */
#if defined(__ADSPBLACKFIN__)
#ifdef __DOUBLES_ARE_FLOATS__
#define HUGE_VAL    _CSTD _FHugeval._Double
#else
#define HUGE_VAL    _CSTD _LHugeval._Double
#endif
#else
#define HUGE_VAL    _CSTD _Hugeval._Double
#endif

_C_LIB_DECL

/* Map ANSI standard & Dinkum entry point
   names to Blackfin entry point names
*/
#define acosl    acosd
#define asinl    asind
#define atanl    atand
#define atan2l   atan2d
#define ceill    ceild
#define cosl     cosd
#define coshl    coshd
#define expl     expd
#define fabsl    fabsd
#define floorl   floord
#define fmodl    fmodd
#define frexpl   frexpd
#define ldexpl   ldexpd
#define logl     logd
#define log10l   log10d
#define modfl    modf
#define powl     powd
#define sinl     sind
#define sinhl    sinhd
#define sqrtl    sqrtd
#define tanl     tand
#define tanhl    tanhd


/* * * *        acos      * * * *
 *    Arc cosine
 */
        float acosf (float _x) asm("__acosf");

        long double acosd (long double _x) asm("__acosd");

#ifdef __DOUBLES_ARE_FLOATS__
        double acos (double _x) asm("__acosf");
#else
        double acos (double _x) asm("__acosd");
#endif


/* * * *        asin      * * * *
 *    Arc sine
 */
        float asinf (float _x) asm("__asinf");

        long double asind (long double _x) asm("__asind");

#ifdef __DOUBLES_ARE_FLOATS__
        double asin (double _x) asm("__asinf");
#else
        double asin (double _x) asm("__asind");
#endif


/* * * *        atan      * * * *
 *    Arc tangent
 */
        float atanf (float _x) asm("__atanf");

        long double atand (long double _x) asm("__atand");

#ifdef __DOUBLES_ARE_FLOATS__
        double atan (double _x) asm("__atanf");
#else
        double atan (double _x) asm("__atand");
#endif


/* * * *        atan2      * * * *
 *    Arc tangent of quotient
 */
        float atan2f (float _x, float _y) asm("__atan2f");

        long double atan2d (long double _x, long double _y) asm("__atan2d");

#ifdef __DOUBLES_ARE_FLOATS__
        double atan2 (double _x, double _y) asm("__atan2f");
#else
        double atan2 (double _x, double _y) asm("__atan2d");
#endif


/* * * *        ceil      * * * *
 *    Ceiling
 */
        float ceilf (float _x) asm("__ceilf");

        long double ceild (long double _x) asm("__ceild");

#ifdef __DOUBLES_ARE_FLOATS__
        double ceil (double _x) asm("__ceilf");
#else
        double ceil (double _x) asm("__ceild");
#endif


/* * * *        cos      * * * *
 *    Cosine - dinkum version used for 32-bit function
 */
        float cosf (float _x);

        long double cosd (long double _x) asm("__cosd");

#if !defined(__DOUBLES_ARE_FLOATS__)
        double cos (double _x) asm("__cosd");
#endif


/* * * *        cosh      * * * *
 *    Hyperbolic Cosine - dinkum version used for 32-bit function
 */
        float coshf (float _x);

        long double coshd (long double _x) asm("__coshd");

#if !defined(__DOUBLES_ARE_FLOATS__)
        double cosh (double _x) asm("__coshd");
#endif


/* * * *        cot      * * * *
 *    Cotangent
 */
        float cotf (float _x) asm("__cotf");

        long double cotd (long double _x) asm("__cotd");

#ifdef __DOUBLES_ARE_FLOATS__
        double cot (double _x) asm("__cotf");
#else
        double cot (double _x) asm("__cotd");
#endif


/* * * *        exp      * * * *
 *    Exponential
 */
        float expf (float _x) asm("__expf");

        long double expd (long double _x) asm("__expd");

#ifdef __DOUBLES_ARE_FLOATS__
        double exp (double _x) asm("__expf");
#else
        double exp (double _x) asm("__expd");
#endif


/* * * *        floor      * * * *
 *    Floor
 */
        float floorf (float _x) asm("__floorf");

        long double floord (long double _x) asm("__floord");

#ifdef __DOUBLES_ARE_FLOATS__
        double floor (double _x) asm("__floorf");
#else
        double floor (double _x) asm("__floord");
#endif


/* * * *        fmod      * * * *
 *    Floating point mod
 *    Using Dinkum for 64-bit floating point 
 */
        float fmodf (float _x, float _y) asm("__fmodf");

        long double fmodd (long double _x, long double _y) asm("_fmodl");

#ifdef __DOUBLES_ARE_FLOATS__
        double fmod (double _x, double _y) asm("__fmodf");
#else
        double fmod (double _x, double _y) asm("__fmodd");
#endif


/* * * *        frexp      * * * *
 *    Get mantissa and exponent
 */
        float frexpf (float _x, int * _power_of_2) asm("__frexpf");

        long double frexpd (long double _x, int * _power_of_2) asm("__frexpd");

#ifdef __DOUBLES_ARE_FLOATS__
        double frexp (double _x, int * _power_of_2) asm("__frexpf");
#else
        double frexp (double _x, int * _power_of_2) asm("__frexpd");
#endif


/* * * *        ldexp      * * * *
 *    Set mantissa and exponent - dinkum version used for 32-bit function
 */
        float  ldexpf (float  _x, int _power_of_2);

        long double ldexpd (long double _x, int _power_of_2) asm("__ldexpd");

#if defined(__DOUBLES_ARE_FLOATS__)
        double ldexp (double _x, int _power_of_2) asm("_ldexpf");
#else
        double ldexp (double _x, int _power_of_2) asm("__ldexpd");
#endif


/* * * *        log      * * * *
 *    Natural Log - dinkum version used for 32-bit function
 */
        float logf (float _x);

        long double logd (long double _x) asm("__logd");

#if !defined(__DOUBLES_ARE_FLOATS__)
        double log (double _x) asm("__logd");
#endif


/* * * *        log10      * * * *
 *    Log base 10 - dinkum version used for 32-bit function
 */
        float log10f (float _x);

        long double log10d (long double _x) asm("__log10d");

#if !defined(__DOUBLES_ARE_FLOATS__)
        double log10 (double _x) asm("__log10d");
#endif


/* * * *        modf      * * * *
 *    Get fraction and integer parts of floating point
 */
        float modff (float _x, float * _integral) asm("__modff");

        long double modfd (long double _x, long double * _integral) asm("__modfd");

#ifdef __DOUBLES_ARE_FLOATS__
        double modf (double _x, double * _integral) asm("__modff");
#else
        double modf (double _x, double * _integral) asm("__modfd");
#endif


/* * * *        pow      * * * *
 *    Power
 */
        float powf (float _x, float _power_of_x) asm("__powf");

        long double powd (long double _x, long double _power_of_x) asm("__powd");

#ifdef __DOUBLES_ARE_FLOATS__
        double pow (double _x, double _power_of_x) asm("__powf");
#else
        double pow (double _x, double _power_of_x) asm("__powd");
#endif


/* * * *        sin      * * * *
 *    Sine - dinkum version used for 32-bit function
 */
        float sinf (float _x);

        long double sind (long double _x) asm("__sind");

#if !defined(__DOUBLES_ARE_FLOATS__)
        double sin (double _x) asm("__sind");
#endif


/* * * *        sinh      * * * *
 *    Hyperbolic Sine - dinkum version used for 32-bit function
 */
        float sinhf (float _x);

        long double sinhd (long double _x) asm("__sinhd");

#if !defined(__DOUBLES_ARE_FLOATS__)
        double sinh (double _x) asm("__sinhd");
#endif


/* * * *        sqrt      * * * *
 *    Square Root
 */
        float sqrtf (float _x) asm("__sqrtf");

        long double sqrtd (long double _x) asm("__sqrtd");

#ifdef __DOUBLES_ARE_FLOATS__
        double sqrt (double _x) asm("__sqrtf");
#else
        double sqrt (double _x) asm("__sqrtd");
#endif


/* * * *        tan      * * * *
 *    Tangent
 */
        float tanf (float _x) asm("__tanf");

        long double tand (long double _x) asm("__tand");

#ifdef __DOUBLES_ARE_FLOATS__
        double tan (double _x) asm("__tanf");
#else
        double tan (double _x) asm("__tand");
#endif


/* * * *        tanh      * * * *
 *    Hyperbolic Tangent
 */
        float tanhf (float _x) asm("__tanhf");

        long double tanhd (long double _x) asm("__tanhd");

#ifdef __DOUBLES_ARE_FLOATS__
        double tanh (double _x) asm("__tanhf");
#else
        double tanh (double _x) asm("__tanhd");
#endif


/* * * *        fabs      * * * *
 *    Float Absolute Value
 */
#if !defined(__NO_BUILTIN) && defined(__ADSPBLACKFIN__) 

        static __inline float fabsf(float _x) {
            union { float _d; unsigned long _l; } _v;
            _v._d = _x;
            _v._l &= 0x7fffffffL;
            return _v._d;
        }

#ifdef __DOUBLES_ARE_FLOATS__
        static __inline double fabs(double _x) {
            union { double _d; unsigned long _l; } _v;
            _v._d = _x;
            _v._l &= 0x7fffffffL;
            return _v._d;
        }
#endif
#else
        float fabsf (float _x);

#ifdef __DOUBLES_ARE_FLOATS__
        double fabs (double _x) asm("_fabsf");
#else
        double fabs (double _x) asm("__fabsd");
#endif
#endif  /* !__NO_BUILTIN && __ADSPBLACKFIN__ */

        long double fabsd (long double _x) asm("__fabsd");

#if !defined(__DOUBLES_ARE_FLOATS__)
        double fabs (double _x) asm("__fabsd");
#endif


/* ANSI C puts fabs() in math.h, and abs() in stdlib.h... */
#if !defined(__ADSP21XX__) && !defined(__ADSPBLACKFIN__)
#if !defined(__NO_BUILTIN) && !defined(abs)

        int __builtin_bfin_abs(int);
        __inline int abs(int _x) { return __builtin_bfin_abs(_x); }

#else
        int abs(int);
#endif
#endif /* !21XX && !BLACKFIN */


_END_C_LIB_DECL


#ifdef __cplusplus


/****** OVERLOAD - float parameters *******/

__inline double abs(double _X)
        {      /* return absolute value*/
        return (fabs(_X));
        }

__inline float abs(float _X)   
        {      /* return absolute value*/
        return (fabsf(_X));
        }

__inline float acos(float _X)
        {      /* return arccosine*/
        return (acosf(_X));
        }

__inline float asin(float _X)
        {      /* return arcsine*/ 
        return (asinf(_X));
        }

__inline float atan(float _X)
        {      /* return arctangent*/
        return (atanf(_X));
        }

__inline float atan2(float _Y, float _X)
        {      /* return arctangent*/
        return (atan2f(_Y, _X));
        }

__inline float ceil(float _X)
        {      /* return ceiling*/
        return (ceilf(_X));
        }

__inline float cos(float _X)
        {      /* return cosine*/
#if defined(_USING_DINKUM_C_LIBRARY)
        return (_FSin(_X, 1));
#else
        return (cosf(_X));
#endif
        }

__inline float cosh(float _X)
        {      /* return hyperbolic cosine*/
        return (_FCosh(_X, 1));
        }

__inline float exp(float _X)
        {      /* return exponential*/
        return (expf(_X));
        }

__inline float fabs(float _X)
        {      /* return absolute value*/
        return (fabsf(_X));
        }

__inline float floor(float _X)
        {      /* return floor*/
        return (floorf(_X));
        }

__inline float fmod(float _X, float _Y)
        {      /* return modulus*/
        return (fmodf(_X, _Y));
        }

__inline float frexp(float _X, int *_Y)
        {      /* unpack exponent*/
        return (frexpf(_X, _Y));
        }

__inline float ldexp(float _X, int _Y)
        {      /* pack exponent*/
        return (ldexpf(_X, _Y));
        }

__inline float log(float _X)
        {      /* return natural logarithm*/
        return (_FLog(_X, 0));
        }

__inline float log10(float _X)
        {      /* return base-10 logarithm*/
#if defined(_USING_DINKUM_C_LIBRARY)
        return (_FLog(_X, 1));
#else
        return (log10f(_X));
#endif /* _USING_DINKUM_C_LIBRARY */
        }

__inline float modf(float _X, float *_Y)
        {      /* unpack fraction*/
        return (modff(_X, _Y));
        }

__inline float pow(float _X, float _Y)
        {      /* raise to power*/
        return (powf(_X, _Y));
        }

__inline float sin(float _X)
        {       /* return sine*/
#if defined(_USING_DINKUM_C_LIBRARY)
        return (_FSin(_X, 0));
#else
        return (sinf(_X));
#endif
        }

__inline float sinh(float _X)
        {      /* return hyperbolic sine*/
#if defined(_USING_DINKUM_C_LIBRARY)
        return (_FSinh(_X, 1));
#else
        return (sinhf(_X));
#endif
        }

__inline float sqrt(float _X)
        {      /* return square root*/
        return (sqrtf(_X));
        }

__inline float tan(float _X)
        {      /* return tangent*/
        return (tanf(_X));
        }

__inline float tanh(float _X)
        {      /* return hyperbolic tangent*/
        return (tanhf(_X));
        }


 #else /* __cplusplus */
_C_LIB_DECL


_END_C_LIB_DECL

#endif /* __cplusplus */

_C_STD_END

#endif /* _MATH */


/*
* Copyright (c) 1992-2001 by P.J. Plauger.  ALL RIGHTS RESERVED.

 * This file is subject to the terms and conditions of the GNU Library General
 * Public License. See the file "COPYING.LIB" in the main directory of this
 * archive for more details.
 *
 * Non-LGPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 *
 * Consult your license regarding permissions and restrictions.
V3.10:1134 */
