/************************************************************************
 *
 * math_bf.h
 *
 * (c) Copyright 2002-2005 Analog Devices, Inc.
 * This file is subject to the terms and conditions of the GNU Library General
 * Public License. See the file "COPYING.LIB" in the main directory of this
 * archive for more details.
 *
 * Non-LGPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 *
 *
 ************************************************************************/

#pragma once
#ifndef __NO_BUILTIN
#pragma GCC system_header /* math_bf.h */
#endif

/*
   This header file contains all ADSP Blackfin specific
   Analog extensions to the ANSI header file math.h.

   The header file is included by math.h by default.
   To disable the extensions, compile with the option:
        -D__NO_ANSI_EXTENSIONS__
 */
   
#ifndef  _MATH_BF_H
#define  _MATH_BF_H

#include <yvals.h>

#include <fract_typedef.h>
#include <fract_math.h>
#include <ccblkfn.h>

_C_STD_BEGIN
_C_LIB_DECL

/* * * *        acos     * * * *
 *    Arc cosine
 */
        fract16 acos_fr16 (fract16 _x) asm("__acos_fr16");

/* * * *        alog     * * * *
 *    Natural anti-log
 */
        float alogf (float _x) asm("__alogf");
        long double alogd (long double _x) asm("__alogd");

#ifdef __DOUBLES_ARE_FLOATS__
        double alog (double _x) asm("__alogf");
#else
        double alog (double _x) asm("__alogd");
#endif

/* * * *        alog10   * * * *
 *    Base-10 anti-log
 */
        float alog10f (float _x) asm("__alog10f");
        long double alog10d (long double _x) asm("__alog10d");

#ifdef __DOUBLES_ARE_FLOATS__
        double alog10 (double _x) asm("__alog10f");
#else
        double alog10 (double _x) asm("__alog10d");
#endif

/* * * *        asin     * * * *
 *    Arc sine
 */
        fract16 asin_fr16 (fract16 _x) asm("__asin_fr16");

/* * * *        atan     * * * *
 *    Arc tangent
 */
        fract16 atan_fr16 (fract16 _x) asm("__atan_fr16");

/* * * *        atan2    * * * *
 *    Arc tangent of quotient
 */
        fract16 atan2_fr16 (fract16 _x, fract16 _y) asm("__atan2_fr16");

/* * * *        cos      * * * *
 *    Cosine
 */
        fract16 cos_fr16 (fract16 _x) asm("__cos_fr16");

/* * * *        rsqrt    * * * *
 *    Inverse Square Root
 */
        float rsqrtf (float _x) asm("__rsqrtf");
        long double rsqrtd (long double _x) asm("__rsqrtd");

#ifdef __DOUBLES_ARE_FLOATS__
        double rsqrt (double _x) asm("__rsqrtf");
#else
        double rsqrt (double _x) asm("__rsqrtd");
#endif

/* * * *        sin      * * * *
 *    Sine
 */
        fract16 sin_fr16 (fract16 _x) asm("__sin_fr16");

/* * * *        sqrt     * * * *
 *    Square Root
 */
        fract16 sqrt_fr16 (fract16 _x) asm("__sqrt_fr16");

/* * * *        tan      * * * *
 *    Tangent
 */
        fract16 tan_fr16 (fract16 _x) asm("__tan_fr16");

/* * * *        max      * * * *
 *    Maximum value
 */

#if !defined(__NO_BUILTIN)
        static __inline float fmaxf(float _x, float _y) 
                { if (_x > _y) return _x; else return _y; }

#ifdef __DOUBLES_ARE_FLOATS__
        static __inline float fmax(double _x, double _y) 
                { if (_x > _y) return _x; else return _y; }
#endif 
#else 
        float fmaxf(float _x, float _y) asm("__fmaxf");
#ifdef __DOUBLES_ARE_FLOATS__
        double fmax(double _x, double _y) asm("__fmaxf");
#endif
#endif

        long double fmaxd(long double _x, long double _y) asm("__fmaxd");
#if !defined( __DOUBLES_ARE_FLOATS__)
        double fmax(double _x, double _y) asm("__fmaxd");
#endif


#if !defined(__NO_BUILTIN) 
        int __builtin_bfin_max(int, int);
        static __inline int max(int _x, int _y) 
                { return __builtin_bfin_max(_x,_y); }

        long __builtin_bfin_lmax(long, long);
        static __inline long lmax(long _x, long _y)
          { return __builtin_bfin_lmax(_x, _y); }
#else
        int max (int _x, int _y) asm("__max");
        long lmax (long _x, long _y) asm("__max");
#endif /* NO_BUILTIN */

        long long  llmax (long long  _x, long long  _y) asm("__llmax");

/* * * *        min      * * * *
 *    Minimum value
 */

#if !defined(__NO_BUILTIN) 
        static __inline float fminf(float _x, float _y) 
                { if (_x < _y) return _x; else return _y; }

#ifdef __DOUBLES_ARE_FLOATS__
        static __inline float fmin(double _x, double _y) 
                { if (_x < _y) return _x; else return _y; }
#endif
#else
        float fminf(float _x, float _y) asm("__fminf");
#ifdef __DOUBLES_ARE_FLOATS__
        double fmin(double _x, double _y) asm("__fminf");
#endif
#endif

        long double fmind(long double _x, long double _y) asm("__fmind");
#if !defined(__DOUBLES_ARE_FLOATS__)
        double fmin(double _x, double _y) asm("__fmind");
#endif


#if !defined(__NO_BUILTIN)
        int __builtin_bfin_min(int, int);
        static __inline int min(int _x, int _y) 
                { return __builtin_bfin_min(_x,_y); }

        long __builtin_bfin_lmin(long, long);
        static __inline long lmin(long _x, long _y)
                { return __builtin_bfin_lmin(_x,_y); }
#else
        int min (int _x, int _y) asm("__min");
        long lmin (long _x, long _y) asm("__min");
#endif

        long long  llmin (long long  _x, long long  _y) asm("__llmin");

/* * * *        clip     * * * *
 *    Clip value to limit
 *
 */
        float fclipf (float _value, float _limit) asm("__fclipf");
        long double fclipd (long double _value, long double _limit) asm("__fclipd");

#ifdef __DOUBLES_ARE_FLOATS__
        double fclip (double _value, double _limit) asm("__fclipf");
#else
        double fclip (double _value, double _limit) asm("__fclipd");
#endif

        fract16 clip_fr16 (fract16 _value, fract16 _limit) asm("__clip_fr16");

        int clip (int _value, int _limit) asm("__clip");
        long lclip (long _value, long _limit);

        long long  llclip (long long  _value, long long  _limit) asm("__llclip");

/* * * *        copysign   * * * *
 *    Copy Sign of y (=reference) to x (=value)
 */
        float copysignf (float _x, float _y) asm("__copysignf");
        long double copysignd (long double _x, long double _y) asm("__copysignd");

#ifdef __DOUBLES_ARE_FLOATS__
        double copysign (double _x, double _y) asm("__copysignf");
#else
        double copysign (double _x, double _y) asm("__copysignd");
#endif

        fract16 copysign_fr16 (fract16 _x, fract16 _y) asm("__copysign_fr16");

/* * * *        countones  * * * *
 *    Count number of 1 bits (parity)
 */
#if !defined(__NO_BUILTIN)
        static __inline int countones (int _x) 
                { return __builtin_bfin_ones(_x); }
        static __inline int lcountones (long _x) 
                { return __builtin_bfin_ones((int)_x); }
#endif /* __NO_BUILTIN */

        int  llcountones (long long  _x) asm("__llcountones ");

/* * * *        isinf      * * * *
 *      Is number +/- Infinity?
 */
#if !defined(__NO_BUILTIN)
        static __inline int isinff(float _x) {
                union { float _xx; unsigned long _l; } _v;
                _v._xx = _x;
                return (_v._l & 0x7fffffff) == 0x7f800000;
        }

#ifdef __DOUBLES_ARE_FLOATS__
        static __inline int isinf(double _x) {
                union { double _xx; unsigned long _l; } _v;
                _v._xx = _x;
                return (_v._l & 0x7fffffff) == 0x7f800000;
        }
#endif
#else
        int isinff(float _x) asm("_isinf");
#ifdef __DOUBLES_ARE_FLOATS__
        int isinf(double _x);
#endif
#endif /* !__NO_BUILTIN */


        int isinfd(long double _x) asm("_isinfd");
#if !defined(__DOUBLES_ARE_FLOATS__)
        int isinf(double _x) asm("_isind");
#endif 

/* * * *        isnan           * * * *
 *      Is number Not A Number?
 */
#if !defined(__NO_BUILTIN)
        static __inline int isnanf(float _x) {
                union { float _xx; unsigned long _l; } _v;
                _v._xx = _x;
                return (_v._l & 0x7fffffff) > 0x7f800000uL;
        }

#ifdef __DOUBLES_ARE_FLOATS__
        static __inline int isnan(double _x) {
                union { double _xx; unsigned long _l; } _v;
                _v._xx = _x;
                return (_v._l & 0x7fffffff) > 0x7f800000uL;
        }
#endif
#else
        int isnanf(float _x) asm("_isnan");
#ifdef __DOUBLES_ARE_FLOATS__
        int isnan(double _x);
#endif
#endif /* !__NO_BUILTIN */


        int isnand(long double _x) asm("_isnand");
#if !defined(__DOUBLES_ARE_FLOATS__)
        int isnan(double _x) asm("_isnand");
#endif



_END_C_LIB_DECL
_C_STD_END

#endif   /* _MATH_BF_H */
