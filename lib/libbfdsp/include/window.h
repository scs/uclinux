/************************************************************************
 *
 * window.h
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
#pragma once
#ifndef __NO_BUILTIN
#pragma GCC system_header /* window.h */
#endif

#ifndef  __WINDOW_DEFINED
 #define __WINDOW_DEFINED


#include <fract_typedef.h>


#ifdef __cplusplus
 extern "C" {
#endif 



/* * * *        gen_bartlett      * * * *
 *
 *    Generate bartlett Window
 * 
 */

        void gen_bartlett_fr16 (fract16 _bartlett_window[], 
                                int _window_stride, 
                                int _window_size) asm("__gen_bartlett_fr16");



/* * * *        gen_blackman      * * * *
 *
 *    Generate blackman Window
 * 
 */

        void gen_blackman_fr16 (fract16 _blackman_window[],
                                int _window_stride,
                                int _window_size) asm("__gen_blackman_fr16");



/* * * *        gen_gaussian      * * * *
 *
 *    Generate gaussian Window
 * 
 */

        void gen_gaussian_fr16 (fract16 _gaussian_window[],
                                float _alpha,
                                int _window_stride,
                                int _window_size) asm("__gen_gaussian_fr16");


/* * * *        gen_hamming      * * * *
 *
 *    Generate hamming Window
 * 
 */

        void gen_hamming_fr16 (fract16 _hamming_window[],
                               int _window_stride,
                               int _window_size) asm("__gen_hamming_fr16");


/* * * *        gen_hanning      * * * *
 *
 *    Generate hanning Window
 * 
 */

        void gen_hanning_fr16 (fract16 _hanning_window[],
                               int _window_stride,
                               int _window_size) asm("__gen_hanning_fr16");


/* * * *        gen_harris      * * * *
 *
 *    Generate harris Window
 * 
 */

        void gen_harris_fr16 (fract16 _harris_window[],
                              int _window_stride,
                              int _window_size) asm("__gen_harris_fr16");


/* * * *        gen_kaiser      * * * *
 *
 *    Generate kaiser Window
 * 
 */

        void gen_kaiser_fr16 (fract16 _kaiser_window[], 
                              float _beta,
                              int _window_stride,
                              int _window_size) asm("__gen_kaiser_fr16");


/* * * *        gen_rectangular      * * * *
 *
 *    Generate rectangular Window
 * 
 */

        void gen_rectangular_fr16 (fract16 _rectangular_window[],
                                   int _window_stride,
                                   int _window_size) asm("__gen_rectangular_fr16");


/* * * *        gen_triangle      * * * *
 *
 *    Generate triangle Window
 * 
 */

        void gen_triangle_fr16 (fract16 _triangle_window[],
                                int _window_stride,
                                int _window_size) asm("__gen_triangle_fr16");


/* * * *        gen_vonhann      * * * *
 *
 *    Generate vonhann Window
 * 
 */

        void gen_vonhann_fr16 (fract16 _vonhann_window[],
                               int _window_stride,
                               int _window_size) asm("__gen_vonhann_fr16");


#ifdef __cplusplus
 }	// end extern "C"
#endif 


#endif   /* __WINDOW_DEFINED  (include guard) */


