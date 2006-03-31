/************************************************************************
 *
 * filter.h : 
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
#pragma GCC system_header /* filter.h */
#endif

#ifndef  __FILTER_DEFINED
#define  __FILTER_DEFINED


#include <fract_typedef.h>
#include <complex.h>


#ifdef __cplusplus
 extern "C" {
#endif 

typedef struct
{
    fract16 *h;    /*  filter coefficients            */
    fract16 *d;    /*  start of delay line            */
    fract16 *p;    /*  read/write pointer             */
    int k;         /*  number of coefficients         */
    int l;         /*  interpolation/decimation index */
} _fir_fr16_state;


typedef struct
{
    fract16 *c;    /* coefficients                   */
    fract16 *d;    /* start of delay line            */
    int k;         /* number of bi-quad stages       */
} _iir_fr16_state;


typedef struct
{
    fract16 *c;    /* coefficients                  */
    fract16 *d;    /* start of delay line           */
    fract16 *p;    /* read/write pointer            */
    int k;         /* 2*number of biquad stages + 1 */
} _iirdf1_fr16_state;


typedef struct
{
    int k;
    complex_fract16 *h;
    complex_fract16 *d;
    complex_fract16 *p;
} _cfir_fr16_state;

/* Macros */

#define fir_init(state, coeffs, delay, ncoeffs, index) \
    (state).h = (coeffs);  \
    (state).d = (delay);   \
    (state).p = (delay);   \
    (state).k = (ncoeffs); \
    (state).l = (index)

#define iir_init(state, coeffs, delay, stages) \
    (state).c = (coeffs); \
    (state).d = (delay);  \
    (state).k = (stages)

#define iirdf1_init(state, coeffs, delay, stages) \
    (state).c = (coeffs); \
    (state).d = (delay);  \
    (state).p = (delay);  \
    (state).k = (2*stages+1)

#define cfir_init(state, coeffs, delay, ncoeffs) \
    (state).h = (coeffs); \
    (state).d = (delay);  \
    (state).p = (delay);  \
    (state).k = (ncoeffs)

#define fir_state_fr16    _fir_fr16_state
#define iir_state_fr16    _iir_fr16_state
#define iirdf1_state_fr16 _iirdf1_fr16_state
#define cfir_state_fr16   _cfir_fr16_state


/* * * *        fir      * * * *
 *
 *    finite impulse response filter
 * 
 */

        void fir_fr16 (const fract16 _input[], 
                       fract16 _output[], int _length, 
                       _fir_fr16_state *_filter_state) asm("__fir_fr16");




/* * * *        iir      * * * *
 *
 *    Direct Form II Infinite Impulse Response filter
 * 
 */

        void iir_fr16 (const fract16 _input[], 
                       fract16 _output[], int _length, 
                       _iir_fr16_state *_filter_state) asm("__iir_fr16");



/* * * *        iirdf1      * * * *
 *
 *    Direct Form I Infinite Impulse Response filter
 *
 */

        void iirdf1_fr16 (const fract16 _input[], 
                          fract16 _output[], int _length,
                          _iirdf1_fr16_state *_filter_state) asm("__iirdf1_fr16");


        void coeff_iirdf1_fr16 (const float _acoeff[], const float _bcoeff[],
                                fract16 _coeff[], int _nstages) asm("__coeff_iirdf1_fr16");


/* * * *        cfir      * * * *
 *
 *    complex finite impulse response filter
 * 
 */

        void cfir_fr16 (const complex_fract16 _input[], 
                        complex_fract16 _output[], int _length,
                        _cfir_fr16_state *_filter_state) asm("__cfir_fr16");




/* * * *        fir_decimation      * * * *
 *
 *    FIR decimation filter
 * 
 */

        void fir_decima_fr16 (const fract16 _input[], 
                              fract16 _output[], int _length, 
                              _fir_fr16_state *_filter_state) asm("__fir_decima_fr16");




/* * * *        fir_interp      * * * *
 *
 *    FIR interpolation filter
 * 
 */

        void fir_interp_fr16 (const fract16 _input[], 
                              fract16 _output[], int _length,
                              _fir_fr16_state *_filter_state) asm("__fir_interp_fr16");




/* * * *        convolve      * * * *
 *
 *    Convolution 1D
 * 
 */

        void convolve_fr16 (const fract16 _input_x[], int _length_x, 
                            const fract16 _input_y[], int _length_y, 
                            fract16 _output[]) asm("__convolve_fr16");




/* * * *        conv2d      * * * *
 *
 *    2D convolution
 * 
 */

        void conv2d_fr16 (const fract16 _input_x[], 
                          int _rows_a, int _columns_a, 
                          const fract16 _input_y[], 
                          int _rows_b, int _columns_b,
                          fract16 _output[]) asm("__conv2d_fr16");




/* * * *        conv2d3x3      * * * *
 *
 *    3D convolution
 * 
 */

        void conv2d3x3_fr16 (const fract16 _input_x[],  
                             int _rows_a, int _columns_a,
                             const fract16 _input_y[], 
                             fract16 _output[]) asm(" __conv2d3x3_fr16"); 


/* * * *        twidfft      * * * *
 *
 *    twiddle functions
 *       twidfft_fr16        3/4 n sized twiddle table (use in Radix4 FFT) <cos/sin>
 *       twidfftrad2_fr16    1/2 n sized twiddle table (use in Radix2 FFT) <cos/-sin>
 *       twidfftrad4_fr16    3/4 n sized twiddle table (use in Radix4 FFT) <cos/sin>
 *       twidfft2d_fr16          n sized twiddle table (use in 2D-FFT)     <cos/-sin>
 *       twidfftf_fr16       3/4 n sized twiddle table (use in Radix4 FFTF <cos/-sin>
 */

        void twidfft_fr16 (complex_fract16 _twiddle_table[], 
                           int _fft_size) asm("__twidfft_fr16");

        void twidfftrad2_fr16 (complex_fract16 _twiddle_table[], 
                               int _fft_size) asm("__twidfftrad2_fr16");

        void twidfftrad4_fr16 (complex_fract16 _twiddle_table[], 
                               int _fft_size) asm("__twidfftrad4_fr16");

        void twidfft2d_fr16 (complex_fract16 _twiddle_table[], 
                             int _fft_size) asm("__twidfft2d_fr16");


        void twidfftf_fr16 (complex_fract16 _twiddle_table[], 
                            int _fft_size) asm("__twidfftf_fr16");



/* * * *        cfftf_fr16      * * * *
 *
 *    Fast N point radix 4 complex input FFT
 *
 */
        void cfftf_fr16(const complex_fract16 _input[], 
                        complex_fract16 _output[],
                        const complex_fract16 _twiddle_table[], 
                        int _twiddle_stride, int _fft_size) asm("__cfftf_fr16");



/* * * *        cfftN      * * * *
 *
 *    N point radix 2 complex input FFT
 * 
 */

        void cfft_fr16 (const complex_fract16 _input[], 
                        complex_fract16 _temp[], 
                        complex_fract16 _output[], 
                        const complex_fract16 _twiddle_table[], 
                        int _twiddle_stride, int _fft_size, 
                        int _block_exponent, int _scale_method) asm("__cfftN_fr16");




/* * * *        rfftN      * * * *
 *
 *    N point radix 2 real input FFT
 * 
 */

        void rfft_fr16 (const fract16 _input[], 
                        complex_fract16 _temp[],
                        complex_fract16 _output[],
                        const complex_fract16 _twiddle_table[],
                        int _twiddle_stride, int _fft_size,
                        int _block_exponent, int _scale_method) asm("__rfftN_fr16");




/* * * *        ifftN      * * * *
 *
 *    N point radix 2 inverse FFT
 * 
 */

        void ifft_fr16 (const complex_fract16 _input[], 
                        complex_fract16 _temp[],
                        complex_fract16 _output[],
                        const complex_fract16 _twiddle_table[],
                        int _twiddle_stride, int _fft_size,
                        int _block_exponent, int _scale_method) asm("__ifftN_fr16");




/* * * *        cfftrad4      * * * *
 *
 *    N point radix 4 complex input FFT
 * 
 */

        void cfftrad4_fr16 (const complex_fract16 _input[], 
                            complex_fract16 _temp[],
                            complex_fract16 _output[],
                            const complex_fract16 _twiddle_table[],
                            int _twiddle_stride, int _fft_size,
                            int _block_exponent, int _scale_method) asm("__cfftrad4_fr16");




/* * * *        rfftrad4      * * * *
 *
 *    N point radix 4 real input FFT
 * 
 */

        void rfftrad4_fr16 (const fract16 _input[], 
                            complex_fract16 _temp[],
                            complex_fract16 _output[],
                            const complex_fract16 _twiddle_table[],
                            int _twiddle_stride, int _fft_size,
                            int _block_exponent, int _scale_method) asm("__rfftrad4_fr16");




/* * * *        ifftrad4      * * * *
 *
 *    N point radix 4 inverse FFT
 * 
 */

        void ifftrad4_fr16 (const complex_fract16 _input[], 
                            complex_fract16 _temp[],
                            complex_fract16 _output[],
                            const complex_fract16 _twiddle_table[],
                            int _twiddle_stride, int _fft_size,
                            int _block_exponent, int _scale_method) asm("__ifftrad4_fr16");




/* * * *        cfft2d      * * * *
 *
 *    NxN point 2 dimensional complex input 
 * 
 */

        void cfft2d_fr16 (const complex_fract16 *_input, 
                          complex_fract16 *_temp,
                          complex_fract16 *_output,
                          const complex_fract16 _twiddle_table[],
                          int _twiddle_stride, int _fft_size,
                          int _block_exponent, int _scale_method) asm("__cfft2d_fr16");




/* * * *        rfft2d      * * * *
 *
 *    NxN point 2 dimensional real input FFT
 * 
 */

        void rfft2d_fr16 (const fract16 *_input, 
                          complex_fract16 *_temp,
                          complex_fract16 *_output,
                          const complex_fract16 _twiddle_table[],
                          int _twiddle_stride, int _fft_size,
                          int _block_exponent, int _scale_method) asm("__rfft2d_fr16");




/* * * *        ifft2d      * * * *
 *
 *    NxN point 2 dimensional inverse FFT
 * 
 */

        void ifft2d_fr16 (const complex_fract16 *_input, 
                          complex_fract16 *_temp,
                          complex_fract16 *_output,
                          const complex_fract16 _twiddle_table[],
                          int _twiddle_stride, int _fft_size,
                          int _block_exponent, int _scale_method) asm("__ifft2d_fr16");




/* * * *        a_compress      * * * *
 *
 *    A-law compression
 * 
 */

        void a_compress (const short _input[], short _output[], int _length) asm("__a_compress");




/* * * *        a_expand      * * * *
 *
 *    A-law expansion
 * 
 */

        void a_expand (const short _input[], short _output[], int _length) asm("__a_expand");




/* * * *        mu_compress      * * * *
 *
 *    mu compression
 * 
 */

        void mu_compress (const short _input[], short _output[], int _length) asm("__mu_compress");




/* * * *        mu_expand      * * * *
 *
 *    mu expansion
 * 
 */

        void mu_expand (const short _input[], short _output[], int _length) asm("__mu_expand");




#ifdef __cplusplus
 }      // end extern "C"
#endif 


#endif   /* __FILTER_DEFINED  (include guard) */


