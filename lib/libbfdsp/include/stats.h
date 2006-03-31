/************************************************************************
 *
 * stats.h
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
#pragma GCC system_header /* stats.h */
#endif

#ifndef __STATS_DEFINED
#define __STATS_DEFINED


#include <fract_typedef.h>


#ifdef __cplusplus
 extern "C" {
#endif 



/* * * *        autocoh      * * * *
 *
 *    Autocoherence
 * 
 */

        void autocoh_fr16 ( const fract16 _samples[], 
                            int _sample_length, int _lags, 
                            fract16 _coherence[] ) asm("__autocoh_fr16");
        void autocohf ( const float _samples[], 
                        int _sample_length, int _lags,
                        float _coherence[] ) asm("__autocohf");
        void autocohd ( const long double _samples[], 
                        int _sample_length, int _lags,
                        long double _coherence[] ) asm("__autocohd");
#ifdef __DOUBLES_ARE_FLOATS__
        void autocoh ( const double _samples[], 
                       int _sample_length, int _lags,
                       double _coherence[]) asm("__autocohf");
#else
        void autocoh ( const double _samples[], 
                       int _sample_length, int _lags,
                       double _coherence[]) asm("__autocohd");
#endif


/* * * *        autocorr      * * * *
 *
 *    Autocorrelation
 * 
 */

        void autocorr_fr16 ( const fract16 _samples[], 
                             int _sample_length, int _lags,
                             fract16 _correlation[] ) asm("__autocorr_fr16");
        void autocorrf ( const float _samples[],
                         int _sample_length, int _lags,
                         float _correlation[] ) asm("__autocorrf");
        void autocorrd ( const long double _samples[], 
                         int _sample_length, int _lags,
                         long double _correlation[] ) asm("__autocorrd");
#ifdef __DOUBLES_ARE_FLOATS__
        void autocorr ( const double _samples[], 
                        int _sample_length, int _lags,
                        double _correlation[] ) asm("__autocorrf");
#else
        void autocorr ( const double _samples[], 
                        int _sample_length, int _lags,
                        double _correlation[] ) asm("__autocorrd");
#endif


/* * * *        crosscoh      * * * *
 *
 *    Cross-Coherence
 * 
 */

        void crosscoh_fr16 ( const fract16 _samples_x[], 
                             const fract16 _samples_y[], 
                             int _sample_length, int _lags,
                             fract16 _coherence[] ) asm("__crosscoh_fr16");
        void crosscohf ( const float _samples_x[], 
                         const float _samples_y[], 
                         int _sample_length, int _lags,
                         float _coherence[] ) asm("__crosscohf");
        void crosscohd ( const long double _samples_x[], 
                         const long double _samples_y[],
                         int _sample_length, int _lags,
                         long double _coherence[] ) asm("__crosscohd");
#ifdef __DOUBLES_ARE_FLOATS__
        void crosscoh ( const double _samples_x[], 
                        const double _samples_y[],
                        int _sample_length, int _lags,
                        double _coherence[] ) asm("__crosscohf");
#else
        void crosscoh ( const double _samples_x[], 
                        const double _samples_y[],
                        int _sample_length, int _lags,
                        double _coherence[] ) asm("__crosscohd");
#endif


/* * * *        crosscorr      * * * *
 *
 *    Cross-Correlation
 * 
 */

        void crosscorr_fr16 ( const fract16 _samples_x[], 
                              const fract16 _samples_y[], 
                              int _sample_length, int _lags,
                              fract16 _correlation[]) asm("__crosscorr_fr16");
        void crosscorrf ( const float _samples_x[], 
                          const float _samples_y[],
                          int _sample_length, int _lags, 
                          float _correlation[]) asm("__crosscorrf");
        void crosscorrd ( const long double _samples_x[], 
                          const long double _samples_y[],
                          int _sample_length, int _lags,
                          long double _correlation[] ) asm("__crosscorrd");
#ifdef __DOUBLES_ARE_FLOATS__
        void crosscorr ( const double _samples_x[],
                         const double _samples_y[],
                         int _sample_length, int _lags,
                         double _correlation[] ) asm("__crosscorrf");
#else
        void crosscorr ( const double _samples_x[],
                         const double _samples_y[],
                         int _sample_length, int _lags,
                         double _correlation[] ) asm("__crosscorrd");
#endif


/* * * *        histogram      * * * *
 *
 *    Histogram 
 * 
 */

        void histogram_fr16 ( const fract16 _samples_x[], 
                              int _histogram_x[], 
                              fract16 _max_sample, fract16 _min_sample, 
                              int _sample_length, int _bin_count ) asm("__histogram_fr16");
        void histogramf ( const float _samples_x[], 
                          int _histogram_x[], 
                          float _max_sample, float _min_sample, 
                          int _sample_length, int _bin_count ) asm("__histogramf");
        void histogramd ( const long double _samples_x[], 
                          int _histogram_x[],
                          long double _max_sample, long double _min_sample, 
                          int _sample_length, int _bin_count ) asm("__histogramd");
#ifdef __DOUBLES_ARE_FLOATS__
        void histogram ( const double _samples_x[],
                          int _histogram_x[],
                          double _max_sample, double _min_sample,
                          int _sample_length, int _bin_count ) asm("__histogramf");
#else
        void histogram ( const double _samples_x[],
                          int _histogram_x[],
                          double _max_sample, double _min_sample,
                          int _sample_length, int _bin_count ) asm("__histogramd");
#endif


/* * * *        mean      * * * *
 *
 *    Mean value
 * 
 */

        fract16 mean_fr16 (const fract16 _samples[], int _sample_length) asm("__mean_fr16");
        float meanf (const float _samples[], int _sample_length) asm("__meanf");
        long double meand (const long double _samples[], int _sample_length) asm("__meand");
#ifdef __DOUBLES_ARE_FLOATS__
        double mean (const double _samples[], int _sample_length) asm("__meanf");
#else
        double mean (const double _samples[], int _sample_length) asm("__meand");
#endif


/* * * *        rms      * * * *
 *
 *    Root Mean Square
 * 
 */

        fract16 rms_fr16 (const fract16 _samples[], int _sample_length) asm("__rms_fr16");
        float rmsf (const float _samples[], int _sample_length) asm("__rmsf");
        long double rmsd (const long double _samples[], int _sample_length) asm("__rmsd");
#ifdef __DOUBLES_ARE_FLOATS__
        double rms (const double _samples[], int _sample_length) asm("__rmsf");
#else
        double rms (const double _samples[], int _sample_length) asm("__rmsd");
#endif


/* * * *        var      * * * *
 *
 *    Variance
 * 
 */

        fract16 var_fr16 (const fract16 _samples[], int _sample_length) asm("__var_fr16");
        float varf (const float _samples[], int _sample_length) asm("__varf");
        long double vard (const long double _samples[], int _sample_length) asm("__vard");
#ifdef __DOUBLES_ARE_FLOATS__
        double var (const double _samples[], int _sample_length) asm("__varf");
#else
        double var (const double _samples[], int _sample_length) asm("__vard");
#endif


/* * * *        zero_cross      * * * *
 *
 *    Count zero crossings
 * 
 */

        int zero_cross_fr16 (const fract16 _samples[], int _sample_length) asm("__zero_cross_fr16");
        int zero_crossf (const float _samples[], int _sample_length) asm("__zero_crossf");
        int zero_crossd (const long double _samples[], int _sample_length) asm("__zero_crossd");

#ifdef __DOUBLES_ARE_FLOATS__
        int zero_cross (const double _samples[], int _sample_length) asm("__zero_crossf");
#else
        int zero_cross (const double _samples[], int _sample_length) asm("__zero_crossd");
#endif


#ifdef __cplusplus
 }	// end extern "C"
#endif 


#endif   /* __STATS_DEFINED  (include guard) */


