/************************************************************************
 *
 * vector.h
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
#pragma GCC system_header /* vector.h */
#endif

#ifndef  __VECTOR_DEFINED
#define  __VECTOR_DEFINED

#include <fract_typedef.h>
#include <complex.h>

#ifdef __cplusplus
 extern "C" {
#endif 



/* * * *        vecsadd      * * * *
 *
 *    real vector + real scalar addition
 * 
 */

        void vecsaddf (const float _vector[], float _scalar, 
                       float _sum[], int _length) asm("__vecsaddf");
        void vecsaddd (const long double _vector[], long double _scalar,
                       long double _sum[], int _length) asm("__vecsaddd");
#ifdef __DOUBLES_ARE_FLOATS__
        void vecsadd (const double _vector[], double _scalar, 
                      double _sum[], int _length) asm("__vecsaddf");
#else
        void vecsadd (const double _vector[], double _scalar, 
                      double _sum[], int _length) asm("__vecsaddd");
#endif
        void vecsadd_fr16 (const fract16 _vector[], fract16 _scalar, 
                           fract16 _sum[], int _length) asm("__vecsadd_fr16");



/* * * *        vecssub      * * * *
 *
 *    real vector - real scalar subtraction
 * 
 */

        void vecssubf (const float _vector[], float _scalar, 
                       float _difference[], int _length) asm("__vecssubf");
        void vecssubd (const long double _vector[], long double _scalar,
                       long double _difference[], int _length) asm("__vecssubd");
#ifdef __DOUBLES_ARE_FLOATS__
        void vecssub (const double _vector[], double _scalar, 
                      double _difference[], int _length) asm("__vecssubf");
#else
        void vecssub (const double _vector[], double _scalar, 
                      double _difference[], int _length) asm("__vecssubd");
#endif
        void vecssub_fr16 (const fract16 _vector[], fract16 _scalar, 
                           fract16 _difference[], int _length) asm("__vecssub_fr16");



/* * * *        vecsmlt      * * * *
 *
 *    real vector * real scalar multiplication
 * 
 */

        void vecsmltf (const float _vector[], float _scalar, 
                       float _product[], int _length) asm("__vecsmltf");
        void vecsmltd (const long double _vector[], long double _scalar,
                       long double _product[], int _length) asm("__vecsmltd");
#ifdef __DOUBLES_ARE_FLOATS__
        void vecsmlt (const double _vector[], double _scalar, 
                      double _product[], int _length) asm("__vecsmltf");
#else
        void vecsmlt (const double _vector[], double _scalar, 
                      double _product[], int _length) asm("__vecsmltd");
#endif
        void vecsmlt_fr16 (const fract16 _vector[], fract16 _scalar, 
                           fract16 _product[], int _length) asm("__vecsmlt_fr16");



/* * * *        vecvadd      * * * *
 *
 *    real vector + real vector addition
 * 
 */

        void vecvaddf (const float _vector_x[], 
                       const float _vector_y[], 
                       float _sum[], int _length) asm("__vecvaddf");
        void vecvaddd (const long double _vector_x[], 
                       const long double _vector_y[],
                       long double _sum[], int _length) asm("__vecvaddd");
#ifdef __DOUBLES_ARE_FLOATS__
        void vecvadd (const double _vector_x[], 
                      const double _vector_y[], 
                      double _sum[], int _length) asm("__vecvaddf");
#else
        void vecvadd (const double _vector_x[], 
                      const double _vector_y[], 
                      double _sum[], int _length) asm("__vecvaddd");
#endif
        void vecvadd_fr16 (const fract16 _vector_x[], 
                           const fract16 _vector_y[], 
                           fract16 _sum[], int _length) asm("__vecvadd_fr16");



/* * * *        vecvsub      * * * *
 *
 *    real vector - real vector subtraction
 * 
 */

        void vecvsubf (const float _vector_x[], 
                       const float _vector_y[], 
                       float _difference[], int _length) asm("__vecvsubf");

        void vecvsubd (const long double _vector_x[], 
                       const long double _vector_y[],
                       long double _difference[], int _length) asm("__vecvsubd");
#ifdef __DOUBLES_ARE_FLOATS__
        void vecvsub (const double _vector_x[], 
                      const double _vector_y[], 
                      double _difference[], int _length) asm("__vecvsubf");
#else
        void vecvsub (const double _vector_x[], 
                      const double _vector_y[], 
                      double _difference[], int _length) asm("__vecvsubd");
#endif
        void vecvsub_fr16 (const fract16 _vector_x[], 
                           const fract16 _vector_y[], 
                           fract16 _difference[], int _length) asm("__vecvsub_fr16");



/* * * *        vecvmlt      * * * *
 *
 *    real vector * real vector multiplication
 * 
 */

        void vecvmltf (const float _vector_x[], 
                       const float _vector_y[], 
                       float _product[], int _length) asm("__vecvmltf");
        void vecvmltd (const long double _vector_x[], 
                       const long double _vector_y[],
                       long double _product[], int _length) asm("__vecvmltd");
#ifdef __DOUBLES_ARE_FLOATS__
        void vecvmlt (const double _vector_x[], 
                      const double _vector_y[], 
                      double _product[], int _length) asm("__vecvmltf");
#else
        void vecvmlt (const double _vector_x[], 
                      const double _vector_y[], 
                      double _product[], int _length) asm("__vecvmltd");
#endif
        void vecvmlt_fr16 (const fract16 _vector_x[], 
                           const fract16 _vector_y[], 
                           fract16 _product[], int _length) asm("__vecvmlt_fr16");



/* * * *        vecdot      * * * *
 *
 *    real vector dot product
 * 
 */

        float vecdotf (const float _vector_x[], 
                       const float _vector_y[], 
                       int _length) asm("__vecdotf");
        long double vecdotd (const long double _vector_x[], 
                             const long double _vector_y[], 
                             int _length) asm("__vecdotd");
#ifdef __DOUBLES_ARE_FLOATS__
        double vecdot (const double _vector_x[], 
                       const double _vector_y[], 
                       int _length) asm("__vecdotf");
#else
        double vecdot (const double _vector_x[], 
                       const double _vector_y[], 
                       int _length) asm("__vecdotd");
#endif
        fract16 vecdot_fr16 (const fract16 _vector_x[], 
                             const fract16 _vector_y[], 
                             int _length) asm("__vecdot_fr16");



/* * * *        vecmax      * * * *
 *
 *    Maximum value of vector elements
 * 
 */

        float vecmaxf (const float _vector[], int _length) asm("__vecmaxf");
        long double vecmaxd (const long double _vector[], int _length) asm("__vecmaxd");
#ifdef __DOUBLES_ARE_FLOATS__
        double vecmax (const double _vector[], int _length) asm("__vecmaxf");
#else
        double vecmax (const double _vector[], int _length) asm("__vecmaxd");
#endif
        fract16 vecmax_fr16 (const fract16 _vector[], int _length) asm("__vecmax_fr16");



/* * * *        vecmin      * * * *
 *
 *    Minimum value of vector elements
 * 
 */

        float vecminf (const float _vector[], int _length) asm("__vecminf");
        long double vecmind (const long double _vector[], int _length) asm("__vecmind");
#ifdef __DOUBLES_ARE_FLOATS__
        double vecmin (const double _vector[], int _length) asm("__vecminf");
#else
        double vecmin (const double _vector[], int _length) asm("__vecmind");
#endif
        fract16 vecmin_fr16 (const fract16 _vector[], int _length) asm("__vecmin_fr16");



/* * * *        vecmaxloc      * * * *
 *
 *    Index of maximum value of vector elements
 * 
 */

        int vecmaxlocf (const float _vector[], int _length) asm("__vecmaxlocf");
        int vecmaxlocd (const long double _vector[], int _length) asm("__vecmaxlocd");
#ifdef __DOUBLES_ARE_FLOATS__
        int vecmaxloc (const double _vector[], int _length) asm("__vecmaxlocf");
#else
        int vecmaxloc (const double _vector[], int _length) asm("__vecmaxlocd");
#endif
        int vecmaxloc_fr16 (const fract16 _vector[], int _length) asm("__vecmaxloc_fr16");



/* * * *        vecminloc      * * * *
 *
 *    Index of minimum value of vector elements
 * 
 */

        int vecminlocf (const float _vector[], int _length) asm("__vecminlocf");
        int vecminlocd (const long double _vector[], int _length) asm("__vecminlocd");
#ifdef __DOUBLES_ARE_FLOATS__
        int vecminloc (const double _vector[], int _length) asm("__vecminlocf");
#else
        int vecminloc (const double _vector[], int _length) asm("__vecminlocd");
#endif
        int vecminloc_fr16 (const fract16 _vector[], int _length) asm("__vecminloc_fr16");



/* * * *        cvecsadd      * * * *
 *
 *    complex vector + complex scalar addition
 * 
 */

        void cvecsaddf (const complex_float _vector[], 
                        complex_float _scalar, 
                        complex_float _sum[], int _length) asm("__cvecsaddf");
        void cvecsaddd (const complex_long_double _vector[], 
                        complex_long_double _scalar,
                        complex_long_double _sum[], int _length) asm("__cvecsaddd");
#ifdef __DOUBLES_ARE_FLOATS__
        void cvecsadd (const complex_double _vector[], 
                       complex_double _scalar, 
                       complex_double _sum[], int _length) asm("__cvecsaddf");
#else
        void cvecsadd (const complex_double _vector[], 
                       complex_double _scalar, 
                       complex_double _sum[], int _length) asm("__cvecsaddd");
#endif
        void cvecsadd_fr16 (const complex_fract16 _vector[], 
                            complex_fract16 _scalar, 
                            complex_fract16 _sum[], int _length) asm("__cvecsadd_fr16");



/* * * *        cvecssub      * * * *
 *
 *    complex vector - complex scalar subtraction
 * 
 */

        void cvecssubf (const complex_float _vector[], 
                        complex_float _scalar, 
                        complex_float _difference[], int _length) asm("__cvecssubf");
        void cvecssubd (const complex_long_double _vector[], 
                        complex_long_double _scalar,
                        complex_long_double _difference[], int _length) asm("__cvecssubd");
#ifdef __DOUBLES_ARE_FLOATS__
        void cvecssub (const complex_double _vector[], 
                       complex_double _scalar, 
                       complex_double _difference[], int _length) asm("__cvecssubf");
#else
        void cvecssub (const complex_double _vector[], 
                       complex_double _scalar, 
                       complex_double _difference[], int _length) asm("__cvecssubd");
#endif
        void cvecssub_fr16 (const complex_fract16 _vector[], 
                            complex_fract16 _scalar, 
                            complex_fract16 _difference[], int _length) asm("__cvecssub_fr16");



/* * * *        cvecsmlt      * * * *
 *
 *    complex vector * complex scalar multiplication
 * 
 */

        void cvecsmltf (const complex_float _vector[], 
                        complex_float _scalar, 
                        complex_float _product[], int _length) asm("__cvecsmltf");
        void cvecsmltd (const complex_long_double _vector[], 
                        complex_long_double _scalar,
                        complex_long_double _product[], int _length) asm("__cvecsmltd");
#ifdef __DOUBLES_ARE_FLOATS__
        void cvecsmlt (const complex_double _vector[], 
                       complex_double _scalar, 
                       complex_double _product[], int _length) asm("__cvecsmltf");
#else
        void cvecsmlt (const complex_double _vector[], 
                       complex_double _scalar, 
                       complex_double _product[], int _length) asm("__cvecsmltd");
#endif
        void cvecsmlt_fr16 (const complex_fract16 _vector[], 
                            complex_fract16 _scalar, 
                            complex_fract16 _product[], int _length) asm("__cvecsmlt_fr16");



/* * * *        cvecvadd      * * * *
 *
 *    complex vector + complex vector addition
 * 
 */

        void cvecvaddf (const complex_float _vector_a[], 
                        const complex_float _vector_b[], 
                        complex_float _sum[], int _length) asm("__cvecvaddf");
        void cvecvaddd (const complex_long_double _vector_a[], 
                        const complex_long_double _vector_b[],
                        complex_long_double _sum[], int _length) asm("__cvecvaddd");
#ifdef __DOUBLES_ARE_FLOATS__
        void cvecvadd (const complex_double _vector_a[], 
                       const complex_double _vector_b[], 
                       complex_double _sum[], int _length) asm("__cvecvaddf");
#else
        void cvecvadd (const complex_double _vector_a[], 
                       const complex_double _vector_b[], 
                       complex_double _sum[], int _length) asm("__cvecvaddd");
#endif
        void cvecvadd_fr16 (const complex_fract16 _vector_a[], 
                            const complex_fract16 _vector_b[], 
                            complex_fract16 _sum[], int _length) asm("__cvecvadd_fr16");



/* * * *        cvecvsub      * * * *
 *
 *    complex vector - complex vector subtraction
 * 
 */

        void cvecvsubf (const complex_float _vector_a[], 
                        const complex_float _vector_b[], 
                        complex_float _difference[], int _length) asm("__cvecvsubf");
        void cvecvsubd (const complex_long_double _vector_a[], 
                        const complex_long_double _vector_b[],
                        complex_long_double _difference[], int _length) asm("__cvecvsubd");
#ifdef __DOUBLES_ARE_FLOATS__
        void cvecvsub (const complex_double _vector_a[], 
                       const complex_double _vector_b[], 
                       complex_double _difference[], int _length) asm("__cvecvsubf");
#else
        void cvecvsub (const complex_double _vector_a[], 
                       const complex_double _vector_b[], 
                       complex_double _difference[], int _length) asm("__cvecvsubd");
#endif
        void cvecvsub_fr16 (const complex_fract16 _vector_a[], 
                            const complex_fract16 _vector_b[], 
                            complex_fract16 _difference[], int _length) asm("__cvecvsub_fr16");



/* * * *        cvecvmlt      * * * *
 *
 *    complex vector * complex vector multiplication
 * 
 */

        void cvecvmltf (const complex_float _vector_a[], 
                        const complex_float _vector_b[], 
                        complex_float _product[], int _length) asm("__cvecvmltf");
        void cvecvmltd (const complex_long_double _vector_a[], 
                        const complex_long_double _vector_b[],
                        complex_long_double _product[], int _length) asm("__cvecvmltd");
#ifdef __DOUBLES_ARE_FLOATS__
        void cvecvmlt (const complex_double _vector_a[], 
                       const complex_double _vector_b[], 
                       complex_double _product[], int _length) asm("__cvecvmltf");
#else
        void cvecvmlt (const complex_double _vector_a[], 
                       const complex_double _vector_b[], 
                       complex_double _product[], int _length) asm("__cvecvmltd");
#endif
        void cvecvmlt_fr16 (const complex_fract16 _vector_a[], 
                            const complex_fract16 _vector_b[], 
                            complex_fract16 _product[], int _length) asm("__cvecvmlt_fr16");



/* * * *        cvecdot      * * * *
 *
 *    complex vector dot product
 * 
 */

        complex_float cvecdotf (const complex_float _vector_a[], 
                                const complex_float _vector_b[], 
                                int _length) asm("__cvecdotf");
        complex_long_double cvecdotd (const complex_long_double _vector_a[],
                                      const complex_long_double _vector_b[], 
                                      int _length) asm("__cvecdotd");
#ifdef __DOUBLES_ARE_FLOATS__
        complex_double cvecdot (const complex_double _vector_a[], 
                                const complex_double _vector_b[], 
                                int _length) asm("__cvecdotf");
#else
        complex_double cvecdot (const complex_double _vector_a[], 
                                const complex_double _vector_b[], 
                                int _length) asm("__cvecdotd");
#endif
        complex_fract16 cvecdot_fr16 (const complex_fract16 _vector_a[], 
                                      const complex_fract16 _vector_b[], 
                                      int _length) asm("__cvecdot_fr16");



#ifdef __cplusplus
 }	// end extern "C"
#endif 


#endif   /* __VECTOR_DEFINED  (include guard) */
