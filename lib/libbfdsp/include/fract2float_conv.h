#pragma once
#ifndef __NO_BUILTIN
#pragma GCC system_header /* fract2float_conv.h */
#endif
/************************************************************************
 *
 * fract2float_conv.h
 *
 * (c) Copyright 2000-2003 Analog Devices, Inc.
 * This file is subject to the terms and conditions of the GNU Library General
 * Public License. See the file "COPYING.LIB" in the main directory of this
 * archive for more details.
 *
 * Non-LGPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 *
 *
 ************************************************************************/

/* Conversions between fract{16|32}'s and floats. */

#include <fract_typedef.h>

#ifndef _FRACT2FLOAT_CONV_H
#define _FRACT2FLOAT_CONV_H

#ifdef __cplusplus
extern "C" {
#endif

    static __inline fract32 fr16_to_fr32(fract16 _x) {
       /* convert a fract16 to a fract32 */
       return ((fract32)(_x)) << 16;
    }

    static __inline fract16 fr32_to_fr16(fract32 _x) {
       /* Convert a fract32 to a fract16. */
       return (fract16)(_x >> 16);
    }

    float   fr32_to_float (fract32);
    fract32 float_to_fr32 (float);

    static __inline float fr16_to_float(fract16 _x) {
       return fr32_to_float(fr16_to_fr32(_x));
    }

    static __inline fract16 float_to_fr16(float _x) {
       return fr32_to_fr16(float_to_fr32(_x));
    }

#ifdef __cplusplus
}
#endif

#endif /* _FRACT2FLOAT_CONV_H */
