#pragma once
#ifndef __NO_BUILTIN
#pragma GCC system_header /* fract.h */
#endif
/************************************************************************
 *
 * fract.h
 *
 * (c) Copyright 2000-2004 Analog Devices, Inc.
 * This file is subject to the terms and conditions of the GNU Library General
 * Public License. See the file "COPYING.LIB" in the main directory of this
 * archive for more details.
 *
 * Non-LGPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 *
 *
 ************************************************************************/

/* General fractional types and operations.  */

#ifndef _FRACT_H
#define _FRACT_H

#include <fract_typedef.h>
#include <fract_math.h>
#include <fract2float_conv.h>

#define FRACT16_BIT     16                     /* bits in a fract16 */
#define FRACT32_BIT     32                     /* bits in a fract32 */

#define FRACT16_MAX     (fract16)0x7fff        /* max value of a fract16 */
#define FRACT16_MIN     (fract16)0x8000        /* min value of a fract16 */

#define FRACT32_MAX     (fract32)0x7fffffff    /* max value of a fract32 */
#define FRACT32_MIN     (fract32)0x80000000    /* min value of a fract32 */


#endif /* _FRACT_H */
