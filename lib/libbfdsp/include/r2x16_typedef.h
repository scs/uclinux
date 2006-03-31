#pragma once
#ifndef __NO_BUILTIN
#pragma GCC system_header /* r2x16_typedef.h */
#endif
/************************************************************************
 *
 * r2x16_typedef.h
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

/* Defines two 16-bit values packed into a single 32-bit word.  */

#ifndef _R2x16_TYPEDEF_H
#define _R2x16_TYPEDEF_H

#if defined(__ADSPBLACKFIN__) || defined(__ADSPTS__)

#include <raw_typedef.h>

typedef __v2hi	raw2x16;

#endif

#endif /* _R2x16_TYPEDEF_H */
