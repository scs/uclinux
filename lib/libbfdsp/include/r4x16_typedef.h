#pragma once
#ifndef __NO_BUILTIN
#pragma GCC system_header /* r4x16_typedef.h */
#endif
/************************************************************************
 *
 * r4x16_typedef.h
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

/* Defines type for handling four 16-bit values in one. */

#ifndef _R4x16_TYPEDEF_H
#define _R4x16_TYPEDEF_H

#include <raw_typedef.h>

#if defined(__ADSPTS__)

typedef _raw64	raw4x16;

#elif defined(__ADSPBLACKFIN__)

#include <r2x16_typedef.h>
typedef struct { raw2x16 l; raw2x16 h; } raw4x16;

#endif

#endif /* _R4x16_TYPEDEF_H */
