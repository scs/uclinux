#pragma once
#ifndef __NO_BUILTIN
#pragma GCC system_header /* raw_typedef.h */
#endif
/************************************************************************
 *
 * raw_typedef.h
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

/* raw type definitions */

#ifndef _RAW_TYPEDEF_H
#define _RAW_TYPEDEF_H

typedef char  _raw8;
typedef short _raw16;
typedef int   _raw32;
#if !defined(__NO_BUILTIN)
typedef short __v2hi __attribute__ ((vector_size (4)));
#endif

#endif /* _RAW_TYPEDEF_H */
