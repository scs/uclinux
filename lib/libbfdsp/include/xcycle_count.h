/************************************************************************
 *
 * xcycle_count.h
 *
 * (c) Copyright 2004 Analog Devices, Inc.  All rights reserved.
 * $Revision$
 ************************************************************************/

/*
   Generic low level support to measure cycles counts
 */

#ifndef __XCYCLE_COUNT_DEFINED
#define __XCYCLE_COUNT_DEFINED

#if !defined(_LANGUAGE_ASM)

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* xcycle_count.h */
#endif

#include <limits.h>


/* Define type used for cycle counting */

#if   defined(__ADSP21000__)
typedef  volatile unsigned long       _cycle_t;
#define  _CYCLES_T_MAX                ULONG_MAX
#define  _PRINT_CYCLES(_STRG, _DAT)   printf("%s %lu \n", _STRG, _DAT);

#elif defined(__ADSPBLACKFIN__)
typedef  volatile unsigned long long  _cycle_t;
#define  _CYCLES_T_MAX                ULLONG_MAX
#define  _PRINT_CYCLES(_STRG, _DAT)   printf("%s %llu \n", _STRG, _DAT);

#elif defined(__ADSPTS__)
typedef  volatile unsigned long long  _cycle_t;
#define  _CYCLES_T_MAX                ULLONG_MAX
#define  _PRINT_CYCLES(_STRG, _DAT)   printf("%s %llu \n", _STRG, _DAT);

#endif


/* The following low level macros are defined, operating on type _cycle_t

      _START_CYCLE_COUNT( S )    - Set S to the current value
                                   in the cycle count register(s)

      _STOP_CYCLE_COUNT( X, S )  - Return in S the elapsed cycle count
                                   since start counting
                                   X = current count
                                       - S (=start count)
                                       - measurement overhead
 */


/* Include platform specific implementation */
#if   defined(__ADSP21000__)
#include <cycle_count_21xxx.h>
#elif defined(__ADSPBLACKFIN__)
#include <cycle_count_bf.h>
#elif defined(__ADSPTS__)
#include <cycle_count_ts.h>
#else
#error  ARCHITECTURE NOT SUPPORTED
#endif

/* Private Data from here (do not remove because it is used by time.h) */

_Pragma ("weak_entry") volatile int _processor_cycles_per_sec = -1;


#else	/* _LANGUAGE_ASM */

#if defined(__ADSPBLACKFIN__)

/* Supply an Assembly Language definition of _processor_cycles_per_sec */

.section data1;
.align 4;
__processor_cycles_per_sec:
.weak  __processor_cycles_per_sec;
.type  __processor_cycles_per_sec,STT_OBJECT;
.byte = 0xff,0xff,0xff,0xff;
.__processor_cycles_per_sec.end:
#endif

#endif	/* _LANGUAGE_ASM */
#endif	/* __XCYCLE_COUNT_DEFINED */
