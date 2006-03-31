/************************************************************************
 *
 * cycle_count.h
 *
 * (c) Copyright 2004 Analog Devices, Inc.
 * This file is subject to the terms and conditions of the GNU Library General
 * Public License. See the file "COPYING.LIB" in the main directory of this
 * archive for more details.
 *
 * Non-LGPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 *
 * $Revision$
 ************************************************************************/

/*
   Generic low level interface to measure cycles counts
 */

#pragma once
#ifndef __NO_BUILTIN
#pragma GCC system_header /* cycle_count.h */
#endif

#ifndef __CYCLE_COUNT_DEFINED
#define __CYCLE_COUNT_DEFINED


/* Include low level support */
#include <xcycle_count.h>


typedef  _cycle_t    cycle_t;


/* The following low level macros are defined, operating on type cycle_t 

      START_CYCLE_COUNT( S )    - Set S to the current value  
                                  in the cycle count register(s) 

      STOP_CYCLE_COUNT( X, S )  - Return in X the elapsed cycle count 
                                  since start counting 
                                  X =   current count 
                                      - S (=start count)
                                      - measurement overhead
      PRINT_CYCLES( STRG, X )   - Print string STRG followed by X
 */


#if defined( DO_CYCLE_COUNTS )

#define  START_CYCLE_COUNT( _S )     _START_CYCLE_COUNT( _S )
#define  STOP_CYCLE_COUNT( _X, _S )  _STOP_CYCLE_COUNT( _X, _S )
#define  PRINT_CYCLES( _STRG, _X )   _PRINT_CYCLES( _STRG, _X )

#else    /* DO_CYCLE_COUNTS */
/* Replace macros with empty statements if no cycle count facility required */

#define  START_CYCLE_COUNT( _S )
#define  STOP_CYCLE_COUNT( _X, _S )
#define  PRINT_CYCLES( _STRG, _X )

#endif   /* DO_CYCLE_COUNTS */
#endif   /* __CYCLE_COUNT_DEFINED */
