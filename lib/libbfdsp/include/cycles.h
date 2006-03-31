/************************************************************************
 *
 * cycles.h
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
   Generic top level interface to measure cycles counts 
 */

#pragma once
#ifndef __NO_BUILTIN
#pragma GCC system_header /* cycles.h */
#endif

#ifndef __CYCLES_DEFINED
#define __CYCLES_DEFINED


/* Include low level support */
#include <xcycle_count.h>


typedef struct
{
#if defined(__ADSPBLACKFIN__)
  _cycle_t  _start_cycles;
#endif
  _cycle_t  _cycles, _max_cycles, _min_cycles, _total_cycles;
  long      _num_calls;
} cycle_stats_t;



#if defined( DO_CYCLE_COUNTS )

  /* Cycle count macros, operating on type cycle_stats_t

        CYCLES_INIT  - Zeros statistics

        CYCLES_START - Starts measuring cycles

        CYCLES_STOP  - Stops measuring cycles and accumulates statistics

        CYCLES_RESET - Re-zeros statistics

        CYCLES_PRINT - Print summary of the accumulated statistics
  */

#define CYCLES_INIT( _X )    _cycles_init( &(_X) );

#if defined(__ADSPBLACKFIN__)
#define CYCLES_START( _X )   _START_CYCLE_COUNT( _X._start_cycles );
#else
#define CYCLES_START( _X )   _START_CYCLE_COUNT( _X._cycles );
#endif

#if defined(__ADSPBLACKFIN__)
#define CYCLES_STOP( _X )    _STOP_CYCLE_COUNT( _X._cycles, _X._start_cycles ); \
                             if (_X._cycles > _X._max_cycles)  \
                                 _X._max_cycles = _X._cycles;  \
                             if (_X._cycles < _X._min_cycles)  \
                                 _X._min_cycles = _X._cycles;  \
                             _X._total_cycles += _X._cycles;   \
                             _X._num_calls++;
#else
#define CYCLES_STOP( _X )    _STOP_CYCLE_COUNT( _X._cycles, _X._cycles ); \
                             if (_X._cycles > _X._max_cycles)  \
                                 _X._max_cycles = _X._cycles;  \
                             if (_X._cycles < _X._min_cycles)  \
                                 _X._min_cycles = _X._cycles;  \
                             _X._total_cycles += _X._cycles;   \
                             _X._num_calls++;
#endif

#define CYCLES_RESET( _X )   _X._max_cycles = 0; \
                             _X._min_cycles = _CYCLES_T_MAX; \
                             _X._total_cycles = 0; \
                             _X._num_calls = 0; 

#define CYCLES_PRINT( _X )   if (_X._num_calls > 1) {  \
                                 _PRINT_CYCLES("\t AVG   :", \
                                           (_X._total_cycles / _X._num_calls)) \
                                 _PRINT_CYCLES("\t MIN   :", _X._min_cycles)   \
                                 _PRINT_CYCLES("\t MAX   :", _X._max_cycles)   \
                                 _PRINT_CYCLES("\t CALLS :", \
                                           ((_cycle_t) _X._num_calls)) \
                             } else { \
                                 _PRINT_CYCLES("\t CYCLES :", _X._total_cycles)}

#else   /* CYCLE_COUNTS */
/* Replace macros with empty statements if no cycle count facility required */

#define CYCLES_INIT( _X )
#define CYCLES_START( _X )
#define CYCLES_STOP( _X )
#define CYCLES_RESET( _X )
#define CYCLES_PRINT( _X )

#endif  /* CYCLE_COUNTS */


static __inline void _cycles_init(cycle_stats_t *_data)
{
  _data->_max_cycles = 0;
  _data->_min_cycles = _CYCLES_T_MAX;

  _data->_total_cycles = 0;

  _data->_num_calls = 0;

#if defined(__ADSPBLACKFIN__)
  _data->_start_cycles = 0;
  _data->_cycles = 0;
#endif
}

#endif  /* __CYCLES_DEFINED */
