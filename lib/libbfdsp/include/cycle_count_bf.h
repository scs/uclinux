/************************************************************************
 *
 * cycle_count_bf.h
 *
 * (c) Copyright 2004 Analog Devices, Inc.  All rights reserved.
 * $Revision$
 ************************************************************************/

/*
   Platform specific functions to measure cycle counts
 */

#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* cycle_count_bf.h */
#endif

#ifndef __CYCLE_COUNT_BF_DEFINED
#define __CYCLE_COUNT_BF_DEFINED


/*  BF Processor Speed (figures denote maximum performance possible) */
#ifndef __PROCESSOR_SPEED__
 
#if defined(__ADSPBF531__)
#define  __PROCESSOR_SPEED__       400000000      /*ADSP-BF531SBBC400*/ 
                                                  /*ADSP-BF531SBST400*/ 
                                                  /*ADSP-BF531SBBZ400*/ 
#elif defined(__ADSPBF532__)
#define  __PROCESSOR_SPEED__       400000000      /*ADSP-BF532SBBC400*/
                                                  /*ADSP-BF532SBST400*/
                                                  /*ADSP-BF532SBBZ400*/
#elif defined(__ADSPBF533__)
#define  __PROCESSOR_SPEED__       594000000      /* EZ-Kit Rev 1.7  */
/* #define  __PROCESSOR_SPEED__    500000000      ADSP-BF533SBBC500  */
/* #define  __PROCESSOR_SPEED__    500000000      ADSP-BF533SBBZ500  */
/* #define  __PROCESSOR_SPEED__    600000000      ADSP-BF533SKBC600  */
/* #define  __PROCESSOR_SPEED__    750000000      ADSP-BF533SKBC750  */

#elif defined(__ADSPBF534__)
#define  __PROCESSOR_SPEED__       500000000      /* 500 MHz */

#elif defined(__ADSPBF535__)
#define  __PROCESSOR_SPEED__       300000000      /* EZ-Kit Rev 1.8  */
/* #define __PROCESSOR_SPEED__     200000000      ADSP-BF535PBB-200  */
/* #define __PROCESSOR_SPEED__     300000000      ADSP-BF535PBB-300  */
/* #define __PROCESSOR_SPEED__     300000000      ADSP-BF535PKB-300  */
/* #define __PROCESSOR_SPEED__     350000000      ADSP-BF535PKB-350  */

#elif defined(__ADSPBF536__)
#define  __PROCESSOR_SPEED__       400000000      /* 400 MHz */

#elif defined(__ADSPBF537__)
#define  __PROCESSOR_SPEED__       500000000      /* EZ-Kit Rev 1.1  */
/* #define  __PROCESSOR_SPEED__    600000000      maximum speed      */

#elif defined(__ADSPBF538__)
#define  __PROCESSOR_SPEED__       600000000      /* 600 MHz */

#elif defined(__ADSPBF539__)
#define  __PROCESSOR_SPEED__       600000000      /* 600 MHz */

#elif defined(__ADSPBF561__)
#define  __PROCESSOR_SPEED__       600000000      /* EZ-Kit Rev 1.3  */
/* #define  __PROCESSOR_SPEED__    500000000      ADSP-BF561SKBCZ500 */
/* #define  __PROCESSOR_SPEED__    500000000      ADSP-BF561SBB500   */
/* #define  __PROCESSOR_SPEED__    600000000      ADSP-BF561SKBCZ600 */
/* #define  __PROCESSOR_SPEED__    600000000      ADSP-BF561SBB600   */
/* #define  __PROCESSOR_SPEED__    750000000      ADSP-BF561SKB750   */ 

#elif defined(__ADSPBF566__)
#define  __PROCESSOR_SPEED__       600000000      /* 600 MHz */
/* #define  __PROCESSOR_SPEED__    500000000      */ 
/* #define  __PROCESSOR_SPEED__    500000000      */
/* #define  __PROCESSOR_SPEED__    750000000      */ 

#elif defined(__AD6532__)
#define  __PROCESSOR_SPEED__       300000000      /* 300 MHz */

#else
#error  PROCESSOR NOT SUPPORTED
#endif

#endif  /* !defined __PROCESSOR_SPEED__ */

/* Define low level macros to handle cycle counts */

/* Return current value in cycle count registers     
   When reading CYCLES, the contents of CYCLES2 is stored with a shadow
   write at the same time (thus reading the cycle count registers is an
   atomic operation). Reading CYCLES2 thereafter will return the upper
   half of the cycle count register at the time CYCLES has been read
   until CYCLES is read again.
 */
#define _GET_CYCLE_COUNT( _CURR_COUNT )      __asm__ volatile         \
                                             ("R2 = CYCLES;  \n"  \
                                              "R1 = CYCLES2; \n"  \
                                              "[%0]   = R2;  \n"  \
                                              "[%0+4] = R1;  \n"  \
                                              : : "a" (&(_CURR_COUNT)) \
                                              : "R1", "R2" );

#if defined( DO_CYCLE_COUNTS )

/* Return current value in cycle count register */
#define _START_CYCLE_COUNT( _START_COUNT )  _GET_CYCLE_COUNT( _START_COUNT )

/* Return cycle count minus measurement overhead incurred 
   If measuring cycle counts for an application built non-optimsed,
   the overhead increases to 6.
 */
#define _STOP_CYCLE_COUNT( _CURR_COUNT, _START_COUNT ) \
                                           __asm__ volatile           \
                                             ("R2 = CYCLES;  \n"  \
                                              "R1 = CYCLES2; \n"  \
                                              "[%0]   = R2;  \n"  \
                                              "[%0+4] = R1;  \n"  \
                                              : : "a" (&(_CURR_COUNT))  \
                                              : "R1", "R2" );           \
                        (_CURR_COUNT) = (_CURR_COUNT) - (_START_COUNT); \
                        (_CURR_COUNT) -= (_cycle_t) 4;  

#else   /* DO_CYCLE_COUNTS */

/* Replace macros with empty statements if no cycle count facility required */
#define _START_CYCLE_COUNT( _START_COUNT )
#define _STOP_CYCLE_COUNT ( _CURR_COUNT, _START_COUNT )

#endif  /* DO_CYCLE_COUNTS */ 
#endif  /* __CYCLE_COUNT_BF_DEFINED */
