/*******************************************************************************
*																			   *
*	Define size independent data types and operations.						   *
*																			   *
*   The following types must be supported by all platforms:					   *
*																			   *
*	UINT8  - Unsigned 8-bit Integer		INT8  - Signed 8-bit integer           *
*	UINT16 - Unsigned 16-bit Integer	INT16 - Signed 16-bit integer          *
*	UINT32 - Unsigned 32-bit Integer	INT32 - Signed 32-bit integer          *
*	UINT64 - Unsigned 64-bit Integer	INT64 - Signed 64-bit integer          *
*																			   *
*																			   *
*   The macro names for the artithmatic operations are composed as follows:    *
*																			   *
*   XXX_R_A_B, where XXX - 3 letter operation code (ADD, SUB, etc.)			   *
*					 R   - The type	of the result							   *
*					 A   - The type of operand 1							   *
*			         B   - The type of operand 2 (if binary operation)		   *
*																			   *
*				     Each type is one of: U8,8,U16,16,U32,32,U64,64			   *
*																			   *
*******************************************************************************/
#ifndef OSD_CPU_H 
#define OSD_CPU_H

/* fixup some clock() related issues */
#include <time.h>
/* this is cut and pasted from sysdep/misc.c ,check sysdep/misc.c for
   changes if you suspect something is wrong with this */
/* some platforms don't define CLOCKS_PER_SEC, according to posix it should
   always be 1000000, so asume that's the case if it is not defined,
   except for openstep which doesn't define it and has it at 64 */
#ifndef CLOCKS_PER_SEC
#ifdef openstep
#define CLOCKS_PER_SEC 64     /* this is correct for OS4.2 intel */
#else
#define CLOCKS_PER_SEC 1000000
#endif
#endif

#ifndef __ARCH_solaris
/* grrr work around some stupid header conflicts */
#if !defined __XF86_DGA_C && !defined __XOPENGL_C_ && !defined LONG64
typedef signed   char      INT8;
typedef signed   short     INT16;
typedef signed   int       INT32;
#endif

#else
#include "X11/Xmd.h"
#endif

#ifndef LONG64
typedef signed   long long INT64;
#endif

typedef unsigned char      UINT8;
typedef unsigned short     UINT16;
typedef unsigned int       UINT32;
typedef unsigned long long UINT64;

/* Combine two 32-bit integers into a 64-bit integer */
#define COMBINE_64_32_32(A,B)     ((((UINT64)(A))<<32) | (UINT32)(B))
#define COMBINE_U64_U32_U32(A,B)  COMBINE_64_32_32(A,B)

/* Return upper 32 bits of a 64-bit integer */
#define HI32_32_64(A)		  (((UINT64)(A)) >> 32)
#define HI32_U32_U64(A)		  HI32_32_64(A)

/* Return lower 32 bits of a 64-bit integer */
#define LO32_32_64(A)		  ((A) & 0xffffffff)
#define LO32_U32_U64(A)		  LO32_32_64(A)

#define DIV_64_64_32(A,B)	  ((A)/(B))
#define DIV_U64_U64_U32(A,B)  ((A)/(UINT32)(B))

#define MOD_32_64_32(A,B)	  ((A)%(B))
#define MOD_U32_U64_U32(A,B)  ((A)%(UINT32)(B))

#define MUL_64_32_32(A,B)	  ((A)*(INT64)(B))
#define MUL_U64_U32_U32(A,B)  ((A)*(UINT64)(UINT32)(B))

/* disable BIG_SWITCH optimization in z80.c and m6809.c on buggy gcc
   versions */
#if (defined __GNUC__) && \
   ((__GNUC__ < 2) || ((__GNUC__ == 2) && (__GNUC_MINOR__ < 8)))
#define BIG_SWITCH          0
#else
#define BIG_SWITCH          1
#endif

/* Suppress warnings about redefining the macro 'PPC' on LinuxPPC. */
#ifdef PPC
#undef PPC
#endif

#endif	/* defined OSD_CPU_H */
