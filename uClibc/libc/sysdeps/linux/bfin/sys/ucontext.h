/* Copyright (C) 1997, 1999, 2001 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

/* System V/blackfin ABI compliant context switching support.  */

#ifndef _SYS_UCONTEXT_H
#define _SYS_UCONTEXT_H	1

#include <features.h>
#include <signal.h>

/* Type for general register.  */
typedef int greg_t;

/* Number of general registers.  */
#define NGREG	20

/* Container for all general registers.  */
typedef greg_t gregset_t[NGREG];

/* Number of each register is the `gregset_t' array.  */
enum
{
  R0 = 0,
#define R0	R0
  R1 = 1,
#define R1	R1
  R2 = 2,
#define R2	R2
  R3 = 3,
#define R3	R3
  R4 = 4,
#define R4	R4
  R5 = 5,
#define R5	R5
  R6 = 6,
#define R6	R6
  R7 = 7,
#define R7	R7
  P0 = 8,
#define P0	P0
  P1 = 9,
#define P1	P1
  P2 = 10,
#define P2	P2
  P3 = 11,
#define P3	P3
  P4 = 12,
#define P4	P4
  P5 = 13,
#define P5	P5
  A0W = 14,
#define A0W	A0W
  A1W = 15,
#define A1W	A1W
  A0X = 16,
#define A0X	A0X
  A1X = 17,
#define A1X	A1X
  ASTAT = 18,
#define ASTAT	ASTAT
  RETS = 19
#define RETS	RETS
};

/* Context to describe whole processor state.  */
typedef struct
{
  int version;
  gregset_t gregs;
} mcontext_t;


/* Userlevel context.  */
typedef struct ucontext
{
  unsigned long int uc_flags;
  struct ucontext *uc_link;
  stack_t uc_stack;
  mcontext_t uc_mcontext;
  __sigset_t uc_sigmask;
} ucontext_t;

#endif /* sys/ucontext.h */
