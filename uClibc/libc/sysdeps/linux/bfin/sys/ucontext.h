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
#define NGREG	47

/* Container for all general registers.  */
typedef greg_t gregset_t[NGREG];

/* Number of each register is the `gregset_t' array.  */
enum
{
  R0 = 0,
#define REG_R0	REG_R0
  R1 = 1,
#define REG_R1	REG_R1
  R2 = 2,
#define REG_R2	REG_R2
  R3 = 3,
#define REG_R3	REG_R3
  R4 = 4,
#define REG_R4	REG_R4
  R5 = 5,
#define REG_R5	REG_R5
  R6 = 6,
#define REG_R6	REG_R6
  R7 = 7,
#define REG_R7	REG_R7
  P0 = 8,
#define REG_P0	REG_P0
  P1 = 9,
#define REG_P1	REG_P1
  P2 = 10,
#define REG_P2	REG_P2
  P3 = 11,
#define REG_P3	REG_P3
  P4 = 12,
#define REG_P4	REG_P4
  P5 = 13,
#define REG_P5	REG_P5
  USP = 14,
#define REG_USP	REG_USP
  A0W = 15,
#define REG_A0W	REG_A0W
  A1W = 16,
#define REG_A1W	REG_A1W
  A0X = 17,
#define REG_A0X	REG_A0X
  A1X = 18,
#define REG_A1X	REG_A1X
  ASTAT = 19,
#define REG_ASTAT	REG_ASTAT
  RETS = 20,
#define REG_RETS	REG_RETS
  PC= 21,
#define REG_PC	REG_PC
  RETX = 22,
#define REG_RETX	REG_RETX
  FP = 23,
#define REG_FP	REG_FP
  I0 = 24,
#define REG_I0	REG_I0
  I1 = 25,
#define REG_I1	REG_I1
  I2 = 26,
#define REG_I2	REG_I2
  I3 = 27,
#define REG_I3	REG_I3
  M0 = 28,
#define REG_M0	REG_M0
  M1 = 29,
#define REG_M1	REG_M1
  M2 = 30,
#define REG_M2	REG_M2
  M3 = 31,
#define REG_M3	REG_M3
  L0 = 32,
#define REG_L0	REG_L0
  L1 = 33,
#define REG_L1	REG_L1
  L2 = 34,
#define REG_L2	REG_L2
  L3 = 35,
#define REG_L3	REG_L3
  B_0 = 36,
#define REG_B_0	REG_B_0
  B1 = 37,
#define REG_B1	REG_B1
  B2 = 38,
#define REG_B2	REG_B2
  B3 = 39,
#define REG_B3	REG_B3
  LC0 = 40,
#define REG_LC0	REG_LC0
  LC1 = 41,
#define REG_LC1	REG_LC1
  LT0 = 42,
#define REG_LT0	REG_LT0
  LT1 = 43,
#define REG_LT1	REG_LT1
  LB0 = 44,
#define REG_LB0	REG_LB0
  LB1 = 45,
#define REG_LB1	REG_LB1
  SEQSTAT = 46
#define	REG_SEQSTAT	REG_SEQSTAT
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
