/* Copyright (C) 1997, 1998 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with the GNU C Library; see the file COPYING.LIB.  If not,
   write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* Define the machine-dependent type `jmp_buf'.  bfin version.  Lineo, Inc. 2001*/

#ifndef _SETJMP_H
# error "Never include <bits/setjmp.h> directly; use <setjmp.h> instead."
#endif

#ifndef _ASM
/* Jump buffer contains r7-r4, p5-p3, fp, sp and pc.  Other registers are not saved.  */
typedef struct
{
	unsigned long p0;
	unsigned long p1;
	unsigned long p2;
	unsigned long p3;
	unsigned long p4;
	unsigned long p5;
	unsigned long fp;
	unsigned long sp;
	unsigned long r0;
	unsigned long r1;
	unsigned long r2;
	unsigned long r3;
	unsigned long r4;
	unsigned long r5;
	unsigned long r6;
	unsigned long r7;
	unsigned long astat;
	unsigned long lc0;
	unsigned long lc1;
	unsigned long a0w;
	unsigned long a0x;
	unsigned long a1w;
	unsigned long a1x;
	unsigned long i0;
	unsigned long i1;
	unsigned long i2;
	unsigned long i3;
	unsigned long m0;
	unsigned long m1;
	unsigned long m2;
	unsigned long m3;
	unsigned long l0;
	unsigned long l1;
	unsigned long l2;
	unsigned long l3;
	unsigned long b0;
	unsigned long b1;
	unsigned long b2;
	unsigned long b3;
	unsigned long pc;
}__jmp_buf[1];

#endif

#define __JMP_BUF_SP	8

/* Test if longjmp to JMPBUF would unwind the frame
   containing a local variable at ADDRESS.  */
#define _JMPBUF_UNWINDS(jmpbuf, address) \
  ((void *) (address) < (void *) (jmpbuf[__JMP_BUF_SP]))
