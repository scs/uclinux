/* GNU/Linux/ARM specific low level interface, for the remote server for GDB.
   Copyright 1995, 1996, 1998, 1999, 2000, 2001, 2002
   Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

#include "server.h"
#include "linux-low.h"
#include <asm/asm-offsets.h>
//#ifdef HAVE_SYS_REG_H
//#include <sys/reg.h>
//#endif

//#define bfin_num_regs 52 
//#define bfin_num_regs 49

 
/* This table must line up with REGISTER_NAMES in tm-bfin.h */
static int bfin_regmap[] =
{
  PT_SYSCFG, /*PT_ORIG_R0,*/  PT_R0, PT_R1, PT_R2, PT_R3, PT_R4, PT_R5, PT_R6, PT_R7,
  PT_P0, PT_P1, PT_P2, PT_P3, PT_P4, PT_P5, PT_FP, PT_USP,
  PT_I0, PT_I1, PT_I2, PT_I3, PT_M0, PT_M1, PT_M2, PT_M3,
  PT_L0, PT_L1, PT_L2, PT_L3, PT_B0, PT_B1, PT_B2, PT_B3,
  PT_A0X,   PT_A0W,   PT_A1X,   PT_A1W,   PT_LC0,   PT_LC1,   PT_LT0,   PT_LT1,
  PT_LB0,   PT_LB1,   PT_ASTAT, PT_RESERVED, PT_RETS, PT_PC,  PT_RETX,  PT_RETN,
  PT_RETE,  PT_SEQSTAT, PT_IPEND, PT_ORIG_PC, PT_EXTRA1, PT_EXTRA2, PT_EXTRA3
};

#define bfin_num_regs  (sizeof(bfin_regmap)/ sizeof(bfin_regmap[0]))

static int
bfin_cannot_store_register (int regno)
{
  return (regno >= bfin_num_regs);
}

static int
bfin_cannot_fetch_register (int regno)
{
  return (regno >= bfin_num_regs);
  //return (regno >= 3 && regno <= 13);
}
static CORE_ADDR
bfin_get_pc ()
{
  unsigned long pc;
  collect_register_by_name ("pc", &pc);
  return pc;
}

static void
bfin_set_pc (CORE_ADDR pc)
{
  unsigned long newpc = pc;
  supply_register_by_name ("pc", &newpc);
}

#define bfin_breakpoint_len 2
static const unsigned char bfin_breakpoint[bfin_breakpoint_len]={0xa1, 0x00};
static int
bfin_breakpoint_at (CORE_ADDR where)
{
  unsigned char insn[bfin_breakpoint_len];

  read_inferior_memory(where, insn, bfin_breakpoint_len);
  if (insn[0] == bfin_breakpoint[0] &&
      insn[1] == bfin_breakpoint[1])
    return 1;

  /* If necessary, recognize more trap instructions here.  GDB only uses the
     one.  */
  return 0;
}

/* We only place breakpoints in empty marker functions, and thread locking
   is outside of the function.  So rather than importing software single-step,
   we can just run until exit.  */
static CORE_ADDR
bfin_reinsert_addr ()
{
  unsigned long pc;

  collect_register_by_name ("rets", &pc);

  return pc;
}

struct linux_target_ops the_low_target = {
  bfin_num_regs,
  bfin_regmap,
  bfin_cannot_fetch_register,
  bfin_cannot_store_register,
  bfin_get_pc, /*0*/
  bfin_set_pc, /*0*/
  bfin_breakpoint, /*0,*/
  bfin_breakpoint_len, /*0,*/
  bfin_reinsert_addr,
  0,
  bfin_breakpoint_at, /*0,*/
};
