//#pragma once
//#ifndef __NO_BUILTIN
//#pragma system_header /* sysreg.h */
//#endif
/************************************************************************
 *
 * sysreg.h
 *
 * (c) Copyright 2001-2003 Analog Devices, Inc.  All rights reserved.
 *
 ************************************************************************/

/* Sysreg definitions for use in sysreg_read/write calls. */

#ifndef _SYSREG_H
#define _SYSREG_H

enum Regno {
        reg_NONE=(-1),
        reg_R0, reg_R1, reg_R2, reg_R3, reg_R4, reg_R5, reg_R6, reg_R7,
        reg_xR0, reg_xR1, reg_xR2, reg_xR3, reg_xR4, reg_xR5, reg_xR6, reg_xR7,
        reg_xR8, reg_xR9, reg_xR10, reg_xR11, reg_xR12, reg_xR13, reg_xR14, reg_xR15,
        reg_HR0,reg_HR1,reg_HR2,reg_HR3,reg_HR4,reg_HR5,reg_HR6,reg_HR7,
        reg_xHR0,reg_xHR1,reg_xHR2,reg_xHR3,reg_xHR4,reg_xHR5,reg_xHR6,reg_xHR7,
        reg_xHR8,reg_xHR9,reg_xHR10,reg_xHR11,reg_xHR12,reg_xHR13,reg_xHR14,reg_xHR15,
        reg_P0, reg_P1, reg_P2, reg_P3, reg_P4, reg_P5,
        reg_xP0, reg_xP1, reg_xP2, reg_xP3, reg_xP4, reg_xP5,
        reg_xP6, reg_xP7, reg_xP8, reg_xP9, reg_xP10, reg_xP11, reg_SP, reg_FP,
        reg_I0, reg_I1, reg_I2, reg_I3,
        reg_B0, reg_B1, reg_B2, reg_B3,
        reg_L0, reg_L1, reg_L2, reg_L3,
        reg_Q0, reg_Q1, reg_Q2, reg_Q3, /* XXX - fake regs to pad quads */
        reg_M0, reg_M1, reg_M2, reg_M3,
        reg_ASTAT,      /* all conditon codes and more */
        reg_SEQSTAT,reg_RETS,reg_CC,
        reg_A0,reg_A1,reg_LC0,reg_LC1,
        reg_RETI,reg_RETX,reg_RETN,
        reg_LT0, reg_LT1, reg_LB0, reg_LB1,
        reg_SYSCFG, reg_CYCLES, reg_CYCLES2,
        num_Regs,
        STACKPOINTER=reg_SP,
        FRAMEPOINTER=reg_FP,
        PARAMREG0=reg_R0,
        PARAMREG1=reg_R1,
        PARAMREG2=reg_R2,
        RESULTREG=reg_R0,
        FRESULTREG=reg_R0
};

#endif /* _SYSREG_H */
