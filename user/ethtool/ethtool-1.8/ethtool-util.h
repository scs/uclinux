/* Portions Copyright 2001 Sun Microsystems (thockin@sun.com) */
/* Portions Copyright 2002 Intel (scott.feldman@intel.com) */
#ifndef ETHTOOL_UTIL_H__
#define ETHTOOL_UTIL_H__

#include <sys/types.h>
typedef unsigned long long u64;         /* hack, so we may include kernel's ethtool.h */
typedef __uint32_t u32;         /* ditto */
typedef __uint16_t u16;         /* ditto */
typedef __uint8_t u8;           /* ditto */
#include "ethtool-copy.h"

/* National Semiconductor DP83815, DP83816 */
int natsemi_dump_regs(struct ethtool_drvinfo *info, struct ethtool_regs *regs);
int natsemi_dump_eeprom(struct ethtool_drvinfo *info, 
	struct ethtool_eeprom *ee);

/* Digital/Intel 21040 and 21041 */
int de2104x_dump_regs(struct ethtool_drvinfo *info, struct ethtool_regs *regs);

/* Intel(R) PRO/1000 Gigabit Adapter Family */
int e1000_dump_regs(struct ethtool_drvinfo *info, struct ethtool_regs *regs);

/* RealTek PCI */
int realtek_dump_regs(struct ethtool_drvinfo *info, struct ethtool_regs *regs);

/* Intel(R) PRO/100 Fast Ethernet Adapter Family */
int e100_dump_regs(struct ethtool_drvinfo *info, struct ethtool_regs *regs);

/* Tigon3 */
int tg3_dump_eeprom(struct ethtool_drvinfo *info, struct ethtool_eeprom *ee);

/* Advanced Micro Devices  AMD8111 based Adapter */
int amd8111e_dump_regs(struct ethtool_drvinfo *info, struct ethtool_regs *regs);

#endif
