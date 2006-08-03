
/*
 * File:         include/asm-blackfin/mach-bf537/anomaly.h
 * Based on:
 * Author:
 *
 * Created:
 * Description:
 *
 * Rev:
 *
 * Modified:
 *
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.
 * If not, write to the Free Software Foundation,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef _MACH_ANOMALY_H_
#define _MACH_ANOMALY_H_

#define ANOMALY_05000281 /*False Hardware Error Exception when ISR context is not restored*/
#define ANOMALY_05000272 /*Certain data cache write through modes fail for VDDint <=0.9V*/
#define ANOMALY_05000273 /*Writes to Synchronous SDRAM memory may be lost*/
#define ANOMALY_05000283 /*A system MMR write is stalled indefinitely when killed in a
         particular stage*/

#if defined(CONFIG_BF_REV_0_2)

#define ANOMALY_05000244 /*With instruction cache enabled, a CSYNC or SSYNC or IDL
         around a Change of Control causes unpredictable results*/
#define ANOMALY_05000264 /*A Sync instruction (CSYNC, SSYNC) or an IDLE instruction will
         cause an infinite stall in the second to last instruction in a
         hardware loop*/
#define ANOMALY_05000258 /*Instruction Cache is corrupted when bit 9 and 12 of the ICPLB
         Data registers differ*/
#define ANOMALY_05000263 /*Hardware loop corrupted when taking an ICPLB exception*/

#endif

#endif /* _MACH_ANOMALY_H_ */
