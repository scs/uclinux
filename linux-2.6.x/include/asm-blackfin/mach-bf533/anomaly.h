
/*
 * File:         include/asm-blackfin/mach-bf533/anomaly.h
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

#define ANOMALY_05000272 /*Certain data cache write through modes fail for VDDint <=0.9V*/
#define ANOMALY_05000273 /*Writes to Synchronous SDRAM memory may be lost*/
#define ANOMALY_05000277 /*Writes to a flag data register one SCLK cycle after an
         		  edge is detected may clear interrupt*/
#define ANOMALY_05000283 /*A system MMR write is stalled indefinitely when killed in a
         		   particular stage*/

#if (defined(CONFIG_BF_REV_0_4) || defined(CONFIG_BF_REV_0_3))
#define ANOMALY_05000198 /*Failing SYSTEM MMR accesses when stalled by
         		  preceding memory read*/
#define ANOMALY_05000158 /*Boot fails when data cache enabled: Data from a Data
        		   Cache Fill can be corrupted after or during Instruction
         		   DMA if certain core stalls exist*/
#define ANOMALY_05000227 /*Scratchpad memory bank reads may return incorrect data*/
#define ANOMALY_05000260 /*ICPLB_STATUS MMR register may be corrupted*/
#define ANOMALY_05000261 /*DCPLB_FAULT_ADDR MMR register may be corrupted*/
#define ANOMALY_05000262 /*Stores to data cache may be lost*/
#define ANOMALY_05000263 /*Hardware loop corrupted when taking an ICPLB exception*/
#define ANOMALY_05000264 /*A Sync instruction (CSYNC, SSYNC) or an IDLE
         		  instruction will cause an infinite stall in the second to last
         		  instruction in a hardware loop*/
#endif

#if defined(CONFIG_BF_REV_0_3)
#define ANOMALY_05000204 /*Incorrect data read with write-through cache and allocate
		           cache lines on reads only mode*/
#endif

#endif /* _MACH_ANOMALY_H_ */
