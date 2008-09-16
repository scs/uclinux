/*
 * Tormenta 2  Quad-T1 PCI EEprom programmer
 *
 * Written by Mark Spencer <markster@linux-suppot.net>
 *
 * Copyright (C) 2001 Jim Dixon / Zapata Telephony.
 * Copyright (C) 2001, Linux Support Services, Inc.
 *
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA. 
 *
 */

#include <sys/types.h>
#include <pci/pci.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/io.h>
#include <netinet/in.h>
#include <linux/ppp_defs.h>
#include <time.h>

#define NEED_PCI_IDS
#include "tor2-hw.h"

#define NUM_REGS 0x86 >> 1

static 
__u16 fcstab[256] =
{
	0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
	0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
	0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
	0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
	0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
	0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
	0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
	0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
	0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
	0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
	0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
	0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
	0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
	0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
	0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
	0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
	0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
	0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
	0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
	0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
	0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
	0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
	0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
	0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
	0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
	0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
	0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
	0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
	0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
	0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
	0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
	0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};

struct pci_eereg {
	int pos;
	char *name;
};

static short calc_crc16(char *s1, int cnt1)
{
	int fcs = PPP_INITFCS;
	int x;
	for (x=0;x<cnt1;x++)
		fcs = PPP_FCS(fcs, s1[x]);
	fcs ^= 0xffff;
	return fcs & 0xffff;
}

static int memfd = -1;
static void *memw = NULL;
static int port = 0;
static size_t memlen;
struct pci_access *pci = NULL;
struct pci_dev *dev = NULL;

static int manual = 0;

#define EEPROM_MAGIC 0xD00dF00d

/* PCI 9030 *EEPROM* offsets */
#define PE_DEVICE_ID			0x00
#define PE_VENDOR_ID			0x02
#define PE_PCI_STATUS			0x04
#define PE_PCI_COMMAND			0x06
#define PE_PCI_CLASS			0x08
#define PE_PCI_REVISION			0x0A
#define PE_PCI_SUBSYS_ID		0x0C
#define PE_PCI_SUBSYS_VENDOR		0x0E
#define PE_PCI_MSB_NCP                  0x10     			   
#define PE_PCI_LSB_NCP                  0x12
#define PE_PCI_MAXLAT_MINGRANT          0x14
#define PE_PCI_INT_PIN                  0x16
#define PE_PCI_MSW_PM_CAP               0x18
#define PE_PCI_LSW_PM_CAP_ID            0x1A
#define PE_PCI_MSW_PMD                  0x1C
#define PE_PCI_LSW_PM_CNT_STAT          0x1E
#define PE_PCI_MSW_HS_CNT_STAT          0x20
#define PE_PCI_LSW_HS_NCP               0x22
#define PE_PCI_VPD_ADDR                 0x24
#define PE_PCI_VPD_NCP                  0x26
#define PE_PCI_MSW_RP2L_ADDR0           0x28
#define PE_PCI_LSW_RP2L_ADDR0           0x2A
#define PE_PCI_MSW_RP2L_ADDR1           0x2C
#define PE_PCI_LSW_RP2L_ADDR1           0x2E
#define PE_PCI_MSW_RP2L_ADDR2           0x30
#define PE_PCI_LSW_RP2L_ADDR2           0x32
#define PE_PCI_MSW_RP2L_ADDR3           0x34
#define PE_PCI_LSW_RP2L_ADDR3           0x36
#define PE_PCI_MSW_RP2L_ROM             0x38
#define PE_PCI_LSW_RP2L_ROM             0x3A
#define PE_PCI_MSW_REMAP_P2L_ADDR0      0x3C
#define PE_PCI_LSW_REMAP_P2L_ADDR0      0x3E
#define PE_PCI_MSW_REMAP_P2L_ADDR1      0x40
#define PE_PCI_LSW_REMAP_P2L_ADDR1      0x42
#define PE_PCI_MSW_REMAP_P2L_ADDR2      0x44
#define PE_PCI_LSW_REMAP_P2L_ADDR2      0x46
#define PE_PCI_MSW_REMAP_P2L_ADDR3      0x48
#define PE_PCI_LSW_REMAP_P2L_ADDR3      0x4A
#define PE_PCI_MSW_REMAP_P2L_ROM        0x4C
#define PE_PCI_LSW_REMAP_P2L_ROM        0x4E
#define PE_PCI_MSW_BRD_LADDR0           0x50       
#define PE_PCI_LSW_BRD_LADDR0           0x52
#define PE_PCI_MSW_BRD_LADDR1           0x54
#define PE_PCI_LSW_BRD_LADDR1           0x56
#define PE_PCI_MSW_BRD_LADDR2           0x58
#define PE_PCI_LSW_BRD_LADDR2           0x5A
#define PE_PCI_MSW_BRD_LADDR3           0x5C
#define PE_PCI_LSW_BRD_LADDR3           0x5E
#define PE_PCI_MSW_BRD_ROM              0x60
#define PE_PCI_LSW_BRD_ROM              0x62    
#define PE_PCI_MSW_CS0                  0x64
#define PE_PCI_LSW_CS0                  0x66
#define PE_PCI_MSW_CS1                  0x68
#define PE_PCI_LSW_CS1                  0x6A
#define PE_PCI_MSW_CS2                  0x6C
#define PE_PCI_LSW_CS2                  0x6E
#define PE_PCI_MSW_CS3                  0x70
#define PE_PCI_LSW_CS3                  0x72
#define PE_PCI_PROT_ADDR                0x74
#define PE_PCI_LSW_INTCSR               0x76
#define PE_PCI_MSW_PTR                  0x78
#define PE_PCI_LSW_PTR                  0x7A
#define PE_PCI_MSW_GPIOC                0x7C
#define PE_PCI_LSW_GPIOC                0x7E
#define PE_PCI_MSW_PMDATA               0x80
#define PE_PCI_LSW_PMDATA               0x82
#define PE_PCI_MSW_PMDATAS              0x84
#define PE_PCI_LSW_PMDATAS              0x86
                         
struct pci_eereg eeregs[] = {
	{ PE_DEVICE_ID, "Device ID" },
	{ PE_VENDOR_ID, "Vendor ID" },
	{ PE_PCI_STATUS, "PCI Status" },
	{ PE_PCI_COMMAND, "PCI Command/Revision" },
	{ PE_PCI_CLASS, "Class Code" },
	{ PE_PCI_REVISION, "Class Code/Revision" },
	{ PE_PCI_SUBSYS_ID, "Subsystem ID" },
	{ PE_PCI_SUBSYS_VENDOR, "Subsystem Vendor ID" },
        { PE_PCI_MSB_NCP            ,"MSB New Capability Pointer"},
        { PE_PCI_LSB_NCP            ,"LSB New Capability Pointer"},
        { PE_PCI_MAXLAT_MINGRANT    ,"Max Latency/Min Grant Not Loadable"},
        { PE_PCI_INT_PIN            ,"Interrupt Pin"},
        { PE_PCI_MSW_PM_CAP         ,"MSW of Power Management Capabilities"},
        { PE_PCI_LSW_PM_CAP_ID      ,"LSW of Power Management Next Capability Pointer/PM Capability ID"},
        { PE_PCI_MSW_PMD            ,"MSW of Power Management Data/PMCSR Bridge Support Extension"},
        { PE_PCI_LSW_PM_CNT_STAT    ,"LSW Power Management Control/Status"},
        { PE_PCI_MSW_HS_CNT_STAT    ,"MSW of Hot Swap Control/Status"},
        { PE_PCI_LSW_HS_NCP         ,"LSW of Hot Swap Next Capability Pointer/Hot Swap Control"},
        { PE_PCI_VPD_ADDR           ,"PCI Vital Product Data Address"},    
        { PE_PCI_VPD_NCP            ,"PCI Vital Product Data Next Capability Pointer"},
        { PE_PCI_MSW_RP2L_ADDR0     ,"MSW of Range for PCI-to-Local Address Space 0"},
        { PE_PCI_LSW_RP2L_ADDR0     ,"LSW of Range for PCI-to-Local Address Space 0"},
        { PE_PCI_MSW_RP2L_ADDR1     ,"MSW of Range for PCI-to-Local Address Space 1"},
        { PE_PCI_LSW_RP2L_ADDR1     ,"LSW of Range for PCI-to-Local Address Space 1"},
        { PE_PCI_MSW_RP2L_ADDR2     ,"MSW of Range for PCI-to-Local Address Space 2"},
        { PE_PCI_LSW_RP2L_ADDR2     ,"LSW of Range for PCI-to-Local Address Space 2"},
        { PE_PCI_MSW_RP2L_ADDR3     ,"MSW of Range for PCI-to-Local Address Space 3"},
        { PE_PCI_LSW_RP2L_ADDR3     ,"LSW of Range for PCI-to-Local Address Space 3"},
        { PE_PCI_MSW_RP2L_ROM       ,"MSW of Range for PCI-to-Local Expansion ROM"},
        { PE_PCI_LSW_RP2L_ROM       ,"LSW of Range for PCI-to-Local Expansion ROM"},
        { PE_PCI_MSW_REMAP_P2L_ADDR0,"MSW of Local Base Address(Remap) PCI-to-Local Address Space 0"}, 
        { PE_PCI_LSW_REMAP_P2L_ADDR0,"LSW of Local Base Address(Remap) PCI-to-Local Address Space 0"},
        { PE_PCI_MSW_REMAP_P2L_ADDR1,"MSW of Local Base Address(Remap) PCI-to-Local Address Space 1"},
        { PE_PCI_LSW_REMAP_P2L_ADDR1,"LSW of Local Base Address(Remap) PCI-to-Local Address Space 1"},
        { PE_PCI_MSW_REMAP_P2L_ADDR2,"MSW of Local Base Address(Remap) PCI-to-Local Address Space 2"},
        { PE_PCI_LSW_REMAP_P2L_ADDR2,"LSW of Local Base Address(Remap) PCI-to-Local Address Space 2"},
        { PE_PCI_MSW_REMAP_P2L_ADDR3,"MSW of Local Base Address(Remap) PCI-to-Local Address Space 3"},
        { PE_PCI_LSW_REMAP_P2L_ADDR3,"LSW of Local Base Address(Remap) PCI-to-Local Address Space 3"},
        { PE_PCI_MSW_REMAP_P2L_ROM  ,"MSW of Local Base Address(Remap) PCI-to-Local Expansion ROM"},
        { PE_PCI_LSW_REMAP_P2L_ROM  ,"LSW of Local Base Address(Remap) PCI-to-Local Expansion ROM"},
        { PE_PCI_MSW_BRD_LADDR0     ,"MSW of Bus Region Descriptors for Local Address Space 0"},
        { PE_PCI_LSW_BRD_LADDR0     ,"LSW of Bus Region Descriptors for Local Address Space 0"},
        { PE_PCI_MSW_BRD_LADDR1     ,"MSW of Bus Region Descriptors for Local Address Space 1"},
        { PE_PCI_LSW_BRD_LADDR1     ,"LSW of Bus Region Descriptors for Local Address Space 1"},
        { PE_PCI_MSW_BRD_LADDR2     ,"MSW of Bus Region Descriptors for Local Address Space 2"},      
        { PE_PCI_LSW_BRD_LADDR2     ,"LSW of Bus Region Descriptors for Local Address Space 2"},
        { PE_PCI_MSW_BRD_LADDR3     ,"MSW of Bus Region Descriptors for Local Address Space 3"},
        { PE_PCI_LSW_BRD_LADDR3     ,"LSW of Bus Region Descriptors for Local Address Space 3"},
        { PE_PCI_MSW_BRD_ROM        ,"MSW of Bus Region Descriptors for Expansion ROM"},     
        { PE_PCI_LSW_BRD_ROM        ,"LSW of Bus Region Descriptors for Expansion ROM"},
        { PE_PCI_MSW_CS0            ,"MSW of Chip Select 0 Base And Range"},
        { PE_PCI_LSW_CS0            ,"LSW of Chip Select 0 Base And Range"},
        { PE_PCI_MSW_CS1            ,"MSW of Chip Select 1 Base And Range"},
        { PE_PCI_LSW_CS1            ,"LSW of Chip Select 1 Base And Range"},
        { PE_PCI_MSW_CS2            ,"MSW of Chip Select 2 Base And Range"},
        { PE_PCI_LSW_CS2            ,"LSW of Chip Select 2 Base And Range"},
        { PE_PCI_MSW_CS3            ,"MSW of Chip Select 3 Base And Range"},
        { PE_PCI_LSW_CS3            ,"LSW of Chip Select 3 Base And Range"},
        { PE_PCI_PROT_ADDR          ,"Serial EEPROM Write-Protected Address Boundary"},
        { PE_PCI_LSW_INTCSR         ,"LSW of Interrupt Control/Status Register"},
        { PE_PCI_MSW_PTR            ,"MSW of PCI Target Response, Serial EEPROM, and Initialization Control"},
        { PE_PCI_LSW_PTR            ,"LSW of PCI Target Response, Serial EEPROM, and Initialization Control"},
        { PE_PCI_MSW_GPIOC          ,"MSW of General Purpose I/O Control"},
	{ PE_PCI_LSW_GPIOC          ,"LSW of General Purpose I/O Control"},
        { PE_PCI_MSW_PMDATA         ,"MSW of Hidden 1 Power Management Data Select"},
        { PE_PCI_LSW_PMDATA         ,"LSW of Hidden 1 Power Management Data Select"},
        { PE_PCI_MSW_PMDATAS        ,"MSW of Hidden 2 Power Management Data Scale"},
        { PE_PCI_LSW_PMDATAS        ,"LSW of Hidden 2 Power Management Data Scale"} 
}; 
 
#define NUM_EEREGS sizeof(eeregs) / sizeof(eeregs[0])

/* This is the structure of an EEPROM file */
struct pci_eeprom {
	u_int32_t magic;
	char revision[32];	/* Revision string */
	u_int16_t data[NUM_REGS];
	u_int16_t crc16;
};

#define BIT_EE_CLK	0x0100
#define BIT_EE_CS	0x0200
#define BIT_EE_WR	0x0400
#define BIT_EE_RD	0x0800

static unsigned short cntrl;

static void write_cntrl(void)
{
	((word *)memw)[0x52/2] = cntrl;
}

static void read_cntrl(void)
{
	cntrl = ((word *)memw)[0x52/2];
}

static void plx_clock(void)
{
	cntrl |= BIT_EE_CLK;
	write_cntrl();
	cntrl &= ~BIT_EE_CLK;
	write_cntrl();
}

static void plx_write_bit(int bit) 
{
	if (bit)
		cntrl |= BIT_EE_WR;
	else
		cntrl &= ~BIT_EE_WR;
	write_cntrl();
	plx_clock();
}

static int plx_read_bit(void)
{
	int res;
	read_cntrl();
	if (cntrl & BIT_EE_RD)
		res= 1;
	else
		res= 0;
	plx_clock();
	return res;
}

static int plx_read_reg(int reg)
{
	int x;
	unsigned short res;

	cntrl &= ~BIT_EE_CS;
	write_cntrl();
	cntrl |= BIT_EE_CS;
	write_cntrl();

	/* Send command 110 to read */
	plx_write_bit(1);
	plx_write_bit(1);
	plx_write_bit(0);

	/* Send address */
	for (x=7;x>=0;x--) {
		if (reg & (1 << x))
			plx_write_bit(1);
		else
			plx_write_bit(0);
	}
	/* Read back start bit */
	if (plx_read_bit()) {
		fprintf(stderr, "Did not get expected start bit 0\n");
		return -1;
	}

	/* Read back result */
	res = 0;
	for (x=0;x<16;x++) {
		res <<= 1;
		if (plx_read_bit())
			res |= 1;
	}
	
	/* Clear the CS again */
	cntrl &= ~BIT_EE_CS;

	write_cntrl();

	/* Return result */
	return res;
}

static int plx_write_reg(int reg, int value)
{
	int x;

	int tries;
	cntrl &= ~BIT_EE_CS;
	write_cntrl();
	cntrl |= BIT_EE_CS;
	write_cntrl();

	/* Send command 101 to write */
	plx_write_bit(1);
	plx_write_bit(0);
	plx_write_bit(1);

	/* Send address */
	for (x=7;x>=0;x--) {
		if (reg & (1 << x))
			plx_write_bit(1);
		else
			plx_write_bit(0);
	}

	/* Send data */
	for (x=15;x>=0;x--) {
		if (value & (1 << x))
			plx_write_bit(1);
		else
			plx_write_bit(0);
	}

	/* Clear the CS again */
	cntrl &= ~BIT_EE_CS;

	write_cntrl();

	/* Raise the CS again and wait for DOUT to drop */
	cntrl |= BIT_EE_CS;
	write_cntrl();

	tries = 0;
	for(;;) {
		read_cntrl();
		if (cntrl & BIT_EE_RD)
			break;
		usleep(1);
		tries++;
		if (tries > 5) {
			fprintf(stderr, "Maximum retries exceeded on write\n");
			return -1;
		}
	}
	/* Drop CS finally */
	cntrl &= ~BIT_EE_CS;
	write_cntrl();
	usleep(1);
	/* Return result */
	return 0;
}

static int plx_write_all(int value)
{
	int x;

	int tries;

	cntrl &= ~BIT_EE_CS;
	write_cntrl();
	cntrl |= BIT_EE_CS;
	write_cntrl();

	/* Send command 100 to write all */
	plx_write_bit(1);
	plx_write_bit(0);
	plx_write_bit(0);

	/* Send address */
	plx_write_bit(0);
	plx_write_bit(1);
	plx_write_bit(0);
	plx_write_bit(0);
	plx_write_bit(0);
	plx_write_bit(0);
	plx_write_bit(0);
	plx_write_bit(0);

	/* Send data */
	for (x=15;x>=0;x--) {
		if (value & (1 << x))
			plx_write_bit(1);
		else
			plx_write_bit(0);
	}

	/* Clear the CS again */
	cntrl &= ~BIT_EE_CS;

	write_cntrl();

	/* Raise the CS again and wait for DOUT to drop */
	cntrl |= BIT_EE_CS;
	write_cntrl();
	tries = 0;
	for(;;) {
		read_cntrl();
		if (cntrl & BIT_EE_RD)
			break;
		usleep(1);
		tries++;
		if (tries > 5) {
			fprintf(stderr, "Maximum retries exceeded on write\n");
			return -1;
		}
	}
	/* Drop CS finally */
	cntrl &= ~BIT_EE_CS;
	write_cntrl();

	/* Return result */
	return 0;
}

static int plx_write_en(void)
{
	cntrl &= ~BIT_EE_CS;
	write_cntrl();
	cntrl |= BIT_EE_CS;
	write_cntrl();

	/* Send command 100 and address 11000000 to enable writing */
	plx_write_bit(1);
	plx_write_bit(0);
	plx_write_bit(0);
	plx_write_bit(1);
	plx_write_bit(1);
	plx_write_bit(0);
	plx_write_bit(0);
	plx_write_bit(0);
	plx_write_bit(0);
	plx_write_bit(0);
	plx_write_bit(0);

	/* Clear the CS again */
	cntrl &= ~BIT_EE_CS;

	write_cntrl();

	return 0;
}

static inline u_int32_t read_eeprom_value(struct pci_dev *dev, int addr)
{
	/* First write the address where we want to read */
	word a,r;
	int tries;
	int retry=0;

attempt_retry:
	if (retry > 10) {
		fprintf(stderr, "Maximum retries exceeded reading position %04x\n", addr);
		exit(1);
	}
	/* Be sure we only execute a read */
	a = addr & 0x7fff;
	pci_write_word(dev, PLX_PCI_VPD_ADDR, a);
	tries = 0;
	/* Wait for read to be validated */
	for(;;) {
		r = pci_read_word(dev, PLX_PCI_VPD_ADDR);

		/* Wait a bit if it's not yet written */
		if (r & 0x8000)
			break;
		else {
			tries++;
			if (tries > 10) {
				retry++;
				goto attempt_retry;
			}
			usleep(1);
		}
	} 
	return pci_read_long(dev, PLX_PCI_VPD_DATA);
}

static int write_eeprom_value(struct pci_dev *dev, int addr, u32 val)
{
	/* First write the address where we want to read */
	word a,r;
	int tries;
	int retry=0;

attempt_retry:
	if (retry > 10) {
		fprintf(stderr, "Maximum retries exceeded reading position %04x\n", addr);
		exit(1);
	}
	/* Load the value to be written */
	pci_write_long(dev, PLX_PCI_VPD_DATA, val);
	/* Be sure we only execute a write */
	a = addr | 0x8000;
	pci_write_word(dev, PLX_PCI_VPD_ADDR, a);
	tries = 0;
	/* Wait for write to be validated */
	for(;;) {
		r = pci_read_word(dev, PLX_PCI_VPD_ADDR);

		/* Wait a bit if it's not yet written */
		if (r & 0x8000) {
			tries++;
			if (tries > 10) {
				retry++;
				goto attempt_retry;
			}
			usleep(1);
		} else 
			break;
	} 
	return 0;
}

static int read_pci_eeprom(struct pci_dev *dev, struct pci_eeprom *ee)
{
	int x;
	u_int32_t v, *tmp;
	printf("Reading from EEPROM..");
	fflush(stdout);
	tmp = (u_int32_t *)(ee->data);
	if (manual) {
		for (x=0;x<sizeof(ee->data)/2;x++) {
			ee->data[x] = plx_read_reg(x);
			printf(".");
			fflush(stdout);
		}
	} else {
		for (x=0;x<sizeof(ee->data)/4;x++) {
			v = read_eeprom_value(dev, x << 2);
			ee->data[x * 2] = (v & 0xFFFF0000) >> 16;
			ee->data[x * 2 + 1] = v & 0xFFFF;
			printf(".");
			fflush(stdout);
		}
	}
	printf("Done\n");
	return 0;
}

static int write_pci_eeprom(struct pci_dev *dev, struct pci_eeprom *ee)
{
	int x;
	u_int32_t v, *tmp;
	int writeboundary;

	writeboundary = ((word *)memw)[PLX_LOC_WP_BOUNDARY/2];

	printf("Original Writeprotect boundary: %04x\n", writeboundary);
	/* Turn off write protect */
	((word *)memw)[PLX_LOC_WP_BOUNDARY/2] = 0;
	printf("Writing to EEPROM..");
	fflush(stdout);
	if (manual) {
		/* Enable writing */
		plx_write_en();

		/* Write values */
		for (x=sizeof(ee->data)/2-1;x>=0;x--) {
			plx_write_reg(x, (int)ee->data[x]);
			printf(".");
			fflush(stdout);
		}
	} else {
		tmp = (u_int32_t *)(ee->data);
		for (x=sizeof(ee->data)/4-1;x>=0;x--) {
			v = (ee->data[x * 2] << 16) | ee->data[x * 2 + 1];
			write_eeprom_value(dev, x << 2, v);
			printf(".");
			fflush(stdout);
		}
	}
	printf("Done\n");
	/* Restore write protect */
	((word *)memw)[PLX_LOC_WP_BOUNDARY/2] = writeboundary;
	return 0;
}

static int reset_pci_eeprom(struct pci_dev *dev)
{
	int writeboundary;

	writeboundary = ((word *)memw)[PLX_LOC_WP_BOUNDARY/2];

	printf("Original Writeprotect boundary: %04x\n", writeboundary);
	/* Turn off write protect */
	((word *)memw)[PLX_LOC_WP_BOUNDARY/2] = 0;
	printf("Resetting EEPROM..");
	fflush(stdout);
	/* Enable writing */
	plx_write_en();
	plx_write_all(0xffff);
	printf("Done\n");
	/* Restore write protect */
	((word *)memw)[PLX_LOC_WP_BOUNDARY/2] = writeboundary;
	return 0;
}

#if 0
static void plx_reset(void)
{
	unsigned short tmp;
	tmp = ((word *)memw)[0x50/2];
	printf("CNTRL: %04x\n", tmp);

	tmp |= 0x4000;
	printf("Writing: %04x\n", tmp);
	tmp = ((word *)memw)[0x50/2];
	printf("Readback: %04x\n", tmp);

	sleep(1);

	tmp = ((word *)memw)[0x50/2];
	printf("CNTRL: %04x\n", tmp);

	tmp &= ~0x4000;
	((word *)memw)[0x50/2] = tmp;
	tmp = ((word *)memw)[0x50/2];
	printf("CNTRL: %04x\n", tmp);

}
#endif

static void plx_manread(void)
{
	int x;
	unsigned short reg;

#if 0
	read_cntrl();
	printf("Cntrl is %02x\n", cntrl);
	cntrl &= ~0xf0ff;
	printf("Clearing all signals\n");
	write_cntrl();
	fgetc(stdin);
	printf("Setting CS\n");
	cntrl |= BIT_EE_CS;
	write_cntrl();
	read_cntrl();
	printf("New read: %04x\n", cntrl);
	fgetc(stdin);
	printf("Setting CLK\n");
	cntrl &= ~BIT_EE_CS;
	cntrl |= BIT_EE_CLK;
	write_cntrl();
	fgetc(stdin);
	printf("Setting WR\n");
	cntrl &= ~BIT_EE_CLK;
	cntrl |= BIT_EE_WR;
	write_cntrl();
	fgetc(stdin);
	cntrl &= ~BIT_EE_WR;
	write_cntrl();
#endif

	for (x=0;x<NUM_REGS;x++) {
		reg = plx_read_reg(x);
		printf("0x%02x: %04x\n", x, reg);
	}
}

static void dump_pci_eeprom(struct pci_eeprom *ee)
{
	int x;
	for (x=0;x<NUM_EEREGS;x++) 
		printf("%60s(%04x): 0x%04x\n", eeregs[x].name, eeregs[x].pos, ee->data[eeregs[x].pos/2]);
}

static int read_eeprom_file(char *filename, struct pci_eeprom *ee)
{
	int res,len;
	int fd;
	len = sizeof(*ee);
	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "Unable to open %s for input\n", filename);
		return -1;
	}
	printf("Reading from file '%s'....", filename);
	fflush(stdout);
	res = read(fd, (char *)ee, len);
	close(fd);
	if (res != len) {
		printf("Failed!\n");
		if (res < 0) {
			fprintf(stderr, "Failed to read from file: %s\n", strerror(errno));
		} else {
			fprintf(stderr, "Only read %d of %d bytes: %s\n", res, len, strerror(errno));
		}
		return -1;
	}
	if (ee->magic != htonl(EEPROM_MAGIC)) {
		printf("Failed!\n");
		fprintf(stderr, "File '%s' does not appear to be a Tormenta2 EEPROM file\n",
			filename);
		return -1;
	}
	if (ee->crc16 != htons(calc_crc16((char *)ee, sizeof(*ee) - 2))) {
		printf("Failed!\n");
		fprintf(stderr, "File '%s' has improper checksum\n", filename);
		return -1;
	}
	printf("Done.\n");
	printf("Read Revision '%s' from file '%s'\n", ee->revision, filename);
	return 0;
}

static int write_eeprom_file(char *filename, char *revision, struct pci_eeprom *ee)
{
	int res;
	int len;

	int fd;
	fd = open(filename, O_CREAT | O_TRUNC | O_WRONLY, 0666);
	if (fd < 0) {
		fprintf(stderr, "Unable to open %s for output\n", filename);
		return -1;
	}
	/* Record magic */
	ee->magic = htonl(EEPROM_MAGIC);

	/* Store revision number */
	memset(ee->revision, 0, sizeof(ee->revision));
	strncpy(ee->revision, revision, sizeof(ee->revision));

	/* Calculate FCS on revision and data */
	ee->crc16 = htons(calc_crc16((char *)ee, sizeof(*ee) - 2));

	len = sizeof(*ee);
	printf("Writing Revision '%s' to file '%s'....",
	       ee->revision, filename);
	fflush(stdout);
	res = write(fd, (char *)ee, len);
	close(fd);
	if (res != len) {
		printf("Failed!\n");
		if (res < 0) {
			fprintf(stderr, "Failed to write to file: %s\n", strerror(errno));
		} else {
			fprintf(stderr, "Only wrote %d of %d bytes: %s\n", res, len, strerror(errno));
		}
		return -1;
	}
	printf("Done.\n");
	return 0;
}

static int openmem(off_t offset, size_t len, int inport)
{
	if (iopl(3)) {
		fprintf(stderr, "Unable to set I/O Permissions: %s\n", strerror(errno));
		return -1;
	}
	if (memfd > -1) {
		fprintf(stderr, "Huh?  Memory already exists?\n");
		return 0;
	}
	memfd = open("/dev/mem", O_RDWR);
	if (memfd < 0) {
		fprintf(stderr, "Unable to open /dev/mem: %s\n", strerror(errno));
		return -1;
	}
	memw = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, offset);
	if (memw == MAP_FAILED) {
		fprintf(stderr, "Memory map failed: %s\n", strerror(errno));
		close(memfd);
		memfd = -1;
		return -1;
	}
	memlen = len;
	port = inport & PCI_ADDR_IO_MASK;
	return 0;
}

static char *makerev(void)
{
	static char rev[32];
	time_t t;
	struct tm *tm;
	t = time(NULL);
	tm = localtime(&t);
	strftime(rev, sizeof(rev), "Rev[%d/%m/%Y][%T]", tm);
	return rev;
}

static void closemem(void)
{
	if (memfd > -1) {
		munmap(memw, memlen);
		close(memfd);
	}
	memfd = -1;
	if (pci)
		pci_cleanup(pci);
}

int detect_tormenta2(int index)
{
	/* Detect presense of Tormenta 2 card or return -1. 
	   Sets up base addresses, etc as necessary as well. */
	int which=0;
	char *variant;
	pci = pci_alloc();
	pci_init(pci);
	pci_scan_bus(pci);
	dev = pci->devices;
	while(dev) {
#if 0
		printf("[%d:%d:%d] VendorID: %04x DeviceID: %04x\n", 
		       dev->bus, dev->dev, dev->func, dev->vendor_id, 
		       dev->device_id);
#endif
		if (tor2_pci_match(dev->vendor_id, dev->device_id, &variant)) 
			if (index == which++)
				break;
		dev = dev->next;
	}
	if (!dev) {
		if (which) 
			fprintf(stderr, "Only %d Tormenta2 card(s) found\n", which);
		else
			fprintf(stderr, "No Tormenta2 card found in system\n");
		return -1;
	}
	printf("Tormenta2 Card (%s) Found!\n"
	       "Vendor ID: %04x Device ID: %04x\n"
	       "PLX Control Base Address: 0x%08lx [0x%04lx window]\n"
	       "PLX Control I/O Space: 0x%lx\n",
	       variant,
		dev->vendor_id, dev->device_id,
	        dev->base_addr[0], dev->size[0], 
	        dev->base_addr[1]);
	if (!dev->base_addr[0] || !dev->size[0]) {
		fprintf(stderr, "Invalid base address info\n");
		return -1;
	}
	if (openmem(dev->base_addr[0], dev->size[0], dev->base_addr[1])) {
		fprintf(stderr, "Unable to open memory\n");
		return -1;
	}
	printf("Mapped registers at %p\n", memw);
	return 0;
}

void usage(int exitstatus)
{
	fprintf(stderr, 
"tor2ee -- Tormenta 2 EEPROM controller\n"
"Usage: tor2ee command [args...]\n"
"       tor2ee detect\n"
"              -- Detect presense of Tormenta 2 card\n"
"       tor2ee [man]save <filename> [revision]\n"
"              -- Read contents of eeprom and write to file\n"
"	tor2ee reset\n"
"              -- Reset the PLX EEPROM\n"
"	tor2ee manread\n"
"	       -- Manually read registers\n"
"       tor2ee [man]load <filename>\n"
"              -- Write EEPROM from contents of file\n"
"       tor2ee modify <filename> [hex offset] [hex value]\n"
"              -- Change a specific offset and value in a given filename\n"
"       tor2ee verify <filename>\n"
"              -- Verify integrity of EEPROM file\n"
"       tor2ee compare <filename>\n"
"              -- Compare EEPROM file to current contents\n"
"       tor2ee dump [filename]\n"
"              -- Dump current EEPROM contents or filename if specified\n");
	exit(exitstatus);
}

#define MODE_DETECT	0
#define MODE_DUMP	1
#define MODE_SAVE	2
#define MODE_MODIFY	3
#define MODE_LOAD	4
#define MODE_RESET	5
#define MODE_MANREAD	6

static void modify(struct pci_eeprom *ee, int reg, int val)
{
	int x;
	char *regn = "<Unknown>";
	for (x=0;x<NUM_EEREGS;x++) 
		if (eeregs[x].pos == reg)
			regn = eeregs[x].name;
	ee->data[reg/2] = val;
	printf("Setting %s to %04x\n", regn, val);
}

int main(int argc, char *argv[])
{
	struct pci_eeprom ee;
	int mode;
	int reg;
	int val;
	char tmp[32];
	char *readfile = NULL;
	char *writefile = NULL;
	char *revision = NULL;
	if (argc < 2) {
		usage(1);
	}
	if (!strcasecmp(argv[1], "dump")) {
		mode = MODE_DUMP;
		if (argc > 2)
			readfile = argv[2];
	} else if (!strcasecmp(argv[1], "save") ||
		   !strcasecmp(argv[1], "mansave")) {
		if (argc < 3)
			usage(1);
		writefile = argv[2];
		if (argc > 3)
			revision = argv[3];
		else
			revision = makerev();
		mode = MODE_SAVE;
		if (!strcasecmp(argv[1], "mansave"))
			manual = 1;
	} else if (!strcasecmp(argv[1], "detect")) {
		mode = MODE_DETECT;
	} else if (!strcasecmp(argv[1], "load") ||
		   !strcasecmp(argv[1], "manload")) {
		if (argc < 3)
			usage(1);
		readfile = argv[2];
		if (!strcasecmp(argv[1], "manload"))
			manual = 1;
		mode = MODE_LOAD;
	} else if (!strcasecmp(argv[1], "reset"))  {
		mode = MODE_RESET;
	} else if (!strcasecmp(argv[1], "manread")) {
		mode = MODE_MANREAD;
	} else if (!strcasecmp(argv[1], "modify")) {
		if (argc < 5)
			usage(1);
		readfile = writefile = argv[2];
		if ((sscanf(argv[3], "%x", &reg) != 1) ||
		    (reg >= (NUM_REGS) * 2) || (reg < 0)) {
			fprintf(stderr, "Invalid register number: %s\n", argv[3]);
			usage(1);
		}
		if (sscanf(argv[4], "%x", &val) != 1) {
			fprintf(stderr, "Invalid value number: %s\n", argv[3]);
			usage(1);
		}
		mode = MODE_MODIFY;
	} else {
		usage(1);
	}
	if (detect_tormenta2(0)) {
		fprintf(stderr, "Tormenta 2 Not found in System\n");
		closemem();
		exit(1);
	}
	if (mode == MODE_RESET) {
		reset_pci_eeprom(dev);
	}
	if (mode == MODE_MANREAD) {
		plx_manread();
	}
	if ((mode == MODE_DUMP)) {
		if (readfile) {
			if (read_eeprom_file(readfile, &ee)) {
				fprintf(stderr, "Unable to read EEPROM file\n");
				closemem();
				exit(1);
			}
		} else {
			if (read_pci_eeprom(dev, &ee)) {
				fprintf(stderr, "Unable to read existing EEPROM\n");
				closemem();
				exit(1);
			}
		}
		dump_pci_eeprom(&ee);
	}
	if (mode == MODE_SAVE) {
		if (read_pci_eeprom(dev, &ee)) {
			fprintf(stderr, "Unable to read existiing EEPROM\n");
			closemem();
			exit(1);
		}
		if (write_eeprom_file(writefile, revision, &ee)) {
			fprintf(stderr, "Unable to save EEPROM contents\n");
			closemem();
			exit(1);
		}
	}
	if (mode == MODE_MODIFY) {
		if (read_eeprom_file(readfile, &ee)) {
			fprintf(stderr, "Unable to read EEPROM file\n");
			closemem();
			exit(1);
		}
		modify(&ee, reg, val);
		strncpy(tmp, ee.revision, sizeof(tmp));
		if (write_eeprom_file(writefile, tmp, &ee)) {
			fprintf(stderr, "Unable to write EEPROM file\n");
			closemem();
			exit(1);
		}
	}
	if (mode == MODE_LOAD) {
		if (read_eeprom_file(readfile, &ee)) {
			fprintf(stderr, "Unable to read EEPROM file\n");
			closemem();
			exit(1);
		}
		if (write_pci_eeprom(dev, &ee)) {
			fprintf(stderr, "Unable to write to EEPROM\n");
			closemem();
			exit(1);
		}
		printf("EEPROM successfully written.  Please reboot to make changes\n");
		printf("take effect.\n");
	}
	closemem();
	return 0;
}
