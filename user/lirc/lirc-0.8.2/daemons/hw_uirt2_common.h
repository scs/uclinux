/*      $Id: hw_uirt2_common.h,v 5.3 2006/11/22 21:28:39 lirc Exp $   */

/****************************************************************************
 ** hw_uirt2_common.h *******************************************************
 ****************************************************************************
 *
 * Routines for UIRT2 receiver/transmitter
 * 
 * Copyright (C) 2003 Mikael Magnusson <mikma@users.sourceforge.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 */

#ifndef HW_UIRT2_H
#define HW_UIRT2_H

#define UIRT2_UNIT 50 /* 50 us */


/* UIRT2 Commands */
#define UIRT2_SETMODEUIR   0x20
#define UIRT2_SETMODERAW   0x21
#define UIRT2_SETMODESTRUC 0x22
#define UIRT2_GETVERSION   0x23
#define UIRT2_GETGPIOCAPS  0x30
#define UIRT2_GETGPIOCFG   0x31
#define UIRT2_SETGPIOCFG   0x32
#define UIRT2_GETGPIO      0x33
#define UIRT2_SETGPIO      0x34
#define UIRT2_REFRESHGPIO  0x35
#define UIRT2_DOTXRAW      0x36
#define UIRT2_DOTXSTRUCT   0x37

/* UIRT2 Responses */
#define UIRT2_TRANSMITTING 0x20
#define UIRT2_CMDOK        0x21
#define UIRT2_CSERROR      0x80
#define UIRT2_TOERROR      0x81
#define UIRT2_CMDERROR     0x82

/* UIRT2 Actions */
#define UIRT2_ACTION_PULSE  0x00
#define UIRT2_ACTION_SET    0x40
#define UIRT2_ACTION_CLEAR  0x80
#define UIRT2_ACTION_TOGGLE 0xC0

/* UIRT2 Ports */
#define UIRT2_PORT_A 0x00
#define UIRT2_PORT_B 0x08
#define UIRT2_PORT_C 0x10
#define UIRT2_PORT_D 0x18

/* UIRT2 Frequences */
#define UIRT2_FREQ_40 0x00
#define UIRT2_FREQ_38 0x40
#define UIRT2_FREQ_36 0xC0

/* uirt2_setmode */
#define UIRT2_MODE_UIR   0x00
#define UIRT2_MODE_RAW   0x01
#define UIRT2_MODE_STRUC 0x02
#define UIRT2_MODE_MASK  0x03


#define UIRT2_CODE_SIZE 6

/* Remstruct1 */
#define UIRT2_MAX_BITS (16 * 8)

typedef unsigned char byte_t;

typedef struct {
	byte_t bISDlyHi,bISDlyLo;
	byte_t bBits,bHdr1,bHdr0;
	byte_t bOff0,bOff1,bOn0,bOn1;
	byte_t bDatBits [UIRT2_MAX_BITS / 8];
	byte_t bCheck;
} __attribute__ ((packed)) remstruct1_data_t; 

typedef struct {
	byte_t bCmd;
	remstruct1_data_t data;
} __attribute__ ((packed)) remstruct1_t; 

typedef struct {
	byte_t bFrequency;
	byte_t bRepeatCount;
	remstruct1_data_t data;
} __attribute__ ((packed)) remstruct1_ext_t; 

typedef struct tag_uirt2_t uirt2_t;

typedef byte_t uirt2_code_t[UIRT2_CODE_SIZE];

uirt2_t *uirt2_init(int fd);
int uirt2_uninit(uirt2_t *dev);
int uirt2_getfd(uirt2_t *dev);
int uirt2_setmode(uirt2_t *dev, int mode);
int uirt2_setmodeuir(uirt2_t *dev);
int uirt2_setmoderaw(uirt2_t *dev);
int uirt2_setmodestruc(uirt2_t *dev);
int uirt2_getversion(uirt2_t *dev, int *version);
int uirt2_getgpiocaps(uirt2_t *dev, int *slots, byte_t masks[4]);
int uirt2_getgpiocfg(uirt2_t *dev, int slot, uirt2_code_t code,
		     int *action, int *duration);
int uirt2_setgpio(uirt2_t *dev, int action, int duration);
int uirt2_read_uir(uirt2_t *dev, byte_t *buf, int length);
lirc_t uirt2_read_raw(uirt2_t *dev, lirc_t timeout);
int uirt2_send_raw(uirt2_t *dev, byte_t *buf, int length);
int uirt2_send_struct1(uirt2_t *dev, int freq, int bRepeatCount,
		       remstruct1_data_t *buf);
int uirt2_calc_freq(int freq);

#endif /* HW_UIRT2_H */
