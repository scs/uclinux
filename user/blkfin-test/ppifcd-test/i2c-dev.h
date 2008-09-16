/*
 *
 *    Rev:          $Id: i2c-dev.h 987 2005-07-18 10:13:16Z hennerich $
 *    Revision:     $Revision: 987 $
 *    Source:       $Source$  
 *    Created:      06.07.2005 18:16
 *    Author:       Michael Hennerich
 *    mail:         hennerich@blackfin.uclinux.org
 *    Description:  User Space friendly include files for /dev/I2C-x access 
 *                  
 *   Copyright (C) 2005 Michael Hennerich
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 ****************************************************************************
 * MODIFICATION HISTORY:
 ***************************************************************************/ 
/*
    i2c-dev.h - i2c-bus driver, char device interface

    Copyright (C) 1995-97 Simon G. Vogl
    Copyright (C) 1998-99 Frodo Looijaard <frodol@dds.nl>

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
    Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

/* $Id: i2c-dev.h 987 2005-07-18 10:13:16Z hennerich $ */

#ifndef _LINUX_I2C_DEV_H
#define _LINUX_I2C_DEV_H



/* Some IOCTL commands are defined in <linux/i2c.h> */
/* Note: 10-bit addresses are NOT supported! */

struct i2c_msg {
    unsigned short addr;    /* slave address            */
    unsigned short flags;       
#define I2C_M_TEN   0x10    /* we have a ten bit chip address   */
#define I2C_M_RD    0x01
#define I2C_M_NOSTART   0x4000
#define I2C_M_REV_DIR_ADDR  0x2000
#define I2C_M_IGNORE_NAK    0x1000
#define I2C_M_NO_RD_ACK     0x0800
    unsigned short len;     /* msg length               */
    unsigned char *buf;     /* pointer to msg data          */
};

/* This is the structure as used in the I2C_SMBUS ioctl call */



struct i2c_smbus_ioctl_data {
    unsigned char read_write;
    unsigned char command;
    unsigned int size;
    union i2c_smbus_data  *data;
};

/* This is the structure as used in the I2C_RDWR ioctl call */
struct i2c_rdwr_ioctl_data {
    struct i2c_msg  *msgs;  /* pointers to i2c_msgs */
    unsigned int nmsgs;         /* number of i2c_msgs */
};


#define  I2C_RDRW_IOCTL_MAX_MSGS    42

/* ----- commands for the ioctl like i2c_command call:
 * note that additional calls are defined in the algorithm and hw 
 *  dependent layers - these can be listed here, or see the 
 *  corresponding header files.
 */
/* -> bit-adapter specific ioctls   */
#define I2C_RETRIES 0x0701  /* number of times a device address      */
                            /* should be polled when not            */
                            /* acknowledging            */
#define I2C_TIMEOUT 0x0702  /* set timeout - call with int      */


/* this is for i2c-dev.c    */
#define I2C_SLAVE   0x0703  /* Change slave address         */
                            /* Attn.: Slave address is 7 or 10 bits */
#define I2C_SLAVE_FORCE 0x0706  /* Change slave address         */
                            /* Attn.: Slave address is 7 or 10 bits */
                            /* This changes the address, even if it */
                            /* is already taken!            */
#define I2C_TENBIT  0x0704  /* 0 for 7 bit addrs, != 0 for 10 bit   */

#define I2C_FUNCS   0x0705  /* Get the adapter functionality */
#define I2C_RDWR    0x0707  /* Combined R/W transfer (one stop only)*/
#define I2C_PEC     0x0708  /* != 0 for SMBus PEC                   */

#define I2C_ACK_TEST    0x0710  /* See if a slave is at a specific address */


#define I2C_SMBUS   0x0720  /* SMBus-level access */

/* ... algo-bit.c recognizes */
#define I2C_UDELAY  0x0705  /* set delay in microsecs between each  */
                            /* written byte (except address)    */
#define I2C_MDELAY  0x0706  /* millisec delay between written bytes */

/* ----- I2C-DEV: char device interface stuff ------------------------- */

#define I2C_MAJOR   89      /* Device major number      */

#endif /* _LINUX_I2C_DEV_H */
