/*
 *
 *    Rev:          $Id: i2c.c,v 1.1 2007/12/14 09:09:34 mberner Exp $
 *    Revision:     $Revision: 1.1 $
 *    Source:       $Source: /cvs/ferag/BogenerkennungsImplementation/uclinux-dist/user/blkfin-apps/ppifcd-cgi-lcv/src/i2c.c,v $  
 *    Created:      06.07.2005 18:16
 *    Author:       Michael Hennerich
 *    mail:         hennerich@blackfin.uclinux.org
 *    Description:  Simple I2C Routines 
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


#include "i2c-dev.h"

#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h> 


#define I2C_DEVICE "/dev/i2c-0"
#define I2C_SLAVE_ADDR 0x38 /* Randomly picked */ 
#define I2C_DEVID (0xB8>>1)

//#define main
#undef main

int i2c_write_register(char * , unsigned char , unsigned char , unsigned short );
int i2c_read_register(char * , unsigned char , unsigned char );
i2c_dump_register(char * , unsigned char , unsigned short , unsigned short );
i2c_scan_bus(char * );

#if main
int main()
{

	i2c_scan_bus(I2C_DEVICE);
	i2c_write_register(I2C_DEVICE,I2C_DEVID,9,0x0248);
	i2c_dump_register(I2C_DEVICE,I2C_DEVID,0,255);
	printf("Read Register 9 = 0x%X \n",
	i2c_read_register(I2C_DEVICE, I2C_DEVID,9) );

  exit( 0 );
}
#endif


int i2c_write_register(char * device, unsigned char client, unsigned char reg, unsigned short value)
{
    int    addr = I2C_SLAVE_ADDR; 
	char   msg_data[32];
    struct i2c_msg msg = { addr, 0, 0, msg_data };
    struct i2c_rdwr_ioctl_data rdwr = { &msg, 1 };
	
    int fd,i;

  if ( (fd = open( device, O_RDWR ) ) < 0 ) {
    fprintf(stderr, "Error: could not open %s\n", device);
    exit( 1 );
  }

  if ( ioctl( fd, I2C_SLAVE, addr ) < 0 ) {
    fprintf(stderr, "Error: could not bind address %x \n", addr );
  } 

	msg.len   = 3;
    msg.flags = 0;
	msg_data[0] = reg;
	msg_data[2] = (0xFF & value);
	msg_data[1] = (value >> 8);
	msg.addr = client;

  if ( ioctl( fd, I2C_RDWR, &rdwr ) < 0 ) {
    fprintf(stderr, "Error: could not write \n");
  }

  close( fd );
  return 0;
}

int i2c_read_register(char * device, unsigned char client, unsigned char reg)
{
    int addr = I2C_SLAVE_ADDR; 
    char msg_data[32];
    struct i2c_msg msg = { addr, 0, 0, msg_data };
    struct i2c_rdwr_ioctl_data rdwr = { &msg, 1 };
	
    int fd,i;

  if ( (fd = open( device, O_RDWR ) ) < 0 ) {
    fprintf(stderr, "Error: could not open %s\n", device);
    exit( 1 );
  }

  if ( ioctl( fd, I2C_SLAVE, addr ) < 0 ) {
    fprintf(stderr, "Error: could not bind address %x \n", addr );
  } 

	  msg_data[0]= reg;
	  msg.addr = client;
	  msg.len   = 1;
	  msg.flags = 0;

	  if ( ioctl( fd, I2C_RDWR, &rdwr ) < 0 ) {
	    fprintf(stderr, "Error: could not write \n");
	  };

		msg.len   = 2;
		msg_data[0]=0;
		msg_data[1]=0;
		msg.flags = I2C_M_RD ;

	    if ( ioctl( fd, I2C_RDWR, &rdwr ) < 0 ) {
	      fprintf(stderr, "Error: could not read back\n");
			  close( fd );
  			  return -1;	    
	    } 

  close( fd );
  return (((unsigned char)msg_data[0])<<8 | ((unsigned char)msg_data[1]) );
}

i2c_dump_register(char * device, unsigned char client, unsigned short start, unsigned short end)
{
    int    addr = I2C_SLAVE_ADDR; 
	char   msg_data[32];
    struct i2c_msg msg = { addr, 0, 0, msg_data };
    struct i2c_rdwr_ioctl_data rdwr = { &msg, 1 };
	
    int fd,i;

  if ( (fd = open( device, O_RDWR ) ) < 0 ) {
    fprintf(stderr, "Error: could not open %s\n", device);
    exit( 1 );
  }

  if ( ioctl( fd, I2C_SLAVE, addr ) < 0 ) {
    fprintf(stderr, "Error: could not bind address %x \n", addr );
  } 



  for(i = start; i < end; i++) {

	  msg_data[0]= i;
	  msg.addr = client;
	  msg.len   = 1;
	  msg.flags = 0;

	  if ( ioctl( fd, I2C_RDWR, &rdwr ) < 0 ) {
	    fprintf(stderr, "Error: could not write \n");
	  };

		msg.len   = 2;
		msg_data[0]=0;
		msg_data[1]=0;
		msg.flags = I2C_M_RD ;

	    if ( ioctl( fd, I2C_RDWR, &rdwr ) < 0 ) {
	      fprintf(stderr, "Error: could not read back\n");
	    } else {
	      fprintf(stderr, "Register %02x : %02x%02x \n",i, (unsigned char)msg_data[0],(unsigned char)msg_data[1]);
	    }
  }
 
  close( fd );
  return;
}

i2c_scan_bus(char * device)
{
    int    addr = I2C_SLAVE_ADDR; 
	char   msg_data[32];
    struct i2c_msg msg = { addr, 0, 0, msg_data };
    struct i2c_rdwr_ioctl_data rdwr = { &msg, 1 };
	
    int fd,i;

  if ( (fd = open( device, O_RDWR ) ) < 0 ) {
    fprintf(stderr, "Error: could not open %s\n", device);
    exit( 1 );
  }

  if ( ioctl( fd, I2C_SLAVE, addr ) < 0 ) {
    fprintf(stderr, "Error: could not bind address %x \n", addr );
  } 

	msg.len   = 1;
    msg.flags = 0;
	msg_data[0]=0;
	msg_data[1]=0;

  for ( i = 0; i < 128; i++){  

	msg.addr = i;

  if ( ioctl( fd, I2C_RDWR, &rdwr ) < 0 ) {
    //fprintf(stderr, "Error: could not write \n");
  }else  
  	fprintf(stderr, "FOUND I2C device at 0x%X (8-bit Adrress 0x%X) \n",msg.addr,msg.addr<<1);
}

  close( fd );
  return;
}
