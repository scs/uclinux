/*      $Id: lirc_cmdir.c,v 1.6 2007/02/13 06:45:15 lirc Exp $      */

/*
 * lirc_cmdir.c - Driver for InnovationOne's COMMANDIR USB Transceiver
 *
 *  This driver requires the COMMANDIR hardware driver, available at
 *  http://www.commandir.com/.
 *
 *  Copyright (C) 2005  InnovationOne - Evelyn Yeung
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
 
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 2, 18)
#error "**********************************************************"
#error " Sorry, this driver needs kernel version 2.2.18 or higher "
#error "**********************************************************"
#endif

#include <linux/autoconf.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/kernel.h>
#include <linux/time.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/poll.h>
#include "drivers/lirc.h"
#include "drivers/lirc_dev/lirc_dev.h"
#include "drivers/kcompat.h"
#include "lirc_cmdir.h"

struct lirc_cmdir
{
	int features;
};

struct lirc_cmdir hardware=
{
	(
	/* LIRC_CAN_SET_SEND_DUTY_CYCLE|   */
	LIRC_CAN_SET_SEND_CARRIER|
	LIRC_CAN_SEND_PULSE|
	LIRC_CAN_SET_TRANSMITTER_MASK|
	LIRC_CAN_REC_MODE2)
	,
};

#define LIRC_DRIVER_NAME "lirc_cmdir"
#define RBUF_LEN   256
#define WBUF_LEN   256
#define MAX_PACKET 64

static struct lirc_buffer rbuf;
static lirc_t wbuf[WBUF_LEN];
static unsigned char cmdir_char[4*WBUF_LEN];
static unsigned char write_control[MCU_CTRL_SIZE];
static unsigned int last_mc_time = 0;
static int usb_status=ON;
static unsigned char signal_num=0;
char timerval=0;

unsigned int freq = 38000;
/* unsigned int duty_cycle = 50; */


#ifndef MAX_UDELAY_MS
#define MAX_UDELAY_US 5000
#else
#define MAX_UDELAY_US (MAX_UDELAY_MS*1000)
#endif

static inline void safe_udelay(unsigned long usecs)
{
	while(usecs>MAX_UDELAY_US)
	{
		udelay(MAX_UDELAY_US);
		usecs-=MAX_UDELAY_US;
	}
	udelay(usecs);
}

static unsigned int get_time_value(unsigned int firstint, unsigned int secondint, unsigned char overflow) 
{	/* get difference between two timestamps from MCU */
	unsigned int t_answer = 0;
	
	if (secondint > firstint) 
	{
		t_answer = secondint - firstint + overflow*65536;
	} 
	else 
	{
		if (overflow > 0) 
		{
			t_answer = (65536 - firstint) + secondint + (overflow - 1)*65536;
		} 
		else 
		{
			t_answer = (65536 - firstint) + secondint;
		}
	}

	/* clamp to long signal  */
	if (t_answer > 16000000) t_answer = PULSE_MASK;
	
	return t_answer;
}


static int set_use_inc(void* data)
{
	/* Init read buffer. */
	if (lirc_buffer_init(&rbuf, sizeof(lirc_t), RBUF_LEN) < 0)
	{
		return -ENOMEM;
	}
	
	MOD_INC_USE_COUNT;
	return 0;
}

static void set_use_dec(void* data)
{
	lirc_buffer_free(&rbuf);
	MOD_DEC_USE_COUNT;
}


static void usb_error_handle(int retval)
{
	switch (retval)
	{
		case -ENODEV:
			/* device has been unplugged */
			if (usb_status == ON)
			{
				usb_status = OFF;
				printk(LIRC_DRIVER_NAME ": device is unplugged\n");
			}
			break;
		default:
			printk(LIRC_DRIVER_NAME ": usb error = %d\n", retval);
			break;
	}
}

static int write_to_usb(unsigned char *buffer, int count, int time_elapsed)
{
	int write_return;
	
	write_return = cmdir_write(buffer, count, NULL, time_elapsed);
	if (write_return != count)
	{
		usb_error_handle(write_return);
	}
	else
	{
		if (usb_status == OFF) 
		{
			printk(LIRC_DRIVER_NAME ": device is now plugged in\n");
			usb_status = ON;
		}
	}
	return write_return;
}

static void set_freq(void)
{
	/* float tempfreq=0.0; */
	int write_return;
	
	/* can't use floating point in 2.6 kernel! May be some loss of precision */
	timerval = (1000000 / freq) / 2;
	write_control[0]=FREQ_HEADER;
	write_control[1]=timerval;
	write_control[2]=0;
	write_return = write_to_usb(write_control, MCU_CTRL_SIZE, 0);
	if (write_return == MCU_CTRL_SIZE) printk(LIRC_DRIVER_NAME ": freq set to %dHz\n", freq);
	else printk(LIRC_DRIVER_NAME ": freq unchanged\n");

}

static int cmdir_convert_RX(unsigned char *orig_rxbuffer)
{
	unsigned char tmp_char_buffer[80];
	unsigned int tmp_int_buffer[20];
	unsigned int final_data_buffer[20];	
	unsigned int num_data_values = 0;
	unsigned char num_data_bytes = 0;
	unsigned int orig_index = 0;
	int i;
	
	for (i=0; i<80; i++) tmp_char_buffer[i]=0;
	for (i=0; i<20; i++) tmp_int_buffer[i]=0;

	/* get number of data bytes that follow the control bytes (NOT including them)	 */
	num_data_bytes = orig_rxbuffer[1];
	
	/* check if num_bytes is multiple of 3; if not, error  */
	if (num_data_bytes%3 > 0) return -1;
	if (num_data_bytes > 60) return -3; 
	if (num_data_bytes < 3) return -2;
	
	/* get number of ints to be returned; num_data_bytes does NOT include control bytes */
	num_data_values = num_data_bytes/3;
	
	for (i=0; i<num_data_values; i++) 
	{
		tmp_char_buffer[i*4] = orig_rxbuffer[(i+1)*3];
		tmp_char_buffer[i*4+1] = orig_rxbuffer[(i+1)*3+1];
		tmp_char_buffer[i*4+2] = 0;
		tmp_char_buffer[i*4+3] = 0;
	}
		
	/* convert to int array */
	memcpy((unsigned char*)tmp_int_buffer, tmp_char_buffer, (num_data_values*4));

	if (orig_rxbuffer[5] < 255) // space
	{
		final_data_buffer[0] = get_time_value(last_mc_time, tmp_int_buffer[0],
			 orig_rxbuffer[5]);
	} 
	else 
	{
		/* is pulse */
		final_data_buffer[0] = get_time_value(last_mc_time, tmp_int_buffer[0], 0);
		final_data_buffer[0] |= PULSE_BIT;
	}
	for (i=1; i<num_data_values; i++) 
	{
		/* index of orig_rxbuffer that corresponds to overflow/pulse/space  */
		orig_index = (i+1)*3 + 2;
		if (orig_rxbuffer[orig_index] < 255) 
		{
			final_data_buffer[i] = get_time_value(tmp_int_buffer[i-1],
				 tmp_int_buffer[i], orig_rxbuffer[orig_index]);
		} 
		else 
		{
			final_data_buffer[i] = get_time_value(tmp_int_buffer[i-1],
				 tmp_int_buffer[i], 0);
			final_data_buffer[i] |= PULSE_BIT;
		}
	}
	last_mc_time = tmp_int_buffer[num_data_values-1];
		
	if(lirc_buffer_full(&rbuf))   
	{
		printk(KERN_ERR  LIRC_DRIVER_NAME ": lirc_buffer is full\n");
		return -EOVERFLOW;
	}	
	lirc_buffer_write_n(&rbuf, (char*)final_data_buffer, num_data_values);

	return 0;
}


static int usb_read_once(void)
{
	int read_retval = 0;
	int conv_retval = 0;
	unsigned char read_buffer[MAX_PACKET];
	int i=0;
	int tooFull = 5;  // read up to 5 packets 
	
	for (i=0; i<MAX_PACKET; i++) read_buffer[i] = 0;
	
	while(tooFull--){
		read_retval = cmdir_read(read_buffer, MAX_PACKET); 
		if(read_buffer[1] < 60) tooFull = 0;  // loop until we unload the data build-up
		if (!(read_retval == MAX_PACKET)) 
		{
			if (read_retval == -ENODEV) 
			{
				if (usb_status==ON) 
				{
					printk(KERN_ALERT LIRC_DRIVER_NAME ": device is unplugged\n");
					usb_status = OFF;
				}
			}
			else
			{
				/* supress errors */
				printk(KERN_ALERT LIRC_DRIVER_NAME ": usb error on read = %d\n",
						read_retval);  
				return -ENODATA;
			}
			// printk("Error 3\n");
			return -ENODATA;
		}
		else
		{
			if (usb_status==OFF) 
			{
				usb_status = ON;
				printk(LIRC_DRIVER_NAME ": device is now plugged in\n");
			}
		}
	
		if (read_buffer[0] & 0x08) 
		{
			conv_retval = cmdir_convert_RX(read_buffer);
			if (conv_retval == 0) 
			{
				if(!tooFull) {
					return 0; // else printk("Looping for more data...\n");
				}
			}
			else
			{
				// printk("Error 2: %d\n", (int)conv_retval);
				return -ENODATA;
			}
		} 
		else 
		{
			// printk("Empty RX Buffer!\n");
			return -ENODATA;  // There really is no data in their buffer
		}
	}
	return -1;
}

int add_to_buf (void* data, struct lirc_buffer* buf)
{
	return usb_read_once();
}


static ssize_t lirc_write(struct file *file, const char *buf,
			 size_t n, loff_t * ppos)
{
	int i,count;
	int num_bytes_to_send;
	unsigned int mod_signal_length=0;
	unsigned int cur_freq=0;
	unsigned int time_elapse=0;
	unsigned int total_time_elapsed=0;
	/* double wbuf_mod=0.0;			//no floating point in 2.6 kernel  */
	unsigned int num_bytes_already_sent=0;
	unsigned int hibyte=0;
	unsigned int lobyte=0;
	int cmdir_cnt =0;
	unsigned int wait_this = 0;
	struct timeval start_time; 
	struct timeval end_time; 
	unsigned int real_time_elapsed = 0; 
	// int first_signal = 0;
	
	// save the time we started the write:
	do_gettimeofday(&start_time);
		
	if(n%sizeof(lirc_t)) return(-EINVAL);

	count=n/sizeof(lirc_t);
	if(count>WBUF_LEN || count%2==0) return(-EINVAL);	
	if(copy_from_user(wbuf,buf,n)) return -EFAULT;

	// the first time we have to flag that this is the start of a new signal
	// otherwise COMMANDIR may receive 2 back-to-back pulses & invert the signal
	cmdir_char[0] = TX_HEADER_NEW;
	signal_num++;
	cmdir_char[1] = signal_num;
	cmdir_cnt = 2;
	for(i=0;i<count;i++)
	{
		// prev_length_waited += wbuf[i];
	
		/* conversion to number of modulation frequency pulse edges */
		mod_signal_length = wbuf[i] >> 3;

		//if (mod_signal_length%2 == 1) mod_signal_length++;  //want even number
		/* if (i%2==0) mod_signal_length-=5;
		else mod_signal_length+=5;	
		*/
		// account for minor rounding errors - calculate length from this:
		time_elapse += mod_signal_length * timerval;

		hibyte = mod_signal_length/256;
		lobyte = mod_signal_length%256;
		cmdir_char[cmdir_cnt+1] = lobyte;
		cmdir_char[cmdir_cnt] = hibyte;
		// (unsigned short)(cmdir_char[cmdir_cnt]) = mod_signal_length;
		cmdir_cnt += 2;
		
		/* write data to usb if full packet is collected */
		if (cmdir_cnt%MAX_PACKET == 0)
		{
			write_to_usb(cmdir_char, MAX_PACKET,  time_elapse);
			
			total_time_elapsed += time_elapse;
			
			num_bytes_already_sent+= MAX_PACKET;
			time_elapse = 0;
			
			if ((i+1)<count) // still more to send:
			{
				cmdir_char[0] =	TX_HEADER;  // Next Packet
				cmdir_char[1] = signal_num;
				cmdir_cnt = 2; // reset the count
			}
		}
	}
	
	/* send last chunk of data */
	if (cmdir_cnt > 0)
	{
		// time_elapse
		total_time_elapsed += time_elapse; //time_elapse;
		write_to_usb(cmdir_char, cmdir_cnt, time_elapse);
	}
	// ---------------------------------------------------------------------------
	//  we need to _manually delay ourselves_ to remain backwards compatible with
	// LIRC and prevent our queue buffer from overflowing.  Queuing in this driver
	// is about instant, and send_start for example will fill it up quickly and 
	// prevent send_stop from taking immediate effect.  
	// ---------------------------------------------------------------------------
	// printk("Total elapsed time is: %d. \n", total_time_elapsed);
	do_gettimeofday(&end_time);
	// udelay for the difference between endtime and start+total_time_elapsed
	if(start_time.tv_usec < end_time.tv_usec){
		real_time_elapsed = (end_time.tv_usec - start_time.tv_usec);
	} else {
		real_time_elapsed = ((end_time.tv_usec +  1000000) - start_time.tv_usec);
	}
	// printk("Real time elapsed was %u.\n", real_time_elapsed);
	if(real_time_elapsed < (total_time_elapsed-1000)){
		wait_this = total_time_elapsed - real_time_elapsed - 1000;
	}
	//  safe_udelay(wait_this); // enable this for backwards compatibility
	
	return(n);
}


static int lirc_ioctl(struct inode *node,struct file *filep,unsigned int cmd,
		      unsigned long arg)
{
        int result;
	unsigned long value;
	unsigned int ivalue;
	unsigned int multiplier=1;
	unsigned int mask=0;
	int i;
	switch(cmd)
	{
	case LIRC_SET_TRANSMITTER_MASK:
		if (!(hardware.features&LIRC_CAN_SET_TRANSMITTER_MASK))
		{
			return(-ENOIOCTLCMD);
		}
		result=get_user(ivalue,(unsigned int *) arg);
		if(result) return(result);
		for(i=0;i<MAX_CHANNELS;i++) 
		{
			multiplier=multiplier*0x10;
			mask|=multiplier;
		}
		if(ivalue >= mask) return (MAX_CHANNELS);
		set_tx_channels(ivalue);
		return (0);
		break;
				
	case LIRC_GET_SEND_MODE:
		if(!(hardware.features&LIRC_CAN_SEND_MASK))
		{
			return(-ENOIOCTLCMD);
		}
		
		result=put_user(LIRC_SEND2MODE
				(hardware.features&LIRC_CAN_SEND_MASK),
				(unsigned long *) arg);
		if(result) return(result); 
		break;
	
	case LIRC_SET_SEND_MODE:
		if(!(hardware.features&LIRC_CAN_SEND_MASK))
		{
			return(-ENOIOCTLCMD);
		}
		
		result=get_user(value,(unsigned long *) arg);
		if(result) return(result);
		break;
		
	case LIRC_GET_LENGTH:
		return(-ENOSYS);
		break;
		
	case LIRC_SET_SEND_DUTY_CYCLE:
#               ifdef DEBUG
		printk(KERN_WARNING LIRC_DRIVER_NAME ": SET_SEND_DUTY_CYCLE\n");
#               endif

		if(!(hardware.features&LIRC_CAN_SET_SEND_DUTY_CYCLE))
		{
			return(-ENOIOCTLCMD);
		}
				
		result=get_user(ivalue,(unsigned int *) arg);
		if(result) return(result);
		if(ivalue<=0 || ivalue>100) return(-EINVAL);
		
		/* TODO: */
		/* printk(LIRC_DRIVER_NAME ": set_send_duty_cycle not yet supported\n"); */
	
		return 0;
		break;
		
	case LIRC_SET_SEND_CARRIER:
#               ifdef DEBUG
		printk(KERN_WARNING LIRC_DRIVER_NAME ": SET_SEND_CARRIER\n");
#               endif
		
		if(!(hardware.features&LIRC_CAN_SET_SEND_CARRIER))
		{
			return(-ENOIOCTLCMD);
		}
		
		result=get_user(ivalue,(unsigned int *) arg);
		if(result) return(result);
		if(ivalue>500000 || ivalue<24000) return(-EINVAL);
		if (ivalue != freq) 
		{
			freq=ivalue;
			set_freq();
		}
		return 0;
		break;
		
	default:
		return(-ENOIOCTLCMD);
	}
	return(0);
}

static struct file_operations lirc_fops =
{
	write:   lirc_write,
};

static struct lirc_plugin plugin = {
	name:		LIRC_DRIVER_NAME,
	minor:		-1,
	code_length:	1,
	sample_rate:	20,
	data:		NULL,
	add_to_buf:	add_to_buf,
	get_queue:	NULL,
	rbuf:		&rbuf,
	set_use_inc:	set_use_inc,
	set_use_dec:	set_use_dec,
	ioctl:		lirc_ioctl,
	fops:		&lirc_fops,
	dev:		NULL,
	owner:		THIS_MODULE,
};

#ifdef MODULE

MODULE_AUTHOR("Evelyn Yeung, Matt Bodkin");
MODULE_DESCRIPTION("InnovationOne driver for CommandIR USB infrared transceiver");
#ifdef MODULE_LICENSE
MODULE_LICENSE("GPL");
#endif

#ifndef KERNEL_2_5
EXPORT_NO_SYMBOLS;
#endif

int init_module(void)
{
	plugin.features = hardware.features;
	if ((plugin.minor = lirc_register_plugin(&plugin)) < 0) 
	{
		printk(KERN_ERR  LIRC_DRIVER_NAME  
		       ": register_chrdev failed!\n");
		return -EIO;
	}
	set_freq();
	return 0;
}

void cleanup_module(void)
{
	lirc_unregister_plugin(plugin.minor);
	printk(KERN_INFO  LIRC_DRIVER_NAME  ": module removed\n");
}

#endif


