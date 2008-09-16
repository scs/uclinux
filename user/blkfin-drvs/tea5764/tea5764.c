/*
 * File:         drivers/char/tea5764.c
 * Based on:	 drivers/
 * Author:	 Michael Hennerich <michael.hennerich@analog.com>
 *
 * Created:	 March 9th, 2007
 * Description:	
 * Rev:          $Id: tea5764.c 2460 2006-11-23 17:19:56Z hennerich $
 *
 * Modified:
 *               Copyright 2005-2007 Analog Devices Inc.
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

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/input.h>
#include <linux/interrupt.h>
#include <linux/i2c.h>
#include <linux/delay.h>
#include <linux/kthread.h>

#include <asm/uaccess.h>
#include <asm/blackfin.h>
#include <asm/irq.h>
#include <asm/gpio.h>


//#define CONFIG_SAA6588

#undef CONFIG_SAA6588

#undef CONFIG_TIME_MEASURE

#ifdef CONFIG_TIME_MEASURE
#define TIME_MEASURE_GPIO 11
#endif

#define TEA5764_MAJOR 122		//experimental

#define TEA5764_DRV_NAME         "tea5764"
#define TEA5764_FM_DRV_NAME      "tea5764 FM"
#define TEA5764_RDS_DRV_NAME     "tea5764 RDS"

#define TEA5764_FM_I2C_ID		0xE623
#define TEA5764_RDS_I2C_ID		0xE624

#define TEA5764_FM_I2C_ADDR		0x10
#define TEA5764_RDS_I2C_ADDR		0x11


#define FM_I2C_READ		1
#define FM_I2C_WRITE		2

#define RDS_I2C_READ		3
#define RDS_I2C_WRITE		4
#define RDS_CLEAR_BUFFER	5

#define RDS_BUFFER 256

#define POLL_INTERVAL (HZ/25)	/*40 ms*/

// Register Bitmasks

// INTFLG
#define INTFLG_BLFLAG                   0x01
#define INTFLG_FRRFLAG                  0x02
#define INTFLG_PDFLAG                   0x04
#define INTFLG_LEVFLAG                  0x08
#define INTFLG_IFFLAG                   0x10
#define INTFLG_LSYNCFL					0x20
#define INTFLG_TESTBIT					0x40
#define INTFLG_DAVFLAG					0x80
// INTMSK
#define INTMSK_FRMSK                    0x02    
#define INTMSK_DAVMSK                   0x80
#define INTMSK_LSYMSK					0x20
// TNCTRL1                                        
#define TNCTRL1_PUPD_1                  0x80
#define TNCTRL1_PUPD_0                  0x40
// TNCTRL2
#define TNCTRL2_SSL_1                   0x40
#define TNCTRL2_SSL_0                   0x20
// FRQSETMSB
#define FREQSETMSB_SUD                  0x80
#define FREQSETMSB_SM                   0x40
#define FREQSETMSB_87_5MHZ              0x29
#define FREQSETMSB_96_3MHZ              0x2E
#define FREQSETMSB_100_1MHZ             0x2F
#define FREQSETMSB_108MHZ               0x33
// FRQSETLSB
#define FREQSETLSB_87_5MHZ              0xD4
#define FREQSETLSB_96_3MHZ              0x0c
#define FREQSETLSB_100_1MHZ             0xD6
#define FREQSETLSB_108MHZ               0x9B
//RDSCTRL1
#define RDSCTRL1_NWSY                   0x80
#define RDSCTRL1_SYM_5                  0x40
#define RDSCTRL1_SYM_2                  0x02
#define RDSCTRL1_RDBS                   0x10
#define RDSCTRL1_RDS                    0x00
#define RDSCTRL1_DAC_DAVA               0x00
#define RDSCTRL1_DAC_DAVB               0x40
#define RDSCTRL1_DAC_DAVC               0x80



#define I2C_RDS_READ_UP_TO_RDSLBLSB      8  //  8 bytes

#define STAT_LAST	0
#define STAT_PREV	1
#define DATA_MSB_LAST	2
#define DATA_LSB_LAST	3
#define DATA_MSB_PREV	4
#define DATA_LSB_PREV	5
                                                                            
//----------------------------------------------------------------------------//
// Structure definitions of TEA5764 registers                                 //
//----------------------------------------------------------------------------//

#pragma pack(1)
typedef struct FM_READ {
    u8 INTFLAG;  //0R
    u8 INTMSK;   //1R
    u8 FRQSETMSB;//2R
    u8 FRQSETLSB;//3R
    u8 TNCTRL1;  //4R
    u8 TNCTRL2;  //5R
    u8 FRQCHKMSB;//6R
    u8 FRQCHKLSB;//7R
    u8 IFCHK;    //8R
    u8 LEVCHK;   //9R
    u8 TESTBITS; //10R
    u8 TESTMODE; //11R
} FM_READ;

#pragma pack(1)
typedef struct RDS_READ {
    u8 RDSSTAT1; //12R
    u8 RDSSTAT2; //13R
    u8 RDSLBMSB; //14R
    u8 RDSLBLSB; //15R
    u8 RDSPBMSB; //16R
    u8 RDSPBLSB; //17R
    u8 RDSBBC;   //18R
    u8 RDSGBC;   //19R
    u8 RDSCTRL1; //20R
    u8 RDSCTRL2; //21R
    u8 PAUSEDET; //22R
    u8 RDSBBL;   //23R
    u8 MANID1;   //24R
    u8 MANID2;   //25R
    u8 CHIPID1;  //26R
    u8 CHIPID2;  //27R
} RDS_READ;

#pragma pack(1)
typedef struct FM_RDS_READ {
    FM_READ FM;  // 0R-11R
    RDS_READ RDS;//12R-27R
} FM_RDS_READ;

#pragma pack(1)
typedef struct FM_WRITE {    
    u8 INTMSK;   //0W
    u8 FRQSETMSB;//1W
    u8 FRQSETLSB;//2W
    u8 TNCTRL1;  //3W
    u8 TNCTRL2;  //4W
    u8 TESTBITS; //5W
    u8 TESTMODE; //6W
} FM_WRITE;

#pragma pack(1)
typedef struct RDS_WRITE {    
    u8 RDSCTRL1; //7W
    u8 RDSCTRL2; //8W
    u8 PAUSEDET; //9W
    u8 RDSBBL;   //10W
} RDS_WRITE;

#pragma pack(1)
typedef struct FM_RDS_WRITE {
    FM_WRITE FM;  // 0W- 6W
    RDS_WRITE RDS;// 7W-10W
} FM_RDS_WRITE;

                                                                            
typedef struct i2c_message
{
	u8 	*buf;
	u16	len;
}i2c_message;

static DECLARE_WAIT_QUEUE_HEAD(tea5764_wait);


static __u8 rdsin=0,rdsout=0,rdsstat=0;
static int users=0;
static struct timer_list readtimer;
static unsigned char rdsbuf[RDS_BUFFER];
static unsigned char prev_blid;

static spinlock_t tea5764_io_lock;
static wait_queue_head_t read_queue;

static void tea5764_defer_work(void *arg);

static struct workqueue_struct *tea5764_workqueue;
static DECLARE_WORK(tea5764_work, tea5764_defer_work);

static struct i2c_driver tea5764_fm_driver;
static struct i2c_client *tea5764_fm_client;

static struct i2c_driver tea5764_rds_driver;
static struct i2c_client *tea5764_rds_client;

static unsigned short ignore[] = { I2C_CLIENT_END };
static unsigned short normal_addr_tea5764_fm[] = { TEA5764_FM_I2C_ADDR, I2C_CLIENT_END };
static unsigned short normal_addr_tea5764_rds[] = { TEA5764_RDS_I2C_ADDR, I2C_CLIENT_END };

static struct i2c_client_address_data addr_data_tea5764_fm = {
  .normal_i2c = normal_addr_tea5764_fm,
  .probe = ignore,
  .ignore = ignore,
};

static struct i2c_client_address_data addr_data_tea5764_rds = {
  .normal_i2c = normal_addr_tea5764_rds,
  .probe = ignore,
  .ignore = ignore,
};

static int
tea5764_fm_probe (struct i2c_adapter *adap, int addr, int kind)
{
  struct i2c_client *client;
  int rc;

  client = kmalloc (sizeof (struct i2c_client), GFP_KERNEL);
  if (!client)
    return -ENOMEM;


  memset (client, 0, sizeof (struct i2c_client));
  strncpy (client->name, TEA5764_FM_DRV_NAME, I2C_NAME_SIZE);
  client->addr = addr;
  client->adapter = adap;
  client->driver = &tea5764_fm_driver;

  if ((rc = i2c_attach_client (client)) != 0)
    {
      kfree (client);
      printk ("i2c_attach_client fail: %d\n", rc);
      return rc;
    }

  tea5764_fm_client = client;
  printk(KERN_INFO "%s_attach: at 0x%02x\n",
                        client->name, client->addr);
  return 0;
}



static int
tea5764_fm_attach (struct i2c_adapter *adap)
{
    return i2c_probe(adap, &addr_data_tea5764_fm, &tea5764_fm_probe);
}

static int
detach_client (struct i2c_client *client)
{
  int rc;
  if ((rc = i2c_detach_client (client)) == 0)
    kfree (i2c_get_clientdata (client));
  return rc;
}

static struct i2c_driver tea5764_fm_driver = {
  .driver = {
  .name = TEA5764_FM_DRV_NAME,
  },
  .id = TEA5764_FM_I2C_ID,
  .attach_adapter = tea5764_fm_attach,
  .detach_client = detach_client,
};


static int
tea5764_rds_probe (struct i2c_adapter *adap, int addr, int kind)
{
  struct i2c_client *client;
  int rc;

  client = kmalloc (sizeof (struct i2c_client), GFP_KERNEL);
  if (!client)
    return -ENOMEM;

  memset (client, 0, sizeof (struct i2c_client));
  strncpy (client->name, TEA5764_RDS_DRV_NAME, I2C_NAME_SIZE);
  client->addr = addr;
  client->adapter = adap;
  client->driver = &tea5764_rds_driver;

  if ((rc = i2c_attach_client (client)) != 0)
    {
      kfree (client);
      printk ("i2c_attach_client fail: %d\n", rc);
      return rc;
    }

  tea5764_rds_client = client;
  printk(KERN_INFO "%s_attach: at 0x%02x\n",
                        client->name, client->addr);
  return 0;
}

static int
tea5764_rds_attach (struct i2c_adapter *adap)
{
    return i2c_probe(adap, &addr_data_tea5764_rds, &tea5764_rds_probe);
}


static struct i2c_driver tea5764_rds_driver = {
  .driver = {
  .name = TEA5764_RDS_DRV_NAME,
  },
  .id = TEA5764_RDS_I2C_ID,
  .attach_adapter = tea5764_rds_attach,
  .detach_client = detach_client,
};


static int 
tea5764_i2c_read(struct i2c_client *client,u8 *buf,u16 len)
{
	int ret = -1;
		
//        if (i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {

                if((ret = i2c_master_recv(client, buf, len)) < 0){
                        printk("TEA5764: I2C transfer error\n");
                        return ret;
                }
//        } else
//                printk("AD7142: i2c bus doesn't support raw I2C operation\n");
        return ret;	
}

static int 
tea5764_i2c_send(struct i2c_client *client,u8 *buf,u16 len)
{
	int ret = -1;
	
//        if (i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {

                if((ret = i2c_master_send(client, buf, len)) < 0){
                        printk("TEA5764: I2C transfer error\n");
                        return ret;
                }
//        } else
//                printk("AD7142: i2c bus doesn't support raw I2C operation\n");
        return ret;	
}


static DEFINE_SPINLOCK(tea5764_lock);


/***********************************************************
*
* FUNCTION NAME :tea5764_open
*
* INPUTS/OUTPUTS:
* in_inode - Description of openned file.
* in_filp - Description of openned file.
*
* RETURN
* 0: Open ok.
* -ENXIO  No such device
*
* FUNCTION(S) CALLED:
*
* GLOBAL VARIABLES REFERENCED:
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: It is invoked when user call 'open' system call
*              to open spi device.
*
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/
static int tea5764_open(struct inode *inode, struct file *filp)
{
	unsigned long flags;


	spin_lock_irqsave(&tea5764_lock, flags);
	users++;
	if (1 == users) 
		init_waitqueue_head(&read_queue);
		
	spin_unlock_irqrestore(&tea5764_lock, flags);

#ifdef CONFIG_TIME_MEASURE
    if(gpio_request(TIME_MEASURE_GPIO, NULL)){
	printk(KERN_ERR "Failed ro request GPIO_%d\n",TIME_MEASURE_GPIO);
	return -EBUSY;
    }
    gpio_direction_output(TIME_MEASURE_GPIO);
#endif

#if 0
	unsigned char init[5]={0x80,0x30,0x69,0xc8,0xd2}; //Antenne
	unsigned char init_rds[5]={0xC8};


	tea5764_i2c_send(tea5764_fm_client,&init,5);
	tea5764_i2c_send(tea5764_rds_client,init_rds,1);
#endif
	return 0;
}

static int tea5764_release(struct inode *inode, struct file *filp)
{
	unsigned long flags;

	spin_lock_irqsave(&tea5764_lock, flags);

	users--;
	if (0 == users){
		del_timer_sync(&readtimer);
		rdsstat=0;
	}

#ifdef CONFIG_TIME_MEASURE
    gpio_free(TIME_MEASURE_GPIO);
#endif

	spin_unlock_irqrestore(&tea5764_lock, flags);

	return 0;
}


static void tea5764_handler(unsigned long data)
{
	queue_work(tea5764_workqueue, &tea5764_work);
}

static void tea5764_defer_work(void *arg)
{
	/*
	 * Service the RDS fifo
	 */

	unsigned char status[2];
	unsigned char buf[8];

#ifdef CONFIG_TIME_MEASURE	
	gpio_set_value(TIME_MEASURE_GPIO, 1);
#endif
	tea5764_i2c_read(tea5764_fm_client,&status[0],2);

	mod_timer(&readtimer, jiffies + POLL_INTERVAL);

#ifdef CONFIG_SAA6588
	unsigned char flag = 0;
	tea5764_i2c_read(tea5764_rds_client,&buf[0],I2C_RDS_READ_UP_TO_RDSLBLSB);


if((buf[STAT_PREV] & 0xE0) == prev_blid  || !(status[0] & INTFLG_DAVFLAG)) {
	
	rdsbuf[rdsin]=((buf[STAT_LAST]<<1) & 0xE0) | ((buf[STAT_PREV] & 4)>>2);
	rdsbuf[rdsin+1]= buf[DATA_MSB_LAST];
	rdsbuf[rdsin+2]= buf[DATA_LSB_LAST];
	rdsbuf[rdsin+3]= 0x00;
	rdsin+=4;

	prev_blid = (buf[STAT_LAST]<<1) & 0xE0;
	flag = 1;

} else {
	
	rdsbuf[rdsin]=(buf[STAT_PREV] & 0xE0) | ((buf[STAT_PREV] & 4)>>2);
	rdsbuf[rdsin+1]= buf[DATA_MSB_PREV];
	rdsbuf[rdsin+2]= buf[DATA_LSB_PREV];
	rdsbuf[rdsin+3]= 0x00;

	rdsbuf[rdsin+4]=((buf[STAT_LAST]<<1) & 0xE0) | ((buf[STAT_PREV] & 4)>>2);
	rdsbuf[rdsin+5]= buf[DATA_MSB_LAST];
	rdsbuf[rdsin+6]= buf[DATA_LSB_LAST];
	rdsbuf[rdsin+7]= 0x00;

	rdsin+=8;
	prev_blid = (buf[STAT_LAST]<<1) & 0xE0;	

}
#else
	tea5764_i2c_read(tea5764_rds_client,&buf[0],I2C_RDS_READ_UP_TO_RDSLBLSB);

		buf[STAT_LAST] = ( buf[STAT_LAST] & 0x70 ) >> 4 ;
	    	buf[STAT_PREV] = ( buf[STAT_PREV] & 0xE0 ) >> 5 ;


	if( (buf[STAT_PREV] == prev_blid)  || !(status[0] & INTFLG_DAVFLAG)) {

	    // move block-id to LSBs

		
	   	rdsbuf[rdsin]= buf[STAT_LAST];
		rdsbuf[rdsin+1]= buf[DATA_MSB_LAST];
		rdsbuf[rdsin+2]= buf[DATA_LSB_LAST];	
	    
	    	prev_blid = buf[STAT_LAST];
		rdsin+=4;
    
	} else {
	
		rdsbuf[rdsin]=buf[STAT_PREV];
		rdsbuf[rdsin+1]= buf[DATA_MSB_PREV];
		rdsbuf[rdsin+2]= buf[DATA_LSB_PREV];	
	
		rdsbuf[rdsin+4]=buf[STAT_LAST];
		rdsbuf[rdsin+5]= buf[DATA_MSB_LAST];
		rdsbuf[rdsin+6]= buf[DATA_LSB_LAST];
	 
	    	prev_blid = buf[STAT_LAST];	
		rdsin+=8;

}
#endif

	i2c_smbus_write_byte(tea5764_fm_client, INTMSK_DAVMSK);		
#ifdef CONFIG_TIME_MEASURE
	gpio_set_value(TIME_MEASURE_GPIO, 0);
#endif


//if(buf[STAT_PREV]== buf[STAT_LAST]) {
//
//	printk("p=%d\n",(buf[STAT_PREV]));
//	printk("l=%d\n",(buf[STAT_LAST]));
//	printk("MSB: %x  %x\n",buf[DATA_MSB_PREV],buf[DATA_MSB_LAST]);
//	printk("LSB: %x  %x\n",buf[DATA_LSB_PREV],buf[DATA_LSB_LAST]);
//
//}

	if( rdsin!=rdsout)
		wake_up_interruptible(&read_queue);

}

/***********************************************************
*
* FUNCTION NAME :tea5764_read
*
* INPUTS/OUTPUTS:
* in_filp - Description of openned file.
* in_count - how many bytes user wants to get.
* out_buf - data would be write to this address.
*
* RETURN
* positive number: bytes read back
* -ENODEV When minor not available.
* -EMSGSIZE When size more than a single ASCII digit followed by /n.
*
* FUNCTION(S) CALLED:
*
* GLOBAL VARIABLES REFERENCED:
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: It is invoked when user call 'read' system call
*              to read from system.
*
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/


static ssize_t tea5764_read(struct file *file, char __user *data,
			  size_t count, loff_t *ppos)
{
	int i=0;
	unsigned char readbuf[RDS_BUFFER];

	if(rdsstat==0) {
		spin_lock(&tea5764_io_lock);
		rdsstat=1;
		spin_unlock(&tea5764_io_lock);
		init_timer(&readtimer);
		readtimer.function=tea5764_handler;
		readtimer.data=(unsigned long)0;
		readtimer.expires=jiffies+POLL_INTERVAL;
		add_timer(&readtimer);
	}

	if(rdsin==rdsout) {
		if (file->f_flags & O_NONBLOCK)
			return -EWOULDBLOCK;
		interruptible_sleep_on(&read_queue);
	}

	while( i<count && rdsin!=rdsout)
		readbuf[i++]=rdsbuf[rdsout++];

	if (copy_to_user(data,readbuf,i))
		return -EFAULT;
	return i;
}


/***********************************************************
*
* FUNCTION NAME :tea5764_ioctl
*
* INPUTS/OUTPUTS:
* in_inode - Description of openned file.
* in_filp - Description of openned file.
* in_cmd - Command passed into ioctl system call.
* in/out_arg - It is parameters which is specified by last command
*
* RETURN:
* 0 OK
* -EINVAL
*
* FUNCTION(S) CALLED:
*
* GLOBAL VARIABLES REFERENCED:
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION:
*
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/
static int tea5764_ioctl(struct inode *inode, struct file *filp, uint cmd,
	     unsigned long arg)
{

	i2c_message msg;
	unsigned long flags;

	switch (cmd) {
	case FM_I2C_READ:
		{
		if (copy_from_user(&msg,(struct i2c_message __user *)arg,sizeof(msg)))
			return -EFAULT;
						
			tea5764_i2c_read(tea5764_fm_client,msg.buf,msg.len);
			break;
		}
	case FM_I2C_WRITE:
		{
		if (copy_from_user(&msg,(struct i2c_message __user *)arg,sizeof(msg)))
			return -EFAULT;

			tea5764_i2c_send(tea5764_fm_client,msg.buf,msg.len);
			break;
		}
	case RDS_I2C_READ:
		{
		if (copy_from_user(&msg,(struct i2c_message __user *)arg,sizeof(msg)))
			return -EFAULT;

			tea5764_i2c_read(tea5764_rds_client,msg.buf,msg.len);
			break;
		}
	case RDS_I2C_WRITE:
		{
		if (copy_from_user(&msg,(struct i2c_message __user *)arg,sizeof(msg)))
			return -EFAULT;

			tea5764_i2c_send(tea5764_rds_client,msg.buf,msg.len);
			break;
		}
	case RDS_CLEAR_BUFFER:
		{
			spin_lock_irqsave(&tea5764_lock, flags);
	
				rdsin = 0;
				rdsout = 0;
	
			spin_unlock_irqrestore(&tea5764_lock, flags);

			break;
		}
	default:
		return -EINVAL;
	}

	return 0;
}

static struct file_operations tea5764_fops = {
      .read    = tea5764_read,
      .ioctl   = tea5764_ioctl,
      .open    = tea5764_open,
      .release = tea5764_release,
};

static int __init tea5764_init(void)
{

	i2c_add_driver (&tea5764_fm_driver);
	i2c_add_driver (&tea5764_rds_driver);
	register_chrdev(TEA5764_MAJOR, TEA5764_DRV_NAME, &tea5764_fops);

	tea5764_workqueue = create_singlethread_workqueue("tea5764");
		
	return 0;
}

static void __exit tea5764_exit(void)
{
	i2c_del_driver (&tea5764_fm_driver);
	i2c_del_driver (&tea5764_rds_driver);
	unregister_chrdev(TEA5764_MAJOR, TEA5764_DRV_NAME);

	destroy_workqueue(tea5764_workqueue);

}

module_init(tea5764_init);
module_exit(tea5764_exit);

MODULE_AUTHOR("Michael Hennerich <michael.hennerich@analog.com>");
MODULE_DESCRIPTION("Driver for TEA5764");
MODULE_LICENSE("GPL");
