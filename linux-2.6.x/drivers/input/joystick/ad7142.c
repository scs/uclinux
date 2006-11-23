/*
 * File:         drivers/input/joystick/ad7142.c
 * Based on:	 drivers/input/joystick/amijoy.c
 * Author:	 Aubrey.Li <aubrey.li@analog.com>
 *
 * Created:	 Apr 7th, 2006
 * Description:	
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright 2005-2005 Analog Devices Inc.
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

#undef  DEBUG
//#define DEBUG

#ifdef DEBUG
#define DPRINTK(x...)   printk(x)
#else
#define DPRINTK(x...)   do { } while (0)
#endif

MODULE_AUTHOR("Aubrey Li <aubrey.li@analog.com>");
MODULE_DESCRIPTION("Driver for AD7142 joysticks");
MODULE_LICENSE("GPL");

/*
 * Feeding the output queue to the device is handled by way of a
 * workqueue.
 */
static struct task_struct *ad7142_task;
static DECLARE_WAIT_QUEUE_HEAD(ad7142_wait);

static int ad7142_used=0;
static struct input_dev *ad7142_dev;
static char *ad7142_phys={"ad7142/input0"};

static char *ad7142_name = "ad7142 joystick";

#define AD7142_DRV_NAME         "ad7142_js"
#define AD7142_I2C_ID		0xE622
#define AD7142_I2C_ADDR		0x2C
/*
 * Ram map - these registers are defined as we go along
 */
#define PWRCONVCTL              0x00    // RW   Power & conversion control

#define AMBCOMPCTL_REG0         0x01    // RW   Ambient compensation control register 0
#define AMBCOMPCTL_REG1         0x02    // RW   Ambient compensation control register 1
#define AMBCOMPCTL_REG2         0x03    // RW   Ambient compensation control register 2
#define AMBCOMPCTL_REG3         0x04    // RW   Ambient compensation control register 3

#define INTEN_REG0              0x05    // RW   Interrupt enable register 0
#define INTEN_REG1              0x06    // RW   Interrupt enable register 1
#define INTEN_REG2              0x07    // RW   Interrupt enable register 2
#define INTSTAT_REG0            0x08    // R    Low limit interrupt status register 0
#define INTSTAT_REG1            0x09    // R    High limit interrupt status register 1
#define INTSTAT_REG2            0x0A    // R    Interrupt status register 2

#define ADCRESULT_S0            0x0B    // R    ADC stage 0 result (uncompensated) actually located in SRAM
#define ADCRESULT_S1            0x0C    // R    ADC stage 1 result (uncompensated) actually located in SRAM
#define ADCRESULT_S2            0x0D    // R    ADC stage 2 result (uncompensated) actually located in SRAM
#define ADCRESULT_S3            0x0E    // R    ADC stage 3 result (uncompensated) actually located in SRAM

#define ADCRESULT_S4            0x0F    // R    ADC stage 4 result (uncompensated) actually located in SRAM
#define ADCRESULT_S5            0x10    // R    ADC stage 5 result (uncompensated) actually located in SRAM
#define ADCRESULT_S6            0x11    // R    ADC stage 6 result (uncompensated) actually located in SRAM
#define ADCRESULT_S7            0x12    // R    ADC stage 7 result (uncompensated) actually located in SRAM

#define ADCRESULT_S8            0x13    // R    ADC stage 8 result (uncompensated) actually located in SRAM
#define ADCRESULT_S9            0x14    // R    ADC stage 9 result (uncompensated) actually located in SRAM
#define ADCRESULT_S10           0x15    // R    ADC stage 10 result (uncompensated) actually located in SRAM
#define ADCRESULT_S11           0x16    // R    ADC stage 11 result (uncompensated) actually located in SRAM

#define DEVID                   0x17    // R    I.D. Register

#define THRES_STAT_REG0         0x40    // R    Current threshold status register 0
#define THRES_STAT_REG1         0x41    // R    Current threshold status register 1
#define PROX_STAT_REG           0x42    // R    Current proximity status register 2

#define STAGE0_CONNECTION       0x80
#define STAGE1_CONNECTION       0x88
#define STAGE2_CONNECTION       0x90
#define STAGE3_CONNECTION       0x98
#define STAGE4_CONNECTION       0xA0
#define STAGE5_CONNECTION       0xA8
#define STAGE6_CONNECTION       0xB0
#define STAGE7_CONNECTION       0xB8
#define STAGE8_CONNECTION       0xC0
#define STAGE9_CONNECTION       0xC8
#define STAGE10_CONNECTION      0xD0
#define STAGE11_CONNECTION      0xD8

/*
 *	STAGE0: Button1   <----> CIN6(+)	Button2    <----> CIN5(-)	
 *	STAGE1: Button3   <----> CIN4(-)	Button4    <----> CIN3(+)
 *	STAGE2: Axes.Left <----> CIN11(-)  	Axes.Right <----> CIN13(+)
 *	STAGE3: Axes.Up   <----> CIN12(-)  	Axes.Down  <----> CIN10(+)
 */
static unsigned short stage[5][8]={
	{0xE7FF, 0x3FFF, 0x0005, 0x2626, 0x01F4, 0x01F4, 0x028A, 0x028A},
        {0xFDBF, 0x3FFF, 0x0001, 0x2626, 0x01F4, 0x01F4, 0x028A, 0x028A},
        {0xFFFF, 0x2DFF, 0x0001, 0x2626, 0x01F4, 0x01F4, 0x028A, 0x028A},
        {0xFFFF, 0x37BF, 0x0001, 0x2626, 0x01F4, 0x01F4, 0x028A, 0x028A},
        {0xFFFF, 0x3FFF, 0x0000, 0x0606, 0x01F4, 0x01F4, 0x0320, 0x0320},
};

static struct i2c_driver ad7142_driver;
static struct i2c_client *ad7142_client;

static unsigned short ignore[] = { I2C_CLIENT_END };
static unsigned short normal_addr[] = { AD7142_I2C_ADDR, I2C_CLIENT_END };

static struct i2c_client_address_data addr_data = {
  .normal_i2c = normal_addr,
  .probe = ignore,
  .ignore = ignore,
};

static int
ad7142_probe (struct i2c_adapter *adap, int addr, int kind)
{
  struct i2c_client *client;
  int rc;

  client = kmalloc (sizeof (struct i2c_client), GFP_KERNEL);
  if (!client)
    return -ENOMEM;

  memset (client, 0, sizeof (struct i2c_client));
  strncpy (client->name, AD7142_DRV_NAME, I2C_NAME_SIZE);
  client->addr = addr;
  client->adapter = adap;
  client->driver = &ad7142_driver;

  if ((rc = i2c_attach_client (client)) != 0)
    {
      kfree (client);
      printk ("i2c_attach_client fail: %d\n", rc);
      return rc;
    }

  ad7142_client = client;
  printk(KERN_INFO "%s_attach: at 0x%02x\n",
                        client->name, client->addr << 1);
  return 0;
}

static int
ad7142_i2c_write(struct i2c_client *client,
		     unsigned short    offset,
                     unsigned short    *data,
                     unsigned int       len)
{
        int ret = -1;
	int i;
	
	if(len<1 || len>16){
		printk("AD7142: Write data length error\n");
		return ret;
	}
        /* the adv7142 has an autoincrement function, use it if
         * the adapter understands raw I2C */
        if (i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
                /* do raw I2C, not smbus compatible */
		u8 block_data[34];

		block_data[0] = (offset & 0xFF00)>>8;
		block_data[1] = (offset & 0x00FF);
		for(i=0;i<len;i++){
			block_data[2*i+2] = (*data & 0xFF00)>>8;
			block_data[2*i+3] = *data++ & 0x00FF;
		}
		if((ret = i2c_master_send(client, block_data,len*2+2))<0){
			printk("AD7142: I2C write error\n");
			return ret;
		}
	} else
		printk("AD7142: i2c bus doesn't support raw I2C operation\n");
	return ret;
}

static int 
ad7142_i2c_read(struct i2c_client *client,
		    unsigned short offset,
		    unsigned short *data,
		    unsigned int    len)
{
	int ret = -1;
	int i;
	
	if(len<1 && len>16){
		printk("AD7142: read data length error\n");
		return ret;
	}
	/* the adv7142 has an autoincrement function, use it if
         * the adapter understands raw I2C */
        if (i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
                /* do raw I2C, not smbus compatible */
                u8 block_data[32];

                block_data[0] = (offset & 0xFF00)>>8;
                block_data[1] = (offset & 0x00FF);
		if((ret = i2c_master_send(client, block_data, 2))<0){
                        printk("AD7142: I2C read error\n");
                        return ret;
                }
                if((ret = i2c_master_recv(client, block_data, len*2)) < 0){
                        printk("AD7142: I2C transfer error\n");
                        return ret;
                }
		for(i=0;i<len;i++){
			unsigned short temp;
			temp = block_data[2*i];
			temp = (temp<<8) & 0xFF00;
			*data++ = temp | block_data[2*i+1];
		}
        } else
                printk("AD7142: i2c bus doesn't support raw I2C operation\n");
        return ret;	
}

static int
ad7142_attach (struct i2c_adapter *adap)
{
    return i2c_probe(adap, &addr_data, &ad7142_probe);
}

static int
ad7142_detach_client (struct i2c_client *client)
{
  int rc;
  if ((rc = i2c_detach_client (client)) == 0)
    kfree (i2c_get_clientdata (client));
  return rc;
}

static struct i2c_driver ad7142_driver = {
  .driver = {
  .name = AD7142_DRV_NAME,
  },
  .id = AD7142_I2C_ID,
  .attach_adapter = ad7142_attach,
  .detach_client = ad7142_detach_client,
};

unsigned short old_status_low=0,old_status_high=0;

static void ad7142_decode(void)
{
	unsigned short irqno_low=0,irqno_high=0;
        unsigned short temp;

        ad7142_i2c_read(ad7142_client,INTSTAT_REG0,&irqno_low,1);
        temp = irqno_low ^ old_status_low;
	switch(temp){
	case 0x0001: 	input_report_key(ad7142_dev, BTN_BASE, irqno_low&0x0001);
			old_status_low = irqno_low;
			break;
	case 0x0002:    input_report_key(ad7142_dev, BTN_BASE4, (irqno_low&0x0002)>>1);
                        old_status_low = irqno_low;
                        break;
	case 0x0004:    input_report_key(ad7142_dev, KEY_UP, (irqno_low&0x0004)>>2);
                        old_status_low = irqno_low;
                        break;
	case 0x0008:    input_report_key(ad7142_dev, KEY_RIGHT, (irqno_low&0x0008)>>3);
                        old_status_low = irqno_low;
                        break;
        }
        ad7142_i2c_read(ad7142_client,INTSTAT_REG1,&irqno_high,1);
        temp = irqno_high ^ old_status_high;
	switch(temp){
	case 0x0001:	input_report_key(ad7142_dev, BTN_BASE2, irqno_high&0x0001);
			old_status_high = irqno_high;
			break;
	case 0x0002:    input_report_key(ad7142_dev, BTN_BASE3, (irqno_high&0x0002)>>1);
                        old_status_high = irqno_high;
                        break;
	case 0x0004:    input_report_key(ad7142_dev, KEY_DOWN, (irqno_high&0x0004)>>2);
                        old_status_high = irqno_high;
                        break;
	case 0x0008:    input_report_key(ad7142_dev, KEY_LEFT, (irqno_high&0x0008)>>3);
                        old_status_high = irqno_high;
                        break;
        }
        input_sync(ad7142_dev);
}


static int intr_flag = 0;
static int ad7142_thread(void *nothing)
{
        do {
		wait_event_interruptible(ad7142_wait, kthread_should_stop() || (intr_flag!=0));
		ad7142_decode();
                intr_flag = 0;
  		enable_irq(CONFIG_BFIN_JOYSTICK_IRQ_PFX);
        } while (!kthread_should_stop());
        printk(KERN_DEBUG "ad7142: kthread exiting\n");
        return 0;
}

static irqreturn_t ad7142_interrupt(int irq, void *dummy, struct pt_regs *fp)
{
  	disable_irq(CONFIG_BFIN_JOYSTICK_IRQ_PFX);
	intr_flag = 1;
	wake_up_interruptible(&ad7142_wait);
	return IRQ_HANDLED;
}

static int ad7142_open(struct input_dev *dev)
{
	int *used = dev->private;
	unsigned short id,value;
	ad7142_i2c_read(ad7142_client, DEVID, &id, 1);
	if(id != AD7142_I2C_ID){
		printk(KERN_ERR "Open AD7142 error\n");
		return -ENODEV;
	}
	if ((*used)++)
		return 0;

	if (request_irq(CONFIG_BFIN_JOYSTICK_IRQ_PFX, ad7142_interrupt, \
		IRQF_TRIGGER_LOW, "ad7142_joy", ad7142_interrupt)) {
		(*used)--;
		printk(KERN_ERR "ad7142.c: Can't allocate irq %d\n",CONFIG_BFIN_JOYSTICK_IRQ_PFX);
		return -EBUSY;
	}


	ad7142_i2c_write(ad7142_client,STAGE0_CONNECTION,stage[0],8);
	ad7142_i2c_write(ad7142_client,STAGE1_CONNECTION,stage[1],8);
	ad7142_i2c_write(ad7142_client,STAGE2_CONNECTION,stage[2],8);
	ad7142_i2c_write(ad7142_client,STAGE3_CONNECTION,stage[3],8);
	ad7142_i2c_write(ad7142_client,STAGE4_CONNECTION,stage[4],8);
	ad7142_i2c_write(ad7142_client,STAGE5_CONNECTION,stage[4],8);
	ad7142_i2c_write(ad7142_client,STAGE6_CONNECTION,stage[4],8);
	ad7142_i2c_write(ad7142_client,STAGE7_CONNECTION,stage[4],8);
	ad7142_i2c_write(ad7142_client,STAGE8_CONNECTION,stage[4],8);
	ad7142_i2c_write(ad7142_client,STAGE9_CONNECTION,stage[4],8);
	ad7142_i2c_write(ad7142_client,STAGE10_CONNECTION,stage[4],8);
	ad7142_i2c_write(ad7142_client,STAGE11_CONNECTION,stage[4],8);

	value = 0x00B0;
	ad7142_i2c_write(ad7142_client,PWRCONVCTL,&value,1);
	
	value = 0x0690;
	ad7142_i2c_write(ad7142_client,AMBCOMPCTL_REG1,&value,1);

	value = 0x0664;
	ad7142_i2c_write(ad7142_client,AMBCOMPCTL_REG2,&value,1);

	value = 0x290F;
	ad7142_i2c_write(ad7142_client,AMBCOMPCTL_REG3,&value,1);
	
	value = 0x000F;
	ad7142_i2c_write(ad7142_client,INTEN_REG0,&value,1);
	ad7142_i2c_write(ad7142_client,INTEN_REG1,&value,1);
	
	value = 0x0000;
	ad7142_i2c_write(ad7142_client,INTEN_REG2,&value,1);

	ad7142_i2c_read(ad7142_client,AMBCOMPCTL_REG1,&value,1);

	value = 0x000F;
	ad7142_i2c_write(ad7142_client,AMBCOMPCTL_REG0,&value,1);
	
	ad7142_task = kthread_run(ad7142_thread, NULL, "ad7142_task");
        if (IS_ERR(ad7142_task)) {
                printk(KERN_ERR "serio: Failed to start kseriod\n");
                return PTR_ERR(ad7142_task);
        }
	return 0;
}

static void ad7142_close(struct input_dev *dev)
{
	int *used = dev->private;

	if (!--(*used))
		free_irq(CONFIG_BFIN_JOYSTICK_IRQ_PFX, ad7142_interrupt);
	kthread_stop(ad7142_task);
}

static int __init ad7142_init(void)
{
	ad7142_dev = input_allocate_device();
	if(!ad7142_dev)
		return -ENOMEM;
	ad7142_dev->open = ad7142_open;
	ad7142_dev->close = ad7142_close;
	ad7142_dev->evbit[0] = BIT(EV_KEY);
	ad7142_dev->keybit[LONG(BTN_BASE)] = BIT(BTN_BASE) | BIT(BTN_BASE2) | BIT(BTN_BASE3) | BIT(BTN_BASE4);
	ad7142_dev->keybit[LONG(KEY_UP)] |= BIT(KEY_UP) | BIT(KEY_DOWN) | BIT(KEY_LEFT) | BIT(KEY_RIGHT);

	ad7142_dev->name = ad7142_name;
	ad7142_dev->phys = ad7142_phys;
	ad7142_dev->id.bustype = BUS_I2C;
	ad7142_dev->id.vendor = 0x0001;
	ad7142_dev->id.product = 0x0001;
	ad7142_dev->id.version = 0x0100;

	ad7142_dev->private = &ad7142_used;

	input_register_device(ad7142_dev);
	i2c_add_driver (&ad7142_driver);

	return 0;
}

static void __exit ad7142_exit(void)
{
	i2c_del_driver (&ad7142_driver);
	input_unregister_device(ad7142_dev);
}

module_init(ad7142_init);
module_exit(ad7142_exit);
