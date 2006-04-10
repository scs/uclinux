/************************************************************
*
* Copyright (C) 2006, Analog Devices. All Rights Reserved
*
* FILE twi_keypad.c
* PROGRAMMER(S): Michael Hennerich (Analog Devices Inc.)
*				 <hennerich@blackfin.uclinux.org>	
*
* $Id$
*
* DATE OF CREATION: Feb. 24th 2006
*
* SYNOPSIS:
*
* DESCRIPTION: TWI Driver for an 4x4 Keybaord Matrix connected to 
*              a PCF8574 I2C IO expander	
* CAUTION:    
**************************************************************
* MODIFICATION HISTORY:
* 24.02.2006 11:00  twi_keypad.c Created. (Michael Hennerich)
************************************************************
*
* This program is free software; you can distribute it and/or modify it
* under the terms of the GNU General Public License (Version 2) as
* published by the Free Software Foundation.
*
* This program is distributed in the hope it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
* FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
* for more details.
*
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 59 Temple Place - Suite 330, Boston MA 02111-1307, USA.
*
************************************************************/

#include <linux/module.h>
#include <linux/init.h>
#include <linux/input.h>
#include <linux/major.h>
#include <asm/uaccess.h>
#include <asm/blackfin.h>
#include <asm/irq.h>
#include <linux/proc_fs.h>
#include <linux/interrupt.h>
#include <linux/i2c.h>
#include <linux/workqueue.h>


MODULE_AUTHOR ("Michael Hennerich <hennerich@blackfin.uclinux.org>");
MODULE_DESCRIPTION ("TWI Keypad input driver");
MODULE_LICENSE ("GPL");

#undef SENDASCII
#undef	DEBUG
//#define DEBUG

#ifdef DEBUG
#define DPRINTK(x...)	printk(x)
#else
#define DPRINTK(x...)	do { } while (0)
#endif

#define BUTTONS 16

#ifdef SENDASCII
static unsigned char twi_keypad_btncode[BUTTONS + 1] = {
  [0] =  KEY_RESERVED,
  [1] =  'd',
  [2] =  '#',
  [3] =  '0',
  [4] =  '*',
  [5] =  'c',
  [6] =  '9',
  [7] =  '8',
  [8] =  '7',
  [9] =  'b',
  [10] =  '6',
  [11] =  '5',
  [12] =  '4',
  [13] =  'a',
  [14] =  '3',
  [15] =  '2',
  [16] =  '1'
};
#else
static unsigned char twi_keypad_btncode[BUTTONS + 1] = {
  [0] =  KEY_RESERVED,
  [1] =  KEY_ENTER,
  [2] =  KEY_BACKSLASH,
  [3] =  KEY_0,
  [4] =  KEY_RIGHTBRACE,
  [5] =  KEY_C,
  [6] =  KEY_9,
  [7] =  KEY_8,
  [8] =  KEY_7,
  [9] =  KEY_B,
  [10] =  KEY_6,
  [11] =  KEY_5,
  [12] =  KEY_4,
  [13] =  KEY_A,
  [14] =  KEY_3,
  [15] =  KEY_2,
  [16] =  KEY_1
};

#endif


struct TWIKeypad
{

  unsigned char *btncode;
  struct input_dev *dev;
  char name[64];
  char phys[32];
  unsigned char laststate;
  unsigned char statechanged;
  unsigned long irq_handled;
  unsigned long events_sended;
  unsigned long events_processed;
};


#define	PCF8574_KP_DRV_NAME		"pcf8574_kp"
static struct i2c_driver pcf8574_kp_driver;
static struct i2c_client *pcf8574_kp_client;

static unsigned short ignore[] = { I2C_CLIENT_END };
static unsigned short normal_addr[] = { 0x27, I2C_CLIENT_END };

static struct i2c_client_address_data addr_data = {
  .normal_i2c = normal_addr,
  .probe = ignore,
  .ignore = ignore,
};

static irqreturn_t twi_keypad_irq_handler (int irq, void *dev_id,
					   struct pt_regs *regs);
static short read_state (struct TWIKeypad *TWIKeypad);

static struct workqueue_struct *twi_keypad_workqueue;
static struct work_struct twi_keypad_work;

static int
pcf8574_kp_probe (struct i2c_adapter *adap, int addr, int kind)
{
  struct i2c_client *client;
  int rc;

  client = kmalloc (sizeof (struct i2c_client), GFP_KERNEL);
  if (!client)
    return -ENOMEM;

  memset (client, 0, sizeof (struct i2c_client));
  strncpy (client->name, PCF8574_KP_DRV_NAME, I2C_NAME_SIZE);
  client->addr = addr;
  client->adapter = adap;
  client->driver = &pcf8574_kp_driver;

  if ((rc = i2c_attach_client (client)) != 0)
    {
      kfree (client);
      printk ("i2c_attach_client fail: %d\n", rc);
      return rc;
    }

  pcf8574_kp_client = client;

  if(i2c_smbus_write_byte (pcf8574_kp_client, 240)<0) {
    printk("in keypad probe: write fail\n");
    return -1;
  }
  
  return 0;
}

static int
pcf8574_kp_attach (struct i2c_adapter *adap)
{
  if (adap->algo->functionality)
    return i2c_probe (adap, &addr_data, pcf8574_kp_probe);
  else
    return pcf8574_kp_probe (adap, 0x27, 0);
}

static int
pcf8574_kp_detach_client (struct i2c_client *client)
{
  int rc;
  if ((rc = i2c_detach_client (client)) == 0)
    kfree (i2c_get_clientdata (client));
  return rc;
}


static struct i2c_driver pcf8574_kp_driver = {
  .driver = {
  .name		= PCF8574_KP_DRV_NAME,
  },
  .id = 0x65,
  .attach_adapter = pcf8574_kp_attach,
  .detach_client = pcf8574_kp_detach_client,
};


static short
read_state (struct TWIKeypad *TWIKeypad)
{
  unsigned char x, y, a, b;

  if (pcf8574_kp_client)
  {
      i2c_smbus_write_byte (pcf8574_kp_client, 240);
      x = 0xF & (~(i2c_smbus_read_byte (pcf8574_kp_client) >> 4));

      i2c_smbus_write_byte (pcf8574_kp_client, 15);
      y = 0xF & (~i2c_smbus_read_byte (pcf8574_kp_client));

      for (a = 0; x > 0; a++)
	x = x >> 1;
      for (b = 0; y > 0; b++)
	y = y >> 1;

      return (((a - 1) * 4) + b);

    }

  return -1;

}


static void
check_and_notify (void *arg)
{
  struct TWIKeypad *TWIKeypad = (struct TWIKeypad *) arg;
  unsigned char nextstate = read_state (TWIKeypad);
  TWIKeypad->statechanged = TWIKeypad->laststate ^ nextstate;

  if (TWIKeypad->statechanged)
    {
      input_report_key (TWIKeypad->dev,
			nextstate >
			17 ? TWIKeypad->btncode[TWIKeypad->
						laststate] : TWIKeypad->
			btncode[nextstate], nextstate > 17 ? 0 : 1);

      TWIKeypad->events_sended++;
    }

  TWIKeypad->laststate = nextstate;
  input_sync (TWIKeypad->dev);

  if (CONFIG_BFIN_TWIKEYPAD_IRQ == IRQ_PROG_INTA) {
    *pFIO_MASKA_D |= (1 << CONFIG_BFIN_TWIKEYPAD_IRQ_PFX);
    __builtin_bfin_ssync();
  }
  else if (CONFIG_BFIN_TWIKEYPAD_IRQ == IRQ_PROG_INTB) {
    *pFIO_MASKB_D |= (1 << CONFIG_BFIN_TWIKEYPAD_IRQ_PFX);
    __builtin_bfin_ssync();
  }
}



static irqreturn_t
twi_keypad_irq_handler (int irq, void *dev_id, struct pt_regs *regs)
{
  if (irq == IRQ_PROG_INTA) {
    *pFIO_MASKA_D &= ~(1 << CONFIG_BFIN_TWIKEYPAD_IRQ_PFX);
    __builtin_bfin_ssync();
  }
  else if (irq == IRQ_PROG_INTB) {
    *pFIO_MASKB_D &= ~(1 << CONFIG_BFIN_TWIKEYPAD_IRQ_PFX);
    __builtin_bfin_ssync();
  }

  queue_work(twi_keypad_workqueue, &twi_keypad_work);

  DPRINTK ("twi_keypad_irq_handler \n");
  return IRQ_HANDLED;
}

#if 0
/*
 * sunkbd_event() handles events from the input module.
 */

static int
twi_keypad_dev_event (struct input_dev *dev, unsigned int type,
		      unsigned int code, int value)
{
  struct TWIKeypad *TWIKeypad = (struct TWIKeypad *) dev->private;
  int i;


  switch (type)
    {

    case EV_LED:

    case EV_SND:

      break;
    }

  return 0;
}
#endif


static int __init
twi_keypad_init (void)
{
//  struct TWIKeypad *TWIKeypad = &chip;
  int i;

  struct input_dev *input_dev;
  struct TWIKeypad *TWIKeypad;

  i2c_add_driver (&pcf8574_kp_driver);

  TWIKeypad = kzalloc(sizeof(struct TWIKeypad), GFP_KERNEL);

	input_dev = input_allocate_device();
	if (!input_dev)
		goto fail;

	if (request_irq
	(IRQ_PROG_INTA, twi_keypad_irq_handler, SA_INTERRUPT, "TWIKeypad",
	TWIKeypad))
	{
	printk (KERN_WARNING "TWIKeypad: IRQ %d is not free.\n", IRQ_PROG_INTA);
	return -EIO;
	}
	
	bfin_gpio_interrupt_setup (CONFIG_BFIN_TWIKEYPAD_IRQ,
				IRQ_PF0 + CONFIG_BFIN_TWIKEYPAD_IRQ_PFX,
				IRQT_LOW);

  TWIKeypad->dev = input_dev;
  TWIKeypad->btncode = twi_keypad_btncode;

  input_dev->evbit[0] = 0;

  input_dev->evbit[0] |= BIT (EV_KEY);
  input_dev->keycode = TWIKeypad->btncode;
  input_dev->keycodesize = sizeof (twi_keypad_btncode);
  input_dev->keycodemax = ARRAY_SIZE (twi_keypad_btncode);

  for (i = 0; i <= BUTTONS; i++)
    {
      set_bit (TWIKeypad->btncode[i], input_dev->keybit);
    }

  sprintf (TWIKeypad->name, "BF5xx TWIKeypad");
  sprintf (TWIKeypad->phys, "twikeypad/input0");

  input_dev->name = TWIKeypad->name;
  input_dev->phys = TWIKeypad->phys;
  input_dev->id.bustype = BUS_I2C;
  input_dev->id.vendor = 0x0001;
  input_dev->id.product = 0x0001;
  input_dev->id.version = 0x0100;

  input_register_device (TWIKeypad->dev);

  printk (KERN_INFO "input: %s at %s\n", TWIKeypad->name,
	  TWIKeypad->phys);

  TWIKeypad->statechanged = 0x0;

  TWIKeypad->laststate = read_state (TWIKeypad);
  DPRINTK ("twikeypad: Keypad driver for bf5xx IRQ %d\n", IRQ_PROG_INTA);

  /* Set up our workqueue. */
  INIT_WORK(&twi_keypad_work, check_and_notify, TWIKeypad);
  twi_keypad_workqueue = create_singlethread_workqueue("twi_keypad");
  
  return 0;

fail:
  input_free_device(input_dev);
  i2c_del_driver (&pcf8574_kp_driver);
  kfree(TWIKeypad);

  return 0;

}

void __exit
twi_keypad_exit (void)
{

  free_irq (CONFIG_BFIN_TWIKEYPAD_IRQ, twi_keypad_irq_handler);
  i2c_del_driver (&pcf8574_kp_driver);

}

module_init (twi_keypad_init);
module_exit (twi_keypad_exit);
