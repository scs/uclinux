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


MODULE_AUTHOR ("Michael Hennerich <hennerich@blackfin.uclinux.org>");
MODULE_DESCRIPTION ("TWI Keypad input driver");
MODULE_LICENSE ("GPL");

#define SENDASCII
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
  [0] = (unsigned short) KEY_RESERVED,
  [1] = (unsigned short) 'D',
  [2] = (unsigned short) '#',
  [3] = (unsigned short) '0',
  [4] = (unsigned short) '*',
  [5] = (unsigned short) 'C',
  [6] = (unsigned short) '9',
  [7] = (unsigned short) '8',
  [8] = (unsigned short) '7',
  [9] = (unsigned short) 'B',
  [10] = (unsigned short) '6',
  [11] = (unsigned short) '5',
  [12] = (unsigned short) '4',
  [13] = (unsigned short) 'A',
  [14] = (unsigned short) '3',
  [15] = (unsigned short) '2',
  [16] = (unsigned short) '1'
};
#else
static unsigned char twi_keypad_btncode[BUTTONS + 1] = {
  [0] = (unsigned short) KEY_RESERVED,
  [1] = (unsigned short) KEY_D,
  [2] = (unsigned short) KEY_F13,
  [3] = (unsigned short) KEY_0,
  [4] = (unsigned short) KEY_KPASTERISK,
  [5] = (unsigned short) KEY_C,
  [6] = (unsigned short) KEY_9,
  [7] = (unsigned short) KEY_8,
  [8] = (unsigned short) KEY_7,
  [9] = (unsigned short) KEY_B,
  [10] = (unsigned short) KEY_6,
  [11] = (unsigned short) KEY_5,
  [12] = (unsigned short) KEY_4,
  [13] = (unsigned short) KEY_A,
  [14] = (unsigned short) KEY_3,
  [15] = (unsigned short) KEY_2,
  [16] = (unsigned short) KEY_1
};

#endif


struct TWIKeypad
{

  unsigned char *btncode;
  struct input_dev dev;
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
  .normal_i2c_range = ignore,
  .probe = ignore,
  .probe_range = ignore,
  .ignore = ignore,
  .ignore_range = ignore,
  .force = ignore,
};

static irqreturn_t twi_keypad_irq_handler (int irq, void *dev_id,
					   struct pt_regs *regs);
static short read_state (struct TWIKeypad *TWIKeypad);
static void check_and_notify (struct TWIKeypad *TWIKeypad);


static struct TWIKeypad chip = {
  .btncode = twi_keypad_btncode,
  .laststate = 0,
  .statechanged = 0,
  .irq_handled = 0,
  .events_sended = 0,
  .events_processed = 0,
};


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
  client->flags = I2C_DF_NOTIFY;
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

  i2c_smbus_write_byte (pcf8574_kp_client, 240);

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
  .owner = THIS_MODULE,
  .name = PCF8574_KP_DRV_NAME,
  .id = 0x65,
  .flags = I2C_DF_NOTIFY,
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
check_and_notify (struct TWIKeypad *TWIKeypad)
{

  unsigned char nextstate = read_state (TWIKeypad);
  TWIKeypad->statechanged = TWIKeypad->laststate ^ nextstate;

  if (TWIKeypad->statechanged)
    {

      input_report_key (&TWIKeypad->dev,
			nextstate >
			17 ? TWIKeypad->btncode[TWIKeypad->
						laststate] : TWIKeypad->
			btncode[nextstate], nextstate > 17 ? 0 : 1);

      TWIKeypad->events_sended++;
    }

  TWIKeypad->laststate = nextstate;
  input_sync (&TWIKeypad->dev);

}



static irqreturn_t
twi_keypad_irq_handler (int irq, void *dev_id, struct pt_regs *regs)
{
  struct TWIKeypad *TWIKeypad = (struct TWIKeypad *) dev_id;

  check_and_notify (TWIKeypad);

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
  struct TWIKeypad *TWIKeypad = &chip;
  int i;

/*FIXME: Someone has masked a Interrupt */
  *pFIO_MASKA_C = 0xFFFF;

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

  i2c_add_driver (&pcf8574_kp_driver);

  init_input_dev (&TWIKeypad->dev);

  TWIKeypad->dev.evbit[0] = 0;

  TWIKeypad->dev.evbit[0] |= BIT (EV_KEY);
  TWIKeypad->dev.keycode = TWIKeypad->btncode;
  TWIKeypad->dev.keycodesize = sizeof (TWIKeypad->btncode);
  TWIKeypad->dev.keycodemax = ARRAY_SIZE (twi_keypad_btncode);

  for (i = 0; i <= BUTTONS; i++)
    {
      set_bit (TWIKeypad->btncode[i], TWIKeypad->dev.keybit);
    }

  sprintf (TWIKeypad->name, "BF5xx TWIKeypad");
  sprintf (TWIKeypad->phys, "twikeypad/input0");

  TWIKeypad->dev.name = TWIKeypad->name;
  TWIKeypad->dev.phys = TWIKeypad->phys;
  TWIKeypad->dev.id.bustype = BUS_I2C;
  TWIKeypad->dev.id.vendor = 0x0001;
  TWIKeypad->dev.id.product = 0x0001;
  TWIKeypad->dev.id.version = 0x0100;

  input_register_device (&TWIKeypad->dev);

  printk (KERN_INFO "input: %s at %s\n", TWIKeypad->name,
	  TWIKeypad->dev.phys);

  TWIKeypad->statechanged = 0x0;

  TWIKeypad->laststate = read_state (TWIKeypad);
  DPRINTK ("twikeypad: Keypad driver for bf5xx IRQ %d\n", IRQ_PROG_INTA);

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
