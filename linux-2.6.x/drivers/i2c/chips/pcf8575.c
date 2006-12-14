/*
    pcf8575.c - Part of lm_sensors, Linux kernel modules for hardware
             monitoring
    Copyright (c) 2000  Frodo Looijaard <frodol@dds.nl>, 
                        Philip Edelbrock <phil@netroedge.com>,
                        Dan Eaton <dan.eaton@rocketlogix.com>
    Ported to Linux 2.6 by Aurelien Jarno <aurel32@debian.org> with 
    the help of Jean Delvare <khali@linux-fr.org>

    Copyright (C) 2006 Michael Hennerich, Analog Devices Inc.
    			<hennerich@blackfin.uclinux.org>
	based on the pcf8574.c

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

/* A few notes about the pcf8575:

* The pcf8575 is an 16-bit I/O expander for the I2C bus produced by
  Philips Semiconductors.  It is designed to provide a byte I2C
  interface to up to 8 separate devices.

  --Dan

*/

#include <linux/module.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/i2c.h>

/* Addresses to scan */
static unsigned short normal_i2c[] = { 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
					I2C_CLIENT_END };

/* Insmod parameters */
I2C_CLIENT_INSMOD_1(pcf8575);


/* Each client has this additional data */
struct pcf8575_data {
	struct i2c_client client;

	u16 write;			/* Remember last written value */
	u8 buf[3];
};

static int pcf8575_attach_adapter(struct i2c_adapter *adapter);
static int pcf8575_detect(struct i2c_adapter *adapter, int address, int kind);
static int pcf8575_detach_client(struct i2c_client *client);

/* This is the driver that will be inserted */
static struct i2c_driver pcf8575_driver = {
	.driver = {
		.name	= "pcf8575",
	},
	.id		= I2C_DRIVERID_PCF8575,
	.attach_adapter	= pcf8575_attach_adapter,
	.detach_client	= pcf8575_detach_client,
};

/* following are the sysfs callback functions */
static ssize_t show_read(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct pcf8575_data *data = i2c_get_clientdata(client);
	unsigned short val;

		i2c_master_recv(client,data->buf,2);
		
		val = data->buf[0];
		val |= data->buf[1]<<8;  

	return sprintf(buf, "%u\n", val);
}

static DEVICE_ATTR(read, S_IRUGO, show_read, NULL);

static ssize_t show_write(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct pcf8575_data *data = i2c_get_clientdata(to_i2c_client(dev));
	return sprintf(buf, "%u\n", data->write);
}

static ssize_t set_write(struct device *dev, struct device_attribute *attr, const char *buf,
			 size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct pcf8575_data *data = i2c_get_clientdata(client);
	unsigned long val = simple_strtoul(buf, NULL, 10);

	if (val > 0xffff)
		return -EINVAL;

	data->write = val;
	
	data->buf[0] = val & 0xFF;
	data->buf[1] = val >> 8;
	
	i2c_master_send(client,data->buf,2);
	
	return count;
}

static DEVICE_ATTR(write, S_IWUSR | S_IRUGO, show_write, set_write);

static ssize_t set_set_bit(struct device *dev, struct device_attribute *attr, const char *buf,
			 size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct pcf8575_data *data = i2c_get_clientdata(client);
	unsigned long val = simple_strtoul(buf, NULL, 10);
	unsigned short dummy;
	if (val > 15)
		return -EINVAL;

	i2c_master_recv(client,data->buf,2);
		
	dummy = data->buf[0];
	dummy |= data->buf[1]<<8; 

	dummy |= 1 << val;
	
	data->buf[0] = dummy & 0xFF;
	data->buf[1] = dummy >> 8;
	
	i2c_master_send(client,data->buf,2);
	
	return count;
}

static DEVICE_ATTR(set_bit, S_IWUSR, show_write, set_set_bit);

static ssize_t set_clear_bit(struct device *dev, struct device_attribute *attr, const char *buf,
			 size_t count)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct pcf8575_data *data = i2c_get_clientdata(client);
	unsigned long val = simple_strtoul(buf, NULL, 10);
	unsigned short dummy;
	if (val > 15)
		return -EINVAL;

	i2c_master_recv(client,data->buf,2);
		
	dummy = data->buf[0];
	dummy |= data->buf[1]<<8; 

	dummy &= ~(1 << val);
	
	data->buf[0] = dummy & 0xFF;
	data->buf[1] = dummy >> 8;
	
	i2c_master_send(client,data->buf,2);
	
	return count;
}

static DEVICE_ATTR(clear_bit, S_IWUSR, show_write, set_clear_bit);

/*
 * Real code
 */

static int pcf8575_attach_adapter(struct i2c_adapter *adapter)
{
	return i2c_probe(adapter, &addr_data, pcf8575_detect);
}

/* This function is called by i2c_probe */
static int pcf8575_detect(struct i2c_adapter *adapter, int address, int kind)
{
	struct i2c_client *new_client;
	struct pcf8575_data *data;
	int err = 0;
	const char *client_name = "";

	if (!i2c_check_functionality(adapter, I2C_FUNC_SMBUS_BYTE))
		goto exit;

	/* OK. For now, we presume we have a valid client. We now create the
	   client structure, even though we cannot fill it completely yet. */
	if (!(data = kzalloc(sizeof(struct pcf8575_data), GFP_KERNEL))) {
		err = -ENOMEM;
		goto exit;
	}

	new_client = &data->client;
	i2c_set_clientdata(new_client, data);
	new_client->addr = address;
	new_client->adapter = adapter;
	new_client->driver = &pcf8575_driver;
	new_client->flags = 0;

	/* Now, we would do the remaining detection. But the pcf8575 is plainly
	   impossible to detect! Stupid chip. */


	client_name = "pcf8575";

	/* Fill in the remaining client fields and put it into the global list */
	strlcpy(new_client->name, client_name, I2C_NAME_SIZE);

	/* Tell the I2C layer a new client has arrived */
	if ((err = i2c_attach_client(new_client)))
		goto exit_free;
	

	/* Register sysfs hooks */
	device_create_file(&new_client->dev, &dev_attr_read);
	device_create_file(&new_client->dev, &dev_attr_write);
	device_create_file(&new_client->dev, &dev_attr_set_bit);
	device_create_file(&new_client->dev, &dev_attr_clear_bit);
	return 0;

/* OK, this is not exactly good programming practice, usually. But it is
   very code-efficient in this case. */

      exit_free:
	kfree(data);
      exit:
	return err;
}

static int pcf8575_detach_client(struct i2c_client *client)
{
	int err;

	if ((err = i2c_detach_client(client)))
		return err;

	kfree(i2c_get_clientdata(client));
	return 0;
}

static int __init pcf8575_init(void)
{
	return i2c_add_driver(&pcf8575_driver);
}

static void __exit pcf8575_exit(void)
{
	i2c_del_driver(&pcf8575_driver);
}


MODULE_AUTHOR
    ("Frodo Looijaard <frodol@dds.nl>, "
     "Philip Edelbrock <phil@netroedge.com>, "
     "Dan Eaton <dan.eaton@rocketlogix.com> "
     "and Aurelien Jarno <aurelien@aurel32.net>"
     "Michael Hennerich <hennerich@blackfin.uclinux.org>");
MODULE_DESCRIPTION("pcf8575 driver");
MODULE_LICENSE("GPL");

module_init(pcf8575_init);
module_exit(pcf8575_exit);
