#include <linux/init.h>
#include <linux/module.h>
#include <linux/i2c.h>

/* AD5280 vcomm */
static unsigned char vcomm_value = 150;

static char ad5280_drv_name[] = "ad5280";
static struct i2c_driver ad5280_driver;

static unsigned short ignore[] 		= { I2C_CLIENT_END };
static unsigned short normal_addr[] = { 0x58>>1, I2C_CLIENT_END };

static struct i2c_client_address_data addr_data = {
	.normal_i2c			= normal_addr,
	.probe				= normal_addr,
	.ignore				= ignore,
};

static int ad5280_probe(struct i2c_adapter *adap, int addr, int kind)
{
	struct i2c_client client;
	int rc;
	unsigned char new_vcomm=0;

	memset(&client, 0, sizeof(struct i2c_client));
	strncpy(client.name, ad5280_drv_name, I2C_NAME_SIZE);
	client.addr = addr;
	client.adapter = adap;
	client.driver = &ad5280_driver;

	if ((rc = i2c_attach_client(&client)) != 0) {
		printk("TWI_SMBUS_TEST: i2c_attach_client fail: %d\n", rc);
		return rc;
	}

	rc = i2c_smbus_write_byte_data(&client, 0x00, vcomm_value);
	if(rc) {
		i2c_detach_client(&client);
		printk("TWI_SMBUS_TEST: i2c_smbus_write_byte_data fail: %d\n", rc);
		return -1;
	}

	new_vcomm = i2c_smbus_read_byte_data(&client, 0x00);
	i2c_detach_client(&client);
	if(new_vcomm != vcomm_value) {
		printk("TWI_SMBUS_TEST: i2c_smbus_read_byte_data fails: %d\n", new_vcomm);
		return -1;
	}

	printk("TWI_SMBUS_TEST.....[PASS]\n");
	return 0;
}

static int ad5280_attach(struct i2c_adapter *adap)
{
	if (adap->algo->functionality)
		return i2c_probe(adap, &addr_data, ad5280_probe);
	else
		return ad5280_probe(adap, 0x58>>1, 0);
}

static int ad5280_dettach(struct i2c_adapter *adap) {
	return 0;
}

static struct i2c_driver ad5280_driver = {
	.id              = 0x65,
	.attach_adapter  = ad5280_attach,
	.detach_adapter  = ad5280_dettach,
	.driver		= {
		.name	= ad5280_drv_name,
		.owner	= THIS_MODULE,
	},
};

static int test_init(void)
{

	printk("TWI smbus api test\n");
	i2c_add_driver(&ad5280_driver);

	return 0;
}

static void test_exit(void)
{
	i2c_del_driver(&ad5280_driver);
}

MODULE_LICENSE("GPL");

module_init(test_init);
module_exit(test_exit);
