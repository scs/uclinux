/****************************************************************
 * $ID: i2c-hhbf.c     Sat, 09 Oct 2004 17:29:10 +0800  mhfan $ *
 *                                                              *
 * Description:                                                 *
 *                                                              *
 * Maintainer:  ��Meihui Fan)  <mhfan@ustc.edu>            *
 *                                                              *
 * CopyRight (c)  2004  HHTech                                  *
 *   www.hhcn.com, www.hhcn.org                                 *
 *   All rights reserved.                                       *
 *                                                              *
 * This file is free software;                                  *
 *   you are free to modify and/or redistribute it   	        *
 *   under the terms of the GNU General Public Licence (GPL).   *
 *                                                              *
 * Last modified: Wed, 01 Dec 2004 01:19:01 +0800      by mhfan #
 ****************************************************************/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/i2c.h>
#include <linux/i2c-algo-bit.h>

#include <asm/blackfin.h>

#define	I2C_HW_B_HHBF		    I2C_HW_B_FRODO  /* 0x13 */

static void hhbf_setsda(void *data, int state)
{
    if (state) {
	set_gpio_dir(CONFIG_BFIN_SDA, GPIO_DIR_INPUT);
	set_gpio_inen(CONFIG_BFIN_SDA, GPIO_INPUT_ENABLE);

    } else {

	set_gpio_inen(CONFIG_BFIN_SDA, GPIO_INPUT_DISABLE);
	set_gpio_dir(CONFIG_BFIN_SDA, GPIO_DIR_OUTPUT);
	set_gpio_data(CONFIG_BFIN_SDA, 0);

    }
}

static void hhbf_setscl(void *data, int state)
{

	set_gpio_data(CONFIG_BFIN_SCL, state);

}

static int hhbf_getsda(void *data)
{

      return (get_gpio_data(CONFIG_BFIN_SDA) != 0);

}


static struct i2c_algo_bit_data bit_hhbf_data = {
    .setsda  = hhbf_setsda,
    .setscl  = hhbf_setscl,
    .getsda  = hhbf_getsda,
    .udelay  = CONFIG_I2C_BFIN_GPIO_CYCLE_DELAY,
    .mdelay  = CONFIG_I2C_BFIN_GPIO_CYCLE_DELAY,
    .timeout = HZ
};

static struct i2c_adapter hhbf_ops = {
    .owner 	= THIS_MODULE,
    .id 	= I2C_HW_B_HHBF,
    .algo_data 	= &bit_hhbf_data,
    .name	= "HHBF I2C driver",
};

static int __init i2c_hhbf_init(void)
{

    if(request_gpio(CONFIG_BFIN_SCL, REQUEST_GPIO)) {
    	printk(KERN_ERR "%s: request_gpio GPIO %d failed \n",__FUNCTION__, CONFIG_BFIN_SCL);
	return -1;
	}

    if(request_gpio(CONFIG_BFIN_SDA, REQUEST_GPIO)) {
    	printk(KERN_ERR "%s: request_gpio GPIO %d failed \n",__FUNCTION__, CONFIG_BFIN_SDA);
	return -1;
	}


    set_gpio_dir(CONFIG_BFIN_SCL, GPIO_DIR_OUTPUT);
//    set_gpio_polar(CONFIG_BFIN_SDA, GPIO_POLAR_AH_RE);    /*default*/
//    set_gpio_edge(CONFIG_BFIN_SDA, GPIO_EDGE_LEVEL);	/*default*/ 
    set_gpio_inen(CONFIG_BFIN_SDA, GPIO_INPUT_ENABLE);
//    set_gpio_dir(CONFIG_BFIN_SDA, GPIO_DIR_INPUT);  /*default*/
    set_gpio_data(CONFIG_BFIN_SCL, 1);    

    return i2c_bit_add_bus(&hhbf_ops);
}

static void __exit i2c_hhbf_exit(void)
{
    free_gpio(CONFIG_BFIN_SCL);
    free_gpio(CONFIG_BFIN_SDA);    
    i2c_bit_del_bus(&hhbf_ops);
}

MODULE_AUTHOR("Meihui Fan <mhfan@ustc.edu>");
MODULE_DESCRIPTION("I2C-Bus adapter routines for Blackfin and HHBF Boards");
MODULE_LICENSE("GPL");

module_init(i2c_hhbf_init);
module_exit(i2c_hhbf_exit);

/******************* End Of File: i2c-hhbf.c *******************/
