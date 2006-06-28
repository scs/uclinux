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

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/i2c.h>
#include <linux/i2c-algo-bit.h>

#include <asm/blackfin.h>


#define	HHBF_I2C_SCLK		    (1 << CONFIG_BFIN_SCL)
#define	HHBF_I2C_SDATA		    (1 << CONFIG_BFIN_SDA)

#define	I2C_HW_B_HHBF		    I2C_HW_B_FRODO  /* 0x13 */

static void hhbf_setsda(void *data, int state)
{
#if 0 	/* comment by mhfan */
    if (state)
	bfin_write_FIO_FLAG_D(bfin_read_FIO_FLAG_D() |  HHBF_I2C_SDATA);
    else
	bfin_write_FIO_FLAG_D(bfin_read_FIO_FLAG_D() & ~HHBF_I2C_SDATA);
#else
    if (state) {
	bfin_write_FIO_DIR(bfin_read_FIO_DIR() & ~HHBF_I2C_SDATA);
	bfin_write_FIO_INEN(bfin_read_FIO_INEN() |  HHBF_I2C_SDATA);
    } else {
	bfin_write_FIO_INEN(bfin_read_FIO_INEN() & ~HHBF_I2C_SDATA);
	bfin_write_FIO_DIR(bfin_read_FIO_DIR() |  HHBF_I2C_SDATA);
	bfin_write_FIO_FLAG_C(HHBF_I2C_SDATA);
    }
#endif	/* comment by mhfan */
}

static void hhbf_setscl(void *data, int state)
{
    if (state)
	bfin_write_FIO_FLAG_S(HHBF_I2C_SCLK);
    else
	bfin_write_FIO_FLAG_C(HHBF_I2C_SCLK);
}

static int hhbf_getsda(void *data)
{
    return ((bfin_read_FIO_FLAG_D() & HHBF_I2C_SDATA) != 0);
}

#if 0 	/* comment by mhfan */
static int hhbf_getscl(void *data)
{
    return ((bfin_read_FIO_FLAG_D() & HHBF_I2C_SCLK) != 0);
}
#endif	/* comment by mhfan */

static struct i2c_algo_bit_data bit_hhbf_data = {
    .setsda  = hhbf_setsda,
    .setscl  = hhbf_setscl,
    .getsda  = hhbf_getsda,
#if 0 	/* comment by mhfan */
    .getscl  = hhbf_getscl,
#endif	/* comment by mhfan */
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
    bfin_write_FIO_DIR(bfin_read_FIO_DIR() |  HHBF_I2C_SCLK);		// Set SCLK as output
    bfin_write_FIO_POLAR(bfin_read_FIO_POLAR() & ~HHBF_I2C_SDATA);		// Enable Active Hight
    bfin_write_FIO_EDGE(bfin_read_FIO_EDGE() & ~HHBF_I2C_SDATA);		// Enable Level Sensitivity
    bfin_write_FIO_INEN(bfin_read_FIO_INEN() |  HHBF_I2C_SDATA);		// Enable SDATA Input Buffer
    bfin_write_FIO_DIR(bfin_read_FIO_DIR() & ~HHBF_I2C_SDATA); 	// Set SDATA as input/high
#if 0 	/* comment by mhfan */
    bfin_write_FIO_DIR(bfin_read_FIO_DIR() |  HHBF_I2C_SDATA);
    bfin_write_FIO_FLAG_D(bfin_read_FIO_FLAG_D() |  HHBF_I2C_SDATA);
#endif	/* comment by mhfan */
    bfin_write_FIO_FLAG_S  (  HHBF_I2C_SCLK);		// Set SCLK high

    return i2c_bit_add_bus(&hhbf_ops);
}

static void __exit i2c_hhbf_exit(void)
{
    i2c_bit_del_bus(&hhbf_ops);
}

MODULE_AUTHOR("Meihui Fan <mhfan@ustc.edu>");
MODULE_DESCRIPTION("I2C-Bus adapter routines for Blackfin and HHBF Boards");
MODULE_LICENSE("GPL");

module_init(i2c_hhbf_init);
module_exit(i2c_hhbf_exit);

/******************* End Of File: i2c-hhbf.c *******************/
