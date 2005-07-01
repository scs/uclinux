/****************************************************************
 * $ID: i2c-hhbf.c     Sat, 09 Oct 2004 17:29:10 +0800  mhfan $ *
 *                                                              *
 * Description:                                                 *
 *                                                              *
 * Maintainer:  ∑∂√¿ª‘(Meihui Fan)  <mhfan@ustc.edu>            *
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

#define	HHBF_I2C_SCLK		    PF0
#define	HHBF_I2C_SDATA		    PF1
#define	I2C_HW_B_HHBF		    I2C_HW_B_FRODO  /* 0x13 */

static void hhbf_setsda(void *data, int state)
{
#if 0 	/* comment by mhfan */
    if (state)
	*pFIO_FLAG_D |=  HHBF_I2C_SDATA;
    else
	*pFIO_FLAG_D &= ~HHBF_I2C_SDATA;
#else
    if (state) {
	*pFIO_DIR    &= ~HHBF_I2C_SDATA;
	*pFIO_INEN   |=  HHBF_I2C_SDATA;   //
    } else {
	*pFIO_INEN   &= ~HHBF_I2C_SDATA;   //
	*pFIO_DIR    |=  HHBF_I2C_SDATA;
	*pFIO_FLAG_D &= ~HHBF_I2C_SDATA;
    }
#endif	/* comment by mhfan */
}

static void hhbf_setscl(void *data, int state)
{
    if (state)
	*pFIO_FLAG_D |=  HHBF_I2C_SCLK;
    else
	*pFIO_FLAG_D &= ~HHBF_I2C_SCLK;
}

static int hhbf_getsda(void *data)
{
    return ((*pFIO_FLAG_D & HHBF_I2C_SDATA) != 0);
}

#if 0 	/* comment by mhfan */
static int hhbf_getscl(void *data)
{
    return ((*pFIO_FLAG_D & HHBF_I2C_SCLK) != 0);
}
#endif	/* comment by mhfan */

static struct i2c_algo_bit_data bit_hhbf_data = {
    .setsda  = hhbf_setsda,
    .setscl  = hhbf_setscl,
    .getsda  = hhbf_getsda,
#if 0 	/* comment by mhfan */
    .getscl  = hhbf_getscl,
#endif	/* comment by mhfan */
    .udelay  = 80,
    .mdelay  = 0,
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
    *pFIO_DIR      |=  HHBF_I2C_SCLK;		// Set SCLK as output
    *pFIO_POLAR    &= ~HHBF_I2C_SDATA;		// Enable Active Hight
    *pFIO_EDGE     &= ~HHBF_I2C_SDATA;		// Enable Level Sensitivity
    *pFIO_INEN     |=  HHBF_I2C_SDATA;		// Enable SDATA Input Buffer
    *pFIO_DIR      &= ~HHBF_I2C_SDATA; 	// Set SDATA as input/high
#if 0 	/* comment by mhfan */
    *pFIO_DIR      |=  HHBF_I2C_SDATA;
    *pFIO_FLAG_D   |=  HHBF_I2C_SDATA;
#endif	/* comment by mhfan */
    *pFIO_FLAG_D   |=  HHBF_I2C_SCLK;		// Set SCLK high

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
