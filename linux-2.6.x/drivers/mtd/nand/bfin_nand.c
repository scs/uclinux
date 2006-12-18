/*
 * File:         drivers/mtd/nand/bfin_nand.c
 * Based on:     drivers/mtd/nand/au1550nd.c
 * Author:	 Aubrey.Li	<aubrey.li@analog.com>
 *
 * Created:
 * Description:
 *
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright 2004-2005 Analog Devices Inc.
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

#include <linux/slab.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/nand.h>
#include <linux/mtd/partitions.h>

#include <asm/blackfin.h>

#define BFIN_NAND_BASE		CONFIG_BFIN_NAND_BASE
#define BFIN_NAND_CLE           (1<<CONFIG_BFIN_NAND_CLE)	/* Ax -> Command Enable */
#define BFIN_NAND_ALE           (1<<CONFIG_BFIN_NAND_ALE)	/* Ax -> Address Enable */

/*
 * MTD structure for NAND controller
 */
static struct mtd_info *bfin_mtd = NULL;
static void __iomem *p_nand;

/*
 * Define partitions for flash device
 */
const static struct mtd_partition partition_info[] = {
	{
		.name = "linux kernel",
		.offset = 0,
		.size = 0x400000,
	},
#ifdef CONFIG_PNAV10 /* 1G x 8 NAND Flash */
	{
		.name = "file system",
		.offset = 0x400000,
		.size = 0x3FC00000,
	}
#else
	{
		.name = "file system",
		.offset = 0x400000,
		.size = 0xC00000,
	}
#endif
};

/*
 * bfin_read_byte -  read one byte from the chip
 * @mtd:	MTD device structure
 *
 *  read function for 8bit buswith
 */
static u_char bfin_read_byte(struct mtd_info *mtd)
{
	struct nand_chip *this = mtd->priv;
	u_char ret = readb(this->IO_ADDR_R);
	__builtin_bfin_ssync();
	return ret;
}

/**
 * bfin_read_word -  read one word from the chip
 * @mtd:	MTD device structure
 *
 *  read function for 16bit buswith without
 * endianess conversion
 */
static u16 bfin_read_word(struct mtd_info *mtd)
{
	struct nand_chip *this = mtd->priv;
	u16 ret = readw(this->IO_ADDR_R);
	__builtin_bfin_ssync();
	return ret;
}

/**
 * bfin_read_buf -  read chip data into buffer
 * @mtd:	MTD device structure
 * @buf:	buffer to store date
 * @len:	number of bytes to read
 *
 *  read function for 8bit buswith
 */
static void bfin_read_buf(struct mtd_info *mtd, u_char *buf, int len)
{
	int i;
	struct nand_chip *this = mtd->priv;

	for (i=0; i<len; i++)
		buf[i] = readb(this->IO_ADDR_R);
	__builtin_bfin_ssync();
}

/**
 * bfin_write_buf -  write buffer to chip
 * @mtd:	MTD device structure
 * @buf:	data buffer
 * @len:	number of bytes to write
 *
 *  write function for 8bit buswith
 */
static void bfin_write_buf(struct mtd_info *mtd, const u_char *buf, int len)
{
	int i;
	struct nand_chip *this = mtd->priv;

	for (i=0; i<len; i++)
		writeb(buf[i], this->IO_ADDR_W);

	__builtin_bfin_ssync();
}

/**
 * bfin_verify_buf -  Verify chip data against buffer
 * @mtd:	MTD device structure
 * @buf:	buffer containing the data to compare
 * @len:	number of bytes to compare
 *
 *  verify function for 8bit buswith
 */
static int bfin_verify_buf(struct mtd_info *mtd, const u_char *buf, int len)
{
	int i;
	struct nand_chip *this = mtd->priv;

	for (i=0; i<len; i++) {
		if (buf[i] != readb(this->IO_ADDR_R))
			return -EFAULT;
	}
	__builtin_bfin_ssync();

	return 0;
}

static void bfin_hwcontrol(struct mtd_info *mtd, int cmd, unsigned int ctrl)
{
	if (cmd == NAND_CMD_NONE)
                return;

        if (ctrl & NAND_CLE)
                writeb(cmd, p_nand + BFIN_NAND_CLE);
        else
                writeb(cmd, p_nand + BFIN_NAND_ALE);

	__builtin_bfin_ssync();
}

int bfin_device_ready(struct mtd_info *mtd)
{

	return gpio_get_value(CONFIG_BFIN_NAND_READY);

}

/*
 * Main initialization routine
 */
int __init bfin_nand_init (void)
{
	struct nand_chip *this;
	int retval;

	/* Allocate memory for MTD device structure and private data */
	bfin_mtd = kmalloc (sizeof(struct mtd_info) +
			sizeof (struct nand_chip), GFP_KERNEL);
	if (!bfin_mtd) {
		printk ("Unable to allocate NAND MTD dev structure.\n");
		return -ENOMEM;
	}

	/* Get pointer to private data */
	this = (struct nand_chip *) (&bfin_mtd[1]);

	/* Initialize structures */
	memset((char *) bfin_mtd, 0, sizeof(struct mtd_info));
	memset((char *) this, 0, sizeof(struct nand_chip));

	/* Link the private data with the MTD structure */
	bfin_mtd->priv = this;
	bfin_mtd->owner = THIS_MODULE;
	
	/* Configure GPIO-BFIN_NAND_READY */

	if (gpio_request(CONFIG_BFIN_NAND_READY, NULL))
		printk(KERN_ERR"Requesting NAND Ready GPIO %d faild\n",CONFIG_BFIN_NAND_READY);

	gpio_direction_input(CONFIG_BFIN_NAND_READY);

	p_nand = ioremap(BFIN_NAND_BASE, 0x1000);

	/* Set address of hardware control function */
	this->cmd_ctrl = bfin_hwcontrol;
	this->dev_ready = bfin_device_ready;
	/* 30 us command delay time */
	this->chip_delay = 30;		
	this->ecc.mode = NAND_ECC_SOFT;

	this->options = NAND_NO_AUTOINCR;

	this->read_byte = bfin_read_byte;
	this->read_word = bfin_read_word;
	this->write_buf = bfin_write_buf;
	this->read_buf = bfin_read_buf;
	this->verify_buf = bfin_verify_buf;

	this->IO_ADDR_W = p_nand;
	this->IO_ADDR_R = this->IO_ADDR_W;

	/* Scan to find existence of the device */
	if (nand_scan (bfin_mtd, 1)) {
		retval = -ENXIO;
		goto outio;
	}

	/* Register the partitions */
	add_mtd_partitions(bfin_mtd, partition_info, ARRAY_SIZE(partition_info));

	return 0;
 outio:
	iounmap ((void *)p_nand);

	kfree (bfin_mtd);
	return retval;
}

module_init(bfin_nand_init);

/*
 * Clean up routine
 */
static void __exit bfin_cleanup (void)
{
	/* Release resources, unregister device */

	gpio_free(CONFIG_BFIN_NAND_READY);
	nand_release (bfin_mtd);

	/* Free the MTD device structure */
	kfree (bfin_mtd);

	/* Unmap */
	iounmap ((void *)p_nand);
}
module_exit(bfin_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aubrey.Li <aubrey.li@analog.com>");
MODULE_DESCRIPTION("NAND flash driver for BF537 STAMP board");
