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
#define BFIN_NAND_READY		(1<<CONFIG_BFIN_NAND_READY)

/*
 * MTD structure for NAND controller
 */
static struct mtd_info *bfin_mtd = NULL;
static void __iomem *p_nand;
static int nand_width = 1; /* default x8*/

#define NB_OF(x)  (sizeof(x)/sizeof(x[0]))

/*
 * Define partitions for flash device
 */
const static struct mtd_partition partition_info[] = {
	{ 
		.name = "linux kernel",
	  	.offset = 0,
	  	.size = 0x400000, 
	},
	{
		.name = "file system",
		.offset = 0x400000,
		.size = 0xC00000,
	}
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
 * bfin_write_byte -  write one byte to the chip
 * @mtd:	MTD device structure
 * @byte:	pointer to data byte to write
 *
 *  write function for 8it buswith
 */
static void bfin_write_byte(struct mtd_info *mtd, u_char byte)
{
	struct nand_chip *this = mtd->priv;
	writeb(byte, this->IO_ADDR_W);
	__builtin_bfin_ssync();
}

/**
 * bfin_read_byte16 -  read one byte endianess aware from the chip
 * @mtd:	MTD device structure
 *
 *  read function for 16bit buswith with 
 * endianess conversion
 */
static u_char bfin_read_byte16(struct mtd_info *mtd)
{
	struct nand_chip *this = mtd->priv;
	u_char ret = (u_char) cpu_to_le16(readw(this->IO_ADDR_R));
	__builtin_bfin_ssync();
	return ret;
}

/**
 * bfin_write_byte16 -  write one byte endianess aware to the chip
 * @mtd:	MTD device structure
 * @byte:	pointer to data byte to write
 *
 *  write function for 16bit buswith with
 * endianess conversion
 */
static void bfin_write_byte16(struct mtd_info *mtd, u_char byte)
{
	struct nand_chip *this = mtd->priv;
	writew(le16_to_cpu((u16) byte), this->IO_ADDR_W);
	__builtin_bfin_ssync();
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
 * bfin_write_word -  write one word to the chip
 * @mtd:	MTD device structure
 * @word:	data word to write
 *
 *  write function for 16bit buswith without 
 * endianess conversion
 */
static void bfin_write_word(struct mtd_info *mtd, u16 word)
{
	struct nand_chip *this = mtd->priv;
	writew(word, this->IO_ADDR_W);
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

	for (i=0; i<len; i++) {
		writeb(buf[i], this->IO_ADDR_W);
		__builtin_bfin_ssync();
	}
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

	for (i=0; i<len; i++) {
		buf[i] = readb(this->IO_ADDR_R);
		__builtin_bfin_ssync();
	}
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
		__builtin_bfin_ssync();
	}

	return 0;
}

/**
 * bfin_write_buf16 -  write buffer to chip
 * @mtd:	MTD device structure
 * @buf:	data buffer
 * @len:	number of bytes to write
 *
 *  write function for 16bit buswith
 */
static void bfin_write_buf16(struct mtd_info *mtd, const u_char *buf, int len)
{
	int i;
	struct nand_chip *this = mtd->priv;
	u16 *p = (u16 *) buf;
	len >>= 1;
	
	for (i=0; i<len; i++) {
		writew(p[i], this->IO_ADDR_W);
		__builtin_bfin_ssync();
	}
		
}

/**
 * bfin_read_buf16 -  read chip data into buffer 
 * @mtd:	MTD device structure
 * @buf:	buffer to store date
 * @len:	number of bytes to read
 *
 *  read function for 16bit buswith
 */
static void bfin_read_buf16(struct mtd_info *mtd, u_char *buf, int len)
{
	int i;
	struct nand_chip *this = mtd->priv;
	u16 *p = (u16 *) buf;
	len >>= 1;

	for (i=0; i<len; i++) {
		p[i] = readw(this->IO_ADDR_R);
		__builtin_bfin_ssync();
	}
}

/**
 * bfin_verify_buf16 -  Verify chip data against buffer 
 * @mtd:	MTD device structure
 * @buf:	buffer containing the data to compare
 * @len:	number of bytes to compare
 *
 *  verify function for 16bit buswith
 */
static int bfin_verify_buf16(struct mtd_info *mtd, const u_char *buf, int len)
{
	int i;
	struct nand_chip *this = mtd->priv;
	u16 *p = (u16 *) buf;
	len >>= 1;

	for (i=0; i<len; i++) {
		if (p[i] != readw(this->IO_ADDR_R))
			return -EFAULT;
		__builtin_bfin_ssync();
	}
	return 0;
}


static void bfin_hwcontrol(struct mtd_info *mtd, int cmd)
{
	register struct nand_chip *this = mtd->priv;

	switch(cmd){

	case NAND_CTL_SETCLE: this->IO_ADDR_W = p_nand + BFIN_NAND_CLE; break;
	case NAND_CTL_CLRCLE: this->IO_ADDR_W = p_nand; break;

	case NAND_CTL_SETALE: this->IO_ADDR_W = p_nand + BFIN_NAND_ALE; break;
	case NAND_CTL_CLRALE: this->IO_ADDR_W = p_nand; break;
	case NAND_CTL_SETNCE: 
	case NAND_CTL_CLRNCE: break;
	}

	this->IO_ADDR_R = this->IO_ADDR_W;
	
	/* Drain the writebuffer */
	__builtin_bfin_ssync();
}

int bfin_device_ready(struct mtd_info *mtd)
{
	int ret = (*pFIO_FLAG_D & BFIN_NAND_READY) ? 1 : 0 ;
	__builtin_bfin_ssync();
	return ret;
}

/*
 * Main initialization routine
 */
int __init bfin_nand_init (void)
{
	struct nand_chip *this;
	int nb_parts = 0;
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
	
	/* Configure GPIO-BFIN_NAND_READY */
#if defined(CONFIG_BF534)|defined(CONFIG_BF536)|defined(CONFIG_BF537)
	*pPORT_FER   &= ~BFIN_NAND_READY;
#endif
        *pFIO_DIR &= ~BFIN_NAND_READY;
        *pFIO_INEN|=  BFIN_NAND_READY;
	__builtin_bfin_ssync();

	p_nand = ioremap(BFIN_NAND_BASE, 0x1000);

	/* Set address of hardware control function */
	this->hwcontrol = bfin_hwcontrol;
	this->dev_ready = bfin_device_ready;
	/* 30 us command delay time */
	this->chip_delay = 30;		
	this->eccmode = NAND_ECC_SOFT;

	this->options = NAND_NO_AUTOINCR;

	if (!nand_width)
		this->options |= NAND_BUSWIDTH_16;

	this->read_byte = (!nand_width) ? bfin_read_byte16 : bfin_read_byte;
	this->write_byte = (!nand_width) ? bfin_write_byte16 : bfin_write_byte;
	this->write_word = bfin_write_word;
	this->read_word = bfin_read_word;
	this->write_buf = (!nand_width) ? bfin_write_buf16 : bfin_write_buf;
	this->read_buf = (!nand_width) ? bfin_read_buf16 : bfin_read_buf;
	this->verify_buf = (!nand_width) ? bfin_verify_buf16 : bfin_verify_buf;

	/* Scan to find existence of the device */
	if (nand_scan (bfin_mtd, 1)) {
		retval = -ENXIO;
		goto outio;
	}
	nb_parts = NB_OF(partition_info);

	/* Register the partitions */
	add_mtd_partitions(bfin_mtd, partition_info, nb_parts);

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
#ifdef MODULE
static void __exit bfin_cleanup (void)
{
	/* Release resources, unregister device */
	nand_release (bfin_mtd);

	/* Free the MTD device structure */
	kfree (bfin_mtd);

	/* Unmap */
	iounmap ((void *)p_nand);
}
module_exit(bfin_cleanup);
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Aubrey.Li <aubrey.li@analog.com>");
MODULE_DESCRIPTION("NAND flash driver for BF537 STAMP board");
