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
#include <linux/interrupt.h>
#include <linux/delay.h>
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
static void (*bf5xx_write_byte)(struct mtd_info *, u_char);

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

	for (i = 0; i < len; i++) {
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

	for (i = 0; i < len; i++) {
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

	for (i = 0; i < len; i++) {
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

	for (i = 0; i < len; i++) {
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

	for (i = 0; i < len; i++) {
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

	for (i = 0; i < len; i++) {
		if (p[i] != readw(this->IO_ADDR_R))
			return -EFAULT;
		__builtin_bfin_ssync();
	}
	return 0;
}

/* Select the chip by setting nCE to low */
#define NAND_CTL_SETNCE         1
/* Deselect the chip by setting nCE to high */
#define NAND_CTL_CLRNCE         2
/* Select the command latch by setting CLE to high */
#define NAND_CTL_SETCLE         3
/* Deselect the command latch by setting CLE to low */
#define NAND_CTL_CLRCLE         4
/* Select the address latch by setting ALE to high */
#define NAND_CTL_SETALE         5
/* Deselect the address latch by setting ALE to low */
#define NAND_CTL_CLRALE         6

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
	int ret = (bfin_read_FIO_FLAG_D() & BFIN_NAND_READY) ? 1 : 0 ;
	return ret;
}

/**
 * bfin_select_chip - control -CE line
 *	Forbid driving -CE manually permitting the NAND controller to do this.
 *	Keeping -CE asserted during the whole sector reads interferes with the
 *	NOR flash and PCMCIA drivers as it causes contention on the static bus.
 *	We only have to hold -CE low for the NAND read commands since the flash
 *	chip needs it to be asserted during chip not ready time but the NAND
 *	controller keeps it released.
 *
 * @mtd:	MTD device structure
 * @chip:	chipnumber to select, -1 for deselect
 */
static void bfin_select_chip(struct mtd_info *mtd, int chip)
{
}

/**
 * bfin_command - Send command to NAND device
 * @mtd:	MTD device structure
 * @command:	the command to be sent
 * @column:	the column address for this command, -1 if none
 * @page_addr:	the page address for this command, -1 if none
 */
static void bfin_command(struct mtd_info *mtd, unsigned command, int column, int page_addr)
{
	register struct nand_chip *this = mtd->priv;
	int ce_override = 0, i;
	ulong flags = 0;

	/* Begin command latch cycle */
	bfin_hwcontrol(mtd, NAND_CTL_SETCLE);
	/*
	 * Write out the command to the device.
	 */
	if (command == NAND_CMD_SEQIN) {
		int readcmd;

		if (column >= mtd->writesize) {
			/* OOB area */
			column -= mtd->writesize;
			readcmd = NAND_CMD_READOOB;
		} else if (column < 256) {
			/* First 256 bytes --> READ0 */
			readcmd = NAND_CMD_READ0;
		} else {
			column -= 256;
			readcmd = NAND_CMD_READ1;
		}
		bf5xx_write_byte(mtd, readcmd);
	}
	bf5xx_write_byte(mtd, command);

	/* Set ALE and clear CLE to start address cycle */
	bfin_hwcontrol(mtd, NAND_CTL_CLRCLE);

	if (column != -1 || page_addr != -1) {
		bfin_hwcontrol(mtd, NAND_CTL_SETALE);

		/* Serially input address */
		if (column != -1) {
			/* Adjust columns for 16 bit buswidth */
			if (this->options & NAND_BUSWIDTH_16)
				column >>= 1;
			bf5xx_write_byte(mtd, column);
		}
		if (page_addr != -1) {
			bf5xx_write_byte(mtd, (u8)(page_addr & 0xff));

			if (command == NAND_CMD_READ0 ||
			    command == NAND_CMD_READ1 ||
			    command == NAND_CMD_READOOB) {
				/*
				 * NAND controller will release -CE after
				 * the last address byte is written, so we'll
				 * have to forcibly assert it. No interrupts
				 * are allowed while we do this as we don't
				 * want the NOR flash or PCMCIA drivers to
				 * steal our precious bytes of data...
				 */
				ce_override = 1;
				local_irq_save(flags);
				bfin_hwcontrol(mtd, NAND_CTL_SETNCE);
			}

			bf5xx_write_byte(mtd, (u8)(page_addr >> 8));

			/* One more address cycle for devices > 32MiB */
			if (this->chipsize > (32 << 20))
				bf5xx_write_byte(mtd, (u8)((page_addr >> 16) & 0x0f));
		}
		/* Latch in address */
		bfin_hwcontrol(mtd, NAND_CTL_CLRALE);
	}

	/*
	 * Program and erase have their own busy handlers.
	 * Status and sequential in need no delay.
	 */
	switch (command) {

	case NAND_CMD_PAGEPROG:
	case NAND_CMD_ERASE1:
	case NAND_CMD_ERASE2:
	case NAND_CMD_SEQIN:
	case NAND_CMD_STATUS:
		return;

	case NAND_CMD_RESET:
		break;

	case NAND_CMD_READ0:
	case NAND_CMD_READ1:
	case NAND_CMD_READOOB:
		/* Check if we're really driving -CE low (just in case) */
		if (unlikely(!ce_override))
			break;

		/* Apply a short delay always to ensure that we do wait tWB. */
		ndelay(100);
		/* Wait for a chip to become ready... */
		for (i = this->chip_delay; !this->dev_ready(mtd) && i > 0; --i)
			udelay(1);

		/* Release -CE and re-enable interrupts. */
		bfin_hwcontrol(mtd, NAND_CTL_CLRNCE);
		local_irq_restore(flags);
		return;
	}
	/* Apply this short delay always to ensure that we do wait tWB. */
	ndelay(100);

	while(!this->dev_ready(mtd));
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
	memset(bfin_mtd, 0, sizeof(struct mtd_info));
	memset(this, 0, sizeof(struct nand_chip));

	/* Link the private data with the MTD structure */
	bfin_mtd->priv = this;
	bfin_mtd->owner = THIS_MODULE;
	
	/* Configure GPIO-BFIN_NAND_READY */
#if defined(CONFIG_BF534) || defined(CONFIG_BF536) || defined(CONFIG_BF537)
	bfin_write_PORT_FER(bfin_read_PORT_FER() & ~BFIN_NAND_READY);
#endif
        bfin_write_FIO_DIR(bfin_read_FIO_DIR() & ~BFIN_NAND_READY);
        bfin_write_FIO_INEN(bfin_read_FIO_INEN() | BFIN_NAND_READY);
	__builtin_bfin_ssync();

	p_nand = ioremap(BFIN_NAND_BASE, 0x1000);

	/* Set address of hardware control function */
	this->dev_ready = bfin_device_ready;
	this->select_chip = bfin_select_chip;
	this->cmdfunc = bfin_command;

	/* 30 us command delay time */
	this->chip_delay = 30;
	this->ecc.mode = NAND_ECC_SOFT;

	this->options = NAND_NO_AUTOINCR;

	if (!nand_width)
		this->options |= NAND_BUSWIDTH_16;

	this->read_byte = (!nand_width) ? bfin_read_byte16 : bfin_read_byte;
	bf5xx_write_byte = (!nand_width) ? bfin_write_byte16 : bfin_write_byte;
	this->read_word = bfin_read_word;
	this->write_buf = (!nand_width) ? bfin_write_buf16 : bfin_write_buf;
	this->read_buf = (!nand_width) ? bfin_read_buf16 : bfin_read_buf;
	this->verify_buf = (!nand_width) ? bfin_verify_buf16 : bfin_verify_buf;

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
