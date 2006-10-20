/*
 * $Id$
 *
 * drivers/mtd/maps/ezkit561.c
 *
 * FLASH map for the ADI BF561 EZ-KIT
 *
 * Author: Griffin Technology, Inc.
 *
 * 2006 (c) Griffin Technology, Inc. This file is licensed under
 * the terms of the GNU General Public License version 2. This program
 * is licensed "as is" without any warranty of any kind, whether express
 * or implied.
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/mtd/mtd.h>
#include <linux/mtd/map.h>
#include <linux/mtd/partitions.h>

#include <asm/io.h>

#if !defined (CONFIG_BFIN) && !defined(CONFIG_BF561)
#warn Intended for use with BF561 ezkit, proceed at your own risk!!!
#endif

// 8 MiB flash wired to ASYNC mem bank 0
#define EZKIT561_FLASH_BASE 0x20000000
#define EZKIT561_FLASH_SIZE 0x00800000

/*
	Flash partition scheme: (default partition map used on blackfin.uclinux.org, modify as needed)
	0x20000000 - 0x2003FFFF (256 KiB) : U-Boot partition
	0x20040000 - 0x200FFFFF (768 KiB) : Linux kernel
	0x20100000 - 0x207FFFFF (7 MiB) : root fs (8 MiB flash)

	Alternate configuration (1MiB for kernel)
	0x20000000 - 0x2003FFFF (256 KiB) : U-Boot partition
	0x20040000 - 0x2013FFFF (1 MiB) : Linux kernel
	0x20140000 - 0x207FFFFF (6.75 MiB) : root fs (8 MiB flash)
*/

#define EZKIT561_PART_COUNT 3

/* First is similar to the bf5xx map, 256KiB u-boot, 768KiB kernel, then 7MiB filesystem */
#if 1
#define EZKIT561_PART0_OFFSET 0x00000000
#define EZKIT561_PART0_SIZE 0x40000
#define EZKIT561_PART1_OFFSET (EZKIT561_PART0_OFFSET + EZKIT561_PART0_SIZE)
#define EZKIT561_PART1_SIZE 0xC0000
#define EZKIT561_PART2_OFFSET (EZKIT561_PART1_OFFSET + EZKIT561_PART1_SIZE)
#define EZKIT561_PART2_SIZE 0x700000
#else /* 256KiB u-boot, 1MiB kernel, 6.75MiB filesystem */
#define EZKIT561_PART0_OFFSET 0x00000000
#define EZKIT561_PART0_SIZE 0x40000
#define EZKIT561_PART1_OFFSET (EZKIT561_PART0_OFFSET + EZKIT561_PART0_SIZE)
#define EZKIT561_PART1_SIZE 0x100000
#define EZKIT561_PART2_OFFSET (EZKIT561_PART1_OFFSET + EZKIT561_PART1_SIZE)
#define EZKIT561_PART2_SIZE 0x6C0000
#endif

static struct mtd_partition ezkit561_parts[] = {
	{
		.name = "Das U-Boot",
		.offset = EZKIT561_PART0_OFFSET,
		.size = EZKIT561_PART0_SIZE,
		.mask_flags = MTD_WRITEABLE	/* disable write access */
	},
	{
		.name = "Linux kernel",
		.offset = EZKIT561_PART1_OFFSET,
		.size = EZKIT561_PART1_SIZE,
		.mask_flags = MTD_WRITEABLE	/* disable at your own peril... */
	},
	{
		.name = "Linux root fs",
		.offset = EZKIT561_PART2_OFFSET,
		.size = EZKIT561_PART2_SIZE,
//		.mask_flags = MTD_WRITEABLE	/* uncomment to force filesystem read-only */
	}
};

struct map_info ezkit561_map = {
	.name = "BF561 EZKIT Map",
	.phys = EZKIT561_FLASH_BASE,
	.size = EZKIT561_FLASH_SIZE,
	.bankwidth = 2,  // 16 bit
};

static struct mtd_info *ezkit561_mtd;

int __init init_ezkit561_flash(void)
{
	printk(KERN_NOTICE "ezkit561 map: mapping %ld MiB flash at 0x%x\n", EZKIT561_FLASH_SIZE/0x100000, EZKIT561_FLASH_BASE);

	ezkit561_map.virt = ioremap(EZKIT561_FLASH_BASE, EZKIT561_FLASH_SIZE);
	
	if (!ezkit561_map.virt) {
		printk("init_ezkit561_flash: failed to ioremap\n");
		return -EIO;
	}
	simple_map_init(&ezkit561_map);
	
	ezkit561_mtd = do_map_probe("cfi_probe", &ezkit561_map);
	if (ezkit561_mtd) {
		ezkit561_mtd->owner = THIS_MODULE;
		return add_mtd_partitions(ezkit561_mtd, ezkit561_parts, EZKIT561_PART_COUNT);
	}

	return -ENXIO;
}

static void __exit cleanup_ezkit561_flash(void)
{
	if (ezkit561_mtd) {
		del_mtd_partitions(ezkit561_mtd);
		/* moved iounmap after map_destroy - armin */
		map_destroy(ezkit561_mtd);
		iounmap((void *)ezkit561_map.virt);
	}
}

module_init(init_ezkit561_flash);
module_exit(cleanup_ezkit561_flash);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Griffin Technology, Inc");
MODULE_DESCRIPTION("Flash map driver for ADI BF561 EZKIT development boards");
