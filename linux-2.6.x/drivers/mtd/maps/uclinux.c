/****************************************************************************/

/*
 *	uclinux.c -- generic memory mapped MTD driver for uclinux
 *
 *	(C) Copyright 2002, Greg Ungerer (gerg@snapgear.com)
 *
 * 	$Id$
 */

/****************************************************************************/

#include <linux/config.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/major.h>
#include <linux/root_dev.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/map.h>
#include <linux/mtd/partitions.h>
#include <asm/io.h>

/****************************************************************************/


/****************************************************************************/

struct map_info uclinux_ram_map = {
	.name = "RAM",
};

struct mtd_info *uclinux_ram_mtdinfo;

/****************************************************************************/

struct mtd_partition uclinux_romfs[] = {
	{
#if defined CONFIG_EXT2_FS	
	.name = "EXT2fs",
#elif defined  CONFIG_EXT3_FS
	.name = "EXT3fs",
#elif defined  CONFIG_ROMFS_FS
	.name = "ROMfs" ,
#elif defined  CONFIG_CRAMFS
	.name = "CRAMfs", 
#elif defined CONFIG_JFFS2_FS
	.name = "JFFS2fs",
#endif

	}
};

#define	NUM_PARTITIONS	(sizeof(uclinux_romfs) / sizeof(uclinux_romfs[0]))

/****************************************************************************/

int uclinux_point(struct mtd_info *mtd, loff_t from, size_t len,
	size_t *retlen, u_char **mtdbuf)
{
	struct map_info *map = mtd->priv;
	*mtdbuf = (u_char *) (map->virt + ((int) from));
	*retlen = len;
	return(0);
}

/****************************************************************************/

extern struct mtd_info *mtd_table[];

int __init uclinux_mtd_init(void)
{
	struct mtd_info *mtd, *root = NULL;
	struct map_info *mapp;
	extern char _ebss;
	unsigned long addr = (unsigned long)&_ebss;
	int i;

#ifdef CONFIG_PILOT
	extern char _etext, _sdata, __init_end;
	addr = (unsigned long) (&_etext + (&__init_end - &_sdata));
#endif

	mapp = &uclinux_ram_map;
	mapp->phys = (unsigned long) &_ebss;
	mapp->size = PAGE_ALIGN(*((unsigned long *)(addr + 8)));

#if defined(CONFIG_EXT2_FS) || defined(CONFIG_EXT3_FS)
	mapp->size = *((unsigned long *)(addr + 0x404)) * 1024;
#endif

	mapp->bankwidth = 4;

	printk("uclinux[mtd]: RAM probe address=0x%x size=0x%x\n",
	       	(int) mapp->phys, (int) mapp->size);

	mapp->virt = ioremap_nocache(mapp->phys, mapp->size);

	if (mapp->virt == 0) {
		printk("uclinux[mtd]: ioremap_nocache() failed\n");
		return(-EIO);
	}

	simple_map_init(mapp);

	mtd = do_map_probe("map_ram", mapp);
	if (!mtd) {
		printk("uclinux[mtd]: failed to find a mapping?\n");
		iounmap(mapp->virt);
		return(-ENXIO);
	}
		
	mtd->owner = THIS_MODULE;
	mtd->point = uclinux_point;
	mtd->priv = mapp;
	++mtd->usecount;

	uclinux_ram_mtdinfo = mtd;
#ifdef CONFIG_MTD_PARTITIONS
	i = add_mtd_partitions(mtd, uclinux_romfs, NUM_PARTITIONS);
#else
        i = add_mtd_device(mtd);
#endif
	if (i) {
		printk("uclinux[mtd]: failed to add mtd device\n");
		return i;
	}

	/* That sucks! any other way to find partition we just created? */
	for (i=0; i < MAX_MTD_DEVICES; i++) {
		if (mtd_table[i] && !strcmp(mtd_table[i]->name, uclinux_romfs[0].name)) {
		    root = mtd_table[i];
		}
	}

	if (root) {
		printk("uclinux[mtd%d]: set %s to be root filesystem\n", root->index,
	    		uclinux_romfs[0].name);
		ROOT_DEV = MKDEV(MTD_BLOCK_MAJOR, root->index);
	} else {
	    /* fault ?? */
	}

	return(0);
}

/****************************************************************************/

void __exit uclinux_mtd_cleanup(void)
{
	if (uclinux_ram_mtdinfo) {
#ifdef CONFIG_MTD_PARTITIONS
		del_mtd_partitions(uclinux_ram_mtdinfo);
#else
	        del_mtd_device(uclinux_ram_mtdinfo);
#endif
		map_destroy(uclinux_ram_mtdinfo);
		uclinux_ram_mtdinfo = NULL;
	}
	if (uclinux_ram_map.virt) {
		iounmap((void *) uclinux_ram_map.virt);
		uclinux_ram_map.virt = 0;
	}
}

/****************************************************************************/

module_init(uclinux_mtd_init);
module_exit(uclinux_mtd_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Greg Ungerer <gerg@snapgear.com>");
MODULE_DESCRIPTION("Generic RAM based MTD for uClinux");

/****************************************************************************/
