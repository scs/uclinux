/****************************************************************************/

/*
 *	se4000.c -- MTD map driver for SnapGear SE4000 platform
 *
 *	(C) Copyright 2003,  Greg Ungerer <gerg@snapgear.com>
 */

/****************************************************************************/

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/notifier.h>
#include <linux/init.h>
#include <linux/reboot.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/map.h>
#include <linux/mtd/partitions.h>
#include <linux/mtd/cfi.h>
#include <linux/ioport.h>
#include <asm/io.h>

/****************************************************************************/

static struct map_info se4000_map = {
	.name =		"SnapGear SE4000 Flash",
	.buswidth = 	2,
	.phys =		0x50000000,
	.size =		0x01000000,
};

static struct mtd_partition *parsed_parts;

/****************************************************************************/

#ifdef CONFIG_MTD_CFI_INTELEXT
/*
 * Set the Intel flash back to read mode as MTD may leave it in command mode.
 */

static int se4000_reboot_notifier(
	struct notifier_block *nb,
	unsigned long val,
	void *v)
{
	struct cfi_private *cfi = se4000_map.fldrv_priv;
	int i;
	
	for (i = 0; cfi && i < cfi->numchips; i++)
		cfi_send_gen_cmd(0xff, 0x55, cfi->chips[i].start, &se4000_map,
			cfi, cfi->device_type, NULL);

	return NOTIFY_OK;
}

static struct notifier_block se4000_notifier_block = {
	se4000_reboot_notifier, NULL, 0
};

#endif


/****************************************************************************/

static struct mtd_info *se4000_mtd;
static const char *probes[] = { "RedBoot", NULL };

/****************************************************************************/

static void se4000_exit(void)
{
    if (se4000_mtd) {
	del_mtd_partitions(se4000_mtd);
	map_destroy(se4000_mtd);
    }
    if (se4000_map.virt)
	iounmap((void *)se4000_map.virt);
  
    if (parsed_parts)
	kfree(parsed_parts);

    /* Disable flash write */
    *IXP425_EXP_CS0 &= ~IXP425_FLASH_WRITABLE;
}

/****************************************************************************/

static int __init se4000_init(void)
{
    int res, npart;

    /* Enable flash write */
    *IXP425_EXP_CS0 |= IXP425_FLASH_WRITABLE;

    se4000_map.virt = (unsigned long) ioremap(se4000_map.phys, se4000_map.size);
    if (!se4000_map.virt) {
	printk(KERN_ERR "SE4000: ioremap(%x) failed\n", (int)se4000_map.phys);
	res = -EIO;
	goto Error;
    }

    /* Probe for the CFI complaint chip */
    se4000_mtd = do_map_probe("cfi_probe", &se4000_map);
    if (!se4000_mtd) {
	res = -ENXIO;
	goto Error;
    }
    se4000_mtd->owner = THIS_MODULE;
   
    /* Try to parse RedBoot partitions */
    npart = parse_mtd_partitions(se4000_mtd, probes, &parsed_parts, 0);
    if (npart > 0) {
	/* found "npart" RedBoot partitions */
	res = add_mtd_partitions(se4000_mtd, parsed_parts, npart);
    } else {
	res = -EIO;
    }

    if (res)
	goto Error;

#ifdef CONFIG_MTD_CFI_INTELEXT
	register_reboot_notifier(&se4000_notifier_block);
#endif

    return res;
Error:
    se4000_exit();
    return res;
}

/****************************************************************************/

module_init(se4000_init);
module_exit(se4000_exit);

MODULE_DESCRIPTION("MTD map driver for SnapGear SE4000");

/****************************************************************************/
