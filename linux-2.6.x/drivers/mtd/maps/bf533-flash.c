/*
 * Flash memory access on BlackFin BF533 based devices
 * 
 * (C) 2000 Nicolas Pitre <nico@cam.org>
 * 
 * $Id$
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/mtd/mtd.h>
#include <linux/mtd/map.h>
#include <linux/mtd/partitions.h>

#ifndef CONFIG_EZKIT
#error This is for BlackFin ADDS-BF533-EZLITE boards only
#endif


#define WINDOW_ADDR 0x20000000

#ifndef lo
# define lo(addr)	(addr & 0xFFFF)
#endif
#ifndef hi
# define hi(addr)	(addr >> 16)
#endif


static __u16 bf533_read16(struct map_info *map, unsigned long ofs)
{
	int nValue = 0x0;
	__asm__ __volatile__ (
		"p2.l = 0x0000; \n\t"
		"p2.h = 0x2000; \n\t"
		"r3 = %1; \n\t"
		"r2 = p2; \n\t"
		"r2 = r2 + r3; \n\t"
		"p2 = r2; \n\t"
		/* The actual thing */
		"ssync; \n\t"
		"%0 = w[p2] (z); \n\t"
		"ssync; \n\t"
		: "=d" (nValue)
		: "d" (ofs));
	return (__u16)nValue;
}

static void bf533_copy_from(struct map_info *map, void *to, unsigned long from, ssize_t len)
{
	unsigned long i;

	for (i = 0; i < len; i += 2)
		*((u16*)(to + i)) = bf533_read16(map, from + i);
	if (len & 0x01)
		*((u8*)(to + (i-1))) = (u8)(bf533_read16(map, from + i) >> 8);
}

static void bf533_write16(struct map_info *map, __u16 d, unsigned long ofs)
{
	__asm__ __volatile__ (
		"p2.l = 0x0000; \n\t"
		"p2.h = 0x2000; \n\t"
		"r3 = %1; \n\t"
		"r2 = p2; \n\t"
		"r2 = r2 + r3; \n\t"
		"p2 = r2; \n\t"
		/* The actual thing */
		"ssync; \n\t"
		"w[p2] = %0; \n\t"
		"ssync; \n\t"
		: 
		: "d" (d), "d" (ofs));
#if 0
		long addr;
	
        	addr = 0x20000000 + ofs;
        	asm("ssync;");
        	*(unsigned volatile short *) addr = d;
        	asm("ssync;");
        	printk("");     /* FIXME */
#endif

}

static void bf533_copy_to(struct map_info *map, unsigned long to, const void *from, ssize_t len)
{
	memcpy((void *)(WINDOW_ADDR + to), from, len);
}


static struct map_info bf533_map = {
	name:    	"BF533 flash",
	read8:		NULL,
	read16:		bf533_read16,
	read32:		NULL,
	copy_from:	bf533_copy_from,
	write8:		NULL,
	write16:	bf533_write16,
	write32: 	NULL,
	copy_to:	bf533_copy_to
};


/*
 * Here are partition information for all known BlackFin-based devices.
 * See include/linux/mtd/partitions.h for definition of the mtd_partition
 * structure.
 * 
 * The *_max_flash_size is the maximum possible mapped flash size which
 * is not necessarily the actual flash size.  It must correspond to the 
 * value specified in the mapping definition defined by the
 * "struct map_desc *_io_desc" for the corresponding machine.
 */

static unsigned long bf533_max_flash_size = 0x00200000;

static struct mtd_partition bf533_partitions[] = {
	{
		name: "bootloader",
		size: 0x00010000,
		offset: 0,
		mask_flags: MTD_CAP_ROM
	},{
		name: "kernel image",
		/*size: MTDPART_SIZ_FULL,*/
		size: 0x80000,
		offset: MTDPART_OFS_APPEND
	}
};



#define NB_OF(x)  (sizeof(x)/sizeof(x[0]))


static struct mtd_info *mymtd;

int __init bf533_mtd_init(void)
{
	struct mtd_partition *parts;
	int nb_parts = 0;
	char *part_type;

	bf533_map.buswidth = 2;
	bf533_map.size = bf533_max_flash_size;

	printk(KERN_NOTICE "BF533 flash: probing %d-bit flash bus\n", bf533_map.buswidth*8);
	mymtd = do_map_probe("stm_flash", &bf533_map);
	if (!mymtd)
		return -ENXIO;
/*	mymtd->module = THIS_MODULE;*/

	/*
	 * Static partition definition selection
	 */
	part_type = "static";
#ifdef CONFIG_EZKIT
	parts = bf533_partitions;
	nb_parts = NB_OF(bf533_partitions);
#endif

	if (nb_parts == 0) {
		printk(KERN_NOTICE "BF533 flash: no partition info available, registering whole flash at once\n");
		add_mtd_device(mymtd);
	} else {
		printk(KERN_NOTICE "Using %s partition definition\n", part_type);
		add_mtd_partitions(mymtd, parts, nb_parts);
	}
	return 0;
}

static void __exit bf533_mtd_cleanup(void)
{
	if (mymtd) {
		del_mtd_partitions(mymtd);
		map_destroy(mymtd);
	}
}

module_init(bf533_mtd_init);
module_exit(bf533_mtd_cleanup);
