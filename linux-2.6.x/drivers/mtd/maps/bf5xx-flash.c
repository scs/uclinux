/*
 * Flash memory access on BlackFin BF5xx based devices
 *
 * (C) 2000 Nicolas Pitre <nico@cam.org>
 * (C) 2004 LG Soft India
 *
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <linux/mtd/mtd.h>
#include <linux/mtd/map.h>
#include <linux/mtd/partitions.h>

#include <asm/blackfin.h>
#include <asm/io.h>
#include <asm/unaligned.h>

#ifndef CONFIG_BFIN
#error This is for BlackFin BF5xx boards only
#endif

#define BFIN_FLASH_AMBCTL0VAL	((CONFIG_BFIN_FLASH_BANK_1 << 16) | CONFIG_BFIN_FLASH_BANK_0)
#define BFIN_FLASH_AMBCTL1VAL	((CONFIG_BFIN_FLASH_BANK_3 << 16) | CONFIG_BFIN_FLASH_BANK_2)

struct flash_save {
#if defined(CONFIG_BFIN_SHARED_FLASH_ENET)
    u32 ambctl0;
    u32 ambctl1;
#endif
    unsigned long flags;
} ;

#if defined(CONFIG_BFIN_SHARED_FLASH_ENET)
static inline void switch_to_flash(struct flash_save *save)
{
	local_irq_save(save->flags);

	*pFIO_FLAG_C	= CONFIG_ENET_FLASH_PIN;

	__builtin_bfin_ssync();


	save->ambctl0	= *pEBIU_AMBCTL0;
	save->ambctl1	= *pEBIU_AMBCTL1;
	*pEBIU_AMBCTL0 = BFIN_FLASH_AMBCTL0VAL;
	*pEBIU_AMBCTL1 = BFIN_FLASH_AMBCTL1VAL;
	__builtin_bfin_ssync();
}
#else
static inline void switch_to_flash(struct flash_save *save) {}
#endif

#if defined(CONFIG_BFIN_SHARED_FLASH_ENET)
static inline void switch_back(struct flash_save *save)
{

	*pEBIU_AMBCTL0	= save->ambctl0;
	*pEBIU_AMBCTL1	= save->ambctl1;
	__builtin_bfin_ssync();

	*pFIO_FLAG_S	= CONFIG_ENET_FLASH_PIN;

	local_irq_restore(save->flags);
}
#else
static inline void switch_back(struct flash_save *save) {}
#endif

#if defined(CONFIG_BFIN_SHARED_FLASH_ENET)
static inline void setup_pfpins(void)
{
	*pFIO_INEN		&= ~CONFIG_ENET_FLASH_PIN;
	*pFIO_DIR 		|=  CONFIG_ENET_FLASH_PIN;
}
#else
static inline void setup_pfpins(void) {}
#endif


static map_word bf5xx_read(struct map_info *map, unsigned long ofs)
{
	int nValue = 0x0;
	map_word test;

	struct flash_save save;

	switch_to_flash(&save);
	__builtin_bfin_ssync();
        nValue = readw(CONFIG_EBIU_FLASH_BASE + ofs);
	__builtin_bfin_ssync();
	switch_back(&save);


	test.x[0]=(__u16)nValue;
	return test;
}

static void bf5xx_copy_from(struct map_info *map, void *to, unsigned long from, ssize_t len)
{
	unsigned long i;
	map_word test;


  if( (unsigned long)to & 0x1 )
	  {
	   for (i = 0; i < len/2*2; i += 2)
		{
			test = bf5xx_read(map,from+i);
			put_unaligned(test.x[0], (__le16 *) (to + i));
		}
	  }
	   else
	  {
	   for (i = 0; i < len/2*2; i += 2)
	 	{
			test = bf5xx_read(map,from+i);
			*((u16*)(to + i)) = test.x[0];
		}
	  }

	if (len & 0x01) {

		test = bf5xx_read(map, from + i);
		*((u8*)(to + i)) = (u8)test.x[0];
	}
}

static void bf5xx_write(struct map_info *map, map_word d1, unsigned long ofs)
{

	__u16 d;
	struct flash_save save;

	d = (__u16)d1.x[0];

	switch_to_flash(&save);

		__builtin_bfin_ssync();
		  writew(d, CONFIG_EBIU_FLASH_BASE + ofs);
		__builtin_bfin_ssync();

	switch_back(&save);

}

static void bf5xx_copy_to(struct map_info *map, unsigned long to, const void *from, ssize_t len)
{

	struct flash_save save;

	switch_to_flash(&save);

      memcpy((void *)(CONFIG_EBIU_FLASH_BASE + to), from, len);

	switch_back(&save);
}

static struct map_info bf5xx_map = {
	name:    	"BF5xx flash",
	0x400000,
	0x20000000,
	0x20000000,
	NULL,
	read:		bf5xx_read,
	copy_from:	bf5xx_copy_from,
	write:		bf5xx_write,
	copy_to:	bf5xx_copy_to
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


static unsigned long bf5xx_max_flash_size = CONFIG_BFIN_FLASH_SIZE;

static struct mtd_partition bf5xx_partitions[] = {
	{
		name: "Bootloader",
		size: 0x40000,
		//size: 0x3FFFF,
		offset: 0,
	},{
		name: "Kernel",
		size: 0xC0000,
		//size: 0xBFFFF,
		offset: 0x40000,
	},
#ifdef CONFIG_BF537
	{
		name: "JFFS2",
		size: 0x2f0000,
		//size: 0x2effff,
		offset: 0x100000,
	}
#else
	{
                name: "JFFS2",
                size: 0x300000,
                //size: 0x2fffff,
                offset: 0x100000,
        }
#endif
};

#define NB_OF(x)  (sizeof(x)/sizeof(x[0]))


static struct mtd_info *mymtd;

int __init bf5xx_mtd_init(void)
{
	struct mtd_partition *parts;
	int nb_parts = 0;
	char *part_type;

	bf5xx_map.bankwidth = 2;
	bf5xx_map.size = bf5xx_max_flash_size;

	setup_pfpins();

	printk(KERN_NOTICE "BF5xx flash: probing %d-bit flash bus\n", bf5xx_map.bankwidth*8);
	mymtd = do_map_probe("stm_flash", &bf5xx_map);
	if (!mymtd)
		return -ENXIO;

	/*
	 * Static partition definition selection
	 */
	part_type = "static";
#ifdef CONFIG_BFIN
	parts = bf5xx_partitions;
	nb_parts = NB_OF(bf5xx_partitions);
#endif

	if (nb_parts == 0) {
		printk(KERN_NOTICE "BF5xx flash: no partition info available, registering whole flash at once\n");
		add_mtd_device(mymtd);
	} else {
		printk(KERN_NOTICE "Using %s partition definition\n", part_type);
		add_mtd_partitions(mymtd, parts, nb_parts);
	}
	return 0;
}

static void __exit bf5xx_mtd_cleanup(void)
{
	if (mymtd) {
		del_mtd_partitions(mymtd);
		map_destroy(mymtd);
	}
}

module_init(bf5xx_mtd_init);
module_exit(bf5xx_mtd_cleanup);

MODULE_LICENSE("GPL");
