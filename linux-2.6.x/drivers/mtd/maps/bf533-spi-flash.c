/*
 * SPI Flash memory access on BlackFin BF533 based devices
 * 
 * (C) 2005 Aubrey Li <aubrey.li@analog.com>
 * 
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/delay.h>

#include <linux/mtd/mtd.h>
#include <linux/mtd/map.h>
#include <linux/mtd/partitions.h>

#include <asm/blackfin.h>

#ifndef CONFIG_BFIN
#error This is for BlackFin BF533 boards only
#endif

#define	 NUM_SECTORS 	128	/* number of sectors */
#define SECTOR_SIZE		0x10000

#define COMMON_SPI_SETTINGS (SPE|MSTR|CPHA|CPOL) /* Settings to the SPI_CTL */
#define TIMOD01 (0x01)		/*  stes the SPI to work with core instructions */
#define BAUD_RATE_DIVISOR 2
#define SPI_READ            (0x03)  /* Read data from memory */
#define SPI_RDSR            (0x05)  /* Read Status Register */

static void spi_ready(void);
static void spi_setup( const int spi_setting );
static void spi_off(void);
static void spi_read_data(  unsigned long ulStart, long lCount,int *pnData  );

static void spi_setup( const int spi_setting )
{
	
#if defined(CONFIG_BLKFIN_CACHE) || defined(CONFIG_BLKFIN_DCACHE)  
   udelay(CONFIG_CCLK_HZ/50000000);
#endif
	/*sets up the PF2 to be the slave select of the SPI */
	*pSPI_FLG = 0xFB04;
	*pSPI_BAUD = BAUD_RATE_DIVISOR;
	*pSPI_CTL = spi_setting;
	 __builtin_bfin_ssync();
}

static void spi_off(void)
{
	
	*pSPI_CTL = 0x0400;	/* disable SPI*/
	*pSPI_FLG = 0;
	*pSPI_BAUD = 0;
	 __builtin_bfin_ssync();
	udelay(CONFIG_CCLK_HZ/50000000);
	
}

static void spi_ready(void)
{
	unsigned short dummyread;
	while( (*pSPI_STAT&TXS));
	while(!(*pSPI_STAT&SPIF));
	while(!(*pSPI_STAT&RXS));
	dummyread = *pSPI_RDBR;			/* Read dummy to empty the receive register	*/
	
}

static void spi_read_data(  unsigned long ulStart, long lCount,int *pnData  )
{
	unsigned long ShiftValue;
	char *cnData;
	int i;
	int flags;

	cnData = (char *)pnData; /* Pointer cast to be able to increment byte wise */

	local_irq_save(flags);
	/* Start SPI interface	*/
	spi_setup( (COMMON_SPI_SETTINGS|TIMOD01) );

	*pSPI_TDBR = SPI_READ;			/* Send the read command to SPI device */
	 __builtin_bfin_ssync();
	spi_ready();						/* Wait until the instruction has been sent */
	ShiftValue = (ulStart >> 16);	/* Send the highest byte of the 24 bit address at first */
	*pSPI_TDBR = ShiftValue;			/* Send the byte to the SPI device */
	 __builtin_bfin_ssync();
	spi_ready();						/* Wait until the instruction has been sent */
	ShiftValue = (ulStart >> 8);		/* Send the middle byte of the 24 bit address  at second */
	*pSPI_TDBR = ShiftValue;			/* Send the byte to the SPI device	*/
	 __builtin_bfin_ssync();
	spi_ready();						/* Wait until the instruction has been sent */
	*pSPI_TDBR = ulStart;			/* Send the lowest byte of the 24 bit address finally */
	 __builtin_bfin_ssync();
	spi_ready();						/* Wait until the instruction has been sent */


	/* After the SPI device address has been placed on the MOSI pin the data can be
	 received on the MISO pin. */
	for (i=0; i<lCount; i++)
	{
		*pSPI_TDBR = 0;			/* send dummy */
		 __builtin_bfin_ssync();
		while(!(*pSPI_STAT&RXS));
		*cnData++  = *pSPI_RDBR;	/* read */
		
	}
	
	spi_off();					/* Turn off the SPI */
	local_irq_restore(flags);
}
static map_word bf533_read(struct map_info *map, unsigned long ofs)
{
	int nValue = 0x0;
	map_word test;
	spi_read_data(ofs, sizeof(__u16), &nValue);
	test.x[0]=(__u16)nValue;
	return test;	
}

static void bf533_copy_from(struct map_info *map, void *to, unsigned long from, ssize_t len)
{
	spi_read_data(from, len, (int *)to);
}

static void bf533_write(struct map_info *map, map_word d1, unsigned long ofs)
{
	printk(KERN_NOTICE "####################bf533 copy to not implement##################\n");
}

static void bf533_copy_to(struct map_info *map, unsigned long to, const void *from, ssize_t len)
{
	printk(KERN_NOTICE "####################bf533 copy to not implement##################\n");
}

static struct map_info bf533_map = {
	name:    	"BF533 SPI flash",
	0x800000,
	0x0,
	0x0,
	NULL,		
	read:		bf533_read,
	copy_from:	bf533_copy_from,
	write:		bf533_write,
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

static unsigned long bf533_max_flash_size = 0x00800000;

static struct mtd_partition bf533_partitions[] = {
	{
		name: "bootloader",
		size: 0x00040000,
		offset: 0,
		mask_flags: MTD_CAP_ROM
	},{
		name: "kernel",
		size: 0xc0000,
		offset: 0x40000
	},{
		name: "file system", 
		size: 0x300000,
		offset: 0x00100000,
	}	
};

#define NB_OF(x)  (sizeof(x)/sizeof(x[0]))


static struct mtd_info *mymtd;

int __init bf533_mtd_init(void)
{
	struct mtd_partition *parts;
	int nb_parts = 0;
	char *part_type;

	bf533_map.bankwidth = 1;
	bf533_map.size = bf533_max_flash_size;

	printk(KERN_NOTICE "BF533 SPI flash: probing %d-bit flash bus\n", bf533_map.bankwidth*8);
	mymtd = do_map_probe("stm_spi_flash", &bf533_map);
	if (!mymtd)
		return -ENXIO;

	/*
	 * Static partition definition selection
	 */
	part_type = "static";
#ifdef CONFIG_BFIN
	parts = bf533_partitions;
	nb_parts = NB_OF(bf533_partitions);
#endif

	if (nb_parts == 0) {
		printk(KERN_NOTICE "BF533 SPI flash: no partition info available, registering whole flash at once\n");
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
