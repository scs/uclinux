/*
 * File:         arch/blackfin/kernel/setup.c
 * Based on:
 * Author:
 *
 * Created:
 * Description:
 *
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright 2004-2006 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see the file COPYING, or write
 * to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <linux/delay.h>
#include <linux/console.h>
#include <linux/bootmem.h>
#include <linux/seq_file.h>
#include <linux/cpu.h>
#include <linux/module.h>
#include <linux/console.h>

#include <linux/ext2_fs.h>
#include <linux/cramfs_fs.h>
#include <linux/romfs_fs.h>

#include <asm/cacheflush.h>
#include <asm/blackfin.h>

#ifdef CONFIG_CONSOLE
struct consw *conswitchp;
#ifdef CONFIG_FRAMEBUFFER
struct consw fb_con;
#endif
#endif

unsigned long memory_start;
unsigned long memory_end;
unsigned long memory_mtd_end;
unsigned long memory_mtd_start;
unsigned long _ebss;
unsigned long mtd_phys, mtd_size;
unsigned long physical_mem_end;
unsigned long reserved_mem_dcache_on;
unsigned long reserved_mem_icache_on;

EXPORT_SYMBOL(memory_start);
EXPORT_SYMBOL(memory_end);
EXPORT_SYMBOL(physical_mem_end);
EXPORT_SYMBOL(memory_mtd_end);
EXPORT_SYMBOL(_ramend);
EXPORT_SYMBOL(memory_mtd_start);
EXPORT_SYMBOL(mtd_size);

char command_line[COMMAND_LINE_SIZE];

void init_leds(void);
void bf53x_cache_init(void);
static u_int get_dsp_rev_id(void);
static inline u_int get_compiled_rev_id(void);
static void generate_cpl_tables(void);


void __init bf53x_cache_init(void)
{
	generate_cpl_tables();

#ifdef CONFIG_BLKFIN_CACHE
	bfin_icache_init();
	printk(KERN_INFO "Instruction Cache Enabled\n");
#endif

#ifdef CONFIG_BLKFIN_DCACHE
	bfin_dcache_init();
	printk(KERN_INFO "Data Cache Enabled"
# if defined CONFIG_BLKFIN_WB
		" (write-back)"
# elif defined CONFIG_BLKFIN_WT
		" (write-through)"
# endif
		"\n");
#endif
}

void bf53x_relocate_l1_mem(void)
{
	unsigned long l1_length;

	l1_length = _etext_l1 - _stext_l1;
	if (l1_length > L1_CODE_LENGTH)
		l1_length = L1_CODE_LENGTH;
	/* cannot complain as printk is not available as yet.
	 * But we can continue booting and complain later!
	 */

	/* Copy _stext_l1 to _etext_l1 to L1 instruction SRAM */
	dma_memcpy(_stext_l1, _l1_lma_start, l1_length);

	l1_length = _ebss_l1 - _sdata_l1;
	if (l1_length > L1_DATA_A_LENGTH)
		l1_length = L1_DATA_A_LENGTH;

	/* Copy _sdata_l1 to _ebss_l1 to L1 instruction SRAM */
	dma_memcpy(_sdata_l1, _l1_lma_start + (_etext_l1 - _stext_l1),l1_length);

}

/*
 * Initial parsing of the command line.  Currently, we support:
 *  - Controlling the linux memory size: mem=xxx[KMG]
 *  - Controlling the physical memory size: max_mem=xxx[KMG][$][#]
 *       $ -> reserved memory is dcacheable
 *       # -> reserved memory is icacheable
 */
static __init void parse_cmdline_early(char *cmdline_p)
{
	char c = ' ', *to = cmdline_p;
	unsigned int memsize;
	for (;;) {
		if (c == ' ') {

			if (!memcmp(to, "mem=", 4)) {
				to += 4;
				memsize = memparse(to, &to);
				if (memsize)
					_ramend = memsize;

			} else if (!memcmp(to, "max_mem=", 8)) {
				to += 8;
				memsize = memparse(to, &to);
				if (memsize) {
					physical_mem_end = memsize;
					if (*to != ' ') {
						if (*to == '$' || *(to+1) == '$')
							reserved_mem_dcache_on = 1;
						if (*to == '#' || *(to+1) == '#')
							reserved_mem_icache_on = 1;
					}
				}
			}

		}
		c = *(to++);
		if (!c)
			break;
	}
}

void __init setup_arch(char **cmdline_p)
{
	int bootmap_size, id;
	unsigned long l1_length,sclk,cclk;

	cclk = get_cclk();
	sclk = get_sclk();

#if !defined(CONFIG_BFIN_KERNEL_CLOCK) && defined(ANOMALY_05000273)
	if (cclk == sclk)
		panic("ANOMALY 05000273, SCLK can not be same as CCLK");
#endif

#ifdef DEBUG_SERIAL_EARLY_INIT
	bfin_console_init();	/* early console registration */
	/* this give a chance to get printk() working before crash. */
#endif

#if defined(CONFIG_CHR_DEV_FLASH) || defined(CONFIG_BLK_DEV_FLASH)
	/* we need to initialize the Flashrom device here since we might
	 * do things with flash early on in the boot
	 */
	flash_probe();
#endif
#if defined(CONFIG_BOOTPARAM)
	memset(command_line, 0, sizeof(command_line));
	strncpy(&command_line[0], CONFIG_BOOTPARAM_STRING,
		sizeof(command_line));
	command_line[sizeof(command_line) - 1] = 0;
#endif
	/* Keep a copy of command line */
	*cmdline_p = &command_line[0];
	memcpy(saved_command_line, command_line, COMMAND_LINE_SIZE);
	saved_command_line[COMMAND_LINE_SIZE - 1] = 0;

	/* setup memory defaults from the user config */
	physical_mem_end = 0;
	_ramend = CONFIG_MEM_SIZE * 1024 * 1024;

	parse_cmdline_early(&command_line[0]);

	if (physical_mem_end == 0)
		physical_mem_end = _ramend;

	/* by now the stack is part of the init task */
	memory_end = _ramend - DMA_UNCACHED_REGION;

	memory_mtd_end = memory_end;

#if defined(CONFIG_MTD_UCLINUX)
	/* generic memory mapped MTD driver */
	mtd_phys = (unsigned long)__bss_stop;
	mtd_size = PAGE_ALIGN(*((unsigned long *)(mtd_phys + 8)));

# if defined(CONFIG_EXT2_FS) || defined(CONFIG_EXT3_FS)
	if (*((unsigned short *)(mtd_phys + 0x438)) == EXT2_SUPER_MAGIC)
		mtd_size = PAGE_ALIGN(*((unsigned long *)(mtd_phys + 0x404)) << 10);
# endif

# if defined(CONFIG_CRAMFS)
	if (*((unsigned long *)(mtd_phys)) == CRAMFS_MAGIC)
		mtd_size = PAGE_ALIGN(*((unsigned long *)(mtd_phys + 0x4)) );
# endif
#if defined(CONFIG_ROMFS_FS)
	if (((unsigned long *)mtd_phys)[0] == ROMSB_WORD0
	    && ((unsigned long *)mtd_phys)[1] == ROMSB_WORD1)
		mtd_size = PAGE_ALIGN(be32_to_cpu(((unsigned long *)mtd_phys)[2]));
#endif

	memory_end -= mtd_size;

	/* Relocate MTD image to the top of memory after the uncached memory area */
	dma_memcpy((char *)memory_end, __bss_stop, mtd_size);

	_ramstart = mtd_phys;
#endif

	memory_mtd_start = memory_end;
	_ebss = memory_mtd_start;       /* define _ebss for compatible */
	memory_start = PAGE_ALIGN(_ramstart);

#if (defined(CONFIG_BLKFIN_CACHE) && defined(ANOMALY_05000263))
	/* Due to a Hardware Anomaly we need to limit the size of usable
	 * instruction memory to max 60MB, 56 if HUNT_FOR_ZERO is on
	 * 05000263 - Hardware loop corrupted when taking an ICPLB exception */

#if (defined(CONFIG_DEBUG_HUNT_FOR_ZERO))
	 if (memory_end >= 56 * 1024 * 1024)
		memory_end = 56 * 1024 * 1024;
#else
	if (memory_end >= 60 * 1024 * 1024)
		memory_end = 60 * 1024 * 1024;
#endif

#endif

	init_mm.start_code = (unsigned long)_stext;
	init_mm.end_code = (unsigned long)_etext;
	init_mm.end_data = (unsigned long)_edata;
	init_mm.brk = (unsigned long)0;

	init_leds();
	id = get_dsp_rev_id();

	printk(KERN_INFO "Blackfin support (C) 2004-2006 Analog Devices, Inc.\n");
	printk(KERN_INFO "Compiled for ADSP-%s Rev. 0.%d\n", CPU, get_compiled_rev_id());
	if (id != get_compiled_rev_id())
		printk(KERN_ERR
		       "Warning: Compiled for Rev %d, but running on Rev %d\n",
			get_compiled_rev_id(), id );
	if (id < SUPPORTED_DSPID)
		printk(KERN_ERR
		       "Warning: Unsupported Chip Revision ADSP-%s Rev. 0.%d detected\n",
		       CPU, id);
	printk(KERN_INFO "Blackfin uClinux support by http://blackfin.uclinux.org/\n");

	printk(KERN_INFO "Processor Speed: %lu MHz core clock and %lu Mhz System Clock\n",
	       cclk / 1000000,  sclk / 1000000);

#if defined(ANOMALY_05000273)
	if ((cclk >> 1) <= sclk)
		printk(KERN_ERR "\n\n\nANOMALY_05000273: CCLK must be >= 2*SCLK !!!\n\n\n");
#endif

	printk(KERN_INFO "Board Memory: %ldMB\n", physical_mem_end>>20);
	printk(KERN_INFO "Kernel Managed Memory: %ldMB\n", _ramend>>20);

	printk(KERN_INFO "Memory map:\n"
	       KERN_INFO "  text      = 0x%p-0x%p\n"
	       KERN_INFO "  init      = 0x%p-0x%p\n"
	       KERN_INFO "  data      = 0x%p-0x%p\n"
	       KERN_INFO "  stack     = 0x%p-0x%p\n"
	       KERN_INFO "  bss       = 0x%p-0x%p\n"
	       KERN_INFO "  available = 0x%p-0x%p\n"
	       KERN_INFO "  rootfs    = 0x%p-0x%p\n"
#if DMA_UNCACHED_REGION > 0
	       KERN_INFO "  DMA Zone  = 0x%p-0x%p\n"
#endif
	       , _stext, _etext,
	       __init_begin, __init_end,
	       _sdata, _edata,
	       (void*)&init_thread_union, (void*)((int)(&init_thread_union) + 0x2000),
	       __bss_start, __bss_stop,
	       (void*)_ramstart, (void*)memory_end,
	       (void*)memory_mtd_start, (void*)(memory_mtd_start + mtd_size)
#if DMA_UNCACHED_REGION > 0
	       , (void*)(_ramend - DMA_UNCACHED_REGION), (void*)(_ramend)
#endif
	       );

#ifdef CONFIG_CONSOLE
#ifdef CONFIG_FRAMEBUFFER
	conswitchp = &fb_con;
#else
	conswitchp = 0;
#endif
#endif

	/*
	 * give all the memory to the bootmap allocator,  tell it to put the
	 * boot mem_map at the start of memory
	 */
	bootmap_size = init_bootmem_node(NODE_DATA(0), memory_start >> PAGE_SHIFT,	/* map goes here */
					 PAGE_OFFSET >> PAGE_SHIFT,
					 memory_end >> PAGE_SHIFT);
	/*
	 * free the usable memory,  we have to make sure we do not free
	 * the bootmem bitmap so we then reserve it after freeing it :-)
	 */
	free_bootmem(memory_start, memory_end - memory_start);

	reserve_bootmem(memory_start, bootmap_size);
	/*
	 * get kmalloc into gear
	 */
	paging_init();

	/* check the size of the l1 area */
	l1_length = _etext_l1 - _stext_l1;
	if (l1_length > L1_CODE_LENGTH)
		panic("L1 memory overflow\n");

	l1_length = _ebss_l1 - _sdata_l1;
	if (l1_length > L1_DATA_A_LENGTH)
		panic("L1 memory overflow\n");

	bf53x_cache_init();

	printk(KERN_INFO "Hardware Trace Enabled\n");
	bfin_write_TBUFCTL(0x03);
}

#if defined (CONFIG_BF561)
static struct cpu cpu[2];
#else
static struct cpu cpu[1];
#endif
static int __init topology_init(void)
{
#if defined (CONFIG_BF561)
	register_cpu(&cpu[0], 0, NULL);
	register_cpu(&cpu[1], 1, NULL);
	return 0;
#else
	return register_cpu(cpu, 0, NULL);
#endif
}

subsys_initcall(topology_init);

#if defined(CONFIG_BLKFIN_DCACHE) || defined(CONFIG_BLKFIN_CACHE)
static unsigned short __init
fill_cpl_tables(unsigned long *table, unsigned short pos,
		unsigned long start, unsigned long end,
		unsigned long block_size, unsigned long CPLB_data)
{
	int i;

	switch (block_size) {
	case SIZE_4M:
		i = 3;
		break;
	case SIZE_1M:
		i = 2;
		break;
	case SIZE_4K:
		i = 1;
		break;
	case SIZE_1K:
	default:
		i = 0;
		break;
	}

	CPLB_data = (CPLB_data & ~(3 << 16)) | (i << 16);

	while (start < end) {
		table[pos++] = start;
		table[pos++] = CPLB_data;
		start += block_size;
	}
	return pos;
}
#endif

static void __init generate_cpl_tables(void)
{
#if defined(CONFIG_BLKFIN_DCACHE) || defined(CONFIG_BLKFIN_CACHE)
	unsigned long pos, unalign_ram_tmp, physical_mem_aligned_end;

	unalign_ram_tmp = ((_ramend / 1024 / 1024) % 4) * 1024 * 1024;
	if (unalign_ram_tmp == 0)
		physical_mem_aligned_end = _ramend;
	else
		physical_mem_aligned_end = (SIZE_4M - unalign_ram_tmp) + _ramend;
#endif

#ifdef CONFIG_BLKFIN_DCACHE

/* Generarte initial DCPLB table */
	pos = 0;
#ifdef CONFIG_DEBUG_HUNT_FOR_ZERO
	pos =
	    fill_cpl_tables(dcplb_table, pos, 0x0, SIZE_4K, SIZE_4K,
			    SDRAM_OOPS);
#endif
	pos =
	    fill_cpl_tables(dcplb_table, pos, ZERO, SIZE_4M, SIZE_4M,
			    SDRAM_DKERNEL);
#if defined (CONFIG_BF561)
# if defined (CONFIG_BFIN561_EZKIT)
	pos =
	    fill_cpl_tables(dcplb_table, pos, ASYNC_BANK0_BASE,
			    ASYNC_BANK0_BASE + 0x800000,
			    SIZE_4M, SDRAM_EBIU);
	pos =
	    fill_cpl_tables(dcplb_table, pos, ASYNC_BANK3_BASE,
			    ASYNC_BANK3_BASE + 0x400000,
			    SIZE_4M, SDRAM_EBIU);

# else
//#  error "Check the CPLB entries for your BF561 platform in arch/blackfin/kernel/setup.c"
# endif
#else
	pos =
	    fill_cpl_tables(dcplb_table, pos, ASYNC_BANK0_BASE,
			    ASYNC_BANK3_BASE + ASYNC_BANK3_SIZE,
			    SIZE_4M, SDRAM_EBIU);
#endif
	pos =
	    fill_cpl_tables(dcplb_table, pos, _ramend - SIZE_1M, _ramend,
			    SIZE_1M, SDRAM_DNON_CHBL);

	if (unalign_ram_tmp == 0) {
		pos =
			fill_cpl_tables(dcplb_table, pos, _ramend - SIZE_4M,
					_ramend - SIZE_1M, SIZE_1M, SDRAM_DGENERIC);
		pos =
			fill_cpl_tables(dcplb_table, pos, SIZE_4M,
					min((SIZE_4M + (16 - pos / 2) * SIZE_4M),
					    _ramend - SIZE_4M), SIZE_4M, SDRAM_DGENERIC);
	} else {
		pos =
			fill_cpl_tables(dcplb_table, pos, _ramend - unalign_ram_tmp,
					_ramend - SIZE_1M, SIZE_1M, SDRAM_DGENERIC);
		pos =
			fill_cpl_tables(dcplb_table, pos, SIZE_4M,
					min((SIZE_4M + (16 - pos / 2) * SIZE_4M),
					    _ramend - unalign_ram_tmp), SIZE_4M, SDRAM_DGENERIC);
	}

	if (physical_mem_end > _ramend) {
		if (reserved_mem_dcache_on) {
			pos = fill_cpl_tables(dcplb_table, pos, _ramend,
					      physical_mem_aligned_end, SIZE_1M, SDRAM_DGENERIC);
			pos = fill_cpl_tables(dcplb_table, pos, physical_mem_aligned_end,
					      physical_mem_end, SIZE_4M, SDRAM_DGENERIC);
		} else {
			pos = fill_cpl_tables(dcplb_table, pos, _ramend,
					      physical_mem_aligned_end, SIZE_1M, SDRAM_DNON_CHBL);
			pos = fill_cpl_tables(dcplb_table, pos, physical_mem_aligned_end,
					      physical_mem_end, SIZE_4M, SDRAM_DNON_CHBL);
		}
	}

	while (pos < 32)
		dcplb_table[pos++] = 0;

	*(dcplb_table + pos) = -1;

/* Generarte DCPLB switch table */
	pos = 0;
	pos =
	    fill_cpl_tables(dpdt_table, pos, ZERO, SIZE_4M, SIZE_4M,
			    SDRAM_DKERNEL);

	if (unalign_ram_tmp == 0) {
		pos =
		    fill_cpl_tables(dpdt_table, pos, SIZE_4M, _ramend - SIZE_4M,
				    SIZE_4M, SDRAM_DGENERIC);
		pos =
		    fill_cpl_tables(dpdt_table, pos, _ramend - SIZE_4M,
				    _ramend - SIZE_1M, SIZE_1M, SDRAM_DGENERIC);
	} else {
		pos =
		    fill_cpl_tables(dpdt_table, pos, SIZE_4M, _ramend - unalign_ram_tmp,
				    SIZE_4M, SDRAM_DGENERIC);
		pos =
		    fill_cpl_tables(dpdt_table, pos, _ramend - unalign_ram_tmp,
				    _ramend - SIZE_1M, SIZE_1M, SDRAM_DGENERIC);
	}
/*TODO: Make mtd none cachable in L1 */
	pos =
	    fill_cpl_tables(dpdt_table, pos, _ramend - SIZE_1M, _ramend,
			    SIZE_1M, SDRAM_DNON_CHBL);

	if (physical_mem_end > _ramend) {
		if (reserved_mem_dcache_on) {
			pos = fill_cpl_tables(dpdt_table, pos, _ramend,
					      physical_mem_aligned_end, SIZE_1M, SDRAM_DGENERIC);
			pos = fill_cpl_tables(dpdt_table, pos, physical_mem_aligned_end,
					      physical_mem_end, SIZE_4M, SDRAM_DGENERIC);
		} else {
			pos = fill_cpl_tables(dpdt_table, pos, _ramend,
					      physical_mem_aligned_end, SIZE_1M, SDRAM_DNON_CHBL);
			pos = fill_cpl_tables(dpdt_table, pos, physical_mem_aligned_end,
					      physical_mem_end, SIZE_4M, SDRAM_DNON_CHBL);
		}
	}


#if defined (CONFIG_BF561)
# if defined (CONFIG_BFIN561_EZKIT) || defined (CONFIG_BFIN561_BLUETECHNIX_CM)
# if defined (CONFIG_BFIN561_EZKIT)
	pos =
	    fill_cpl_tables(dpdt_table, pos, ASYNC_BANK0_BASE,
			    ASYNC_BANK0_BASE + 0x800000,
			    SIZE_4M, SDRAM_EBIU);
	pos =
	    fill_cpl_tables(dpdt_table, pos, ASYNC_BANK3_BASE,
			    ASYNC_BANK3_BASE + 0x400000,
			    SIZE_4M, SDRAM_EBIU);
#endif
#if defined (CONFIG_BFIN561_BLUETECHNIX_CM)
	pos =
	    fill_cpl_tables(dpdt_table, pos, ASYNC_BANK0_BASE,
			    ASYNC_BANK0_BASE + SIZE_4M,
			    SIZE_4M, SDRAM_EBIU);
	pos =
	    fill_cpl_tables(dpdt_table, pos, ASYNC_BANK1_BASE,
			    ASYNC_BANK1_BASE + SIZE_4M,
			    SIZE_4M, SDRAM_EBIU);
	pos =
	    fill_cpl_tables(dpdt_table, pos, ASYNC_BANK2_BASE,
			    ASYNC_BANK2_BASE + SIZE_4M,
			    SIZE_4M, SDRAM_EBIU);
#endif
# else
#  error "Check the CPLB entries for your BF561 platform in arch/blackfin/kernel/setup.c"
# endif
#else
	pos =
	    fill_cpl_tables(dpdt_table, pos, ASYNC_BANK0_BASE,
			    ASYNC_BANK3_BASE + ASYNC_BANK3_SIZE,
			    SIZE_4M, SDRAM_EBIU);
#endif
	pos =
	    fill_cpl_tables(dpdt_table, pos, L1_DATA_A_START,
			    L1_DATA_B_START + L1_DATA_B_LENGTH, SIZE_4M,
			    L1_DMEMORY);

#if defined (CONFIG_BF561)
	pos =
	    fill_cpl_tables(dpdt_table, pos, L2_SRAM,
			    L2_SRAM_END, SIZE_1M, L2_MEMORY);
#endif
#if defined (CONFIG_BF561)
	pos =
	    fill_cpl_tables(dpdt_table, pos, L2_SRAM,
			    L2_SRAM_END, SIZE_1M, L2_MEMORY);
#endif
	*(dpdt_table + pos) = -1;
#endif

#ifdef CONFIG_BLKFIN_CACHE

/* Generarte initial ICPLB table */
	pos = 0;
	pos =
	    fill_cpl_tables(icplb_table, pos, L1_CODE_START,
			    L1_CODE_START + SIZE_1M, SIZE_1M, L1_IMEMORY);
#ifdef CONFIG_DEBUG_HUNT_FOR_ZERO
	pos =
	    fill_cpl_tables(icplb_table, pos, 0x0, SIZE_4K, SIZE_4K,
			    SDRAM_OOPS);
#endif
	pos =
	    fill_cpl_tables(icplb_table, pos, ZERO, SIZE_4M, SIZE_4M,
			    SDRAM_IKERNEL);
	pos =
	    fill_cpl_tables(icplb_table, pos, SIZE_4M,
			    min(SIZE_4M + (16 - pos / 2) * SIZE_4M, _ramend - unalign_ram_tmp),
			    SIZE_4M, SDRAM_IGENERIC);
	pos =
	    fill_cpl_tables(icplb_table, pos, _ramend - unalign_ram_tmp, _ramend,
			    SIZE_1M, SDRAM_IGENERIC);

	if (physical_mem_end > _ramend) {
		if (reserved_mem_icache_on) {
			pos = fill_cpl_tables(icplb_table, pos, _ramend,
					      physical_mem_aligned_end, SIZE_1M, SDRAM_IGENERIC);
			pos = fill_cpl_tables(icplb_table, pos, physical_mem_aligned_end,
					      physical_mem_end, SIZE_4M, SDRAM_IGENERIC);
		} else {
			pos = fill_cpl_tables(icplb_table, pos, _ramend,
					      physical_mem_aligned_end, SIZE_1M, SDRAM_INON_CHBL);
			pos = fill_cpl_tables(icplb_table, pos, physical_mem_aligned_end,
					      physical_mem_end, SIZE_4M, SDRAM_INON_CHBL);
		}
	}

	while (pos < 32)
		icplb_table[pos++] = 0;

	*(icplb_table + pos) = -1;

/* Generarte ICPLB switch table */
	pos = 0;

	pos =
	    fill_cpl_tables(ipdt_table, pos, ZERO, SIZE_4M, SIZE_4M,
			    SDRAM_IKERNEL);
	pos =
	    fill_cpl_tables(ipdt_table, pos, SIZE_4M, _ramend - unalign_ram_tmp,
			    SIZE_4M, SDRAM_IGENERIC);
	pos =
	    fill_cpl_tables(ipdt_table, pos, _ramend - unalign_ram_tmp, _ramend,
			    SIZE_1M, SDRAM_IGENERIC);

	if (physical_mem_end > _ramend) {
		if (reserved_mem_icache_on) {
			pos = fill_cpl_tables(ipdt_table, pos, _ramend,
					      physical_mem_aligned_end, SIZE_1M, SDRAM_IGENERIC);
			pos = fill_cpl_tables(ipdt_table, pos, physical_mem_aligned_end,
					      physical_mem_end, SIZE_4M, SDRAM_IGENERIC);
		} else {
			pos = fill_cpl_tables(ipdt_table, pos, _ramend,
					      physical_mem_aligned_end, SIZE_1M, SDRAM_INON_CHBL);
			pos = fill_cpl_tables(ipdt_table, pos, physical_mem_aligned_end,
					      physical_mem_end, SIZE_4M, SDRAM_INON_CHBL);
		}
	}

#if defined (CONFIG_BF561)
# if defined (CONFIG_BFIN561_EZKIT) || defined (CONFIG_BFIN561_BLUETECHNIX_CM)
# if defined (CONFIG_BFIN561_EZKIT)
	pos =
	    fill_cpl_tables(ipdt_table, pos, ASYNC_BANK0_BASE,
			    ASYNC_BANK0_BASE + 0x800000,
			    SIZE_4M, SDRAM_EBIU);
	pos =
	    fill_cpl_tables(ipdt_table, pos, ASYNC_BANK3_BASE,
			    ASYNC_BANK3_BASE + 0x400000,
			    SIZE_4M, SDRAM_EBIU);
#endif
#if defined (CONFIG_BFIN561_BLUETECHNIX_CM)
	pos =
	    fill_cpl_tables(ipdt_table, pos, ASYNC_BANK0_BASE,
			    ASYNC_BANK0_BASE + SIZE_4M,
			    SIZE_4M, SDRAM_EBIU);
#endif
# else
#  error "Check the CPLB entries for your BF561 platform in arch/blackfin/kernel/setup.c"
# endif
#else
	pos =
	    fill_cpl_tables(ipdt_table, pos, ASYNC_BANK0_BASE,
			    ASYNC_BANK3_BASE + ASYNC_BANK3_SIZE,
			    SIZE_4M, SDRAM_EBIU);
#endif
	pos =
	    fill_cpl_tables(ipdt_table, pos, L1_CODE_START,
			    L1_CODE_START + SIZE_1M, SIZE_1M, L1_IMEMORY);
#if defined (CONFIG_BF561)
	pos =
	    fill_cpl_tables(ipdt_table, pos, L2_SRAM,
			    L2_SRAM_END, SIZE_1M, L2_MEMORY);
#endif
	*(ipdt_table + pos) = -1;
#endif
	return;
}

static inline u_long get_vco(void)
{
	u_long msel;
	u_long vco;

	msel = (bfin_read_PLL_CTL() >> 9) & 0x3F;
	if (0 == msel)
		msel = 64;

	vco = CONFIG_CLKIN_HZ;
	vco >>= (1 & bfin_read_PLL_CTL());	/* DF bit */
	vco = msel * vco;
	return vco;
}

/*Get the Core clock*/
u_long get_cclk()
{
	u_long csel, ssel;
	if (bfin_read_PLL_STAT() & 0x1)
		return CONFIG_CLKIN_HZ;

	ssel = bfin_read_PLL_DIV();
	csel = ((ssel >> 4) & 0x03);
	ssel &= 0xf;
	if (ssel && ssel < (1 << csel))	/* SCLK > CCLK */
		return get_vco() / ssel;
	return get_vco() >> csel;
}
EXPORT_SYMBOL(get_cclk);

/* Get the System clock */
u_long get_sclk()
{
	u_long ssel;

	if (bfin_read_PLL_STAT() & 0x1)
		return CONFIG_CLKIN_HZ;

	ssel = (bfin_read_PLL_DIV() & 0xf);
	if (0 == ssel) {
		printk(KERN_WARNING "Invalid System Clock\n");
		ssel = 1;
	}

	return get_vco() / ssel;
}
EXPORT_SYMBOL(get_sclk);

/*Get the DSP Revision ID*/
static u_int get_dsp_rev_id()
{
	u_int id;
	id = bfin_read_DSPID() & 0xffff;
	return id;
}

static inline u_int get_compiled_rev_id()
{
#if defined (CONFIG_BF_REV_0_0)
	return 0;
#elif defined (CONFIG_BF_REV_0_1)
	return 1;
#elif defined (CONFIG_BF_REV_0_2)
	return 2;
#elif defined (CONFIG_BF_REV_0_3)
	return 3;
#elif defined (CONFIG_BF_REV_0_4)
	return 4;
#elif defined (CONFIG_BF_REV_0_5)
	return 5;
#endif
}

/*
 *	Get CPU information for use by the procfs.
 */
static int show_cpuinfo(struct seq_file *m, void *v)
{
	char *cpu, *mmu, *fpu, *name;
#ifdef CONFIG_BLKFIN_CACHE_LOCK
	int lock;
#endif

	u_long cclk = 0, sclk = 0;
	u_int id;

	cpu = CPU;
	mmu = "none";
	fpu = "none";
	if (&bfin_board_name) {
		name = bfin_board_name;
	} else {
		name = "Unknown";
	}

	cclk = get_cclk();
	sclk = get_sclk();
	id = get_dsp_rev_id();

	seq_printf(m, "CPU:\t\tADSP-%s Rev. 0.%d\n"
		   "MMU:\t\t%s\n"
		   "FPU:\t\t%s\n"
		   "Core Clock:\t%9lu Hz\n"
		   "System Clock:\t%9lu Hz\n"
		   "BogoMips:\t%lu.%02lu\n"
		   "Calibration:\t%lu loops\n",
		   cpu, id, mmu, fpu,
		   cclk,
		   sclk,
		   (loops_per_jiffy * HZ) / 500000,
		   ((loops_per_jiffy * HZ) / 5000) % 100,
		   (loops_per_jiffy * HZ));
	seq_printf(m, "Board Name:\t%s\n", name);
	seq_printf(m, "Board Memory:\t%ld MB\n", physical_mem_end>>20);
	seq_printf(m, "Kernel Memory:\t%ld MB\n", (unsigned long)_ramend>>20);
	if (bfin_read_IMEM_CONTROL() & (ENICPLB | IMC))
		seq_printf(m, "I-CACHE:\tON\n");
	else
		seq_printf(m, "I-CACHE:\tOFF\n");
	if ((bfin_read_DMEM_CONTROL()) & (ENDCPLB | DMC_ENABLE))
		seq_printf(m, "D-CACHE:\tON"
#if defined CONFIG_BLKFIN_WB
			   " (write-back)"
#elif defined CONFIG_BLKFIN_WT
			   " (write-through)"
#endif
			   "\n");
	else
		seq_printf(m, "D-CACHE:\tOFF\n");
	seq_printf(m, "I-CACHE Size:\t%dKB\n", BLKFIN_ICACHESIZE / 1024);
	seq_printf(m, "D-CACHE Size:\t%dKB\n", BLKFIN_DCACHESIZE / 1024);
	seq_printf(m, "I-CACHE Setup:\t%d Sub-banks/%d Ways, %d Lines/Way\n",
		   BLKFIN_ISUBBANKS, BLKFIN_IWAYS, BLKFIN_ILINES);
	seq_printf(m,
		   "D-CACHE Setup:\t%d Super-banks/%d Sub-banks/%d Ways, %d Lines/Way\n",
		   BLKFIN_DSUPBANKS, BLKFIN_DSUBBANKS, BLKFIN_DWAYS,
		   BLKFIN_DLINES);
#ifdef CONFIG_BLKFIN_CACHE_LOCK
	lock = read_iloc();
	switch (lock) {
	case WAY0_L:
		seq_printf(m, "Way0 Locked-Down\n");
		break;
	case WAY1_L:
		seq_printf(m, "Way1 Locked-Down\n");
		break;
	case WAY01_L:
		seq_printf(m, "Way0,Way1 Locked-Down\n");
		break;
	case WAY2_L:
		seq_printf(m, "Way2 Locked-Down\n");
		break;
	case WAY02_L:
		seq_printf(m, "Way0,Way2 Locked-Down\n");
		break;
	case WAY12_L:
		seq_printf(m, "Way1,Way2 Locked-Down\n");
		break;
	case WAY012_L:
		seq_printf(m, "Way0,Way1 & Way2 Locked-Down\n");
		break;
	case WAY3_L:
		seq_printf(m, "Way3 Locked-Down\n");
		break;
	case WAY03_L:
		seq_printf(m, "Way0,Way3 Locked-Down\n");
		break;
	case WAY13_L:
		seq_printf(m, "Way1,Way3 Locked-Down\n");
		break;
	case WAY013_L:
		seq_printf(m, "Way 0,Way1,Way3 Locked-Down\n");
		break;
	case WAY32_L:
		seq_printf(m, "Way3,Way2 Locked-Down\n");
		break;
	case WAY320_L:
		seq_printf(m, "Way3,Way2,Way0 Locked-Down\n");
		break;
	case WAY321_L:
		seq_printf(m, "Way3,Way2,Way1 Locked-Down\n");
		break;
	case WAYALL_L:
		seq_printf(m, "All Ways are locked\n");
		break;
	default:
		seq_printf(m, "No Ways are locked\n");
	}
#endif
	return 0;
}

static void *c_start(struct seq_file *m, loff_t * pos)
{
	return *pos < NR_CPUS ? ((void *)0x12345678) : NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t * pos)
{
	++*pos;
	return c_start(m, pos);
}

static void c_stop(struct seq_file *m, void *v)
{
}

struct seq_operations cpuinfo_op = {
	.start = c_start,
	.next = c_next,
	.stop = c_stop,
	.show = show_cpuinfo,
};

void cmdline_init(unsigned long r0)
{
	if (r0)
		strncpy(command_line, (char *)r0, COMMAND_LINE_SIZE);
}
