/*
 *  linux/arch/bfinnommu/kernel/setup.c
 *
 *  Copyleft  ()) 2000       James D. Schettine {james@telos-systems.com}
 *  Copyright (C) 1999,2000  Greg Ungerer (gerg@lineo.com)
 *  Copyright (C) 1998,1999  D. Jeff Dionne <jeff@lineo.ca>
 *  Copyright (C) 1998       Kenneth Albanowski <kjahds@kjahds.com>
 *  Copyright (C) 2004	     LG Soft India
 */

#include <linux/delay.h>
#include <linux/console.h>
#include <linux/bootmem.h>
#include <linux/seq_file.h>

#include <asm/cacheflush.h>
#include <asm/blackfin.h>

#ifdef CONFIG_CONSOLE
extern struct consw *conswitchp;
#ifdef CONFIG_FRAMEBUFFER
extern struct consw fb_con;
#endif
#endif
  
unsigned long memory_start;
unsigned long memory_end;

char command_line[COMMAND_LINE_SIZE];
u_long vco = 0; 

void init_leds(void);
void bf53x_cache_init(void);
u_long get_cclk(void) ;
u_long get_sclk(void);
u_int get_dsp_rev_id(void);

/* Blackfin cache functions */
extern void icache_init(void);
extern void dcache_init(void);
extern int read_iloc(void);
	
#ifdef CONFIG_BF533
#define CPU "BF533"
#endif
#ifdef CONFIG_BF532
#define CPU "BF532"
#endif
#ifdef CONFIG_BF531
#define CPU "BF531"
#endif
#ifndef CPU
#define	CPU "UNKOWN"
#endif

void bf53x_cache_init(void)
{
#ifdef CONFIG_BLKFIN_CACHE
	icache_init();
	printk("Instruction Cache Enabled\n");
#endif
#ifdef CONFIG_BLKFIN_DCACHE
	dcache_init();
	printk("Data Cache Enabled\n");
#endif
}

extern char _stext, _etext, _sdata, _edata, _sbss, _ebss, _end;
extern int _ramstart, _ramend;
extern int ramdisk_begin,ramdisk_end;

void setup_arch(char **cmdline_p)
{
	int bootmap_size, id;

#if defined(CONFIG_CHR_DEV_FLASH) || defined(CONFIG_BLK_DEV_FLASH)  
	/* we need to initialize the Flashrom device here since we might
	 * do things with flash early on in the boot
	 */
	flash_probe();
#endif 

	memory_start = PAGE_ALIGN(_ramstart);
	memory_end = _ramend; /* by now the stack is part of the init task */

	init_mm.start_code = (unsigned long) &_stext;
	init_mm.end_code = (unsigned long) &_etext;
	init_mm.end_data = (unsigned long) &_edata;
	init_mm.brk = (unsigned long) 0;	
	
	init_leds();
	id = get_dsp_rev_id();

	printk(KERN_INFO "Blackfin support (C) 2004 Analog Devices, Inc.\n");
	printk(KERN_INFO "ADSP-%s Rev. 0.%d\n",CPU,id);
	if(id <= 2)
		printk(KERN_INFO "Warning: Unsupported Chip Revision ADSP-%s Rev. 0.%d detected \n",CPU,id);

#if defined(CONFIG_BOOTPARAM)
	strncpy(&command_line[0], CONFIG_BOOTPARAM_STRING, sizeof(command_line));
	command_line[sizeof(command_line)-1] = 0;
#else
	memset(command_line, 0, sizeof(command_line));
#endif

	printk(KERN_INFO "uClinux/" CPU "\n");

	printk("Blackfin uClinux support by LG Soft India (www.lgsoftindia.com) \n");
	printk("Processor Speed: %lu MHz core clock and %lu Mhz System Clock\n",get_cclk()/1000000,get_sclk()/1000000);
	printk("Board Memory: %dMB\n",CONFIG_MEM_SIZE);

	printk("Memory map:\n  text = 0x%06x-0x%06x\n  data = 0x%06x-0x%06x\n  bss  = 0x%06x-0x%06x\n  rootfs = 0x%06x-0x%06x\n  stack = 0x%06x-0x%06x\n",
		(int)&_stext,(int)&_etext,(int)&_sdata,(int)&_edata,
		(int)&_sbss,(int)&_ebss,
		(int)&ramdisk_begin,(int)&ramdisk_end,
		(int)&init_thread_union,(int)(&init_thread_union) + 0x2000);

	init_task.mm->start_code = (unsigned long) &_stext;
	init_task.mm->end_code = (unsigned long) &_etext;
	init_task.mm->end_data = (unsigned long) &_edata;
	init_task.mm->brk = (unsigned long) &_end;

	/* Keep a copy of command line */
	*cmdline_p = &command_line[0];
	memcpy(saved_command_line, command_line, COMMAND_LINE_SIZE);
	saved_command_line[COMMAND_LINE_SIZE-1] = 0;

	if (strlen(*cmdline_p)) 
		printk("Command line: '%s'\n", *cmdline_p);
	
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
	bootmap_size = init_bootmem_node(
			NODE_DATA(0),
			memory_start >> PAGE_SHIFT, 	/* map goes here */
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

	bf53x_cache_init();
}

/*Get the Core clock*/
u_long get_cclk()
{
	u_long cclk = 0;

	if(*pPLL_STAT & 0x1) return CONFIG_CLKIN_HZ;

	vco = CONFIG_CLKIN_HZ * ((*pPLL_CTL >> 9)& 0x3F);

	if (1 & *pPLL_CTL) /* DF bit */
		vco >>= 1;
	cclk = vco >> (*pPLL_DIV >> 4 & 0x03);

	return cclk;
}

/* Get the System clock */
u_long get_sclk()
{
	u_long sclk=0;
	
	if(*pPLL_STAT & 0x1) return CONFIG_CLKIN_HZ;
	
	vco = CONFIG_CLKIN_HZ * ((*pPLL_CTL >> 9)& 0x3F);
	
	if (1 & *pPLL_CTL) /* DF bit */
		vco >>= 1;

	if((*pPLL_DIV & 0xf) != 0)
		sclk = vco/(*pPLL_DIV & 0xf);
	else
		printk("Invalid System Clock\n");
	
	return sclk;
}

/*Get the DSP Revision ID*/
u_int get_dsp_rev_id()
{
	u_int id;
	id = *pDSPID & 0xffff;
	return id;
}

/*
 *	Get CPU information for use by the procfs.
 */
static int show_cpuinfo(struct seq_file *m, void *v)
{
	char *cpu, *mmu, *fpu;
#ifdef CONFIG_BLKFIN_CACHE_LOCK
	int lock;
#endif

	u_long cclk=0,sclk=0;
	u_int id;

	cpu = CPU;
	mmu = "none";
	fpu = "none";

	cclk = get_cclk();
	sclk = get_sclk();
	id = get_dsp_rev_id();

	seq_printf(m, "CPU:\t\tADSP-%s Rev. 0.%d\n"
		   "MMU:\t\t%s\n"
		   "FPU:\t\t%s\n"
		   "Core Clock:\t%lu Hz\n"
		   "System Clock:\t%lu Hz\n"
		   "BogoMips:\t%lu.%02lu\n"
		   "Calibration:\t%lu loops\n",
		   cpu, id, mmu, fpu,
		   cclk,
		   sclk,
		   (loops_per_jiffy*HZ)/500000,((loops_per_jiffy*HZ)/5000)%100,
		   (loops_per_jiffy*HZ));
#if defined CONFIG_BLKFIN_STAMP	
	seq_printf(m, "BOARD:\t\tADSP-BF533 STAMP\n");
#else
	seq_printf(m, "BOARD:\t\tADSP-BF533 EZ-KIT LITE\n");
#endif
	seq_printf(m, "BOARD Memory:\t%d MB\n",CONFIG_MEM_SIZE);
        if((*(volatile unsigned long *)IMEM_CONTROL) & (ENICPLB | IMC))
		seq_printf(m, "I-CACHE:\tON\n");
	else
		seq_printf(m, "I-CACHE:\tOFF\n");		
        if((*(volatile unsigned long *)DMEM_CONTROL) & (ENDCPLB | DMC_ENABLE))
		seq_printf(m, "D-CACHE:\tON\n");
	else
		seq_printf(m, "D-CACHE:\tOFF\n");		
	seq_printf(m, "I-CACHE Size:\t%dKB\n",BLKFIN_ICACHESIZE/1024);
	seq_printf(m, "D-CACHE Size:\t%dKB\n",BLKFIN_DCACHESIZE/1024);
	seq_printf(m, "I-CACHE Setup:\t%d Sub-banks/%d Ways, %d Lines/Way\n",
			BLKFIN_ISUBBANKS,BLKFIN_IWAYS,BLKFIN_ILINES); 
	seq_printf(m, "D-CACHE Setup:\t%d Super-banks/%d Sub-banks/%d Ways, %d Lines/Way\n",
			BLKFIN_DSUPBANKS,BLKFIN_DSUBBANKS,BLKFIN_DWAYS,BLKFIN_DLINES); 
#ifdef CONFIG_BLKFIN_CACHE_LOCK
	lock = read_iloc();
	switch(lock)
	{
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

static void *c_start(struct seq_file *m, loff_t *pos)
{
	return *pos < NR_CPUS ? ((void *) 0x12345678) : NULL;
}

static void *c_next(struct seq_file *m, void *v, loff_t *pos)
{
	++*pos;
	return c_start(m, pos);
}

static void c_stop(struct seq_file *m, void *v)
{
}

struct seq_operations cpuinfo_op = {
	.start	= c_start,
	.next	= c_next,
	.stop	= c_stop,
	.show	= show_cpuinfo,
};

void panic_bfin(int cplb_panic)
{
	switch(cplb_panic)
	{
	
		case CPLB_NO_UNLOCKED:
			panic("All CPLBs are locked\n");
			break;
		case CPLB_PROT_VIOL:
			panic("Data Access CPLB Protection Voilation \n");
			break;
		case CPLB_NO_ADDR_MATCH:
			panic("No CPLB Address Match \n");
	}
}
