/*
 * Richard Xiao (A2590C@email.mot.com)
 *
 * Copyright (C) 2003 Motorola Corporation.  All rights reserved.
 * Copyright (C) 2004 LG Soft India. 
 *
 * SRAM driver for Blackfin ADSP-BF533.
 *
 *
 * ########################################################################
 *
 *  This program is free software; you can distribute it and/or modify it
 *  under the terms of the GNU General Public License (Version 2) as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 *  for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  59 Temple Place - Suite 330, Boston MA 02111-1307, USA.
 */

#include <linux/autoconf.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/miscdevice.h>
#include <linux/ioport.h>
#include <linux/fcntl.h>
#include <linux/init.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/spinlock.h>
#include <linux/rtc.h>
#include <asm/cplb.h>

spinlock_t l1sram_lock, l2sram_lock;

#define L1_SCRATCH_SADDR    0xFFB00000
#define L1_SCRATCH_SIZE     0x1000

#define L1_MAX_PIECE        16

#define MAX_CPLBS   16
#define NUM_CPLBS   16

/* L1 scratchpad management */

/* L1 scratchpad SRAM */
#define SRAM_SLT_NULL      0
#define SRAM_SLT_FREE      1
#define SRAM_SLT_ALLOCATED 2

void l1sram_init(void);
void l1mem_init(void);
extern void _cache_invalidate(int);
extern void bf53x_icache_init(void);
extern void bf53x_dcache_init(void);
extern unsigned long table_start,table_end;

/* the data structure for L1 scratchpad */ 
/* L1 scratchpad SRAM */
struct {
	unsigned long saddr;
	unsigned long max_size;
	struct {
		unsigned long paddr;
		int size;
		int flag;
	}pfree[L1_MAX_PIECE];
}l1_ssram;

/*Just chenck wether setup.c has already initialized cache*/
void l1mem_init()
{
	/*int imode,dmode;
	imode = CPLB_ENABLE_ANY_CPLBS | CPLB_ENABLE_ICACHE ; 
	dmode = CPLB_ENABLE_ANY_CPLBS | CPLB_ENABLE_DCACHE ; 
	*/
        if(!((*(volatile unsigned long *)IMEM_CONTROL) & (ENICPLB | IMC)))
	{
		/*_cache_invalidate(imode);*/
	#ifdef CONFIG_BLKFIN_CACHE		
		bf53x_icache_init();
		/*printk("Instruction cache Initialized.\n");*/
	#endif
	}	
	if(!((*(volatile unsigned long *)DMEM_CONTROL) & (ENDCPLB | DMC_531_ENABLE)))
	{
		/*_cache_invalidate(dmode);*/
	#ifdef CONFIG_BLKFIN_DCACHE
		bf53x_dcache_init();
	#endif
	}
	else printk("l1 Memory already Initialized.\n");
	/*Initialize the blackfin scratchpad memory*/
	l1sram_init();
	
	/*Move the Page table to SCRATCH PAD memory :)*/
	asm("[--SP] = ( R7:4, P5:5);"
	"p5.h = table_end;"
	"p5.l = table_end;"
	"p4.l = table_start;"
	"p4.h = table_start;"
	"p3.h = 0xffb0;"
	"p3.l = 0x0000;"
	"r4 = p5;"
	"r5 = p4;"
	"r4 = r4 - r5;"
	"p5 = r4;"
	"lsetup (copy_start, copy_end) lc0 = p5;"
	"copy_start:"
	"r3 = [p4++];"
	"[p3++] = r3;"
	"copy_end:"
	"( R7:4, P5:5) = [SP++];");
	return;
}

/* L1 Scratchpad SRAM initialization function */
void l1sram_init(void)
{
	printk("Blackfin Scratchpad data SRAM: %d KB\n",(L1_SCRATCH_SIZE/1000));

	memset((void *)&l1_ssram, 0, sizeof(l1_ssram));
	l1_ssram.saddr = L1_SCRATCH_SADDR;
	l1_ssram.max_size = L1_SCRATCH_SIZE;
	l1_ssram.pfree[0].paddr = L1_SCRATCH_SADDR;
	l1_ssram.pfree[0].size = L1_SCRATCH_SIZE;
	l1_ssram.pfree[0].flag = SRAM_SLT_FREE;

	/* mutex initialize */
	spin_lock_init (&l1sram_lock);
}

/* L1 Scratchpad memory allocate function */
unsigned long l1sram_alloc(unsigned long size)
{
	int i, index=0;
	unsigned long addr=0;
	
	/* add mutex operation*/
	spin_lock (&l1sram_lock);

	if(size <= 0)
		return 0;

	/* not use the good method to match the best slot !!! */
	/* search an available memeory slot */
	for(i = 0; i < L1_MAX_PIECE; i++)  {
		if((l1_ssram.pfree[i].flag == SRAM_SLT_FREE) &&
			(l1_ssram.pfree[i].size >= size))	{
			addr = l1_ssram.pfree[i].paddr;
			l1_ssram.pfree[i].flag = SRAM_SLT_ALLOCATED;
			index = i;
			break;
		}
	}
	if( i >= L1_MAX_PIECE )
		return 0;
		
	/* updated the NULL memeory slot !!!*/
	if(l1_ssram.pfree[i].size > size)	{
		for( i = 0; i < L1_MAX_PIECE; i++ )	{
			if(l1_ssram.pfree[i].flag == SRAM_SLT_NULL)	{
				l1_ssram.pfree[i].flag = SRAM_SLT_FREE;
				l1_ssram.pfree[i].paddr = addr + size;
				l1_ssram.pfree[i].size = l1_ssram.pfree[index].size - size;
				l1_ssram.pfree[index].size = size;
				break;
			}
		}
	}

	/* add mutex operation*/
	spin_unlock (&l1sram_lock);

	return addr;
}

/* L1 Scratchpad memory free function */
int l1sram_free(unsigned long addr)
{
	int i, index=0;
	
	/* add mutex operation*/
	spin_lock (&l1sram_lock);

	/* search the relevant memory slot */
	for(i = 0; i < L1_MAX_PIECE; i++)  {
		if(l1_ssram.pfree[i].paddr == addr)	{
			if(l1_ssram.pfree[i].flag != SRAM_SLT_ALLOCATED) {
				/* error log*/
				return -1;
			}
			index = i;
			break;
		}
	}
	if( i >= L1_MAX_PIECE )
		return -1;
		
	l1_ssram.pfree[index].flag = SRAM_SLT_FREE;
	
	/* link the next address slot */
	for(i = 0; i < L1_MAX_PIECE; i++)  {
		if(((l1_ssram.pfree[index].paddr + l1_ssram.pfree[index].size) == l1_ssram.pfree[i].paddr) &&
			(l1_ssram.pfree[i].flag == SRAM_SLT_FREE))
		{
			l1_ssram.pfree[i].flag = SRAM_SLT_NULL;
			l1_ssram.pfree[index].size += l1_ssram.pfree[i].size;
			l1_ssram.pfree[index].flag = SRAM_SLT_FREE;
			break;
		}
	}

	/* link the last address slot */
	for(i = 0; i < L1_MAX_PIECE; i++)  {
		if(((l1_ssram.pfree[i].paddr + l1_ssram.pfree[i].size) == l1_ssram.pfree[index].paddr) &&
			(l1_ssram.pfree[i].flag == SRAM_SLT_FREE))
		{
			l1_ssram.pfree[index].flag = SRAM_SLT_NULL;
			l1_ssram.pfree[i].size += l1_ssram.pfree[index].size;
			break;
		}
	}

	/* add mutex operation*/
	spin_unlock (&l1sram_lock);

	return 0;
}


