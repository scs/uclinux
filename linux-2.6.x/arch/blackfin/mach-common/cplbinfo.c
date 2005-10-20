 /*
 * File:        arch/blackfin/mach-common/cplbinfo.c
 * Based on:    
 * Author:      Sonic Zhang <sonic.zhang@analog.com>
 *              COPYRIGHT 2005 Analog Devices
 * Created:     Jan. 2005
 * Description: Display CPLB status
 *
 * Rev:
 *
 * Modified:
 *
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


#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>

#include <asm/current.h>
#include <asm/uaccess.h>
#include <asm/system.h>

#include <asm/cplb.h>
#include <asm/blackfin.h>


#define BUFSIZE		256

static char cmdline[BUFSIZE];
static unsigned long len;

#define CPLB_I 1
#define CPLB_D 2

#define SYNC_SYS do{__asm__ ("SSYNC;\n\t" : : : "CC");}while(0)
#define SYNC_CORE do{__asm__ ("CSYNC;\n\t" : : : "CC");}while(0)

#define CPLB_BIT_PAGESIZE 0x30000

static long page_size_table[4] = {
0x00000400,	/* 1K */
0x00001000,	/* 4K */
0x00100000,	/* 1M */
0x00400000	/* 4M */
};

static char *page_size_string_table[4] = {"1K", "4K", "1M", "4M"};

extern unsigned long dpdt_table[];
extern unsigned long ipdt_table[];

extern unsigned long ipdt_swapcount_table[];
extern unsigned long dpdt_swapcount_table[];

static unsigned long * cplb_find_entry(int type, unsigned long addr)
{
	unsigned long* p_data = NULL;
	unsigned long* p_addr = NULL;
	int size;
	int i;

	if(type==CPLB_I) {
		p_data = (unsigned long*)ICPLB_DATA0;
		p_addr = (unsigned long*)ICPLB_ADDR0;
	}
	else {
		p_data = (unsigned long*)DCPLB_DATA0;
		p_addr = (unsigned long*)DCPLB_ADDR0;
	}
	
	for(i=0;i<16;i++,p_data++,p_addr++) {
		size = page_size_table[((*p_data)&CPLB_BIT_PAGESIZE)>>16];
		if(addr>=*p_addr && addr<(*p_addr+size))
			return p_data;
	}
	
	return NULL;
}

static char *cplb_print_entry(char *buf, int type)
{
	unsigned long* p_data = NULL;
	unsigned long* p_addr = NULL;
	unsigned long* p_icount = NULL;
	unsigned long* p_ocount = NULL;
	unsigned long* entry = NULL;
	char locked;
	char valid;
	char swapin;

	if(type==CPLB_I) {
		buf += sprintf(buf, "Instrction CPLB entry:\n");
		p_data = ipdt_table + 1;
		p_addr = ipdt_table;
		p_icount = ipdt_swapcount_table;
		p_ocount = ipdt_swapcount_table + 1;
	}
	else {
		buf += sprintf(buf, "Data CPLB entry:\n");
		p_data = dpdt_table + 1;
		p_addr = dpdt_table;
		p_icount = dpdt_swapcount_table;
		p_ocount = dpdt_swapcount_table + 1;
	}
	
	buf += sprintf(buf, "Address\t\tData\tSize\tValid\t\
Locked\tSwapin\tiCount\toCount\n");
	while(*p_addr != 0xffffffff) {
		if(*p_data & CPLB_VALID)
			valid='Y';
		else
			valid='N';
		if(*p_data & CPLB_LOCK)
			locked='Y';
		else
			locked='N';
		if((entry=cplb_find_entry(type, *p_addr))!=NULL)
			swapin='Y';
		else
			swapin='N';

		if(*p_addr<0x100000) {
			buf += sprintf(buf, "0x%lx\t\t0x%lx\t%s\t%c\t%c\t\
%c\t%ld\t%ld\n", *p_addr, *p_data, 
				page_size_string_table[(*p_data&0x30000)>>16], 
				valid, locked, swapin, *p_icount, *p_ocount);
		}
		else {
			buf += sprintf(buf, "0x%lx\t0x%lx\t%s\t%c\t%c\t%c\t\
%ld\t%ld\n", *p_addr, *p_data, 
				page_size_string_table[(*p_data&0x30000)>>16], 
				valid, locked, swapin, *p_icount, *p_ocount);
		}

		p_addr += 2;
		p_data += 2;
		p_icount +=2;
		p_ocount +=2;
	}

	buf += sprintf(buf, "\n");
	
	return buf;
}

static int cplbinfo_proc_output (char *buf)
{
	char *p;

	p = buf;

	p += sprintf(p, "--------------\
------------ CPLB Information --------------------------\n\n");

	if( *pIMEM_CONTROL & ENICPLB)
		p = cplb_print_entry(p, CPLB_I);
	else
		p += sprintf(p, "Instruction CPLB is disabled.\n\n");

	if( *pDMEM_CONTROL & ENDCPLB)
		p = cplb_print_entry(p, CPLB_D);
	else
		p += sprintf(p, "Data CPLB is disabled.\n");

	return  p - buf;
}

static int cplbinfo_read_proc(char *page, char **start, off_t off,
                         int count, int *eof, void *data)
{
	int len;
        
	len = cplbinfo_proc_output (page);
        if (len <= off+count) *eof = 1;
        *start = page + off;
        len -= off;
        if (len>count) len = count;
        if (len<0) len = 0;
       return len;
}

static int cplbinfo_write_proc(struct file *file, const char *buffer,
			   unsigned long count, void *data)
{
	if(count>=BUFSIZE)
		len = BUFSIZE-1;
	else
		len = count;
	
	memcpy(cmdline, buffer, count);
	cmdline[len] = 0;

	printk("Reset the CPLB swap in/out counts.\n");
	memset(ipdt_swapcount_table, 0, 100*sizeof(unsigned long));
	memset(dpdt_swapcount_table, 0, 120*sizeof(unsigned long));

        return len;
}


static int __init cplbinfo_init(void)
{
	struct proc_dir_entry *entry;

	if ((entry=create_proc_entry ("cplbinfo", 0, NULL)) == NULL) {
		return -ENOMEM;
	}
	
	entry->read_proc = cplbinfo_read_proc;
	entry->write_proc = cplbinfo_write_proc;
	entry->data = NULL;
	cmdline[0] = 0;

	return 0;
}


static void __exit cplbinfo_exit (void)
{
	remove_proc_entry ("cplbinfo", NULL);
}

module_init(cplbinfo_init);
module_exit(cplbinfo_exit);

