/*
 * File:	 arch/blackfin/kernel/vmlinux.lds.S
 * Based on:	 none - original work
 * Author:
 *
 * Created:	 Tue Sep 21 2004
 * Description:	 Master linker script for blackfin architecture
 *
 * Rev:	         $Id$
 *
 * Modified:
 *               Copyright 2004-2005 Analog Devices Inc.
 *
 * Bugs:	 Enter bugs at http:	//blackfin.uclinux.org/
 *
 * This program is free software ;  you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation	;  either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY ;  without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program ;  see the file COPYING.
 * If not, write to the Free Software Foundation,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#define VMLINUX_SYMBOL(_sym_) _##_sym_

#include <asm-generic/vmlinux.lds.h>
#include <linux/config.h>
#include <asm/mem_map.h>


OUTPUT_FORMAT("elf32-bfin")
ENTRY(__start)
_jiffies = _jiffies_64;
MEMORY
	{
	ram		: ORIGIN = CONFIG_BOOT_LOAD,       LENGTH = (CONFIG_MEM_SIZE * 1024 * 1024) - (CONFIG_BOOT_LOAD)
	l1_data_a	: ORIGIN = L1_DATA_A_START, LENGTH = L1_DATA_A_LENGTH
	l1_data_b	: ORIGIN = L1_DATA_B_START, LENGTH = L1_DATA_B_LENGTH
	l1_code		: ORIGIN = L1_CODE_START,   LENGTH = L1_CODE_LENGTH
	l1_scratch	: ORIGIN = L1_SCRATCH_START,LENGTH = L1_SCRATCH_LENGTH
	}

SECTIONS
{
	. = CONFIG_BOOT_LOAD ;

	.text  : {
		 __stext = .;
		*(.text)
		SCHED_TEXT
		*(.text.lock)
		. = ALIGN(16);
		  ___start___ex_table = .;
		*(__ex_table)
		 ___stop___ex_table = .;

		  *($code)
        	  *(.rodata)
        	  *(.rodata.*)
		  *(__vermagic)		/* Kernel version magic */
        	  *(.rodata1)
	          *(.fixup)

		/* Kernel symbol table: Normal symbols */
		. = ALIGN(4);
		___start___ksymtab = .;
		*(__ksymtab)
		___stop___ksymtab = .;

		/* Kernel symbol table: GPL-only symbols */
		___start___ksymtab_gpl = .;
		*(__ksymtab_gpl)
		___stop___ksymtab_gpl = .;

		/* Kernel symbol table: Normal symbols */
		___start___kcrctab = .;
		*(__kcrctab)
		___stop___kcrctab = .;

		/* Kernel symbol table: GPL-only symbols */
		___start___kcrctab_gpl = .;
		*(__kcrctab_gpl)
		___stop___kcrctab_gpl = .;

		/* Kernel symbol table: strings */
		*(__ksymtab_strings)

		 . = ALIGN(4) ;
	  	__etext = . ;
	} > ram

	.init :
	{
		. = ALIGN(4096);
		___init_begin = .;
		__sinittext = .;
		*(.init.text)
		__einittext = .;
		*(.init.data)
		. = ALIGN(16);
		___setup_start = .;
		*(.init.setup)
		___setup_end = .;
		___start___param = .;
		*(__param)
		___stop___param = .;
		___initcall_start = .;
		*(.initcall1.init)
		*(.initcall2.init)
		*(.initcall3.init)
		*(.initcall4.init)
		*(.initcall5.init)
		*(.initcall6.init)
		*(.initcall7.init)
		___initcall_end = .;
		___con_initcall_start = .;
		*(.con_initcall.init)
		___con_initcall_end = .;
		___security_initcall_start = .;
		*(.security_initcall.init)
		___security_initcall_end = .;
		. = ALIGN(4);
		___initramfs_start = .;
		*(.init.ramfs)
		___initramfs_end = .;
		. = ALIGN(4);
		___init_end = .;
	} > ram

	 __l1_lma_start = .;
	.text_l1 L1_CODE_START :
		AT ( __l1_lma_start )
	{
		. = ALIGN(4) ;
		 __stext_l1 = . ;
		*(.text.l1)

		. = ALIGN(4) ;
		 __etext_l1 = . ;
	}

	.data_l1 L1_DATA_A_START :
		AT ( __l1_lma_start + SIZEOF(.text_l1) )
	{
		. = ALIGN(4) ;
		 __sdata_l1 = . ;
		*(.data.l1)
		 __edata_l1 = . ;

		. = ALIGN(4) ;
		 __sbss_l1 = . ;
		*(.bss.l1)

		. = ALIGN(4) ;
		 __ebss_l1 = . ;
	}

	. = __l1_lma_start + SIZEOF(.text_l1) + SIZEOF(.data_l1) ;
	.data (__l1_lma_start + SIZEOF(.text_l1) + SIZEOF(.data_l1)) :	AT ( __l1_lma_start + SIZEOF(.text_l1) + SIZEOF(.data_l1) )
	{
		 __sdata = . ;
		. = ALIGN(0x2000) ;
		*(.data.init_task)
		*(.data)
		__edata = . ;
	} > ram

	/DISCARD/ : {			/* Exit code and data*/
		*(.exit.text)
		*(.exit.data)
		*(.exitcall.exit)
	} > ram


	.bss : AT ( __l1_lma_start + SIZEOF(.text_l1) + SIZEOF(.data_l1) + SIZEOF(.data) )
	{
		. = ALIGN(4) ;
		 ___bss_start = . ;
		*(.bss)
		*(COMMON)
		. = ALIGN(4) ;
		 ___bss_stop = . 	;
		 __end = .	;
    	} > ram
}
