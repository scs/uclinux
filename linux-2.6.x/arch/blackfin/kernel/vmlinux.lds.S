/*
 *	vmlinux.lds.S - Master linker script for blackfin architecture
 *
 *	(C) Copyright 2004-2005 LG Soft India 
 *
 */

#include <asm-generic/vmlinux.lds.h>
#include <linux/config.h>

#ifdef CONFIG_BLKFIN_STAMP
#define RAM_START		0x1000
#define RAM_LENGTH		0x8000000
#endif

#ifdef CONFIG_EZKIT
#define RAM_START		0x1000
#define RAM_LENGTH		0x2000000
#endif

#define L1_DATA_A_START		0xFF800000
#define L1_DATA_A_LENGTH	0x4000
#define L1_DATA_B_START		0xFF900000
#define L1_DATA_B_LENGTH	0x4000
#define L1_CODE_START		0xFFA00000
#define L1_CODE_LENGTH		0x10000
#define L1_SCRATCH_START	0xFFB00000
#define L1_SCRATCH_LENGTH	0x1000
	

OUTPUT_FORMAT("elf32-bfin")
ENTRY(start) 
jiffies = jiffies_64 ;
MEMORY 
	{
	ram		: ORIGIN = RAM_START,       LENGTH = RAM_LENGTH			
	l1_data_a	: ORIGIN = L1_DATA_A_START, LENGTH = L1_DATA_A_LENGTH		/*Data A SRAM*/
	l1_data_b	: ORIGIN = L1_DATA_B_START, LENGTH = L1_DATA_B_START		/*Data B SRAM*/
	l1_code		: ORIGIN = L1_CODE_START,   LENGTH = L1_CODE_LENGTH		/*64K SRAM */
	l1_scratch	: ORIGIN = L1_SCRATCH_START,LENGTH = L1_SCRATCH_LENGTH		/*4K scratchpad SRAM*/
	}

SECTIONS
{
	. = 0x1000 ;

	.text  : {
		 _text = .;                     /*Text and read-only data */
		 _stext = .;                     
		text_start = . ;
		 __text_start = . ;
		*(.text)
		SCHED_TEXT
		*(.text.lock)
		. = ALIGN(16);
		  __start___ex_table = .;
		*(__ex_table)
		 __stop___ex_table = .;

		 __init_begin = .;
		_sinittext = .;
              	*(.init.text)		
		. = ALIGN(4);	
		_einittext = .;
		*(.init.data)  
		. = ALIGN(16);
		__setup_start = .;
		*(.init.setup)
		__setup_end = .;
		__start___param = .;
		*(__param)
		__stop___param = .;
		__initcall_start = .;
		*(.initcall1.init)
		*(.initcall2.init)
		*(.initcall3.init)
		*(.initcall4.init)
		*(.initcall5.init)
		*(.initcall6.init)
		*(.initcall7.init)
		__initcall_end = .;
		__con_initcall_start = .;
		*(.con_initcall.init)
		__con_initcall_end = .;
		__security_initcall_start = .;
		*(.security_initcall.init)
		__security_initcall_end = .;
		. = ALIGN(4);
		__initramfs_start = .;
		   *(.init.ramfs)
		__initramfs_end = .;
		. = ALIGN(4096);
		__init_end = .;

		  *($code)
        	  *(.rodata)
        	  *(.rodata1)
        	  *(.rodata.*)
	          *(.fixup)	
		

		/* Kernel symbol table: Normal symbols */
		__start___ksymtab = .;
		*(__ksymtab)
		__stop___ksymtab = .;

		/* Kernel symbol table: GPL-only symbols */
		__start___ksymtab_gpl = .;
		*(__ksymtab_gpl)
		__stop___ksymtab_gpl = .;

		/* Kernel symbol table: Normal symbols */
		__start___kcrctab = .;
		*(__kcrctab)
		__stop___kcrctab = .;

		/* Kernel symbol table: GPL-only symbols */
		__start___kcrctab_gpl = .;
		*(__kcrctab_gpl)
		__stop___kcrctab_gpl = .;

		/* Kernel symbol table: strings */
		*(__ksymtab_strings)

		 . = ALIGN(4) ;

	  	_etext = . ;
		  etext = . ;
	} > ram
   
	.data :	{

		. = ALIGN(4);	
		 _sdata = . ;
		 __data_start = . ;
		. = ALIGN(0x2000) ;
		*(.data.init_task)
		. = ALIGN(0x2000) ;	
		*(.data)
		. = ALIGN(16);
		ramdisk_begin = .;
		*(.ramdisk)
		ramdisk_end = .;
		. = ALIGN(16);	
		_edata = . ;
		edata = . ;
	} > ram

	/DISCARD/ : {			/* Exit code and data*/
		*(.exit.text)
		*(.exit.data)
		*(.exitcall.exit)
	} > ram

	.bss : {

		. = ALIGN(16) ;
		 _sbss = . ;
		 __bss_start = . ;
		 __data_end = . ;
		*(.bss)
		*(COMMON)
		. = ALIGN(16) ;
		end = . ;
		 _ebss = . ;	  
		 _end = . ;
    	} > ram

   . = RAM_LENGTH ;
	.eram : {
		__ramend = .  ;
		_ramend = .  ;
     	} > ram 	
	
	. = L1_SCRATCH_START;		/*Usage of L1 scratchpad for PAGE TABLE*/	

	.scrpad : {
		*(.scratch);
	} > l1_scratch 

}
