/*
 *	vmlinux.lds.S -- master linker script for blackfin architecture
 *
 *	(C) Copyright 2004-2005 LG Soft India 
 *
 */

#include <asm-generic/vmlinux.lds.h>
#include <linux/config.h>
OUTPUT_FORMAT("elf32-bfin")
ENTRY(start) 
jiffies = jiffies_64 ;
MEMORY 
	{
#ifdef CONFIG_BLKFIN_STAMP
	ram		: ORIGIN = 0x1000,     LENGTH = 0x1000000	/*TODO*/
#endif
#ifdef CONFIG_EZKIT	
	ram		: ORIGIN = 0x1000,     LENGTH = 0x1000000	/*TODO*/
#endif
	l1_data_a	: ORIGIN = 0xFF800000, LENGTH = 0x4000		/*Data A SRAM*/
	l1_data_b	: ORIGIN = 0xFF900000, LENGTH = 0x4000		/*Data B SRAM*/
	l1_code		: ORIGIN = 0xFFA00000, LENGTH = 0x10000		/*64K SRAM */
	l1_scratch	: ORIGIN = 0xFFB00000, LENGTH = 0x1000		/*4K scratchpad SRAM*/
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
   
    .data :
	{
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
	}>ram

	.bss :
	    {
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

#ifdef CONFIG_BLKFIN_STAMP
   . = 0x1000000;
#endif
#ifdef CONFIG_EZKIT
   . = 0x1000000;
#endif

   .eram :
     {	 
	__ramend = .  ;
     } > ram 	
	
   . = 0xFFB00000;		/*Usage of L1 scratchpad for PAGE TABLE*/	
   .scrpad :
     {
	*(.scratch);
     } > l1_scratch 

}
