/*
 *	vmlinux.lds.S - Master linker script for blackfin architecture
 *
 *	(C) Copyright 2004-2005 LG Soft India 
 *
 */

#include <asm-generic/vmlinux.lds.h>
#include <linux/config.h>

#define RAM_START		0x1000
#define RAM_LENGTH		CONFIG_MEM_SIZE * 1024 * 1024

#ifdef CONFIG_BF533
#define L1_DATA_A_START		0xFF800000
#define L1_DATA_A_LENGTH	0x4000
#define L1_DATA_B_START		0xFF900000
#define L1_DATA_B_LENGTH	0x4000
#define L1_CODE_START		0xFFA00000
#define L1_CODE_LENGTH		0x10000
#define L1_SCRATCH_START	0xFFB00000
#define L1_SCRATCH_LENGTH	0x1000
#endif

#ifdef CONFIG_BF532
#define L1_CODE_START	0xFFA08000
#define L1_CODE_LENGTH	0x8000
#endif

#ifdef CONFIG_BF531
#define L1_CODE_START	0xFFA08000
#define L1_CODE_LENGTH	0x4000
#endif

OUTPUT_FORMAT("elf32-bfin")
ENTRY(_start) 
jiffies = jiffies_64;
MEMORY 
	{
	ram		: ORIGIN = RAM_START,       LENGTH = RAM_LENGTH
	#ifdef CONFIG_BF533
	l1_data_a	: ORIGIN = L1_DATA_A_START, LENGTH = L1_DATA_A_LENGTH
	l1_data_b	: ORIGIN = L1_DATA_B_START, LENGTH = L1_DATA_B_LENGTH
	#endif
	l1_code		: ORIGIN = L1_CODE_START,   LENGTH = L1_CODE_LENGTH
	l1_scratch	: ORIGIN = L1_SCRATCH_START,LENGTH = L1_SCRATCH_LENGTH
	}

SECTIONS
{
	. = 0x1000 ;

	.text  : {
		 _stext = .;                     
		*(.text)
		SCHED_TEXT
		*(.text.lock)
		. = ALIGN(16);
		  __start___ex_table = .;
		*(__ex_table)
		 __stop___ex_table = .;

		  *($code)
        	  *(.rodata)
        	  *(.rodata.*)
		  *(__vermagic)		/* Kernel version magic */
        	  *(.rodata1)
	          *(.fixup)	

		/* Kernel symbol table: Normal symbols */
		. = ALIGN(4);
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
	} > ram
   
	.init : {
		. = ALIGN(4096);
		__init_begin = .;
		_sinittext = .;
		*(.init.text)
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
		. = ALIGN(4);
		__init_end = .;
	} > ram

	.data :	{
		 _sdata = . ;
		. = ALIGN(0x2000) ;
		*(.data.init_task)
		*(.data)
		_edata = . ;
	} > ram

	/DISCARD/ : {			/* Exit code and data*/
		*(.exit.text)
		*(.exit.data)
		*(.exitcall.exit)
	} > ram

	.bss : {
		. = ALIGN(4) ;
		 _sbss = . ;
		*(.bss)
		*(COMMON)
		. = ALIGN(4) ;
		 _ebss = . ;	  
		 _end = . ;	  
    	} > ram

	.bss_end : {
 		. = ALIGN(4) ;
 		_bss_end = . ;
 	} > ram

#ifdef CONFIG_FULLDEBUG
  /* Stabs debugging sections.  */
  .stab          0 : { *(.stab) }
  .stabstr       0 : { *(.stabstr) }
  .stab.excl     0 : { *(.stab.excl) }
  .stab.exclstr  0 : { *(.stab.exclstr) }
  .stab.index    0 : { *(.stab.index) }
  .stab.indexstr 0 : { *(.stab.indexstr) }
  .comment       0 : { *(.comment) }
  /* DWARF debug sections.
     Symbols in the DWARF debugging sections are relative to the beginning
     of the section so we begin them at 0.  */
  /* DWARF 1 */
  .debug          0 : { *(.debug) }
  .line           0 : { *(.line) }
  /* GNU DWARF 1 extensions */
  .debug_srcinfo  0 : { *(.debug_srcinfo) }
  .debug_sfnames  0 : { *(.debug_sfnames) }
  /* DWARF 1.1 and DWARF 2 */
  .debug_aranges  0 : { *(.debug_aranges) }
  .debug_pubnames 0 : { *(.debug_pubnames) }
  /* DWARF 2 */
  .debug_info     0 : { *(.debug_info .gnu.linkonce.wi.*) }
  .debug_abbrev   0 : { *(.debug_abbrev) }
  .debug_line     0 : { *(.debug_line) }
  .debug_frame    0 : { *(.debug_frame) }
  .debug_str      0 : { *(.debug_str) }
  .debug_loc      0 : { *(.debug_loc) }
  .debug_macinfo  0 : { *(.debug_macinfo) }
  /* SGI/MIPS DWARF 2 extensions */
  .debug_weaknames 0 : { *(.debug_weaknames) }
  .debug_funcnames 0 : { *(.debug_funcnames) }
  .debug_typenames 0 : { *(.debug_typenames) }
  .debug_varnames  0 : { *(.debug_varnames) }
  /DISCARD/ : { *(.note.GNU-stack) }
#else
  /DISCARD/ : { *(.comment) }
#endif
	.text_l1 : {
		. = ALIGN(4) ;
		 _stext_l1 = . ;
		*(.text.l1)
	
		. = ALIGN(4) ;
		 _etext_l1 = . ;  
	} > l1_code

	.data_l1 : {
		. = ALIGN(4) ;
		 _sdata_l1 = . ;
		*(.data.l1)
	
		. = ALIGN(4) ;
		 _edata_l1 = . ;  
	} > l1_data_a

	.bss_l1 : {
		. = ALIGN(4) ;
		 _sbss_l1 = . ;
		*(.bss.l1)

		. = ALIGN(4) ;
		 _ebss_l1 = . ;  
	} > l1_data_a
}
