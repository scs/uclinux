INCLUDE bf561.lds

PHDRS {
	text PT_LOAD ;
	data PT_LOAD ;
	bss  PT_LOAD ;
}

SECTIONS {
	ENTRY(start)

	. = SIZEOF_HEADERS;

	.text : { . = ALIGN(4); *(.text) } >MEM_L1_CODE_A :text
	.data : { . = ALIGN(4); *(.data) } >MEM_L1_DATA_A :data
	.bss  : { . = ALIGN(4); *(.bss)
		  . = ALIGN(4); __stack_bottom = .;
		  . = 0x1000;   __stack_top = .;
		} >MEM_L1_DATA_B :bss
}
