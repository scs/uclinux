/*
 *  linux/arch/m68knommu/platform/MC68VZ328/de2/zimage/crt0.S
 *
 *  Copyright (C) 2002 Georges Menie
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file COPYING in the main directory of this archive
 * for more details.
 */

	.title "de2/zimage/crt0.S"

	.extern unzip_image
	.extern __stack
	.extern __text_end
	.extern __data_start
	.extern __data_end
	.extern __bss_start
	.extern __bss_end
	.extern start_image

	.text
	.global start
start:

        /* initialize the stack */
        move.l  #__stack,%sp

	/* disable interrupts */
	move.l	#-1,0xfffff304
	move.b	#0,0xfffff300

        /* initialize the data section */
	lea.l	__text_end,%a0
	lea.l	__data_start,%a1
	lea.l	__data_end,%a2
1:	cmpa.l  %a1,%a2
        jbeq	2f
	move.l	(%a0)+,(%a1)+
	jbra	1b
2:
        /* initialize the bss section */
        lea.l   __bss_start,%a0
        lea.l   __bss_end,%a1
1:	cmpa.l  %a0,%a1
        jbeq	2f
	move.l  #0,(%a0)+
	jbra	1b
2:
	
/*
 * Unzip the kernel image
 */
	jsr	unzip_image

/*
 * Start the image
 */
	movea.l	#start_image,%a0
	jmp	(%a0)

/*
 * Infinite loop for exit
 */
        .global exit
exit:
	bra	exit

/*
 * Define putc to send a char to the UART1
 */
        .global putc
putc:
1:	move.w	0xfffff906,%d0
	and.w	#0x2000,%d0
	beq	1b
	move.b	7(%sp),0xfffff907
	rts
