/* bf533_serial.h: Definitions for the BlackFin BF533 DSP serial driver.
 * Copyright (C) 2003	Bas Vermeulen <bas@buyways.nl>
 * 			BuyWays B.V. (www.buyways.nl)
 *
 * Copyright(c) 2004	LG Soft India
 * Copyright (C) 2001	Tony Z. Kou	tonyko@arcturusnetworks.com
 * Copyright (C) 2001   Arcturus Networks Inc. <www.arcturusnetworks.com>
 *
 * Based on code from 68328serial.c which was: 
 * Copyright (C) 1995       David S. Miller    <davem@caip.rutgers.edu>
 * Copyright (C) 1998       Kenneth Albanowski <kjahds@kjahds.com>
 * Copyright (C) 1998, 1999 D. Jeff Dionne     <jeff@uclinux.org>
 * Copyright (C) 1999       Vladimir Gurevich  <vgurevic@cisco.com>
 */

#ifndef _Bf533_SERIAL_H
#define _Bf533_SERIAL_H

#define CACHE_LINE_SIZE		32
#define DMA_DI_ENABLE             0x0080
#define DMA_WDSIZE_8              0x0000
#define DMA_WNR                   0x0002
#define DMA_ENABLE              0x0001
struct dma_descriptor_block;
                                                                                
struct dma_descriptor_block
{
        struct dma_descriptor_block     *next;
        void                            *start_addr;
        unsigned short                  dma_config;
        unsigned short                  x_count;
        unsigned short                  x_modify;
        unsigned short                  y_count;
        unsigned short                  y_modify;
} __attribute__ ((packed));

/*
 * For the close wait times, 0 means wait forever for serial port to
 * flush its output.  65535 means don't wait at all.
 */
#define S_CLOSING_WAIT_INF	0
#define S_CLOSING_WAIT_NONE	65535

/*
 * Definitions for S_struct (and serial_struct) flags field
 */
#define S_HUP_NOTIFY 0x0001 /* Notify getty on hangups and closes 
				   on the callout port */
#define S_FOURPORT  0x0002	/* Set OU1, OUT2 per AST Fourport settings */
#define S_SAK	0x0004	/* Secure Attention Key (Orange book) */
#define S_SPLIT_TERMIOS 0x0008 /* Separate termios for dialin/callout */

#define S_SPD_MASK	0x0030
#define S_SPD_HI	0x0010	/* Use 56000 instead of 38400 bps */

#define S_SPD_VHI	0x0020  /* Use 115200 instead of 38400 bps */
#define S_SPD_CUST	0x0030  /* Use user-specified divisor */

#define S_SKIP_TEST	0x0040   /* Skip UART test during autoconfiguration */
#define S_AUTO_IRQ	0x0080   /* Do automatic IRQ during autoconfiguration */
#define S_SESSION_LOCKOUT 0x0100 /* Lock out cua opens based on session */
#define S_PGRP_LOCKOUT    0x0200 /* Lock out cua opens based on pgrp */
#define S_CALLOUT_NOHUP   0x0400 /* Don't do hangups for cua device */

#define S_FLAGS		0x0FFF	 /* Possible legal S flags */
#define S_USR_MASK	0x0430	 /* Legal flags that non-privileged
				  * users can set or reset */

/* Internal flags used only by kernel/chr_drv/serial.c */
#define S_INITIALIZED		0x80000000 /* Serial port was initialized */
#define S_CALLOUT_ACTIVE	0x40000000 /* Call out device is active */
#define S_NORMAL_ACTIVE		0x20000000 /* Normal device is active */
#define S_CLOSING		0x08000000 /* Serial port is closing */

/* Software state per channel */

#ifdef __KERNEL__

/*
 * This is our internal structure for each serial port's state.
 * 
 * Many fields are paralleled by the structure used by the serial_struct
 * structure.
 *
 * For definitions of the flags field, see tty.h
 */

struct bf533_serial {
	/* We need to know the current clock divisor
	 * to read the bps rate the chip has currently
	 * loaded.
	 */
	int			magic;
	int			irq;
	int			flags; 		/* defined in tty.h */

	char break_abort;   /* Is serial console in, so process brk/abrt */
	char is_cons;       /* Is this our console. */

	int			baud;
	int			baud_base;
	int			type; 		/* UART type */
	struct tty_struct 	*tty;
	int			xmit_fifo_size;
	int			recv_fifo_size;
	int			custom_divisor;
	int			x_char;	/* xon/xoff character */
	int			close_delay;
	unsigned short		closing_wait;
	unsigned long		event;
	int			line;
	int			count;	    /* # of fd on device */
	int			blocked_open; /* # of blocked opens */
        struct dma_descriptor_block *xmit_desc;
	unsigned char 		*xmit_buf;
	int			xmit_head;
	int			xmit_tail;
	int			xmit_cnt;
        unsigned char           *recv_buf;
        int                     recv_head;
        int                     recv_tail;
        int                     recv_cnt;
        struct timer_list       recv_timer;
        spinlock_t              recv_lock;

	struct work_struct	tqueue;
	struct work_struct	tqueue_hangup;
	struct termios		normal_termios;
	
	wait_queue_head_t	open_wait;
	wait_queue_head_t	close_wait;
};

#define UART_IRQ_NUM	10	/* change accordingly */

/*
 * Events are used to schedule things to happen at timer-interrupt
 * time, instead of at rs interrupt time.
 */
#define RS_EVENT_WRITE_WAKEUP	0
#define RS_EVENT_READ		1

#endif /* __KERNEL__ */
#endif /* (_Bf533_SERIAL_H) */
