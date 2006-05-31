/* bfin_serial_5xx.h: Definitions for the BlackFin DSP serial driver.
 * Copyright (C) 2003	Bas Vermeulen <bas@buyways.nl>
 * 			BuyWays B.V. (www.buyways.nl)
 *
 * Copyright (C) 2005   Sonic Zhang	<sonic.zhang@analog.com>
 * Copyright (C) 2004   LG Soft India
 * Copyright (C) 2001   Tony Z. Kou	tonyko@arcturusnetworks.com
 * Copyright (C) 2001   Arcturus Networks Inc. <www.arcturusnetworks.com>
 *
 * Based on code from 68328serial.c which was:
 * Copyright (C) 1995       David S. Miller    <davem@caip.rutgers.edu>
 * Copyright (C) 1998       Kenneth Albanowski <kjahds@kjahds.com>
 * Copyright (C) 1998, 1999 D. Jeff Dionne     <jeff@uclinux.org>
 * Copyright (C) 1999       Vladimir Gurevich  <vgurevic@cisco.com>
 *
 * $Id$
 */

#ifndef _BFIN_SERIAL_5xx_H
#define _BFIN_SERIAL_5xx_H

struct dma_descriptor_block;

struct dma_descriptor_block {
	struct dma_descriptor_block *next;
	void *start_addr;
	unsigned short dma_config;
	unsigned short x_count;
	unsigned short x_modify;
	unsigned short y_count;
	unsigned short y_modify;
} __attribute__ ((packed));

/*
 * For the close wait times, 0 means wait forever for serial port to
 * flush its output.  65535 means don't wait at all.
 */
#define S_CLOSING_WAIT_NONE	65535

/*
 * Definitions for S_struct (and serial_struct) flags field
 */
#define S_HUP_NOTIFY		0x0001	/* Notify getty on hangups and closes on the callout port */
#define S_FLAGS			0x0FFF	/* Possible legal S flags */
#define S_USR_MASK		0x0430	/* Legal flags that non-privileged users can set or reset */

/* Internal flags used only by kernel/chr_drv/serial.c */
#define S_INITIALIZED		0x80000000	/* Serial port was initialized */
#define S_CALLOUT_ACTIVE	0x40000000	/* Call out device is active */
#define S_NORMAL_ACTIVE		0x20000000	/* Normal device is active */
#define S_CLOSING		0x08000000	/* Serial port is closing */

/* Software state per channel */

#ifdef __KERNEL__
/*
 * This is our internal structure for each serial port's registers.
 *
 */
struct uart_registers {
	volatile unsigned short *rpUART_THR;
	volatile unsigned short *rpUART_RBR;
	volatile unsigned short *rpUART_DLL;
	volatile unsigned short *rpUART_IER;
	volatile unsigned short *rpUART_DLH;
	volatile unsigned short *rpUART_IIR;
	volatile unsigned short *rpUART_LCR;
	volatile unsigned short *rpUART_MCR;
	volatile unsigned short *rpUART_LSR;
	volatile unsigned short *rpUART_SCR;
	volatile unsigned short *rpUART_GCTL;
};

/*
 * This is our internal structure for each serial port's state.
 *
 * Many fields are paralleled by the structure used by the serial_struct
 * structure.
 *
 * For definitions of the flags field, see tty.h
 */

struct bfin_serial {
	/* We need to know the current clock divisor
	 * to read the bps rate the chip has currently
	 * loaded.
	 */
	int magic;
	int rx_DMA_channel;
	int tx_DMA_channel;
	int rx_irq;
	int tx_irq;
	unsigned int tx_xcount;	/* tx_xcount>0 means TX DMA is working. */
	int flags;		/* defined in tty.h */

	char break_abort;	/* Is serial console in, so process brk/abrt */
	char is_cons;		/* Is this our console. */

	int baud;
	int baud_base;
	int type;		/* UART type */
	struct tty_struct *tty;
	int xmit_fifo_size;
	int recv_fifo_size;
	int custom_divisor;
	int x_char;		/* xon/xoff character */
	int close_delay;
	unsigned short closing_wait;
	unsigned long event;
	int line;
	int count;		/* # of fd on device */
	int blocked_open;	/* # of blocked opens */
	unsigned char *xmit_buf;
	int xmit_head;
	int xmit_tail;
	int xmit_cnt;
	spinlock_t xmit_lock;
	unsigned char *recv_buf;
	int recv_head;
	int recv_tail;
	int recv_cnt;
	spinlock_t recv_lock;
	struct timer_list dma_timer;

	struct work_struct tqueue;
	struct work_struct tqueue_hangup;
	struct termios normal_termios;

	wait_queue_head_t open_wait;
	wait_queue_head_t close_wait;

	struct uart_registers regs;
};

/*
 * Events are used to schedule things to happen at timer-interrupt
 * time, instead of at rs interrupt time.
 */
#define	RS_EVENT_WRITE_WAKEUP	0
#define	RS_EVENT_READ		1
#define	RS_EVENT_WRITE		2

#endif				/* __KERNEL__ */
#endif				/* (_BFIN_SERIAL_5xx_H) */
