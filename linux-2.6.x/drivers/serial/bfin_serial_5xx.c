/* bf5xx_serial.c: Serial driver for BlackFin DSP internal UART.
 * Copyright (c) 2003	Bas Vermeulen <bas@buyways.nl>,
 * 			BuyWays B.V. (www.buyways.nl)
 *
 * Copyright(c) 2005	Sonic Zhang	<sonic.zhang@analog.com>
 * Copyright(c) 2004	LG Soft India
 * Copyright(c) 2003	Metrowerks	<mwaddel@metrowerks.com>
 * Copyright(c)	2001	Tony Z. Kou	<tonyko@arcturusnetworks.com>
 * Copyright(c)	2001-2002 Arcturus Networks Inc. <www.arcturusnetworks.com>
 *
 * Based on code from 68328 version serial driver imlpementation which was:
 * Copyright (C) 1995       David S. Miller    <davem@caip.rutgers.edu>
 * Copyright (C) 1998       Kenneth Albanowski <kjahds@kjahds.com>
 * Copyright (C) 1998, 1999 D. Jeff Dionne     <jeff@uclinux.org>
 * Copyright (C) 1999       Vladimir Gurevich  <vgurevic@cisco.com>
 *
 * $Id$
 */

#include <linux/module.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/serial.h>
#include <linux/serialP.h>
#include <linux/console.h>
#include <linux/reboot.h>
#include <linux/delay.h>

#include <asm/uaccess.h>
#include <asm/blackfin.h>
#include <asm/irq.h>
#ifdef CONFIG_SERIAL_BLACKFIN_DMA
#include <asm/dma.h>
#include <asm/cacheflush.h>
#include <linux/dma-mapping.h>
#endif

#include <asm/dpmc.h>		/* get_sclk() */

#include "bfin_serial_5xx.h"

#undef SERIAL_DEBUG_OPEN
#undef SERIAL_DEBUG_CALLTRACE
#undef SERIAL_DEBUG_TERMIOS

#if defined(CONFIG_BF534) || defined(CONFIG_BF536) || defined(CONFIG_BF537)
#define SIC_UART_MASK ((1<<(IRQ_UART_RX - IVG7)) | (1<<(IRQ_UART_TX - IVG7)) | (1<<(IRQ_UART1_RX - IVG7)) | (1<<(IRQ_UART1_TX - IVG7)))
#else				/* BF531/2/3, BF561 */
#define SIC_UART_MASK ((1<<(IRQ_UART_RX - IVG7)) | (1<<(IRQ_UART_TX - IVG7)) | (1<<(IRQ_UART_ERROR - IVG7)))
#endif

#define CSYNC __builtin_bfin_csync()
#define SSYNC __builtin_bfin_ssync()

#define ACCESS_LATCH(regs)	{ *(regs->rpUART_LCR) |= DLAB; SSYNC;}
#define ACCESS_PORT_IER(regs)	{ *(regs->rpUART_LCR) &= (~DLAB); SSYNC;}

#if defined (SERIAL_DEBUG_CALLTRACE)
#define FUNC_ENTER()  printk(KERN_DEBUG "%s: entered\n", __FUNCTION__)
#else
#define FUNC_ENTER()  do {} while (0)
#endif

#if defined (SERIAL_DEBUG_TERMIOS)
#define DUMP_TERMIOS(termios) printk(KERN_DEBUG "%s: termios %p c_iflag %08x " \
                      "c_oflag %08x c_cflag %08x c_lflag %08x c_line %02x " \
                      "VINTR %02x VQUIT %02x VERASE %02x VKILL %02x " \
                      "VEOF %02x VTIME %02x VMIN %02x VSWTC %02x "    \
                      "VSTART %02x VSTOP %02x VSUSP %02x VEOL %02x "  \
                      "VREPRINT %02x VDISCARD %02x VWERASE %02x "     \
                      "VLNEXT %02x VEOL2 %02x.\n",                    \
                      __FUNCTION__, termios, termios->c_iflag,        \
                      termios->c_oflag, termios->c_cflag, termios->c_lflag, \
                      termios->c_line, termios->c_cc[VINTR],          \
                      termios->c_cc[VQUIT], termios->c_cc[VERASE],    \
                      termios->c_cc[VKILL], termios->c_cc[VEOF],      \
                      termios->c_cc[VTIME], termios->c_cc[VMIN],      \
                      termios->c_cc[VSWTC], termios->c_cc[VSTART],    \
                      termios->c_cc[VSTOP], termios->c_cc[VSUSP],     \
                      termios->c_cc[VEOL], termios->c_cc[VREPRINT],   \
                      termios->c_cc[VDISCARD], termios->c_cc[VWERASE], \
                      termios->c_cc[VLNEXT], termios->c_cc[VEOL2])
#else
#define DUMP_TERMIOS(termios) do {} while (0)
#endif

/*
 *	Setup for console. Argument comes from the menuconfig
 */

#if defined(CONFIG_BAUD_9600)
#define CONSOLE_BAUD_RATE 	9600
#define DEFAULT_CBAUD		B9600
#elif defined(CONFIG_BAUD_19200)
#define CONSOLE_BAUD_RATE 	19200
#define DEFAULT_CBAUD		B19200
#elif defined(CONFIG_BAUD_38400)
#define CONSOLE_BAUD_RATE 	38400
#define DEFAULT_CBAUD		B38400
#elif defined(CONFIG_BAUD_57600)
#define CONSOLE_BAUD_RATE 	57600
#define DEFAULT_CBAUD		B57600
#elif defined(CONFIG_BAUD_115200)
#define CONSOLE_BAUD_RATE 	115200
#define DEFAULT_CBAUD		B115200
#endif

static int bfin_console_initted = 0;
static int bfin_console_baud = CONSOLE_BAUD_RATE;
static int bfin_console_cbaud = DEFAULT_CBAUD;

#ifdef CONFIG_CONSOLE
extern wait_queue_head_t keypress_wait;
#endif

/*
 *	Driver data structures.
 */
struct tty_driver *bfin_serial_driver;

/* serial subtype definitions */
#define SERIAL_TYPE_NORMAL	1

/* number of characters left in xmit buffer before we ask for more */
#define WAKEUP_CHARS 256

#if defined(CONFIG_BF534) || defined(CONFIG_BF536) || defined(CONFIG_BF537)
#define NR_PORTS 2
#else
#define NR_PORTS 1
#endif
static struct bfin_serial bfin_uart[NR_PORTS];

#ifndef MIN
#define MIN(a,b)	((a) < (b) ? (a) : (b))
#endif

#ifdef CONFIG_SERIAL_BLACKFIN_DMA

#define RX_XCOUNT  TTY_FLIPBUF_SIZE
#define RX_YCOUNT  (PAGE_SIZE / RX_XCOUNT)

#endif

static int rs_write(struct tty_struct *tty, const unsigned char *buf,
		    int count);
/*
 * This is used to figure out the divisor speeds and the timeouts
 */

static int baud_table[] =
    { 0, 50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800,
	9600, 19200, 38400, 57600, 115200, 230400
};

static int unix_baud_table[] =
    { B0, B50, B75, B110, B134, B150, B200, B300, B600, B1200, B1800, B2400, B4800,
	B9600, B19200, B38400, B57600, B115200, B230400
};

#define BAUD_TABLE_SIZE (sizeof(baud_table)/sizeof(baud_table[0]))

/* Forward declarations.... */
static void bfin_change_speed(struct bfin_serial *info);
static void bfin_set_baud(struct bfin_serial *info);

static unsigned short calc_divisor(int baud)
{
	unsigned long divisor = (get_sclk() / 8 + baud) / 2;
	/* accurate rounding */
	if (baud)
		divisor /= baud;

	if (divisor > 0xffff)
		divisor = 0x10000;	/* 0 is wrapped 0x10000 */
	else if (divisor < 1)
		divisor = 1;

	return (unsigned short)divisor;
}

static inline int serial_paranoia_check(struct bfin_serial *info, char *name,
					const char *routine)
{
	static const char *badmagic =
	    KERN_DEBUG "Warning: bad magic number for serial struct (%d,%d) in %s\n";
	static const char *badinfo =
	    KERN_DEBUG "Warning: null bfin_serial for (%d, %d) in %s\n";

	if (!info) {
		printk(badinfo, name, routine);
		return 1;
	}
	if (info->magic != SERIAL_MAGIC) {
		printk(badmagic, name, routine);
		return 1;
	}
	return 0;
}

/* Sets or clears DTR/RTS on the requested line */
static inline void bfin_rtsdtr(struct bfin_serial *info, int set)
{
	unsigned long flags = 0;
#ifdef SERIAL_DEBUG_OPEN
	printk(KERN_DEBUG "%s(%d): bfin_rtsdtr(info=%p,set=%d)\n",
	       __FILE__, __LINE__, info, set);
#endif
#if !defined(CONFIG_BF561)
	local_irq_save(flags);
	if (set) {
		/* set the RTS/CTS line */
		*pFIO_FLAG_C = (1 << 13);
		SSYNC;
	} else {
		/* clear it */
		*pFIO_FLAG_S = (1 << 13);
		SSYNC;
	}
	local_irq_restore(flags);
#endif
	return;
}

/*
 * ------------------------------------------------------------
 * rs_stop() and rs_start()
 *
 * This routines are called before setting or resetting tty->stopped.
 * They enable or disable transmitter interrupts, as necessary.
 * ------------------------------------------------------------
 */
static void rs_stop(struct tty_struct *tty)
{
	struct bfin_serial *info = (struct bfin_serial *)tty->driver_data;
	struct uart_registers *regs = &(info->regs);
	unsigned long flags = 0;

	if (serial_paranoia_check(info, tty->name, "rs_stop"))
		return;

	local_irq_save(flags);
	ACCESS_PORT_IER(regs)	/* Change access to IER & data port */
	*(regs->rpUART_IER) &= ~ETBEI;
	SSYNC;
	local_irq_restore(flags);
}

static void local_put_char(struct bfin_serial *info, char ch)
{
	struct uart_registers *regs = &(info->regs);
	int flags = 0;
	unsigned short status;

	local_irq_save(flags);

	do {
		CSYNC;
		status = *(regs->rpUART_LSR);
		SSYNC;
	} while (!(status & THRE));

	ACCESS_PORT_IER(regs)
	    * (regs->rpUART_THR) = ch;
	SSYNC;

	local_irq_restore(flags);
}

static void rs_start(struct tty_struct *tty)
{
	struct bfin_serial *info = (struct bfin_serial *)tty->driver_data;
	struct uart_registers *regs = &(info->regs);
	unsigned long flags = 0;
#ifdef CONFIG_SERIAL_BLACKFIN_DMA
	unsigned int irqstat;
#endif

	FUNC_ENTER();

	if (serial_paranoia_check(info, tty->name, "rs_start"))
		return;

	local_irq_save(flags);
	ACCESS_PORT_IER(regs)	/* Change access to IER & data port */
#ifdef CONFIG_SERIAL_BLACKFIN_DMA
	    irqstat = get_dma_curr_irqstat(info->tx_DMA_channel);
	if (irqstat & 8 && info->tx_xcount > 0 && info->xmit_buf) {
		*(regs->rpUART_IER) |= ETBEI;
		SSYNC;
	}
#else
	    if (info->xmit_cnt && info->xmit_buf
		&& !(*(regs->rpUART_IER) & ETBEI)) {
		*(regs->rpUART_IER) |= ETBEI;
		SSYNC;
	}
#endif

	local_irq_restore(flags);
}

/* Drop into either the boot monitor or kgdb upon receiving a break
 * from keyboard/console input.
 */
static void batten_down_hatches(void)
{
	FUNC_ENTER();
}

static inline void status_handle(struct bfin_serial *info,
				 unsigned short status)
{
	FUNC_ENTER();

	/* If this is console input and this is a
	 * 'break asserted' status change interrupt
	 * see if we can drop into the debugger
	 */
	if ((status & BI) && info->break_abort)
		batten_down_hatches();
	return;
}

#ifdef CONFIG_SERIAL_BLACKFIN_DMA
static void dma_receive_chars(struct bfin_serial *info, int in_timer)
{
	struct tty_struct *tty = info->tty;
	int len = 0;
	int curpos;

	spin_lock_bh(&(info->recv_lock));

	/*
	 * Current DMA receiving buffer is one PAGE, which is devied into 8 buffer lines.
	 * Autobuffered 2D DMA operation is applied to receive chars from the UART.
	 * This function is called each time one buffer line is full or the timer is over.
	 */
	if ((curpos = get_dma_curr_xcount(info->rx_DMA_channel)) == 0
	    && in_timer)
		goto unlock_and_exit;
	curpos =
	    TTY_FLIPBUF_SIZE - curpos + (RX_YCOUNT -
					 get_dma_curr_ycount(info->
							     rx_DMA_channel)) *
	    TTY_FLIPBUF_SIZE;

	if (curpos == info->recv_tail)
		goto unlock_and_exit;
	else if (curpos > info->recv_tail)
		info->recv_head = curpos;
	else
		info->recv_head = PAGE_SIZE;

	/*
	 * Check for a valid value of recv_head
	 */
	if ((info->recv_head < 0) || (info->recv_head > PAGE_SIZE)) {
		info->recv_head = 0;
		goto unlock_and_exit;
	}
#if defined(CONFIG_CONSOLE)
	if (info->is_cons && (info->recv_tail != info->recv_head))
		wake_up(&keypress_wait);
#endif
	if (!tty) {
		goto unlock_and_exit;
	}

	len = info->recv_head - info->recv_tail;

	len = tty_buffer_request_room(tty, len);
	if (len > 0) {
		tty_insert_flip_string(tty,
		       info->recv_buf + info->recv_tail, len);
		info->recv_tail += len;
	}

	if (info->recv_head >= PAGE_SIZE)
		info->recv_head = 0;
	if (info->recv_tail >= PAGE_SIZE)
		info->recv_tail = 0;

	tty_flip_buffer_push(tty);
      unlock_and_exit:
	spin_unlock_bh(&(info->recv_lock));
}

static void dma_transmit_chars(struct bfin_serial *info)
{
	struct uart_registers *regs = &(info->regs);
	if (info->tx_xcount) {
		return;
	}

	spin_lock_bh(&(info->xmit_lock));

	/*
	 * tx_xcount is checked here to make sure the dma won't be started if it is working.
	 */
	if (info->tx_xcount) {
		goto clear_and_return;
	}

	if (info->x_char) {	/* Send next char */
		local_put_char(info, info->x_char);
		info->x_char = 0;
	}

	if ((info->xmit_cnt <= 0) || info->tty->stopped) {	/* TX ints off */
		goto clear_and_return;
	}

	/* Send char */
	info->tx_xcount = info->xmit_cnt;
	if (info->tx_xcount > SERIAL_XMIT_SIZE - info->xmit_tail)
		info->tx_xcount = SERIAL_XMIT_SIZE - info->xmit_tail;

	/*
	 * Only transfer data by dma when count >4.
	 * If count <=4, the dma engine may not generate correct interrupt after it is done.
	 */
	if (info->tx_xcount > 4) {
		set_dma_config(info->tx_DMA_channel,
			       set_bfin_dma_config(DIR_READ, DMA_FLOW_STOP,
						   INTR_ON_BUF,
						   DIMENSION_LINEAR,
						   DATA_SIZE_8));
		set_dma_start_addr(info->tx_DMA_channel,
				   (unsigned long)(info->xmit_buf +
						   info->xmit_tail));
		set_dma_x_count(info->tx_DMA_channel, info->tx_xcount);
		ACCESS_PORT_IER(regs)
		    SSYNC;
		enable_dma(info->tx_DMA_channel);
		*(regs->rpUART_IER) |= ETBEI;
		SSYNC;
	} else {
		while (info->tx_xcount > 0) {
			local_put_char(info, info->xmit_buf[info->xmit_tail++]);
			info->xmit_tail %= SERIAL_XMIT_SIZE;
			info->xmit_cnt--;
			info->tx_xcount--;
		}

		if (info->xmit_cnt < WAKEUP_CHARS) {
			info->event |= 1 << RS_EVENT_WRITE_WAKEUP;
			schedule_work(&info->tqueue);
		}
	}

      clear_and_return:
	spin_unlock_bh(&(info->xmit_lock));
}
#endif

void receive_chars(struct bfin_serial *info, struct pt_regs *regs)
{
	struct uart_registers *uart_regs = &(info->regs);
	struct tty_struct *tty = info->tty;
	unsigned char ch = 0, flag = 0;
	unsigned short status = 0;
	FUNC_ENTER();

	/*
	 * This do { } while() loop will get ALL chars out of Rx FIFO
	 */
	do {
		ACCESS_PORT_IER(uart_regs);
		CSYNC;
		ch = (unsigned char)*(uart_regs->rpUART_RBR);

		if (info->is_cons) {
			CSYNC;
			status = *(uart_regs->rpUART_LSR);
			if (status & BI) {	/* break received */
				status_handle(info, status);
				return;
			}
#ifdef CONFIG_CONSOLE
			wake_up(&keypress_wait);
#endif
		}

		if (!tty) {
			goto clear_and_exit;
		}
		if (status & PE) {
			flag = TTY_PARITY;
			status_handle(info, status);
		} else if (status & OE) {
			flag = TTY_OVERRUN;
			status_handle(info, status);
		} else if (status & FE) {
			flag = TTY_FRAME;
			status_handle(info, status);
		}
		tty_insert_flip_char(tty, ch, flag);
	} while (status & DR);
	tty_flip_buffer_push(tty);

      clear_and_exit:
	return;
}

static void transmit_chars(struct bfin_serial *info)
{
	struct uart_registers *regs = &(info->regs);

	if (info->x_char) {	/* Send next char */
		local_put_char(info, info->x_char);
		info->x_char = 0;
		goto clear_and_return;
	}

	if ((info->xmit_cnt <= 0) || info->tty->stopped) {	/* TX ints off */
		ACCESS_PORT_IER(regs)	/* Change access to IER & data port */
		    *(regs->rpUART_IER) &= ~ETBEI;
		SSYNC;
		goto clear_and_return;
	}

	/* Send char */
	local_put_char(info, info->xmit_buf[info->xmit_tail++]);
	info->xmit_tail = info->xmit_tail & (SERIAL_XMIT_SIZE - 1);
	info->xmit_cnt--;

	if (info->xmit_cnt < WAKEUP_CHARS) {
		info->event |= 1 << RS_EVENT_WRITE_WAKEUP;
		schedule_work(&info->tqueue);
	}
	if (info->xmit_cnt <= 0) {	/* All done for now... TX ints off */
		ACCESS_PORT_IER(regs)	/* Change access to IER & data port */
		    *(regs->rpUART_IER) &= ~ETBEI;
		SSYNC;
		goto clear_and_return;
	}

      clear_and_return:
	/* Clear interrupt (should be auto) */
	return;
}

/*
 * This is the serial driver's generic interrupt routine
 * Note: Generally it should be attached to general interrupt 10, responsile
 *       for UART0&1 RCV and XMT interrupt, to make sure the invoked interrupt
 *       source, look into bit 10-13 of SIC_ISR(peripheral interrupt status reg.
 *       Finally, to see what can be done about request_irq(......)
 */
irqreturn_t rs_interrupt(int irq, void *dev_id, struct pt_regs * regs)
{
	struct bfin_serial *info = (struct bfin_serial *)dev_id;
	struct uart_registers *uart_regs = &(info->regs);
	unsigned short iir;	/* Interrupt Identification Register */

	unsigned short rx, lsr;
	unsigned int sic_status = 0;
	CSYNC;
#if defined(CONFIG_BF561)
	sic_status = *pSICA_ISR1;
#else
	sic_status = *pSIC_ISR;
#endif
	if (sic_status & SIC_UART_MASK) {
		CSYNC;
		iir = *(uart_regs->rpUART_IIR);

		if (!(iir & NINT)) {
			switch (iir & 0x06) {
			case 0x06:
				/* Change access to IER & data port */
				ACCESS_PORT_IER(uart_regs);
				CSYNC;
				lsr = *(uart_regs->rpUART_LSR);
				break;
			case STATUS(2):	/*UART_IIR_RBR: */
				/* Change access to IER & data port */
				ACCESS_PORT_IER(uart_regs)
				    CSYNC;
				if (*(uart_regs->rpUART_LSR) & DR) {
					CSYNC;
					rx = *(uart_regs->rpUART_RBR);
					receive_chars(info, regs);
				}
				break;
			case STATUS_P1:	/*UART_IIR_THR: */
				/* Change access to IER & data port */
				ACCESS_PORT_IER(uart_regs)
				    CSYNC;
				if (*(uart_regs->rpUART_LSR) & THRE) {
					transmit_chars(info);
				}
				break;
			case STATUS(0):	/*UART_IIR_MSR: */
				break;
			}
			return IRQ_HANDLED;
		}
		return IRQ_NONE;
	}
	return IRQ_NONE;
}

static void do_softint(void *private_)
{
	struct bfin_serial *info = (struct bfin_serial *)private_;
	struct tty_struct *tty;

	tty = info->tty;
	if (!tty)
		return;

	if (test_and_clear_bit(RS_EVENT_WRITE_WAKEUP, &info->event)) {
		if ((tty->flags & (1 << TTY_DO_WRITE_WAKEUP)) &&
		    tty->ldisc.write_wakeup)
			(tty->ldisc.write_wakeup) (tty);
		wake_up_interruptible(&tty->write_wait);
	}
#ifdef CONFIG_SERIAL_BLACKFIN_DMA
	if (test_and_clear_bit(RS_EVENT_READ, &info->event)) {
		dma_receive_chars(info, 0);
	}
	if (test_and_clear_bit(RS_EVENT_WRITE, &info->event)) {
		dma_transmit_chars(info);
	}
#endif
}

/*
 * This routine is called from the scheduler tqueue when the interrupt
 * routine has signalled that a hangup has occurred.  The path of
 * hangup processing is:
 *
 * 	serial interrupt routine -> (scheduler tqueue) ->
 * 	do_serial_hangup() -> tty->hangup() -> rs_hangup()
 *
 */
static void do_serial_hangup(void *private_)
{
	struct bfin_serial *info = (struct bfin_serial *)private_;
	struct tty_struct *tty;

	FUNC_ENTER();

	tty = info->tty;
	if (!tty)
		return;

	tty_hangup(tty);
}

#ifdef CONFIG_SERIAL_BLACKFIN_DMA

#define TIME_INTERVAL	5

static void dma_start_recv(struct bfin_serial *info)
{
	FUNC_ENTER();

	if (((get_dma_curr_irqstat(info->rx_DMA_channel) & DMA_RUN) == 0)
	    || get_dma_curr_irqstat(info->rx_DMA_channel) & DMA_DONE) {
		set_dma_config(info->rx_DMA_channel,
			       set_bfin_dma_config(DIR_WRITE, DMA_FLOW_AUTO,
						   INTR_ON_ROW, DIMENSION_2D,
						   DATA_SIZE_8));
		set_dma_x_count(info->rx_DMA_channel, RX_XCOUNT);
		set_dma_x_modify(info->rx_DMA_channel, 1);
		set_dma_y_count(info->rx_DMA_channel, RX_YCOUNT);
		set_dma_y_modify(info->rx_DMA_channel, 1);
		set_dma_start_addr(info->rx_DMA_channel,
				   (unsigned long)info->recv_buf);

		enable_dma(info->rx_DMA_channel);
	} else {
		printk(KERN_DEBUG "bfin_serial: DMA started while already running!\n");
	}
}

static void uart_dma_timer(struct bfin_serial *info)
{
	dma_transmit_chars(info);
	dma_receive_chars(info, 1);
	info->dma_timer.expires = jiffies + TIME_INTERVAL;
	add_timer(&info->dma_timer);
}

#endif

static int startup(struct bfin_serial *info)
{
	struct uart_registers *regs = &(info->regs);
	unsigned long flags = 0;

	FUNC_ENTER();
	init_timer(&info->dma_timer);

	*(regs->rpUART_GCTL) |= UCEN;
	SSYNC;

	if (info->flags & S_INITIALIZED)
		return 0;

	if (!info->xmit_buf) {
#ifdef CONFIG_SERIAL_BLACKFIN_DMA
		dma_addr_t dma_handle;
		info->xmit_buf =
		    (unsigned char *)dma_alloc_coherent(NULL, PAGE_SIZE,
							&dma_handle, GFP_DMA);
#else
		info->xmit_buf = (unsigned char *)__get_free_page(GFP_KERNEL);
#endif
		if (!info->xmit_buf)
			return -ENOMEM;
	}

	if (!info->recv_buf) {
#ifdef CONFIG_SERIAL_BLACKFIN_DMA
		dma_addr_t dma_handle;
		info->recv_buf =
		    (unsigned char *)dma_alloc_coherent(NULL, PAGE_SIZE,
							&dma_handle, GFP_DMA);
#else
		info->recv_buf = (unsigned char *)__get_free_page(GFP_KERNEL);
#endif
		if (!info->recv_buf) {
#ifdef CONFIG_SERIAL_BLACKFIN_DMA
			dma_addr_t dma_handle = 0;
			dma_free_coherent(NULL, PAGE_SIZE, info->xmit_buf,
					  dma_handle);
#else
			free_page((unsigned long)info->xmit_buf);
#endif
			return -ENOMEM;
		}
	}

	local_irq_save(flags);

	/*
	 * Clear the FIFO buffers and disable them
	 * (they will be reenabled in bfin_change_speed())
	 */

	info->xmit_fifo_size = 1;
	ACCESS_PORT_IER(regs)
	    /* Change access to IER & data port */
	    bfin_rtsdtr(info, 1);

	if (info->tty)
		clear_bit(TTY_IO_ERROR, &info->tty->flags);
	info->xmit_cnt = info->xmit_head = info->xmit_tail = 0;

#ifdef CONFIG_SERIAL_BLACKFIN_DMA

	set_dma_x_modify(info->tx_DMA_channel, 1);
	info->xmit_lock = SPIN_LOCK_UNLOCKED;
	/*
	 * Start the receive DMA
	 */
	info->recv_cnt = info->recv_head = info->recv_tail = 0;
	info->recv_lock = SPIN_LOCK_UNLOCKED;
	dma_start_recv(info);

	/*
	 * Start the DMA timer
	 */
	info->dma_timer.data = (unsigned long)info;
	info->dma_timer.function = (void *)uart_dma_timer;
	info->dma_timer.expires = jiffies + TIME_INTERVAL;
	add_timer(&info->dma_timer);
#endif

	/*
	 * and set the speed of the serial port
	 */
	bfin_change_speed(info);

	info->flags |= S_INITIALIZED;
	local_irq_restore(flags);
	return 0;
}

/*
 * This routine will shutdown a serial port; interrupts are disabled, and
 * DTR is dropped if the hangup on close termio flag is on.
 */
static void shutdown(struct bfin_serial *info)
{
	struct uart_registers *regs = &(info->regs);
	unsigned long flags = 0;

	FUNC_ENTER();

	if (!(info->flags & S_INITIALIZED))
		return;

	local_irq_save(flags);

#ifdef CONFIG_SERIAL_BLACKFIN_DMA
	del_timer(&info->dma_timer);
#endif

	while(!(*(regs->rpUART_LSR)&TEMT) || info->xmit_cnt>0)
		msleep(50);

	ACCESS_PORT_IER(regs)	/* Change access to IER & data port */
	*(regs->rpUART_IER) = 0;
	SSYNC;
	*(regs->rpUART_GCTL) &= ~UCEN;
	SSYNC;
	*(regs->rpUART_LCR) = 0;
	SSYNC;

#ifdef CONFIG_SERIAL_BLACKFIN_DMA
	disable_dma(info->rx_DMA_channel);
	disable_dma(info->tx_DMA_channel);
#endif

	if (!info->tty || (info->tty->termios->c_cflag & HUPCL))
		bfin_rtsdtr(info, 0);

	if (info->xmit_buf) {
#ifdef CONFIG_SERIAL_BLACKFIN_DMA
		dma_addr_t dma_handle = 0;
		dma_free_coherent(NULL, PAGE_SIZE, info->xmit_buf, dma_handle);
#else
		free_page((unsigned long)info->xmit_buf);
#endif
		info->xmit_buf = 0;
	}

	if (info->recv_buf) {
#ifdef CONFIG_SERIAL_BLACKFIN_DMA
		dma_addr_t dma_handle = 0;
		dma_free_coherent(NULL, PAGE_SIZE, info->recv_buf, dma_handle);
#else
		free_page((unsigned long)info->recv_buf);
#endif
		info->recv_buf = 0;
	}

	if (info->tty)
		set_bit(TTY_IO_ERROR, &info->tty->flags);

	info->flags &= ~S_INITIALIZED;
	local_irq_restore(flags);
}

/*
 * This routine is called to set the UART divisor registers to match
 * the specified baud rate for a serial port.
 */
static void bfin_change_speed(struct bfin_serial *info)
{
	unsigned short uart_dl;
	unsigned cflag, flags, cval;
	struct uart_registers *regs = &(info->regs);

	int i;
	FUNC_ENTER();

	if (!info->tty || !info->tty->termios)
		return;

	cflag = info->tty->termios->c_cflag;

	/* byte size and parity */
	switch (cflag & CSIZE) {
	case CS5:
		cval = WLS(5);
		break;
	case CS6:
		cval = WLS(6);
		break;
	case CS7:
		cval = WLS(7);
		break;
	case CS8:		/* 8-bit should be default */
	default:
		cval = WLS(8);
		break;
	}

	if (cflag & CSTOPB)
		cval |= STB;
	if (cflag & PARENB)
		cval |= PEN;
	if (!(cflag & PARODD))
		cval |= EPS;
	if (cflag & CRTSCTS)
		printk(KERN_DEBUG "%s: CRTSCTS not supported. Ignoring.\n",
		       __FUNCTION__);

	for (i = 0; i < BAUD_TABLE_SIZE; i++) {
		if (unix_baud_table[i] == (cflag & CBAUD))
			break;
	}

	if (i == BAUD_TABLE_SIZE) {
		printk(KERN_DEBUG "%s: baud rate not supported: 0%o\n",
		       __FUNCTION__, cflag & CBAUD);
		i = 3;
	}

	info->baud = baud_table[i];

	uart_dl = calc_divisor(baud_table[i]);

	local_irq_save(flags);
	/* Disable interrupts */
	ACCESS_PORT_IER(regs)
	* (regs->rpUART_IER) &= ~(ETBEI | ERBFI);
	SSYNC;

	ACCESS_LATCH(regs)	/*Set to access divisor latch */
	*(regs->rpUART_DLL) = uart_dl;
	SSYNC;
	*(regs->rpUART_DLH) = uart_dl >> 8;
	SSYNC;

	*(regs->rpUART_LCR) = cval;
	SSYNC;

	/* Enable interrupts */
	ACCESS_PORT_IER(regs)
#ifdef CONFIG_SERIAL_BLACKFIN_DMA
	*(regs->rpUART_IER) = ERBFI | ELSI;
#else
	*(regs->rpUART_IER) = ERBFI | ETBEI | ELSI;
#endif
	SSYNC;

#ifdef CONFIG_IRTTY_SIR
	/* enable irda function */
	if(cflag & TIOCM_RI) {
		*(regs->rpUART_GCTL) |= IREN;
		SSYNC;
		*(regs->rpUART_GCTL) |= RPOLC;
		SSYNC;
		printk(KERN_DEBUG "KSDBG:irda enabled,rpolc changed\n");
	}
#endif
	/* Enable the UART */
	*(regs->rpUART_GCTL) |= UCEN;
	SSYNC;

	local_irq_restore(flags);
	printk(KERN_DEBUG "bfin_change_speed: baud = %d, cval = 0x%x\n", baud_table[i],
	       cval);
	return;
}

static void rs_set_ldisc(struct tty_struct *tty)
{
	struct bfin_serial *info = (struct bfin_serial *)tty->driver_data;

	FUNC_ENTER();

	if (serial_paranoia_check(info, tty->name, "rs_set_ldisc"))
		return;

	info->is_cons = (tty->termios->c_line == N_TTY);

	printk(KERN_DEBUG "ttyS%d console mode %s\n", info->line,
	       info->is_cons ? "on" : "off");
}

static void rs_flush_chars(struct tty_struct *tty)
{
	struct bfin_serial *info = (struct bfin_serial *)tty->driver_data;
#ifndef CONFIG_SERIAL_BLACKFIN_DMA
	struct uart_registers *regs = &(info->regs);
	unsigned long flags = 0;
#endif

	if (serial_paranoia_check(info, tty->name, "rs_flush_chars"))
		return;

	if (info->xmit_cnt <= 0 || tty->stopped || tty->hw_stopped ||
	    !info->xmit_buf)
		return;

#ifdef CONFIG_SERIAL_BLACKFIN_DMA
	if (info->xmit_cnt > 0) {
		dma_transmit_chars(info);
	}
#else
	local_irq_save(flags);

	ACCESS_PORT_IER(regs)	/* Change access to IER & data port */
	    *(regs->rpUART_IER) |= ETBEI;
	SSYNC;
	if (*(regs->rpUART_LSR) & TEMT) {
		/* Send char */
		local_put_char(info, info->xmit_buf[info->xmit_tail++]);
		info->xmit_tail = info->xmit_tail & (SERIAL_XMIT_SIZE - 1);
		info->xmit_cnt--;
	}

	local_irq_restore(flags);
#endif
}

static int rs_write(struct tty_struct *tty, const unsigned char *buf, int count)
{
	int c, total = 0;
	struct bfin_serial *info = (struct bfin_serial *)tty->driver_data;
#ifndef CONFIG_SERIAL_BLACKFIN_DMA
	struct uart_registers *regs = &(info->regs);
#endif
	unsigned long flags = 0;

	if (serial_paranoia_check(info, tty->name, "rs_write"))
		return 0;

	if (!tty || !info->xmit_buf)
		return 0;

	while (1) {
		c = MIN(count, MIN(SERIAL_XMIT_SIZE - info->xmit_cnt - 1,
				   SERIAL_XMIT_SIZE - info->xmit_head));
		if (c <= 0)
			break;

		local_irq_save(flags);

		memcpy(info->xmit_buf + info->xmit_head, buf, c);
		info->xmit_head = (info->xmit_head + c) % SERIAL_XMIT_SIZE;
		info->xmit_cnt += c;
		local_irq_restore(flags);
		buf += c;
		count -= c;
		total += c;
	}

	if (info->xmit_cnt && !tty->stopped && !tty->hw_stopped) {
#ifdef CONFIG_SERIAL_BLACKFIN_DMA
		if (info->xmit_cnt > 0 && info->xmit_head == 0) {
			dma_transmit_chars(info);
		}
#else
		/* Enable transmitter */
		local_irq_save(flags);
		ACCESS_PORT_IER(regs)	/* Change access to IER & data port */
		    *(regs->rpUART_IER) |= ETBEI;
		SSYNC;
		while (!(*(regs->rpUART_LSR) & TEMT))
			SSYNC;

		if (*(regs->rpUART_LSR) & TEMT) {
			local_put_char(info, info->xmit_buf[info->xmit_tail++]);
			info->xmit_tail =
			    info->xmit_tail & (SERIAL_XMIT_SIZE - 1);
			info->xmit_cnt--;
		}

		local_irq_restore(flags);
#endif
	}

	return total;
}

static int rs_write_room(struct tty_struct *tty)
{
	struct bfin_serial *info = (struct bfin_serial *)tty->driver_data;
	int ret;

	if (serial_paranoia_check(info, tty->name, "rs_write_room"))
		return 0;
	ret = SERIAL_XMIT_SIZE - info->xmit_cnt - 1;
	if (ret < 0)
		ret = 0;
	return ret;
}

static int rs_chars_in_buffer(struct tty_struct *tty)
{
	struct bfin_serial *info = (struct bfin_serial *)tty->driver_data;

	if (serial_paranoia_check(info, tty->name, "rs_chars_in_buffer"))
		return 0;
	return 0;
}

static void rs_flush_buffer(struct tty_struct *tty)
{
	unsigned long flags = 0;
	struct bfin_serial *info = (struct bfin_serial *)tty->driver_data;
#ifdef CONFIG_SERIAL_BLACKFIN_DMA
	struct uart_registers *regs = &(info->regs);
	unsigned int irqstat;
#endif
	FUNC_ENTER();

	if (serial_paranoia_check(info, tty->name, "rs_flush_buffer"))
		return;
	local_irq_save(flags);
#ifdef CONFIG_SERIAL_BLACKFIN_DMA
	irqstat = get_dma_curr_irqstat(info->tx_DMA_channel);
	if (irqstat & 8 && info->tx_xcount > 0 && info->xmit_buf) {
		ACCESS_PORT_IER(regs)
		    * (regs->rpUART_IER) &= ~ETBEI;
		SSYNC;
		disable_dma(info->tx_DMA_channel);
		clear_dma_irqstat(info->tx_DMA_channel);
		info->xmit_tail += info->tx_xcount;
		info->xmit_tail %= SERIAL_XMIT_SIZE;
		info->tx_xcount = 0;
	}
#endif
	info->xmit_head = info->xmit_tail;
	info->xmit_cnt = 0;
	local_irq_restore(flags);
	wake_up_interruptible(&tty->write_wait);
	if ((tty->flags & (1 << TTY_DO_WRITE_WAKEUP)) &&
	    tty->ldisc.write_wakeup)
		(tty->ldisc.write_wakeup) (tty);
}

/*
 * ------------------------------------------------------------
 * rs_throttle()
 *
 * This routine is called by the upper-layer tty layer to signal that
 * incoming characters should be throttled.
 * ------------------------------------------------------------
 */
static void rs_throttle(struct tty_struct *tty)
{
	struct bfin_serial *info = (struct bfin_serial *)tty->driver_data;

	FUNC_ENTER();
	if (serial_paranoia_check(info, tty->name, "rs_throttle"))
		return;
	if (I_IXOFF(tty))
		info->x_char = STOP_CHAR(tty);
}

static void rs_unthrottle(struct tty_struct *tty)
{
	struct bfin_serial *info = (struct bfin_serial *)tty->driver_data;

	FUNC_ENTER();
	if (serial_paranoia_check(info, tty->name, "rs_unthrottle"))
		return;

	if (I_IXOFF(tty)) {
		if (info->x_char)
			info->x_char = 0;
		else
			info->x_char = START_CHAR(tty);
	}
}

/*
 * ------------------------------------------------------------
 * rs_ioctl() and friends
 * ------------------------------------------------------------
 */

static int get_serial_info(struct bfin_serial *info,
			   struct serial_struct *retinfo)
{
	struct serial_struct tmp;

	if (!retinfo)
		return -EFAULT;
	memset(&tmp, 0, sizeof(tmp));
	tmp.type = info->type;
	tmp.line = info->line;
	tmp.irq = info->rx_irq;
	tmp.flags = info->flags;
	tmp.baud_base = info->baud_base;
	tmp.close_delay = info->close_delay;
	tmp.closing_wait = info->closing_wait;
	tmp.custom_divisor = info->custom_divisor;
	copy_to_user(retinfo, &tmp, sizeof(*retinfo));
	return 0;
}

static int set_serial_info(struct bfin_serial *info,
			   struct serial_struct *new_info)
{
	struct serial_struct new_serial;
	struct bfin_serial old_info;
	int retval = 0;

	FUNC_ENTER();
	if (!new_info)
		return -EFAULT;
	copy_from_user(&new_serial, new_info, sizeof(new_serial));
	old_info = *info;

	if (!capable(CAP_SYS_ADMIN)) {
		if ((new_serial.baud_base != info->baud_base) ||
		    (new_serial.type != info->type) ||
		    (new_serial.close_delay != info->close_delay) ||
		    ((new_serial.flags & ~S_USR_MASK) !=
		     (info->flags & ~S_USR_MASK)))
			return -EPERM;
		info->flags = ((info->flags & ~S_USR_MASK) |
			       (new_serial.flags & S_USR_MASK));
		info->custom_divisor = new_serial.custom_divisor;
		goto check_and_exit;
	}

	if (info->count > 1)
		return -EBUSY;

	/*
	 * OK, past this point, all the error checking has been done.
	 * At this point, we start making changes.....
	 */

	info->baud_base = new_serial.baud_base;
	info->flags = ((info->flags & ~S_FLAGS) | (new_serial.flags & S_FLAGS));
	info->type = new_serial.type;
	info->close_delay = new_serial.close_delay;
	info->closing_wait = new_serial.closing_wait;

      check_and_exit:
	retval = startup(info);
	return retval;
}

/*
 * get_lsr_info - get line status register info
 *
 * Purpose: Let user call ioctl() to get info when the UART physically
 * 	    is emptied.  On bus types like RS485, the transmitter must
 * 	    release the bus after transmitting. This must be done when
 * 	    the transmit shift register is empty, not be done when the
 * 	    transmit holding register is empty.  This functionality
 * 	    allows an RS485 driver to be written in user space.
 */
static int get_lsr_info(struct bfin_serial *info, unsigned int *value)
{
	unsigned char status = 0;

	FUNC_ENTER();
	put_user(status, value);
	return 0;
}

static int set_modem_info(struct bfin_serial *info, unsigned int cmd,
			  unsigned int *value)
{
	unsigned int arg;

	FUNC_ENTER();
	if (copy_from_user(&arg, value, sizeof(int)))
		return -EFAULT;

	switch (cmd) {
	case TIOCMBIS:
		if (arg & TIOCM_DTR)
			bfin_rtsdtr(info, 1);
		break;
	case TIOCMBIC:
		if (arg & TIOCM_DTR)
			bfin_rtsdtr(info, 0);
		break;
	case TIOCMSET:
		bfin_rtsdtr(info, arg & TIOCM_DTR ? 1 : 0);
		break;
	default:
		return -EINVAL;
	}
	return 0;
}
/*
 * This routine sends a break character out the serial port.
 */
static void send_break(struct bfin_serial *info, unsigned int duration)
{
	unsigned long flags;
	struct uart_registers *regs = &(info->regs);

	local_irq_save(flags);
	*(regs->rpUART_LCR) |= SB;
	SSYNC;
	msleep_interruptible(duration);
	*(regs->rpUART_LCR) &= ~SB;
	SSYNC;
	local_irq_restore(flags);
}

static int rs_ioctl(struct tty_struct *tty, struct file *file,
		    unsigned int cmd, unsigned long arg)
{
	int retval;
	struct bfin_serial *info = (struct bfin_serial *)tty->driver_data;

	if (serial_paranoia_check(info, tty->name, "rs_ioctl"))
		return -ENODEV;

	if ((cmd != TIOCGSERIAL) && (cmd != TIOCSSERIAL) &&
	    (cmd != TIOCSERCONFIG) && (cmd != TIOCSERGWILD) &&
	    (cmd != TIOCSERSWILD) && (cmd != TIOCSERGSTRUCT) &&
	    (cmd != TCSBRK) && (cmd != TCSBRKP)) {
		if (tty->flags & (1 << TTY_IO_ERROR))
			return -EIO;
	}

	switch (cmd) {
	case TCSBRK:    /* SVID version: non-zero arg --> no break */
		retval = tty_check_change(tty);
		if (retval)
			return retval;
		tty_wait_until_sent(tty, 0);
		if (!arg)
			send_break(info, 250);  /* 1/4 second */
		return 0;
	case TCSBRKP:   /* support for POSIX tcsendbreak() */
		retval = tty_check_change(tty);
		if (retval)
			return retval;
		tty_wait_until_sent(tty, 0);
		send_break(info, arg ? arg*(100) : 250);
		return 0;
	case TIOCGSERIAL:
		return get_serial_info(info, (struct serial_struct *)arg);
	case TIOCSSERIAL:
		return set_serial_info(info, (struct serial_struct *)arg);
	case TIOCSERGETLSR:	/* Get line status register */
		return get_lsr_info(info, (unsigned int *)arg);

	case TIOCSERGSTRUCT:
		if (copy_to_user((struct bfin_serial *)arg,
				 info, sizeof(struct bfin_serial)))
			return -EFAULT;
		return 0;
	case TIOCMBIS:
	case TIOCMBIC:
	case TIOCMSET:
		return set_modem_info(info, cmd, (unsigned int *)arg);
	case TIOCSERGWILD:
	case TIOCSERSWILD:
		/* "setserial -W" is called in Debian boot */
		printk(KERN_DEBUG "TIOCSER?WILD ioctl obsolete, ignored.\n");
		return 0;
	default:
		return -ENOIOCTLCMD;
	}
	return 0;
}

static void rs_set_termios(struct tty_struct *tty, struct termios *old_termios)
{
	struct bfin_serial *info = (struct bfin_serial *)tty->driver_data;

	FUNC_ENTER();

	if (tty->termios->c_cflag == old_termios->c_cflag)
		return;

	DUMP_TERMIOS(old_termios);
	DUMP_TERMIOS(tty->termios);

	bfin_change_speed(info);
}

/*
 * ------------------------------------------------------------
 * rs_close()
 *
 * This routine is called when the serial port gets closed.  First, we
 * wait for the last remaining data to be sent.  Then, we unlink its
 * S structure from the interrupt chain if necessary, and we free
 * that IRQ if nothing is left in the chain.
 * ------------------------------------------------------------
 */
static void rs_close(struct tty_struct *tty, struct file *filp)
{
	struct bfin_serial *info = (struct bfin_serial *)tty->driver_data;
	unsigned long flags = 0;

	FUNC_ENTER();

	if (!info || serial_paranoia_check(info, tty->name, "rs_close"))
		return;

	local_irq_save(flags);

	if (tty_hung_up_p(filp)) {
		local_irq_restore(flags);
		return;
	}

	if ((tty->count == 1) && (info->count != 1)) {
		/*
		 * Uh, oh.  tty->count is 1, which means that the tty
		 * structure will be freed.  Info->count should always
		 * be one in these conditions.  If it's greater than
		 * one, we've got real problems, since it means the
		 * serial port won't be shutdown.
		 */
		printk(KERN_DEBUG "rs_close: bad serial port count; tty->count is 1, "
		       "info->count is %d\n", info->count);
		info->count = 1;
	}
	if (--info->count < 0) {
		printk(KERN_DEBUG "rs_close: bad serial port count for ttyS%d: %d\n",
		       info->line, info->count);
		info->count = 0;
	}
	if (info->count) {
		local_irq_restore(flags);
		return;
	}
	info->flags |= S_CLOSING;
	/*
	 * Save the termios structure, since this port may have
	 * separate termios for callout and dialin.
	 */
	if (info->flags & S_NORMAL_ACTIVE)
		info->normal_termios = *tty->termios;
	/*
	 * Now we wait for the transmit buffer to clear; and we notify
	 * the line discipline to only process XON/XOFF characters.
	 */
	tty->closing = 1;
	if (info->closing_wait != S_CLOSING_WAIT_NONE)
		tty_wait_until_sent(tty, info->closing_wait);
	/*
	 * At this point we stop accepting input.  To do this, we
	 * disable the receive line status interrupts, and tell the
	 * interrupt driver to stop checking the data ready bit in the
	 * line status register.
	 */
	shutdown(info);
	if (tty->driver->flush_buffer)
		tty->driver->flush_buffer(tty);
	if (tty->ldisc.flush_buffer)
		tty->ldisc.flush_buffer(tty);
	tty->closing = 0;
	info->event = 0;
	info->tty = 0;
	if (tty->ldisc.num != tty_ldisc_get(N_TTY)->num) {
		if (tty->ldisc.close)
			(tty->ldisc.close) (tty);
		tty->ldisc = *tty_ldisc_get(N_TTY);
		tty->termios->c_line = N_TTY;
		if (tty->ldisc.open)
			(tty->ldisc.open) (tty);
	}
	if (info->blocked_open) {
		if (info->close_delay) {
			current->state = TASK_INTERRUPTIBLE;
			schedule_timeout(info->close_delay);
		}
		wake_up_interruptible(&info->open_wait);
	}
	info->flags &= ~(S_NORMAL_ACTIVE | S_CALLOUT_ACTIVE | S_CLOSING);
#ifdef CONFIG_SERIAL_BLACKFIN_DMA
	free_dma(info->rx_DMA_channel);
	free_dma(info->tx_DMA_channel);
#else
	free_irq(info->rx_irq, info);
	free_irq(info->tx_irq, info);
#endif
	wake_up_interruptible(&info->close_wait);
	local_irq_restore(flags);
}

/*
 * rs_hangup() --- called by tty_hangup() when a hangup is signaled.
 */
void rs_hangup(struct tty_struct *tty)
{
	struct bfin_serial *info = (struct bfin_serial *)tty->driver_data;

	FUNC_ENTER();
	if (serial_paranoia_check(info, tty->name, "rs_hangup"))
		return;

	rs_flush_buffer(tty);
	shutdown(info);
	info->event = 0;
	info->count = 0;
	info->flags &= ~(S_NORMAL_ACTIVE | S_CALLOUT_ACTIVE);
	info->tty = 0;
	wake_up_interruptible(&info->open_wait);
}

/*
 * ------------------------------------------------------------
 * rs_open() and friends
 * ------------------------------------------------------------
 */
static int block_til_ready(struct tty_struct *tty, struct file *filp,
			   struct bfin_serial *info)
{
	DECLARE_WAITQUEUE(wait, current);
	int retval;
	int do_clocal = 0;
	unsigned long flags = 0;

	FUNC_ENTER();
	/*
	 * If the device is in the middle of being closed, then block
	 * until it's done, and then try again.
	 */
	if (info->flags & S_CLOSING) {
		interruptible_sleep_on(&info->close_wait);
#ifdef SERIAL_DO_RESTART
		if (info->flags & S_HUP_NOTIFY)
			return -EAGAIN;
		else
			return -ERESTARTSYS;
#else
		return -EAGAIN;
#endif
	}

	/*
	 * If non-blocking mode is set, or the port is not enabled,
	 * then make the check up front and then exit.
	 */
	if ((filp->f_flags & O_NONBLOCK) || (tty->flags & (1 << TTY_IO_ERROR))) {
		if (info->flags & S_CALLOUT_ACTIVE)
			return -EBUSY;
		info->flags |= S_NORMAL_ACTIVE;
		return 0;
	}

	if (info->flags & S_CALLOUT_ACTIVE) {
		if (info->normal_termios.c_cflag & CLOCAL)
			do_clocal = 1;
	} else {
		if (tty->termios->c_cflag & CLOCAL)
			do_clocal = 1;
	}

	/*
	 * Block waiting for the carrier detect and the line to become
	 * free (i.e., not in use by the callout).  While we are in
	 * this loop, info->count is dropped by one, so that
	 * rs_close() knows when to free things.  We restore it upon
	 * exit, either normal or abnormal.
	 */
	retval = 0;
	add_wait_queue(&info->open_wait, &wait);

	info->count--;
	info->blocked_open++;
	while (1) {
		local_irq_save(flags);
		if (!(info->flags & S_CALLOUT_ACTIVE))
			bfin_rtsdtr(info, 1);
		local_irq_restore(flags);
		current->state = TASK_INTERRUPTIBLE;
		if (tty_hung_up_p(filp) || !(info->flags & S_INITIALIZED)) {
#ifdef SERIAL_DO_RESTART
			if (info->flags & S_HUP_NOTIFY)
				retval = -EAGAIN;
			else
				retval = -ERESTARTSYS;
#else
			retval = -EAGAIN;
#endif
			break;
		}
		if (!(info->flags & S_CALLOUT_ACTIVE) &&
		    !(info->flags & S_CLOSING) && do_clocal)
			break;
		if (signal_pending(current)) {
			retval = -ERESTARTSYS;
			break;
		}
		schedule();
	}
	current->state = TASK_RUNNING;
	remove_wait_queue(&info->open_wait, &wait);
	if (!tty_hung_up_p(filp))
		info->count++;
	info->blocked_open--;

	if (retval)
		return retval;
	info->flags |= S_NORMAL_ACTIVE;
	return 0;
}

#ifdef CONFIG_SERIAL_BLACKFIN_DMA
irqreturn_t uart_rxdma_done(int irq, void *dev_id, struct pt_regs * pt_regs)
{
	struct bfin_serial *info = (struct bfin_serial *)dev_id;

	clear_dma_irqstat(info->rx_DMA_channel);
	info->event |= 1 << RS_EVENT_READ;
	schedule_work(&info->tqueue);
	return IRQ_HANDLED;
}

irqreturn_t uart_txdma_done(int irq, void *dev_id, struct pt_regs * pt_regs)
{
	struct bfin_serial *info = (struct bfin_serial *)dev_id;
	struct uart_registers *regs = &(info->regs);
	unsigned int irqstat;

	irqstat = get_dma_curr_irqstat(info->tx_DMA_channel);

	if (irqstat & 1 && !(irqstat & 8) && info->tx_xcount > 0) {
		ACCESS_PORT_IER(regs)
		    * (regs->rpUART_IER) &= ~ETBEI;
		SSYNC;
		clear_dma_irqstat(info->tx_DMA_channel);

		info->xmit_tail += info->tx_xcount;
		info->xmit_tail %= SERIAL_XMIT_SIZE;
		info->xmit_cnt -= info->tx_xcount;
		info->tx_xcount = 0;

		if (info->xmit_cnt > 0) {
			info->event |= 1 << RS_EVENT_WRITE;
			schedule_work(&info->tqueue);
		}

		if (info->xmit_cnt < WAKEUP_CHARS) {
			info->event |= 1 << RS_EVENT_WRITE_WAKEUP;
			schedule_work(&info->tqueue);
		}
	}
	return IRQ_HANDLED;
}
#endif

/* configure uart IRQ handler */
static int bfin_config_uart_IRQ(struct bfin_serial *info)
{
#ifdef CONFIG_SERIAL_BLACKFIN_DMA
	if (request_dma(info->rx_DMA_channel, "BFIN_UART_RX") < 0) {
		printk(KERN_DEBUG "Unable to attach BlackFin UART RX DMA channel\n");
		return -EBUSY;
	} else
		set_dma_callback(info->rx_DMA_channel, uart_rxdma_done, info);

	if (request_dma(info->tx_DMA_channel, "BFIN_UART_TX") < 0) {
		printk(KERN_DEBUG "Unable to attach BlackFin UART TX DMA channel\n");
		return -EBUSY;
	} else
		set_dma_callback(info->tx_DMA_channel, uart_txdma_done, info);

#else
	if (request_irq
	    (info->rx_irq, rs_interrupt, SA_INTERRUPT | SA_SHIRQ,
	     "BFIN_UART_RX", info)) {
		printk(KERN_DEBUG "Unable to attach BlackFin UART RX interrupt\n");
		return -EBUSY;
	}

	if (request_irq
	    (info->tx_irq, rs_interrupt, SA_INTERRUPT | SA_SHIRQ,
	     "BFIN_UART_TX", info)) {
		printk(KERN_DEBUG "Unable to attach BlackFin UART TX interrupt\n");
		return -EBUSY;
	}
#endif
	return 0;
}

/* configure uart0 */
static void bfin_config_uart0(struct bfin_serial *info)
{
	int flags = 0;
	local_irq_save(flags);

	info->magic = SERIAL_MAGIC;
	info->flags = 0;
	info->tty = 0;
	info->custom_divisor = 16;
	info->close_delay = 50;
	info->closing_wait = 3000;
	info->x_char = 0;
	info->event = 0;
	info->count = 0;
	info->blocked_open = 0;
	INIT_WORK(&info->tqueue, do_softint, info);
	INIT_WORK(&info->tqueue_hangup, do_serial_hangup, info);
	init_waitqueue_head(&info->open_wait);
	init_waitqueue_head(&info->close_wait);

	info->line = 0;
	info->is_cons = 0;	/* Means shortcuts work */
#ifdef CONFIG_SERIAL_BLACKFIN_DMA
	info->rx_DMA_channel = CH_UART_RX;
	info->tx_DMA_channel = CH_UART_TX;
#endif
	info->rx_irq = IRQ_UART_RX;
	info->tx_irq = IRQ_UART_TX;

	info->regs.rpUART_THR = pUART_THR;
	info->regs.rpUART_RBR = pUART_RBR;
	info->regs.rpUART_DLL = pUART_DLL;
	info->regs.rpUART_IER = pUART_IER;
	info->regs.rpUART_DLH = pUART_DLH;
	info->regs.rpUART_IIR = pUART_IIR;
	info->regs.rpUART_LCR = pUART_LCR;
	info->regs.rpUART_MCR = pUART_MCR;
	info->regs.rpUART_LSR = pUART_LSR;
	info->regs.rpUART_SCR = pUART_SCR;
	info->regs.rpUART_GCTL = pUART_GCTL;

	local_irq_restore(flags);

}

#if defined(CONFIG_BF534) || defined(CONFIG_BF536) || defined(CONFIG_BF537)
/* configure uart1 */
static void bfin_config_uart1(struct bfin_serial *info)
{
	int flags = 0;
	local_irq_save(flags);

	info->magic = SERIAL_MAGIC;
	info->flags = 0;
	info->tty = 0;
	info->custom_divisor = 16;
	info->close_delay = 50;
	info->closing_wait = 3000;
	info->x_char = 0;
	info->event = 0;
	info->count = 0;
	info->blocked_open = 0;
	INIT_WORK(&info->tqueue, do_softint, info);
	INIT_WORK(&info->tqueue_hangup, do_serial_hangup, info);
	init_waitqueue_head(&info->open_wait);
	init_waitqueue_head(&info->close_wait);

	info->line = 0;
	info->is_cons = 0;	/* Means shortcuts work */
#ifdef CONFIG_SERIAL_BLACKFIN_DMA
	info->rx_DMA_channel = CH_UART1_RX;
	info->tx_DMA_channel = CH_UART1_TX;
#endif
	info->rx_irq = IRQ_UART1_RX;
	info->tx_irq = IRQ_UART1_TX;

	info->regs.rpUART_THR = pUART1_THR;
	info->regs.rpUART_RBR = pUART1_RBR;
	info->regs.rpUART_DLL = pUART1_DLL;
	info->regs.rpUART_IER = pUART1_IER;
	info->regs.rpUART_DLH = pUART1_DLH;
	info->regs.rpUART_IIR = pUART1_IIR;
	info->regs.rpUART_LCR = pUART1_LCR;
	info->regs.rpUART_MCR = pUART1_MCR;
	info->regs.rpUART_LSR = pUART1_LSR;
	info->regs.rpUART_SCR = pUART1_SCR;
	info->regs.rpUART_GCTL = pUART1_GCTL;

	local_irq_restore(flags);

}
#endif

/*
 * This routine is called whenever a serial port is opened.  It
 * enables interrupts for a serial port, linking in its S structure into
 * the IRQ chain.   It also performs the serial-specific
 * initialization for the tty structure.
 */
int rs_open(struct tty_struct *tty, struct file *filp)
{
	struct bfin_serial *info;
	int retval, line;

	FUNC_ENTER();
	line = tty->index;

	if ((line < 0) || (line >= NR_PORTS))
		return -ENODEV;

	if (strncmp(tty->name, "ttyS0", 6) == 0) {
		info = &bfin_uart[0];
		if (info->tty) {
			if (info->tty != tty)
				return -EBUSY;
			else {
				info->count++;
				return 0;
			}
		}
	}
#if defined(CONFIG_BF534) || defined(CONFIG_BF536) || defined(CONFIG_BF537)
	else if (strncmp(tty->name, "ttyS1", 6) == 0) {
		info = &bfin_uart[1];
		if (info->tty) {
			if (info->tty != tty)
				return -EBUSY;
			else {
				info->count++;
				return 0;
			}
		}
	}
#endif
	else
		return -ENODEV;

	printk(KERN_DEBUG "%s at irq = %d is a builtin BlackFin UART\n", tty->name, info->rx_irq);

	if (bfin_config_uart_IRQ(info) != 0)
		return -ENODEV;

	if (serial_paranoia_check(info, tty->name, "rs_open"))
		return -ENODEV;
#ifdef SERIAL_DEBUG_OPEN
	printk(KERN_DEBUG "bfin_open %s%d, count = %d\n", tty->name, info->line,
	       info->count);
#endif

	info->count++;
	tty->driver_data = info;
	info->tty = tty;
	/*
	 * Start up serial port
	 */
	retval = startup(info);
	if (retval)
		return retval;

	retval = block_til_ready(tty, filp, info);

	return 0;
}


char *rs_drivername = "BlackFin BF5xx serial driver version 2.00 With DMA Support\n";


/*
 * Serial stats reporting...
 */
int rs_readproc(char *page, char **start, off_t off, int count,
		         int *eof, void *data)
{
	struct bfin_serial *info;
	int len, i;

	len = sprintf(page, rs_drivername);
	for (i = 0; (i < NR_PORTS); i++) {
		info = &bfin_uart[i];
		len += sprintf((page + len),
			"%d: rx_DMA_chan: %i rx_irq: %i tx_DMA_chan: %i tx_irq: %i open_count: %i blocked_open_count: %i baud: %i\n",
			i, info->rx_DMA_channel, info->rx_irq, info->tx_DMA_channel, info->tx_irq,
			info->count, info->blocked_open, info->baud);
	}

	return(len);
}

/* Finally, routines used to initialize the serial driver. */

static void show_serial_version(void)
{
	printk(KERN_INFO "%s", rs_drivername);
}

static struct tty_operations rs_ops = {
	.open = rs_open,
	.close = rs_close,
	.write = rs_write,
	.flush_chars = rs_flush_chars,
	.write_room = rs_write_room,
	.chars_in_buffer = rs_chars_in_buffer,
	.flush_buffer = rs_flush_buffer,
	.ioctl = rs_ioctl,
	.throttle = rs_throttle,
	.unthrottle = rs_unthrottle,
	.set_termios = rs_set_termios,
	.stop = rs_stop,
	.start = rs_start,
	.hangup = rs_hangup,
	.read_proc = rs_readproc,
	.set_ldisc = rs_set_ldisc,
};

/* rs_bfin_init inits the driver */
static int __init rs_bfin_init(void)
{
	int i;

	FUNC_ENTER();
	bfin_serial_driver = alloc_tty_driver(NR_PORTS);
	if (!bfin_serial_driver)
		return -ENOMEM;
	/* Setup base handler, and timer table. */
	show_serial_version();

	/* Initialize the tty_driver structure */
	bfin_serial_driver->owner = THIS_MODULE;
	bfin_serial_driver->name = "ttyS";
	bfin_serial_driver->devfs_name = "ttys/";
	bfin_serial_driver->driver_name = "serial";
	bfin_serial_driver->major = TTY_MAJOR;
	bfin_serial_driver->minor_start = 64;
	bfin_serial_driver->type = TTY_DRIVER_TYPE_SERIAL;
	bfin_serial_driver->subtype = SERIAL_TYPE_NORMAL;
	bfin_serial_driver->init_termios = tty_std_termios;
	bfin_serial_driver->init_termios.c_cflag =
	    bfin_console_cbaud | CS8 | CREAD | CLOCAL;
	bfin_serial_driver->init_termios.c_lflag = ISIG | ICANON | IEXTEN;

	bfin_serial_driver->flags = TTY_DRIVER_REAL_RAW;
	tty_set_operations(bfin_serial_driver, &rs_ops);

	if (tty_register_driver(bfin_serial_driver)) {
		printk(KERN_DEBUG "Blackfin: Couldn't register serial driver\n");
		put_tty_driver(bfin_serial_driver);
		return (-EBUSY);
	}

	for (i = 0; i < NR_PORTS; i++) {
		tty_register_device(bfin_serial_driver, i, NULL);
	}

	return 0;
}

module_init(rs_bfin_init);

/* setting console baud rate */
static void bfin_set_baud(struct bfin_serial *info)
{
	struct uart_registers *regs = &(info->regs);
	unsigned short uart_dl;

	FUNC_ENTER();

	/* Change access to IER & data port */
	ACCESS_PORT_IER(regs)
	*(regs->rpUART_IER) &= ~(ETBEI | ERBFI);
	SSYNC;

	uart_dl = calc_divisor(bfin_console_baud);

	ACCESS_LATCH(regs)	/*Set to access divisor latch */
	    *(regs->rpUART_DLL) = uart_dl;
	SSYNC;
	*(regs->rpUART_DLH) = uart_dl >> 8;
	SSYNC;

	*(regs->rpUART_LCR) |= WLS(8);
	SSYNC;
	*(regs->rpUART_LCR) &= ~PEN;
	SSYNC;

	/* Change access to IER & data port */
	ACCESS_PORT_IER(regs)
#ifdef CONFIG_SERIAL_BLACKFIN_DMA
	*(regs->rpUART_IER) |= ELSI;
#else
	*(regs->rpUART_IER) |= (ETBEI | ELSI);
#endif
	SSYNC;
	/* Enable the UART */
	*(regs->rpUART_GCTL) |= UCEN;
	SSYNC;

	bfin_console_initted = 1;
	return;
}

int bfin_console_setup(struct console *cp, char *arg)
{
	struct bfin_serial *info;
	int i, n = CONSOLE_BAUD_RATE;

	FUNC_ENTER();

	if (cp->index < 0 || cp->index >= NR_PORTS)
		cp->index = 0;
	info = &bfin_uart[cp->index];

	if (arg)
		n = simple_strtoul(arg, NULL, 0);

	for (i = 0; i < BAUD_TABLE_SIZE; i++)
		if (baud_table[i] == n)
			break;
	if (i < BAUD_TABLE_SIZE) {
		bfin_console_baud = n;
		bfin_console_cbaud = unix_baud_table[i];
	}

	info->is_cons = 1;

	bfin_set_baud(info);	/* make sure baud rate changes */

	return 0;
}

static struct tty_driver *bfin_console_device(struct console *c, int *index)
{
	FUNC_ENTER();
	if (c)
		*index = c->index;
	return bfin_serial_driver;
}

void bfin_console_write(struct console *co, const char *str, unsigned int count)
{
	struct bfin_serial *info = &bfin_uart[co->index];

	if (!bfin_console_initted)
		bfin_set_baud(info);

	while (count--) {
		if (*str == '\n')	/* if a LF, also do CR... */
			local_put_char(info, '\r');
		local_put_char(info, *str++);
	}
}

static struct console bfin_driver = {
	.name = "ttyS",
	.write = bfin_console_write,
	.device = bfin_console_device,
	.setup = bfin_console_setup,
	.flags = CON_PRINTBUFFER,
	.index = - 1,
};

int bfin_console_init(void)
{
	static int initialized = 0;
	if (initialized)	/* this allow us to call bfin_console_init() more than once */
		return 0;
	else
		initialized = 1;

	bfin_config_uart0(&bfin_uart[0]);
#if defined(CONFIG_BF534) || defined(CONFIG_BF536) || defined(CONFIG_BF537)
	bfin_config_uart1(&bfin_uart[1]);
	*pPORT_MUX &= ~(PFDE|PFTE);
	__builtin_bfin_ssync();
	*pPORTF_FER |= 0xF;
	__builtin_bfin_ssync();
#endif
	register_console(&bfin_driver);
	return 0;
}

console_initcall(bfin_console_init);

MODULE_LICENSE("GPL");
