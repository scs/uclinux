/* bf533_serial.c: Serial driver for BlackFin BF533 DSP internal UART.
 * Copyright (c) 2003	Bas Vermeulen <bas@buyways.nl>,
 * 			BuyWays B.V. (www.buyways.nl)
 *
 * Based heavily on blkfinserial.c
 * blkfinserial.c: Serial driver for BlackFin DSP internal USRTs.
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
 */
 
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/interrupt.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/config.h>
#include <linux/major.h>
#include <linux/string.h>
#include <linux/fcntl.h>
#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/serial.h>
#include <linux/serialP.h>
#include <linux/console.h>
#include <linux/reboot.h>
#include <linux/keyboard.h>
#include <linux/init.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/system.h>
#include <asm/segment.h>
#include <asm/bitops.h>
#include <asm/delay.h>
#include <asm/uaccess.h>
#include <asm/board/cdefBF533.h>

#include "bf533_serial_exp.h"

#define USE_INTS
#define SERIAL_PARANOIA_CHECK

#define SYNC_ALL	__asm__ __volatile__ ("ssync;\n")
#define ACCESS_LATCH		*pUART_LCR |= DLAB;
#define ACCESS_PORT_IER		*pUART_LCR &= (~DLAB);
#ifndef CONFIG_SERIAL_CONSOLE_PORT
#define	CONFIG_SERIAL_CONSOLE_PORT 0 /* default UART1 as serial console */
#endif

/*
 *	Setup for console. Argument comes from the menuconfig 
 */

#ifdef CONFIG_BAUD_9600
#define CONSOLE_BAUD_RATE 	9600
#define DEFAULT_CBAUD		B9600
#elif CONFIG_BAUD_19200		
#define CONSOLE_BAUD_RATE 	19200
#define DEFAULT_CBAUD		B19200
#elif CONFIG_BAUD_38400		
#define CONSOLE_BAUD_RATE 	38400
#define DEFAULT_CBAUD		B38400
#elif CONFIG_BAUD_57600
#define CONSOLE_BAUD_RATE 	57600
#define DEFAULT_CBAUD		B57600
#elif CONFIG_BAUD_115200	
#define CONSOLE_BAUD_RATE 	115200	
#define DEFAULT_CBAUD		B115200
#endif

static int bf533_console_initted = 0;
static int bf533_console_baud    = CONSOLE_BAUD_RATE;
static int bf533_console_cbaud   = DEFAULT_CBAUD;

#ifdef CONFIG_CONSOLE
extern wait_queue_head_t keypress_wait;
#endif

/*
 *	Driver data structures.
 */
struct tty_driver *bf533_serial_driver;

/* serial subtype definitions */
#define SERIAL_TYPE_NORMAL	1
#define SERIAL_TYPE_CALLOUT	2
  
/* number of characters left in xmit buffer before we ask for more */
#define WAKEUP_CHARS 256

#undef SERIAL_DEBUG_INTR
#undef SERIAL_DEBUG_OPEN
#undef SERIAL_DEBUG_FLOW

#define _INLINE_ inline

static struct bf533_serial bf533_soft =
{	0, 	0, 	IRQ_UART_RX, 	0 }; /* ttyS0 */


#define NR_PORTS (sizeof(bf533_soft) / sizeof(struct bf533_serial))


#ifndef MIN
#define MIN(a,b)	((a) < (b) ? (a) : (b))
#endif

static int rs_write(struct tty_struct * tty, int from_user,
		    const unsigned char *buf, int count);
/*
 * This is used to figure out the divisor speeds and the timeouts
 */

static int baud_table[] = {
	 9600, 19200, 38400, 57600, 115200, 0 };

#define BAUD_TABLE_SIZE (sizeof(baud_table)/sizeof(baud_table[0]))

struct {
        unsigned char dl_high;
        unsigned char dl_low;
} hw_baud_table[BAUD_TABLE_SIZE];

/*
 * tmp_buf is used as a temporary buffer by serial_write.  We need to
 * lock it in case the memcpy_fromfs blocks while swapping in a page,
 * and some other program tries to do a serial write at the same time.
 * Since the lock will only come under contention when the system is
 * swapping and available memory is low, it makes sense to share one
 * buffer across all the serial ports, since it significantly saves
 * memory if large numbers of serial ports are open.
 */
static unsigned char tmp_buf[SERIAL_XMIT_SIZE]; /* This is cheating */
DECLARE_MUTEX(tmp_buf_sem);

/* Forward declarations.... */
static void bf533_change_speed(struct bf533_serial *info);
static void bf533_set_baud( void );

void calc_baud(void)
{
        unsigned char i;

        for(i = 0; i < BAUD_TABLE_SIZE; i++) {
                hw_baud_table[i].dl_high = ((CONFIG_SCLK_HZ/(baud_table[i]*16)) >> 8)& 0xFF;
                hw_baud_table[i].dl_low = (CONFIG_SCLK_HZ/(baud_table[i]*16)) & 0xFF;
        }
}

static inline int serial_paranoia_check(struct bf533_serial *info,char *name, const char *routine)
{
#ifdef SERIAL_PARANOIA_CHECK
	static const char *badmagic =
		"Warning: bad magic number for serial struct (%d,%d) in %s\n";
	static const char *badinfo =
		"Warning: null bf533_serial for (%d, %d) in %s\n";

	if (!info) {
		printk(badinfo,name,routine);
		return 1;
	}
	if (info->magic != SERIAL_MAGIC) {
		printk(badmagic, name,routine);
		return 1;
	}
#endif
	return 0;
}

/* Sets or clears DTR/RTS on the requested line */
static inline void bf533_rtsdtr(struct bf533_serial *info, int set)
{
	unsigned long           flags = 0;
#ifdef SERIAL_DEBUG_OPEN
        printk("%s(%d): bf533_rtsdtr(info=%x,set=%d)\n",
                __FILE__, __LINE__, info, set);
#endif

	local_irq_save(flags);
	if (set) {
		/* set the RTS/CTS line */
	} else {
		/* clear it */
	}
	local_irq_restore(flags);
	return;
}

/* Utility routines */
static inline int get_baud(struct bf533_serial *info)
{
        unsigned long result = 115200;
        unsigned short int baud_lo, baud_hi;
        int i;
 
        ACCESS_LATCH /* change access to divisor latch */
        baud_lo = *pUART_DLL;
	SYNC_ALL;
        baud_hi = *pUART_DLH;
	SYNC_ALL;
 
        for (i=0; i<BAUD_TABLE_SIZE ; i++){
                if ( baud_lo == hw_baud_table[i].dl_low && baud_hi == hw_baud_table[i].dl_high)
                {    result = baud_table[i];
                     break;
                }
        }
        return result; 
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
	struct bf533_serial *info = (struct bf533_serial *)tty->driver_data;
	unsigned long flags = 0;

	if (serial_paranoia_check(info, tty->name, "rs_stop"))
		return;
	
	local_irq_save(flags);
	ACCESS_PORT_IER /* Change access to IER & data port */
	*pUART_IER = 0;
	SYNC_ALL; 
	local_irq_restore(flags);
}

extern void cache_delay(void);

static void local_put_char(char ch)
{
	int flags = 0;
	unsigned short status;

	local_irq_save(flags);
	
	do{
		asm("csync;");
		status = *pUART_LSR; 
		SYNC_ALL;
	}while (!(status & THRE)); 

	ACCESS_PORT_IER
	*pUART_THR = ch;
	SYNC_ALL;
	
	local_irq_restore(flags);
}
/*
static void rs_put_char(struct tty_struct *tty, char ch)
{
	rs_write(tty, 1, &ch, 1);
}
*/

static void rs_start(struct tty_struct *tty)
{
	struct bf533_serial *info = (struct bf533_serial *)tty->driver_data;
	unsigned long flags = 0;
	
	if (serial_paranoia_check(info, tty->name, "rs_start"))
		return;
	
	local_irq_save(flags);
	ACCESS_PORT_IER	/* Change access to IER & data port */
	if (info->xmit_cnt && info->xmit_buf && !(*pUART_IER & ETBEI))
	{
		*pUART_IER |= ETBEI;
		SYNC_ALL;
	}
	 
	local_irq_restore(flags);
}

/* Drop into either the boot monitor or kgdb upon receiving a break
 * from keyboard/console input.
 */
static void batten_down_hatches(void)
{
	/* Drop into the debugger */
}

static _INLINE_ void status_handle(struct bf533_serial *info, unsigned short status)
{
	/* If this is console input and this is a
	 * 'break asserted' status change interrupt
	 * see if we can drop into the debugger
	 */
	if((status & BI) && info->break_abort)
		batten_down_hatches();
	return;
}

static void receive_chars(struct bf533_serial *info, struct pt_regs *regs, unsigned short rx)
{
	struct tty_struct *tty = info->tty;
	unsigned char ch;

	/*
	 * This do { } while() loop will get ALL chars out of Rx FIFO 
         */
	do {
		ch = (unsigned char) rx;
	
		if(info->is_cons) {
			if (*pUART_LSR & BI){ /* break received */ 
				status_handle(info, *pUART_LSR);
				return;
			} else if (ch == 0x10) { /* ^P */
				show_state();
				show_free_areas();
				return;
			} else if (ch == 0x12) { /*  */
				machine_restart(NULL);
				return;
			}
			/* It is a 'keyboard interrupt' ;-) */
#ifdef CONFIG_CONSOLE
			wake_up(&keypress_wait);
#endif			
		}

		if(!tty){
			printk("no tty\n");
			goto clear_and_exit;
		}
		
		/*
		 * Make sure that we do not overflow the buffer
		 */
		if (tty->flip.count >= TTY_FLIPBUF_SIZE) {
			schedule_work(&tty->flip.work);
			return;
		}

		if(*pUART_LSR & PE) {
			*tty->flip.flag_buf_ptr++ = TTY_PARITY;
			status_handle(info, *pUART_LSR);
		} else if(*pUART_LSR & OE) {
			*tty->flip.flag_buf_ptr++ = TTY_OVERRUN;
			status_handle(info, *pUART_LSR);
		} else if(*pUART_LSR & FE) {
			*tty->flip.flag_buf_ptr++ = TTY_FRAME;
			status_handle(info, *pUART_LSR);
		} else {
			*tty->flip.flag_buf_ptr++ = 0; /* XXX */
		}

		tty->flip.count++;
                *tty->flip.char_buf_ptr++ = ch;

		ACCESS_PORT_IER /* change access to port data */
		rx = *pUART_RBR;
		SYNC_ALL;
	} while(*pUART_LSR & DR);

	schedule_work(&tty->flip.work);

clear_and_exit:
	return;
}

static void transmit_chars(struct bf533_serial *info)
{

	if (info->x_char) { /* Send next char */
		local_put_char(info->x_char);
		info->x_char = 0;
		goto clear_and_return;
	}

	if((info->xmit_cnt <= 0) || info->tty->stopped) { /* TX ints off */
		ACCESS_PORT_IER /* Change access to IER & data port */
		*pUART_IER &= ~ETBEI;
		SYNC_ALL;
		goto clear_and_return;
	}

	/* Send char */
	local_put_char(info->xmit_buf[info->xmit_tail++]);
	info->xmit_tail = info->xmit_tail & (SERIAL_XMIT_SIZE-1);
	info->xmit_cnt--;

	if (info->xmit_cnt < WAKEUP_CHARS)
		schedule_work(&info->tqueue);

	if(info->xmit_cnt <= 0) { /* All done for now... TX ints off */
		ACCESS_PORT_IER /* Change access to IER & data port */
		*pUART_IER &= ~ETBEI;
		SYNC_ALL;
		goto clear_and_return;
	}

clear_and_return:
	/* Clear interrupt (should be auto)*/
	return;
}

#define UART_INVOKED	3
/*
 * This is the serial driver's generic interrupt routine
 * Note: Generally it should be attached to general interrupt 10, responsile 
 *       for UART0&1 RCV and XMT interrupt, to make sure the invoked interrupt
 *       source, look into bit 10-13 of SIC_ISR(peripheral interrupt status reg.
 *       Finally, to see what can be done about request_irq(......)
 */
int rs_interrupt(int irq, void *dev_id, struct pt_regs * regs)
{
	struct bf533_serial *info; // = &bf533_soft[CONFIG_SERIAL_CONSOLE_PORT];
	unsigned short iir; /* Interrupt Identification Register */
	unsigned short rx; 
	unsigned int sic_status = 0;
	sic_status = *pSIC_ISR;
	SYNC_ALL;
	if (sic_status & 0xC000)
	{ 
		/* test bit 10-11 and 12-13 */
		iir = *pUART_IIR;
		SYNC_ALL;
		info = &bf533_soft;

		if (!(iir & NINT))
		{
			switch (iir & 0x06)
			{
		   	case 0x06:
				break;
		   	case STATUS(2):			/*UART_IIR_RBR:*/
		   		/* Change access to IER & data port */
				ACCESS_PORT_IER 
				if (*pUART_LSR & DR){
				   rx = *pUART_RBR;
				   SYNC_ALL;
				   receive_chars(info, regs, rx);
				}
				break;
		   	case STATUS_P1:				/*UART_IIR_THR:*/
		   		/* Change access to IER & data port */
				ACCESS_PORT_IER 
				if (*pUART_LSR & THRE){
				    transmit_chars(info);
				}
				break;
		   	case 	STATUS(0):			/*UART_IIR_MSR:*/
				break;
	   	   	}
		}
	}	
	return 0;
}

static void do_softint(void *private_)
{
	struct bf533_serial	*info = (struct bf533_serial *) private_;
	struct tty_struct	*tty;
	
	tty = info->tty;
	if (!tty)
		return;

	if (test_and_clear_bit(RS_EVENT_WRITE_WAKEUP, &info->event)) {
		if ((tty->flags & (1 << TTY_DO_WRITE_WAKEUP)) &&
		    tty->ldisc.write_wakeup)
			(tty->ldisc.write_wakeup)(tty);
		wake_up_interruptible(&tty->write_wait);
	}
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
	struct bf533_serial	*info = (struct bf533_serial *) private_;
	struct tty_struct	*tty;
	
	tty = info->tty;
	if (!tty)
		return;

	tty_hangup(tty);
}


static int startup(struct bf533_serial * info)
{
	unsigned long flags = 0;
	
	if (info->flags & S_INITIALIZED)
		return 0;

	if (!info->xmit_buf) {
		info->xmit_buf = (unsigned char *) __get_free_page(GFP_KERNEL);
		if (!info->xmit_buf)
			return -ENOMEM;
	}

	local_irq_save(flags);

	/*
	 * Clear the FIFO buffers and disable them
	 * (they will be reenabled in bf533_change_speed())
	 */

	info->xmit_fifo_size = 1;
	ACCESS_PORT_IER /* Change access to IER & data port */
		
	*pUART_GCTL |= UCEN;
	SYNC_ALL;

	*pUART_IER = ERBFI | ETBEI | ELSI | 0x08;
	SYNC_ALL;
	(void)*pUART_RBR;
	SYNC_ALL;

	/*
	 * Finally, enable sequencing and interrupts
	 */
	*pUART_IER = ERBFI | ELSI | 0x08;
	SYNC_ALL;
	bf533_rtsdtr(info, 1);

	if (info->tty)
		clear_bit(TTY_IO_ERROR, &info->tty->flags);
	info->xmit_cnt = info->xmit_head = info->xmit_tail = 0;

	/*
	 * and set the speed of the serial port
	 */

	bf533_change_speed(info);

	info->flags |= S_INITIALIZED;
	local_irq_restore(flags);
	return 0;
}

/*
 * This routine will shutdown a serial port; interrupts are disabled, and
 * DTR is dropped if the hangup on close termio flag is on.
 */
static void shutdown(struct bf533_serial * info)
{
	unsigned long	flags = 0;

        if (!(info->flags & S_INITIALIZED))
                return; 

	local_irq_save(flags);

	*pUART_LCR = 0;
	SYNC_ALL;
	ACCESS_PORT_IER /* Change access to IER & data port */
	*pUART_IER = 0;
	SYNC_ALL;

	*pUART_GCTL &= ~UCEN;
	SYNC_ALL;
	
        if (!info->tty || (info->tty->termios->c_cflag & HUPCL))
                bf533_rtsdtr(info, 0);
	
	if (info->xmit_buf) {
		free_page((unsigned long) info->xmit_buf);
		info->xmit_buf = 0;
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
static void bf533_change_speed(struct bf533_serial *info)
{
	unsigned short uart_lcr;
	unsigned cflag, flags = 0;
	int	i;

	if (!info->tty || !info->tty->termios)
		return;
	cflag = info->tty->termios->c_cflag;

	local_irq_save(flags);
	ACCESS_PORT_IER /* Change access to IER & data port */

	i = cflag & CBAUD;
        if (i & CBAUDEX) {
                i = (i & ~CBAUDEX) + B38400;
        }

	info->baud = baud_table[i];
	ACCESS_LATCH	/* change to access of divisor latch */
	*pUART_DLL = hw_baud_table[i].dl_low;
	SYNC_ALL;
	*pUART_DLH = hw_baud_table[i].dl_high;
	SYNC_ALL;

	*pUART_LCR &= DLAB; /* clear all except DLAB bit */
	SYNC_ALL;
	uart_lcr = *pUART_LCR;
	SYNC_ALL;

	switch (cflag & CSIZE) {
	case CS6:	uart_lcr |= WLS(6); break;
	case CS7:	uart_lcr |= WLS(7); break;
	case CS8:	uart_lcr |= WLS(8); break;
	default: 	break;
	}
		
	if (cflag & CSTOPB)
		uart_lcr |= STB;

	if (cflag & PARENB){
		uart_lcr |= PEN;
		if (cflag & PARODD)
		uart_lcr &= ~(EPS | STP);
	}

        if (cflag & CRTSCTS) {
		uart_lcr |= SB;
        }
		*pUART_LCR = uart_lcr;
		SYNC_ALL;

	local_irq_restore(flags);
	return;
}

static void rs_set_ldisc(struct tty_struct *tty)
{
	struct bf533_serial *info = (struct bf533_serial *)tty->driver_data;

	if (serial_paranoia_check(info, tty->name, "rs_set_ldisc"))
		return;

	info->is_cons = (tty->termios->c_line == N_TTY);
	
	printk("ttyS%d console mode %s\n", info->line, info->is_cons ? "on" : "off");
}

static void rs_flush_chars(struct tty_struct *tty)
{
	struct bf533_serial *info = (struct bf533_serial *)tty->driver_data;
	unsigned long flags = 0;

	if (serial_paranoia_check(info, tty->name, "rs_flush_chars"))
		return;
#ifndef USE_INTS
	for(;;) {
#endif
		if (info->xmit_cnt <= 0 || tty->stopped || tty->hw_stopped || 
	   	   !info->xmit_buf)
			return;

		local_irq_save(flags);

		ACCESS_PORT_IER /* Change access to IER & data port */
#ifdef USE_INTS
		*pUART_IER |= ETBEI;
		SYNC_ALL;
		if (*pUART_LSR & TEMT) {
#else
		*pUART_IER = 0; /* disable all interrupts for UART0  */
		SYNC_ALL;
		if (1) {
#endif
			/* Send char */
			local_put_char(info->xmit_buf[info->xmit_tail++]);
			info->xmit_tail = info->xmit_tail&(SERIAL_XMIT_SIZE-1);
			info->xmit_cnt--;
		}

#ifndef USE_INTS
		while (!(*pUART_LSR & TEMT)) 
			SYNC_ALL;
	}
#endif
		local_irq_restore(flags);
}

static int rs_write(struct tty_struct * tty, int from_user,
		    const unsigned char *buf, int count)
{
	int	c, total = 0;
	struct bf533_serial *info = (struct bf533_serial *)tty->driver_data;
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
		if (from_user) {
			down(&tmp_buf_sem);
			copy_from_user(tmp_buf, buf, c);
			c = MIN(c, MIN(SERIAL_XMIT_SIZE - info->xmit_cnt - 1,
				       SERIAL_XMIT_SIZE - info->xmit_head));
			memcpy(info->xmit_buf + info->xmit_head, tmp_buf, c);
			up(&tmp_buf_sem);
		} else
			memcpy(info->xmit_buf + info->xmit_head, buf, c);
		info->xmit_head = (info->xmit_head + c) & (SERIAL_XMIT_SIZE-1);
		info->xmit_cnt += c;
		local_irq_restore(flags);
		buf += c;
		count -= c;
		total += c;
	}

	if (info->xmit_cnt && !tty->stopped && !tty->hw_stopped) {
		/* Enable transmitter */
		local_irq_save(flags);
#ifdef USE_INTS
		ACCESS_PORT_IER /* Change access to IER & data port */
		*pUART_IER |= ETBEI;
		SYNC_ALL;
#else
		while(info->xmit_cnt) {
#endif
		while (!(*pUART_LSR & TEMT))
			SYNC_ALL;

		if (*pUART_LSR & TEMT) {
			local_put_char(info->xmit_buf[info->xmit_tail++]);
			info->xmit_tail = info->xmit_tail&(SERIAL_XMIT_SIZE-1);
			info->xmit_cnt--;
		}

#ifndef USE_INTS
		}
#endif
		local_irq_restore(flags);
	}
	return total;
}

static int rs_write_room(struct tty_struct *tty)
{
	struct bf533_serial *info = (struct bf533_serial *)tty->driver_data;
	int	ret;
				
	if (serial_paranoia_check(info, tty->name, "rs_write_room"))
		return 0;
	ret = SERIAL_XMIT_SIZE - info->xmit_cnt - 1;
	if (ret < 0)
		ret = 0;
	return ret;
}

static int rs_chars_in_buffer(struct tty_struct *tty)
{
	struct bf533_serial *info = (struct bf533_serial *)tty->driver_data;
				
	if (serial_paranoia_check(info, tty->name, "rs_chars_in_buffer"))
		return 0;
	return 0;
}

static void rs_flush_buffer(struct tty_struct *tty)
{
	struct bf533_serial *info = (struct bf533_serial *)tty->driver_data;
				
	if (serial_paranoia_check(info, tty->name, "rs_flush_buffer"))
		return;
	cli();
	info->xmit_cnt = info->xmit_head = info->xmit_tail = 0;
	sti();
	wake_up_interruptible(&tty->write_wait);
	if ((tty->flags & (1 << TTY_DO_WRITE_WAKEUP)) &&
	    tty->ldisc.write_wakeup)
		(tty->ldisc.write_wakeup)(tty);
}

/*
 * ------------------------------------------------------------
 * rs_throttle()
 * 
 * This routine is called by the upper-layer tty layer to signal that
 * incoming characters should be throttled.
 * ------------------------------------------------------------
 */
static void rs_throttle(struct tty_struct * tty)
{
	struct bf533_serial *info = (struct bf533_serial *)tty->driver_data;

	if (serial_paranoia_check(info, tty->name, "rs_throttle"))
		return;
	
	if (I_IXOFF(tty))
		info->x_char = STOP_CHAR(tty);

	/* Turn off RTS line (do this atomic) */
}

static void rs_unthrottle(struct tty_struct * tty)
{
	struct bf533_serial *info = (struct bf533_serial *)tty->driver_data;

	if (serial_paranoia_check(info, tty->name, "rs_unthrottle"))
		return;
	
	if (I_IXOFF(tty)) {
		if (info->x_char)
			info->x_char = 0;
		else
			info->x_char = START_CHAR(tty);
	}

	/* Assert RTS line (do this atomic) */
}

/*
 * ------------------------------------------------------------
 * rs_ioctl() and friends
 * ------------------------------------------------------------
 */

static int get_serial_info(struct bf533_serial * info,
			   struct serial_struct * retinfo)
{
	struct serial_struct tmp;
  
	if (!retinfo)
		return -EFAULT;
	memset(&tmp, 0, sizeof(tmp));
	tmp.type = info->type;
	tmp.line = info->line;
	tmp.irq = info->irq;
	tmp.flags = info->flags;
	tmp.baud_base = info->baud_base;
	tmp.close_delay = info->close_delay;
	tmp.closing_wait = info->closing_wait;
	tmp.custom_divisor = info->custom_divisor;
	copy_to_user(retinfo,&tmp,sizeof(*retinfo));
	return 0;
}

static int set_serial_info(struct bf533_serial * info,
			   struct serial_struct * new_info)
{
	struct serial_struct new_serial;
	struct bf533_serial old_info;
	int    retval = 0;

	if (!new_info)
		return -EFAULT;
	copy_from_user(&new_serial,new_info,sizeof(new_serial));
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
	info->flags = ((info->flags & ~S_FLAGS) |
			(new_serial.flags & S_FLAGS));
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
static int get_lsr_info(struct bf533_serial * info, unsigned int *value)
{
	unsigned char status;

	cli();

	status = 0; /* no CTS status pin in BlackFin Serial */
	sti();
	put_user(status,value);
	return 0;
}

/*
 * This routine sends a break character out the serial port.
 */
static void send_break(	struct bf533_serial * info, int duration)
{
        unsigned long flags = 0;

        current->state = TASK_INTERRUPTIBLE;
	local_irq_save(flags);
	*pUART_LCR |= SB;
	SYNC_ALL;
        schedule_timeout(duration);
	*pUART_LCR &= ~SB;
	SYNC_ALL;
	local_irq_restore(flags);
}

static int rs_ioctl(struct tty_struct *tty, struct file * file,
		    unsigned int cmd, unsigned long arg)
{
	int error;
	struct bf533_serial * info = (struct bf533_serial *)tty->driver_data;
	int retval;

	if (serial_paranoia_check(info, tty->name, "rs_ioctl"))
		return -ENODEV;

	if ((cmd != TIOCGSERIAL) && (cmd != TIOCSSERIAL) &&
	    (cmd != TIOCSERCONFIG) && (cmd != TIOCSERGWILD)  &&
	    (cmd != TIOCSERSWILD) && (cmd != TIOCSERGSTRUCT)) {
		if (tty->flags & (1 << TTY_IO_ERROR))
		    return -EIO;
	}
	
	switch (cmd) {
		case TCSBRK:	/* SVID version: non-zero arg --> no break */
			retval = tty_check_change(tty);
			if (retval)
				return retval;
			tty_wait_until_sent(tty, 0);
			if (!arg)
				send_break(info, HZ/4);	/* 1/4 second */
			return 0;
		case TCSBRKP:	/* support for POSIX tcsendbreak() */
			retval = tty_check_change(tty);
			if (retval)
				return retval;
			tty_wait_until_sent(tty, 0);
			send_break(info, arg ? arg*(HZ/10) : HZ/4);
			return 0;
		case TIOCGSOFTCAR:
			error = verify_area(VERIFY_WRITE, (void *) arg,sizeof(long));
			if (error)
				return error;
			put_user(C_CLOCAL(tty) ? 1 : 0,
				    (unsigned long *) arg);
			return 0;
		case TIOCSSOFTCAR:
			get_user(arg, (unsigned long *) arg);
			tty->termios->c_cflag =
				((tty->termios->c_cflag & ~CLOCAL) |
				 (arg ? CLOCAL : 0));
			return 0;
		case TIOCGSERIAL:
			error = verify_area(VERIFY_WRITE, (void *) arg,
						sizeof(struct serial_struct));
			if (error)
				return error;
			return get_serial_info(info,
					       (struct serial_struct *) arg);
		case TIOCSSERIAL:
			return set_serial_info(info,
					       (struct serial_struct *) arg);
		case TIOCSERGETLSR: /* Get line status register */
			error = verify_area(VERIFY_WRITE, (void *) arg,
				sizeof(unsigned int));
			if (error)
				return error;
			else
			    return get_lsr_info(info, (unsigned int *) arg);

		case TIOCSERGSTRUCT:
			error = verify_area(VERIFY_WRITE, (void *) arg,
						sizeof(struct bf533_serial));
			if (error)
				return error;
			copy_to_user((struct bf533_serial *) arg,
				    info, sizeof(struct bf533_serial));
			return 0;
			
		default:
			return -ENOIOCTLCMD;
		}
	return 0;
}

static void rs_set_termios(struct tty_struct *tty, struct termios *old_termios)
{
	struct bf533_serial *info = (struct bf533_serial *)tty->driver_data;

	if (tty->termios->c_cflag == old_termios->c_cflag)
		return;

	bf533_change_speed(info);

	if ((old_termios->c_cflag & CRTSCTS) &&
	    !(tty->termios->c_cflag & CRTSCTS)) {
		tty->hw_stopped = 0;
		rs_start(tty);
	}
	
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
static void rs_close(struct tty_struct *tty, struct file * filp)
{
	struct bf533_serial * info = (struct bf533_serial *)tty->driver_data;
	unsigned long flags = 0;

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
		printk("rs_close: bad serial port count; tty->count is 1, "
		       "info->count is %d\n", info->count);
		info->count = 1;
	}
	if (--info->count < 0) {
		printk("rs_close: bad serial port count for ttyS%d: %d\n",
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
	if (info->flags & S_CALLOUT_ACTIVE)
		info->callout_termios = *tty->termios;
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

	ACCESS_PORT_IER /* Change access to IER & data port */
	*pUART_IER = 0;
	SYNC_ALL;

	shutdown(info);
	if (tty->driver->flush_buffer)
		tty->driver->flush_buffer(tty);
	if (tty->ldisc.flush_buffer)
		tty->ldisc.flush_buffer(tty);
	tty->closing = 0;
	info->event = 0;
	info->tty = 0;
	if (tty->ldisc.num != ldiscs[N_TTY].num) {
		if (tty->ldisc.close)
			(tty->ldisc.close)(tty);
		tty->ldisc = ldiscs[N_TTY];
		tty->termios->c_line = N_TTY;
		if (tty->ldisc.open)
			(tty->ldisc.open)(tty);
	}
	if (info->blocked_open) {
		if (info->close_delay) {
			current->state = TASK_INTERRUPTIBLE;
			schedule_timeout(info->close_delay);
		}
		wake_up_interruptible(&info->open_wait);
	}
	info->flags &= ~(S_NORMAL_ACTIVE|S_CALLOUT_ACTIVE|
			 S_CLOSING);
	wake_up_interruptible(&info->close_wait);
	local_irq_restore(flags);
}

/*
 * rs_hangup() --- called by tty_hangup() when a hangup is signaled.
 */
void rs_hangup(struct tty_struct *tty)
{
	struct bf533_serial * info = (struct bf533_serial *)tty->driver_data;
	
	if (serial_paranoia_check(info, tty->name, "rs_hangup"))
		return;
	
	rs_flush_buffer(tty);
	shutdown(info);
	info->event = 0;
	info->count = 0;
	info->flags &= ~(S_NORMAL_ACTIVE|S_CALLOUT_ACTIVE);
	info->tty = 0;
	wake_up_interruptible(&info->open_wait);
}

/*
 * ------------------------------------------------------------
 * rs_open() and friends
 * ------------------------------------------------------------
 */
static int block_til_ready(struct tty_struct *tty, struct file * filp,
			   struct bf533_serial *info)
{
	DECLARE_WAITQUEUE(wait, current);
	int		retval;
	int		do_clocal = 0;

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
	if ((filp->f_flags & O_NONBLOCK) ||
	    (tty->flags & (1 << TTY_IO_ERROR))) {
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
		cli();
		if (!(info->flags & S_CALLOUT_ACTIVE))
			bf533_rtsdtr(info, 1);
		sti();
		current->state = TASK_INTERRUPTIBLE;
		if (tty_hung_up_p(filp) ||
		    !(info->flags & S_INITIALIZED)) {
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

/*
 * This routine is called whenever a serial port is opened.  It
 * enables interrupts for a serial port, linking in its S structure into
 * the IRQ chain.   It also performs the serial-specific
 * initialization for the tty structure.
 */
int rs_open(struct tty_struct *tty, struct file * filp)
{
	struct bf533_serial	*info;
	int 			retval, line;

	line = tty->index; /* FIXME */
	
	if ((line < 0) || (line >= NR_PORTS)) 
		return -ENODEV;

	info = &bf533_soft;

	if (serial_paranoia_check(info, tty->name, "rs_open"))
		return -ENODEV;
#ifdef SERIAL_DEBUG_OPEN
        printk("bf533_open %s%d, count = %d\n", tty->driver.name, info->line,
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

/* Finally, routines used to initialize the serial driver. */

static void show_serial_version(void)
{
	printk("BlackFin BF533 serial driver version 1.00 (Experimental)\n");
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
	.set_ldisc = rs_set_ldisc,
};

/* rs_bf533_init inits the driver */
static int __init rs_bf533_init(void)
{
	int flags = 0;
	struct bf533_serial *info;
	
	bf533_serial_driver = alloc_tty_driver(NR_PORTS);
	if (!bf533_serial_driver)
		return -ENOMEM;
	/* Setup base handler, and timer table. */
	show_serial_version();

	/* Initialize the tty_driver structure */
	bf533_serial_driver->owner = THIS_MODULE;
	bf533_serial_driver->name = "ttyS";
	bf533_serial_driver->devfs_name = "ttys/";
	bf533_serial_driver->driver_name = "serial";
	bf533_serial_driver->major = TTY_MAJOR;
	bf533_serial_driver->minor_start = 64; 
	bf533_serial_driver->type = TTY_DRIVER_TYPE_SERIAL;
	bf533_serial_driver->subtype = SERIAL_TYPE_NORMAL;
	bf533_serial_driver->init_termios = tty_std_termios;
	bf533_serial_driver->init_termios.c_cflag = 
			bf533_console_cbaud | CS8 | CREAD | HUPCL | CLOCAL;
	bf533_serial_driver->flags = TTY_DRIVER_REAL_RAW;
	tty_set_operations(bf533_serial_driver, &rs_ops);

	if (tty_register_driver(bf533_serial_driver)) {
		printk("Blackfin: Couldn't register serial driver\n");
		put_tty_driver(bf533_serial_driver);
		return(-EBUSY);
	}
	local_irq_save(flags);

        /*
         *      Configure all the attached serial ports.
         */
	info = &bf533_soft;
	info->magic = SERIAL_MAGIC;
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
	info->is_cons = 1; /* Means shortcuts work */
	info->irq = IRQ_UART_RX;
	
	printk("%s0 at irq = %d", \
		bf533_serial_driver->name, info->irq);
	printk(" is a builtin BlackFin BF533 UART\n");

	local_irq_restore(flags);

	if (request_irq(IRQ_UART_RX, rs_interrupt, IRQ_FLG_STD, "BF533_UART_RX", NULL))
		panic("Unable to attach BlackFin UART interrupt\n");

	if (request_irq(IRQ_UART_TX, rs_interrupt, IRQ_FLG_STD, "BF533_UART_TX", NULL))
		panic("Unable to attach BlackFin UART interrupt\n");
	
	printk("Enabling Serial UART Interrupts\n");
	
	enable_irq(IRQ_UART_RX);
	enable_irq(IRQ_UART_TX);

	return 0;
}
module_init(rs_bf533_init);

/* setting console baud rate: CONFIG_SERIAL_CONSOLE_PORT */
static void bf533_set_baud( void )
{
	int	i;

	/* Change access to IER & data port */
	ACCESS_PORT_IER 
	*pUART_IER &= ~ETBEI;
	SYNC_ALL;

	calc_baud();
again:
	for (i = 0; i < sizeof(baud_table) / sizeof(baud_table[0]); i++)
		if (baud_table[i] == bf533_console_baud)
			break;
	if (i >= sizeof(baud_table) / sizeof(baud_table[0])) {
		bf533_console_baud = 9600;
		goto again;
	}

	ACCESS_LATCH /*Set to access divisor latch*/
	*pUART_DLL = hw_baud_table[i].dl_low;
	SYNC_ALL;
	*pUART_DLH = hw_baud_table[i].dl_high;
	SYNC_ALL;

	*pUART_LCR |= WLS(8);
	SYNC_ALL;
	*pUART_LCR &= ~PEN;
	SYNC_ALL;

	/* Change access to IER & data port */
	ACCESS_PORT_IER 
        *pUART_IER |=(ETBEI | ELSI);
	SYNC_ALL;
	/* Enable the UART */
	*pUART_GCTL |= UCEN;
	SYNC_ALL;

	bf533_console_initted = 1;
	return;
}


int bf533_console_setup(struct console *cp, char *arg)
{
	int	i, n = CONSOLE_BAUD_RATE;

	if (!cp)
		return(-1);

	if (arg)
		n = simple_strtoul(arg,NULL,0);

	for (i = 0; i < BAUD_TABLE_SIZE; i++)
		if (baud_table[i] == n)
			break;
	if (i < BAUD_TABLE_SIZE) {
		bf533_console_baud = n;
		bf533_console_cbaud = 0;
		if (i > 15) {
			bf533_console_cbaud |= CBAUDEX;
			i -= 15;
		}
		bf533_console_cbaud |= i;
	}

	bf533_set_baud(); /* make sure baud rate changes */
	return(0);
}

static struct tty_driver * bf533_console_device(struct console *c, int *index)
{
	*index = c->index;
	return bf533_serial_driver;
}

void bf533_console_write (struct console *co, const char *str,
			   unsigned int count)
{
    if (!bf533_console_initted)
	bf533_set_baud();
    while (count--)	{ 
        if (*str == '\n')	/* if a LF, also do CR... */
           local_put_char( '\r');
        local_put_char( *str++ );
    }
}

static struct console bf533_driver = {
	.name		"ttyS",
	.write		bf533_console_write,
	.device		bf533_console_device,
	.setup		bf533_console_setup,
	.flags		CON_PRINTBUFFER,
	.index		CONFIG_SERIAL_CONSOLE_PORT,
};

static int bf533_console_init(void)
{
	register_console(&bf533_driver);
	return 0;
}

console_initcall(bf533_console_init); 
