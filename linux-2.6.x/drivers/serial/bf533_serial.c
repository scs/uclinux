/* bf533_serial.c: Serial driver for BlackFin BF533 DSP internal UART.
 * Copyright (c) 2003	Bas Vermeulen <bas@buyways.nl>,
 * 			BuyWays B.V. (www.buyways.nl)
 *
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
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/serial.h>
#include <linux/serialP.h>
#include <linux/console.h>
#include <linux/reboot.h>

#include <asm/uaccess.h>
#include <asm/board/cdefBF533.h>
#include <asm/board/bf533_irq.h>
#include <asm/irq.h>
#ifdef CONFIG_BLKFIN_SIMPLE_DMA
#include <asm/dma.h>
#include <asm/cacheflush.h>
#endif

#include <asm/dpmc.h> /* get_sclk() */

#include "bf533_serial.h"

#undef SERIAL_DEBUG_OPEN
#undef SERIAL_DEBUG_CALLTRACE
#undef SERIAL_DEBUG_TERMIOS

#define SYNC_ALL	__asm__ __volatile__ ("ssync;\n")
#define ACCESS_LATCH	{ *pUART_LCR |= DLAB; SYNC_ALL;}
#define ACCESS_PORT_IER	{ *pUART_LCR &= (~DLAB); SYNC_ALL;}
#ifndef CONFIG_SERIAL_CONSOLE_PORT
#define	CONFIG_SERIAL_CONSOLE_PORT 0 /* default UART1 as serial console */
#endif

#if defined (SERIAL_DEBUG_CALLTRACE)
#define FUNC_ENTER()  printk("<0> %s: entered\n", __FUNCTION__)
#else
#define FUNC_ENTER()  do {} while (0)
#endif

#if defined (SERIAL_DEBUG_TERMIOS)
#define DUMP_TERMIOS(termios) printk("<0> %s: termios %p c_iflag %08x " \
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

extern unsigned long l1_data_A_sram_alloc(unsigned long size);
extern int l1_data_A_sram_free(unsigned long addr);
/*
 *	Driver data structures.
 */
struct tty_driver *bf533_serial_driver;

/* serial subtype definitions */
#define SERIAL_TYPE_NORMAL	1
  
/* number of characters left in xmit buffer before we ask for more */
#define WAKEUP_CHARS 256

static struct bf533_serial bf533_soft =
{	0, 	IRQ_UART_RX, 	0 }; /* ttyS0 */

#define NR_PORTS (sizeof(bf533_soft) / sizeof(struct bf533_serial))

#ifndef MIN
#define MIN(a,b)	((a) < (b) ? (a) : (b))
#endif

#ifdef CONFIG_BLKFIN_SIMPLE_DMA
static unsigned int tx_xcount=0;

#define RX_XCOUNT  TTY_FLIPBUF_SIZE
#define RX_YCOUNT  (PAGE_SIZE / RX_XCOUNT)

#endif

static int rs_write(struct tty_struct * tty, int from_user,
		    const unsigned char *buf, int count);
/*
 * This is used to figure out the divisor speeds and the timeouts
 */

static int baud_table[] = {
	 9600, 19200, 38400, 57600, 115200};
static int unix_baud_table[] = {
	B9600, B19200, B38400, B57600, B115200};

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
	unsigned int sclk = get_sclk();
        int i;

        for(i = 0; i < BAUD_TABLE_SIZE; i++) {
                hw_baud_table[i].dl_high = ((sclk/(baud_table[i]*16)) >> 8)& 0xFF;
                hw_baud_table[i].dl_low = (sclk/(baud_table[i]*16)) & 0xFF;
        }
}

static inline int serial_paranoia_check(struct bf533_serial *info,char *name, const char *routine)
{
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
	return 0;
}

/* Sets or clears DTR/RTS on the requested line */
static inline void bf533_rtsdtr(struct bf533_serial *info, int set)
{
	unsigned long flags = 0;
#ifdef SERIAL_DEBUG_OPEN
        printk("%s(%d): bf533_rtsdtr(info=%x,set=%d)\n",
                __FILE__, __LINE__, info, set);
#endif

	local_irq_save(flags);
	if (set) {
		/* set the RTS/CTS line */
                *pFIO_FLAG_C = (1 << 13);
		SYNC_ALL;
	} else {
		/* clear it */
                *pFIO_FLAG_S = (1 << 13);
		SYNC_ALL;
	}
	local_irq_restore(flags);
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

static void rs_start(struct tty_struct *tty)
{
	struct bf533_serial *info = (struct bf533_serial *)tty->driver_data;
#ifndef CONFIG_BLKFIN_SIMPLE_DMA
	unsigned long flags = 0;
#endif
	
        FUNC_ENTER();

	if (serial_paranoia_check(info, tty->name, "rs_start"))
		return;
	
#ifndef CONFIG_BLKFIN_SIMPLE_DMA
	local_irq_save(flags);
	ACCESS_PORT_IER	/* Change access to IER & data port */
	if (info->xmit_cnt && info->xmit_buf && !(*pUART_IER & ETBEI))
	{
		*pUART_IER |= ETBEI;
		SYNC_ALL;
	}
	 
	local_irq_restore(flags);
#endif
}

/* Drop into either the boot monitor or kgdb upon receiving a break
 * from keyboard/console input.
 */
static void batten_down_hatches(void)
{
        FUNC_ENTER();
}

static inline void status_handle(struct bf533_serial *info, unsigned short status)
{
        FUNC_ENTER();

	/* If this is console input and this is a
	 * 'break asserted' status change interrupt
	 * see if we can drop into the debugger
	 */
	if((status & BI) && info->break_abort)
		batten_down_hatches();
	return;
}

#ifdef CONFIG_BLKFIN_SIMPLE_DMA
static void dma_receive_chars(struct bf533_serial *info, int in_timer)
{
      struct tty_struct *tty = info->tty;
      unsigned char flag = 0;
      int len = 0;
      int curpos, ttylen=0;

      spin_lock_bh(info->recv_lock);

	/*
	 * Current DMA receiving buffer is one PAGE, which is devied into 8 buffer lines.
	 * Autobuffered 2D DMA operation is applied to receive chars from the UART.
	 * This function is called each time one buffer line is full or the timer is over.
	 */
      if((curpos = get_dma_curr_xcount(CH_UART_RX)) == 0 && in_timer)
              goto unlock_and_exit;
      curpos = TTY_FLIPBUF_SIZE - curpos + (RX_YCOUNT - get_dma_curr_ycount(CH_UART_RX))*TTY_FLIPBUF_SIZE;

      if(curpos == info->recv_tail)
              goto unlock_and_exit;
      else if(curpos > info->recv_tail)
	      info->recv_head = curpos;
      else
	      info->recv_head = PAGE_SIZE;
      
      /*
       * Check for a valid value of recv_head
       */
      if ((info->recv_head < 0) || (info->recv_head > PAGE_SIZE))
      {
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
      
	ttylen = TTY_FLIPBUF_SIZE - tty->flip.count;
	if(ttylen>0) {
		if(len > ttylen)
			len = ttylen;
		memset(tty->flip.flag_buf_ptr, flag, len);
		memcpy(tty->flip.char_buf_ptr, info->recv_buf + info->recv_tail, len);
		tty->flip.flag_buf_ptr += len;
		tty->flip.char_buf_ptr += len;
		tty->flip.count += len;
		info->recv_tail += len;
	}

      if (info->recv_head >= PAGE_SIZE)
              info->recv_head = 0;
      if (info->recv_tail >= PAGE_SIZE)
              info->recv_tail = 0;

      tty_flip_buffer_push(tty);
unlock_and_exit:
      spin_unlock_bh(info->recv_lock);
}

static void dma_transmit_chars(struct bf533_serial *info)
{
	spin_lock_bh(info->xmit_lock);

	/* 
	 * tx_xcount is checked here to make sure the dma won't be started if it is working.
	 */
	if (tx_xcount) {
		/*
		 * The DMA engine sometimes hangs when transfer a large buffer(> about 200 bytes) 
		 * to the UART. It stops working before all data in the buffer is sent.
		 * Current solution is to stop the DMA transmit operatoin in timer handler if the
		 * DMA hang conditioni is met. The DMA hang condition is that the number of byte 
		 * left in the xmit buffer is not 0 and the UART xmit empty status is set.
		 */
		ACCESS_PORT_IER
		if(*pUART_LSR&THRE) {
			tx_xcount-=get_dma_curr_xcount(CH_UART_TX);
			ACCESS_PORT_IER
			*pUART_IER &= ~ETBEI;
			SYNC_ALL;
			disable_dma(CH_UART_TX);
			tx_xcount-=4;
			if(tx_xcount<0)
				tx_xcount=0;
			info->xmit_tail += tx_xcount;
			info->xmit_tail %= SERIAL_XMIT_SIZE;
			info->xmit_cnt -= tx_xcount;
			tx_xcount = 0;
		}
		else
			goto clear_and_return;
	}

	if (info->x_char) { /* Send next char */
		local_put_char(info->x_char);
		info->x_char = 0;
	}

	if((info->xmit_cnt <= 0) || info->tty->stopped) { /* TX ints off */
		goto clear_and_return;
	}

	/* Send char */
	tx_xcount = info->xmit_cnt;
	if(tx_xcount > SERIAL_XMIT_SIZE - info->xmit_tail)
		tx_xcount = SERIAL_XMIT_SIZE - info->xmit_tail; 

	/* 
	 *Only use dma to transfer data when count > 1.
	 */
	if(tx_xcount>1) {
		flush_dcache_range((int)(info->xmit_buf+info->xmit_tail), (int)(info->xmit_buf+info->xmit_tail+tx_xcount));
		set_dma_config(CH_UART_TX, set_bfin_dma_config(DIR_READ, FLOW_STOP, INTR_ON_BUF, DIMENSION_LINEAR, DATA_SIZE_8));
		set_dma_start_addr(CH_UART_TX, (unsigned long)(info->xmit_buf+info->xmit_tail));
		set_dma_x_count(CH_UART_TX, tx_xcount);
		ACCESS_PORT_IER
		SYNC_ALL;
		enable_dma(CH_UART_TX);
		*pUART_IER |= ETBEI;
		SYNC_ALL;
	}
	else {
		local_put_char(info->xmit_buf[info->xmit_tail++]);
		info->xmit_tail %= SERIAL_XMIT_SIZE;
		info->xmit_cnt--;
		tx_xcount = 0;

		if (info->xmit_cnt < WAKEUP_CHARS)
		{
			info->event |= 1 << RS_EVENT_WRITE_WAKEUP;
			schedule_work(&info->tqueue);
		}
	}

clear_and_return:
	spin_unlock_bh(info->recv_lock);
}
#endif

void receive_chars(struct bf533_serial *info, struct pt_regs *regs)
{
	struct tty_struct *tty = info->tty;
	unsigned char ch = 0, flag = 0;
	unsigned short status = 0 ;
	FUNC_ENTER();

	/*
	 * This do { } while() loop will get ALL chars out of Rx FIFO 
         */
	do {
		ACCESS_PORT_IER;
		asm("csync;");
		ch = (unsigned char) *pUART_RBR;
	
		if(info->is_cons) {
			asm("csync;");
			status = *pUART_LSR;
			if (status & BI){ /* break received */ 
				status_handle(info, status);
				return;
			} else if (ch == 0x10) { /* ^P */
				show_state();
				show_free_areas();
				return;
			} else if (ch == 0x12) { /* ^R */
				machine_restart(NULL);
				return;
			}
			/* It is a 'keyboard interrupt' ;-) */
#ifdef CONFIG_CONSOLE
			wake_up(&keypress_wait);
#endif			
		}

		if(!tty){
			goto clear_and_exit;
		}
		/*
		 * Make sure that we do not overflow the buffer
		 */
		if (tty->flip.count >= TTY_FLIPBUF_SIZE) {
			tty_flip_buffer_push(tty);
			return;
		}
		if(status & PE) {
			flag = TTY_PARITY;
			status_handle(info, status);
		} else if(status & OE) {
			flag = TTY_OVERRUN;
			status_handle(info, status);
		} else if(status & FE) {
			flag = TTY_FRAME;
			status_handle(info, status);
		} 
                tty_insert_flip_char(tty, ch, flag);
	} while(status & DR);
        tty_flip_buffer_push(tty);

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
	{
		info->event |= 1 << RS_EVENT_WRITE_WAKEUP;
		schedule_work(&info->tqueue);
	}
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

/*
 * This is the serial driver's generic interrupt routine
 * Note: Generally it should be attached to general interrupt 10, responsile 
 *       for UART0&1 RCV and XMT interrupt, to make sure the invoked interrupt
 *       source, look into bit 10-13 of SIC_ISR(peripheral interrupt status reg.
 *       Finally, to see what can be done about request_irq(......)
 */
irqreturn_t rs_interrupt(int irq, void *dev_id, struct pt_regs * regs)
{
	struct bf533_serial *info; // = &bf533_soft[CONFIG_SERIAL_CONSOLE_PORT];
	unsigned short iir; /* Interrupt Identification Register */

	unsigned short rx, lsr; 
	unsigned int sic_status = 0;
	asm("csync;");
	sic_status = *pSIC_ISR;
	if (sic_status & 0xC040) {
		/* test bit 10-11 and 12-13 */
		info = &bf533_soft;
		asm("csync;");
		iir = *pUART_IIR;

		if (!(iir & NINT))
		{
			switch (iir & 0x06)
			{
		   	case 0x06:
                              	/* Change access to IER & data port */
                              	ACCESS_PORT_IER;
				asm("csync;");
                              	lsr = *pUART_LSR;
				break;
		   	case STATUS(2):			/*UART_IIR_RBR:*/
	   			/* Change access to IER & data port */
				ACCESS_PORT_IER 
				asm("csync;");
				if (*pUART_LSR & DR){
					asm("csync;");
			   		rx = *pUART_RBR;
			   		receive_chars(info, regs);
				}
				break;
		   	case STATUS_P1:				/*UART_IIR_THR:*/
		   		/* Change access to IER & data port */
				ACCESS_PORT_IER 
				asm("csync;");
				if (*pUART_LSR & THRE){
				    transmit_chars(info);
				}
				break;
		   	case 	STATUS(0):			/*UART_IIR_MSR:*/
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
#ifdef CONFIG_BLKFIN_SIMPLE_DMA
        if (test_and_clear_bit(RS_EVENT_READ, &info->event)) {
                dma_receive_chars(info, 0);
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
	struct bf533_serial	*info = (struct bf533_serial *) private_;
	struct tty_struct	*tty;

	FUNC_ENTER();
	
	tty = info->tty;
	if (!tty)
		return;

	tty_hangup(tty);
}

#ifdef CONFIG_BLKFIN_SIMPLE_DMA

#define TIME_INTERVAL	5

static void dma_start_recv(struct bf533_serial * info)
{
       FUNC_ENTER();

	if (((get_dma_curr_irqstat(CH_UART_RX) & DMA_RUN) ==0) || get_dma_curr_irqstat(CH_UART_RX) & DMA_DONE)
       {
		set_dma_config(CH_UART_RX, set_bfin_dma_config(DIR_WRITE, FLOW_AUTO, INTR_ON_ROW, DIMENSION_2D, DATA_SIZE_8));
		set_dma_x_count(CH_UART_RX, RX_XCOUNT); 
		set_dma_x_modify(CH_UART_RX, 1);
		set_dma_y_count(CH_UART_RX, RX_YCOUNT); 
		set_dma_y_modify(CH_UART_RX, 1);
		set_dma_start_addr(CH_UART_RX, (unsigned long)info->recv_buf);
				
		enable_dma(CH_UART_RX);
        } else {
                printk("bf533_serial: DMA started while already running!\n");
        }
}

static void uart_dma_xmit_timer(struct bf533_serial * info)
{
	dma_transmit_chars(info);
        info->dma_xmit_timer.expires = jiffies + TIME_INTERVAL;
        add_timer(&info->dma_xmit_timer);
}
                                                                                
static void uart_dma_recv_timer(struct bf533_serial * info)
{
	dma_receive_chars(info, 1);
        info->dma_recv_timer.expires = jiffies + TIME_INTERVAL;
        add_timer(&info->dma_recv_timer);
}
#endif

static int startup(struct bf533_serial * info)
{
	unsigned long flags = 0;
	
	FUNC_ENTER();
	init_timer(&info->dma_xmit_timer);
	init_timer(&info->dma_recv_timer);

	*pUART_GCTL |= UCEN;
	SYNC_ALL;

	/*
	 * Finally, enable sequencing and interrupts
	 */
#ifdef CONFIG_BLKFIN_SIMPLE_DMA
	*pUART_IER = ERBFI | ELSI | 0x8;
#else
	*pUART_IER = ERBFI | ETBEI | ELSI | 0x8;
#endif
	SYNC_ALL;

	if (info->flags & S_INITIALIZED)
		return 0;

	if (!info->xmit_buf) {
		info->xmit_buf = (unsigned char *) __get_free_page(GFP_KERNEL);
		if (!info->xmit_buf)
			return -ENOMEM;
	}
                                                                                
        if (!info->recv_buf) {
		info->recv_buf = (unsigned char*)l1_data_A_sram_alloc(PAGE_SIZE);
                if (!info->recv_buf)
                {
                        free_page((unsigned long)info->xmit_buf);
                        return -ENOMEM;
                }
        }
                                                                                
	local_irq_save(flags);

	/*
	 * Clear the FIFO buffers and disable them
	 * (they will be reenabled in bf533_change_speed())
	 */

	info->xmit_fifo_size = 1;
	ACCESS_PORT_IER /* Change access to IER & data port */
		
	bf533_rtsdtr(info, 1);

	if (info->tty)
		clear_bit(TTY_IO_ERROR, &info->tty->flags);
	info->xmit_cnt = info->xmit_head = info->xmit_tail = 0;

#ifdef CONFIG_BLKFIN_SIMPLE_DMA

	set_dma_x_modify(CH_UART_TX, 1);
	info->xmit_lock = SPIN_LOCK_UNLOCKED;
        /*
         * Start the receive DMA
         */
        info->recv_cnt = info->recv_head = info->recv_tail = 0;
        info->recv_lock = SPIN_LOCK_UNLOCKED;
        dma_start_recv(info);

	/*
	 * The timer should only start after the receive DMA engine is working.
	 */                         
        info->dma_xmit_timer.data = (unsigned long)info;
        info->dma_xmit_timer.function = (void *)uart_dma_xmit_timer;
        info->dma_xmit_timer.expires = jiffies + TIME_INTERVAL;
        add_timer(&info->dma_xmit_timer);
        info->dma_recv_timer.data = (unsigned long)info;
        info->dma_recv_timer.function = (void *)uart_dma_recv_timer;
        info->dma_recv_timer.expires = jiffies + TIME_INTERVAL;
        add_timer(&info->dma_recv_timer);
#endif

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

	FUNC_ENTER();

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

#ifdef CONFIG_BLKFIN_SIMPLE_DMA
	disable_dma(CH_UART_RX);
	disable_dma(CH_UART_TX);
#endif
	
        if (!info->tty || (info->tty->termios->c_cflag & HUPCL))
                bf533_rtsdtr(info, 0);
	
	if (info->xmit_buf) {
		free_page((unsigned long) info->xmit_buf);
		info->xmit_buf = 0;
	}

        if (info->recv_buf) {
                l1_data_A_sram_free((unsigned long) info->recv_buf);
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
static void bf533_change_speed(struct bf533_serial *info)
{
	unsigned short uart_dll, uart_dlh;
	unsigned cflag, flags, cval;

	int	i;
	FUNC_ENTER();

	if (!info->tty || !info->tty->termios)
		return;

	calc_baud();

	cflag = info->tty->termios->c_cflag;

        /* byte size and parity */
        switch (cflag & CSIZE)
        {
                case CS5:       cval = WLS(5); break;
                case CS6:       cval = WLS(6); break;
                case CS7:       cval = WLS(7); break;
                case CS8:       /* 8-bit should be default */
		default:	cval = WLS(8); break;
        }
                                                                                
        if (cflag & CSTOPB)
                cval |= STB;
        if (cflag & PARENB)
                cval |= PEN;
        if (!(cflag & PARODD))
                cval |= EPS;
        if (cflag & CRTSCTS)
                printk(KERN_DEBUG "%s: CRTSCTS not supported. Ignoring.\n", __FUNCTION__);
                                                                                
	for (i = 0; i < BAUD_TABLE_SIZE; i++) {
	    if (unix_baud_table[i] == (cflag & CBAUD))
		break;
	}
	
	if (i == BAUD_TABLE_SIZE) {
	    printk(KERN_DEBUG "%s: baud rate not supported: 0%o\n", __FUNCTION__, cflag & CBAUD);
	    i = 3;
	} 
	
	info->baud = baud_table[i];

	uart_dll = hw_baud_table[i].dl_low;
	uart_dlh = hw_baud_table[i].dl_high;

	printk("bf533_change_speed: baud = %d, cval = 0x%04x\n", baud_table[i], cval);

	local_irq_save(flags);
	ACCESS_LATCH /*Set to access divisor latch*/
	*pUART_DLL = hw_baud_table[i].dl_low;
	SYNC_ALL;
	*pUART_DLH = hw_baud_table[i].dl_high;
	SYNC_ALL;

	*pUART_LCR = cval;
	SYNC_ALL;

	/* Change access to IER & data port */
	ACCESS_PORT_IER 
        *pUART_IER |= ELSI;
	SYNC_ALL;
	/* Enable the UART */
	*pUART_GCTL |= UCEN;
	SYNC_ALL;

	local_irq_restore(flags);
	return;
}

static void rs_set_ldisc(struct tty_struct *tty)
{
	struct bf533_serial *info = (struct bf533_serial *)tty->driver_data;

	FUNC_ENTER();	

	if (serial_paranoia_check(info, tty->name, "rs_set_ldisc"))
		return;

	info->is_cons = (tty->termios->c_line == N_TTY);
	
	printk("ttyS%d console mode %s\n", info->line, info->is_cons ? "on" : "off");
}

static void rs_flush_chars(struct tty_struct *tty)
{
	struct bf533_serial *info = (struct bf533_serial *)tty->driver_data;
#ifndef CONFIG_BLKFIN_SIMPLE_DMA
	unsigned long flags = 0;
#endif

	if (serial_paranoia_check(info, tty->name, "rs_flush_chars"))
		return;
	
	if (info->xmit_cnt <= 0 || tty->stopped || tty->hw_stopped || 
		!info->xmit_buf)
			return;

#ifdef CONFIG_BLKFIN_SIMPLE_DMA
	if(tx_xcount>0) {
	        mod_timer(&info->dma_xmit_timer, jiffies);
	}
#else
		local_irq_save(flags);

		ACCESS_PORT_IER /* Change access to IER & data port */
		*pUART_IER |= ETBEI;
		SYNC_ALL;
		if (*pUART_LSR & TEMT) {
			/* Send char */
			local_put_char(info->xmit_buf[info->xmit_tail++]);
			info->xmit_tail = info->xmit_tail&(SERIAL_XMIT_SIZE-1);
			info->xmit_cnt--;
		}

		local_irq_restore(flags);
#endif
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
		info->xmit_head = (info->xmit_head + c) % SERIAL_XMIT_SIZE;
		info->xmit_cnt += c;
		local_irq_restore(flags);
		buf += c;
		count -= c;
		total += c;
	}

	if (info->xmit_cnt && !tty->stopped && !tty->hw_stopped) {
#ifdef CONFIG_BLKFIN_SIMPLE_DMA
		if (tx_xcount > 0 && info->xmit_head == 0) {
		        mod_timer(&info->dma_xmit_timer, jiffies);
		}
#else
		/* Enable transmitter */
		local_irq_save(flags);
		ACCESS_PORT_IER /* Change access to IER & data port */
		*pUART_IER |= ETBEI;
		SYNC_ALL;
		while (!(*pUART_LSR & TEMT))
			SYNC_ALL;

		if (*pUART_LSR & TEMT) {
			local_put_char(info->xmit_buf[info->xmit_tail++]);
			info->xmit_tail = info->xmit_tail&(SERIAL_XMIT_SIZE-1);
			info->xmit_cnt--;
		}

		local_irq_restore(flags);
#endif
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
        unsigned long flags = 0;
	struct bf533_serial *info = (struct bf533_serial *)tty->driver_data;
        FUNC_ENTER();
				
	if (serial_paranoia_check(info, tty->name, "rs_flush_buffer"))
		return;
	local_irq_save(flags);
	info->xmit_cnt = info->xmit_head = info->xmit_tail = 0;
	local_irq_restore(flags);
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

        FUNC_ENTER();
	if (serial_paranoia_check(info, tty->name, "rs_throttle"))
		return;
	if (I_IXOFF(tty))
		info->x_char = STOP_CHAR(tty);
}

static void rs_unthrottle(struct tty_struct * tty)
{
	struct bf533_serial *info = (struct bf533_serial *)tty->driver_data;

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

        FUNC_ENTER();
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
	unsigned char status = 0;

        FUNC_ENTER();
	put_user(status,value);
	return 0;
}
                                                                                
static int set_modem_info(struct bf533_serial *info, unsigned int cmd,
                unsigned int *value)
{
        unsigned int arg;
                                                                                
        FUNC_ENTER();
        if (copy_from_user(&arg, value, sizeof(int)))
                return -EFAULT;
                                                                                
        switch (cmd)
        {
        	case TIOCMBIS:
                	if (arg & TIOCM_DTR)
                        	bf533_rtsdtr(info, 1);
	                break;
        	case TIOCMBIC:
                	if (arg & TIOCM_DTR)
                        	bf533_rtsdtr(info, 0);
	                break;
        	case TIOCMSET:
                	bf533_rtsdtr(info, arg & TIOCM_DTR ? 1 : 0);
	                break;
        	default:
                	return -EINVAL;
        }
        return 0;
}

static int rs_ioctl(struct tty_struct *tty, struct file * file,
		    unsigned int cmd, unsigned long arg)
{
	int error;
	struct bf533_serial * info = (struct bf533_serial *)tty->driver_data;

	if (serial_paranoia_check(info, tty->name, "rs_ioctl"))
		return -ENODEV;

	if ((cmd != TIOCGSERIAL) && (cmd != TIOCSSERIAL) &&
	    (cmd != TIOCSERCONFIG) && (cmd != TIOCSERGWILD)  &&
	    (cmd != TIOCSERSWILD) && (cmd != TIOCSERGSTRUCT)) {
		if (tty->flags & (1 << TTY_IO_ERROR))
		    return -EIO;
	}
	
	switch (cmd) {
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
			    return get_lsr_info(info, (unsigned int *) arg);

		case TIOCSERGSTRUCT:
			if (copy_to_user((struct bf533_serial *) arg,
				    info, sizeof(struct bf533_serial)))
				return -EFAULT;
			return 0;
                case TIOCMBIS:
                case TIOCMBIC:
                case TIOCMSET:
                        return set_modem_info(info, cmd, (unsigned int *) arg);
                case TIOCSERGWILD:
                case TIOCSERSWILD:
                        /* "setserial -W" is called in Debian boot */
                        printk("TIOCSER?WILD ioctl obsolete, ignored.\n");
                        return 0;
		default:
			return -ENOIOCTLCMD;
		}
	return 0;
}

static void rs_set_termios(struct tty_struct *tty, struct termios *old_termios)
{
	struct bf533_serial *info = (struct bf533_serial *)tty->driver_data;

	FUNC_ENTER();

	if (tty->termios->c_cflag == old_termios->c_cflag)
		return;
                                                                                
        DUMP_TERMIOS(old_termios);
        DUMP_TERMIOS(tty->termios);

	bf533_change_speed(info);
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
	
	FUNC_ENTER();
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
		local_irq_save(flags);
		if (!(info->flags & S_CALLOUT_ACTIVE))
			bf533_rtsdtr(info, 1);
		local_irq_restore(flags);
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

	FUNC_ENTER();
	line = tty->index;
	
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

#ifdef CONFIG_BLKFIN_SIMPLE_DMA
irqreturn_t uart_rxdma_done(int irq, void *dev_id,struct pt_regs *pt_regs)
{
	struct bf533_serial *info;
	
	clear_dma_irqstat(CH_UART_RX);
	info = &bf533_soft;
	info->event |= 1 << RS_EVENT_READ;
	schedule_work(&info->tqueue);
	return IRQ_HANDLED;
}

irqreturn_t uart_txdma_done(int irq, void *dev_id,struct pt_regs *pt_regs)
{
	struct bf533_serial *info;
	unsigned int irqstat;

	irqstat = get_dma_curr_irqstat(CH_UART_TX);
	
	if(irqstat&1 && !(irqstat&8) && tx_xcount>0) {
		ACCESS_PORT_IER
		*pUART_IER &= ~ETBEI;
		SYNC_ALL;
		clear_dma_irqstat(CH_UART_TX);
		
		info = &bf533_soft;
		info->xmit_tail += tx_xcount;
		info->xmit_tail %= SERIAL_XMIT_SIZE;
		info->xmit_cnt -= tx_xcount;
		tx_xcount = 0;
		
		if(info->xmit_cnt > 0) {
		        mod_timer(&info->dma_xmit_timer, jiffies);
		}

		if (info->xmit_cnt < WAKEUP_CHARS)
		{
			info->event |= 1 << RS_EVENT_WRITE_WAKEUP;
			schedule_work(&info->tqueue);
		}
	}
	return IRQ_HANDLED;
}
#endif

/* Finally, routines used to initialize the serial driver. */

static void show_serial_version(void)
{
	printk("BlackFin BF533 serial driver version 2.00 With DMA Support \n");
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
	
	FUNC_ENTER();
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
                        bf533_console_cbaud | CS8 | CREAD | CLOCAL;
        bf533_serial_driver->init_termios.c_lflag =
                        ISIG | ICANON | IEXTEN;

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
	info->is_cons = 0; /* Means shortcuts work */
	info->irq = IRQ_UART_RX;
        info->xmit_desc = NULL;
	
	printk("%s0 at irq = %d", \
		bf533_serial_driver->name, info->irq);
	printk(" is a builtin BlackFin BF533 UART\n");

	local_irq_restore(flags);

#ifndef CONFIG_BLKFIN_SIMPLE_DMA
	if (request_irq(IRQ_UART_RX, rs_interrupt, SA_INTERRUPT|SA_SHIRQ, "BF533_UART_RX",bf533_serial_driver))
		panic("Unable to attach BlackFin UART RX interrupt\n");

	if (request_irq(IRQ_UART_TX, rs_interrupt, SA_INTERRUPT|SA_SHIRQ, "BF533_UART_TX",bf533_serial_driver))
		panic("Unable to attach BlackFin UART TX interrupt\n");
#else
	if(request_dma(CH_UART_RX, "BF533_UART_RX")<0)
		panic("Unable to attach BlackFin UART RX DMA channel\n");
	else
	     set_dma_callback(CH_UART_RX, uart_rxdma_done,NULL);
	
	if(request_dma(CH_UART_TX, "BF533_UART_TX")<0)
		panic("Unable to attach BlackFin UART TX DMA channel\n");
	else 
	     set_dma_callback(CH_UART_TX,uart_txdma_done,NULL);
#endif	
	
	printk("Enabling Serial UART Interrupts\n");

	return 0;
}
module_init(rs_bf533_init);

/* setting console baud rate: CONFIG_SERIAL_CONSOLE_PORT */
static void bf533_set_baud( void )
{
	int	i;

	FUNC_ENTER();
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
#ifdef CONFIG_BLKFIN_SIMPLE_DMA
        *pUART_IER |= ELSI;
#else
        *pUART_IER |=(ETBEI | ELSI);
#endif
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

	FUNC_ENTER();

	if (arg)
		n = simple_strtoul(arg,NULL,0);

	for (i = 0; i < BAUD_TABLE_SIZE; i++)
		if (baud_table[i] == n)
			break;
	if (i < BAUD_TABLE_SIZE) {
		bf533_console_baud = n;
		bf533_console_cbaud = unix_baud_table[i];
	}

	bf533_soft.is_cons = 1;
	bf533_set_baud(); /* make sure baud rate changes */
	return 0;
}

static struct tty_driver * bf533_console_device(struct console *c, int *index)
{
	FUNC_ENTER();
	if(c)
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
