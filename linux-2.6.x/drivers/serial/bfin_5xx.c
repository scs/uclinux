/*
 *  linux/drivers/serial/bfin_5xx.c
 *
 *  Driver for blackfin 5xx serial ports
 *
 *  Based on drivers/char/serial.c, by Linus Torvalds, Theodore Ts'o.
 *
 *  Copyright (C) 2000 Deep Blue Solutions Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  $Id$
 *
 */
#include <linux/config.h>

#if defined(CONFIG_SERIAL_BFIN_CONSOLE) && defined(CONFIG_MAGIC_SYSRQ)
#define SUPPORT_SYSRQ
#endif

#include <linux/module.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/console.h>
#include <linux/sysrq.h>
#include <linux/platform_device.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/serial_core.h>

#include <asm/mach/bfin_serial_5xx.h>

#include <asm/io.h>
#include <asm/irq.h>

/* We've been assigned a range on the "Low-density serial ports" major */
#define SERIAL_BFIN_MAJOR	TTY_MAJOR
#define MINOR_START		64

#define DEBUG

#ifdef DEBUG
#define DPRINTK(x...)   printk(x)
#else
#define DPRINTK(x...)   do { } while (0)
#endif

/*
 * Handle any change of modem status signal since we were last called.
 */
static void bfin_serial_mctrl_check(struct bfin_serial_port *uart)
{
	unsigned int status, changed;

	status = uart->port.ops->get_mctrl(&uart->port);
	changed = status ^ uart->old_status;

	if (changed == 0)
		return;

	uart->old_status = status;

	if (changed & TIOCM_RI)
		uart->port.icount.rng++;
	if (changed & TIOCM_DSR)
		uart->port.icount.dsr++;
	if (changed & TIOCM_CAR)
		uart_handle_dcd_change(&uart->port, status & TIOCM_CAR);
	if (changed & TIOCM_CTS)
		uart_handle_cts_change(&uart->port, status & TIOCM_CTS);

	wake_up_interruptible(&uart->port.info->delta_msr_wait);
}

/*
 * interrupts disabled on entry
 */
static void bfin_serial_stop_tx(struct uart_port *port)
{
	struct bfin_serial_port *uart = (struct bfin_serial_port *)port;
	unsigned short ier;
	ier = UART_GET_IER(uart);
	ier &= ~ETBEI;
	UART_PUT_IER(uart, ier);
}

/*
 * port locked and interrupts disabled
 */
static void bfin_serial_start_tx(struct uart_port *port)
{
	struct bfin_serial_port *uart = (struct bfin_serial_port *)port;
	unsigned short ier;
	ier = UART_GET_IER(uart);
	ier |= ETBEI;
	UART_PUT_IER(uart, ier);
}

/*
 * Interrupts enabled
 */
static void bfin_serial_stop_rx(struct uart_port *port)
{
	struct bfin_serial_port *uart = (struct bfin_serial_port *)port;
	unsigned short ier;
	ier = UART_GET_IER(uart);
	ier &= ERBFI;
	UART_PUT_IER(uart, ier);
}

/*
 * Set the modem control timer to fire immediately.
 */
static void bfin_serial_enable_ms(struct uart_port *port)
{
}

static void
bfin_serial_rx_chars(struct bfin_serial_port *uart, struct pt_regs *regs)
{
	struct tty_struct *tty = uart->port.info->tty;
	unsigned int status=0, ch, flg;
	ch = UART_GET_CHAR(uart);
	uart->port.icount.rx++;
	flg = TTY_NORMAL;
	if(uart_handle_sysrq_char(&uart->port, ch, regs))
		goto ignore_char;
	uart_insert_char(&uart->port, status, 1, ch, flg);

ignore_char:
	tty_flip_buffer_push(tty);
}

static void bfin_serial_tx_chars(struct bfin_serial_port *uart)
{
        struct circ_buf *xmit = &uart->port.info->xmit;

        if (uart->port.x_char) {
		UART_PUT_CHAR(uart, uart->port.x_char);
                uart->port.icount.tx++;
                uart->port.x_char = 0;
                return;
        }
        /*
         * Check the modem control lines before
         * transmitting anything.
         */
        bfin_serial_mctrl_check(uart);

        if (uart_circ_empty(xmit) || uart_tx_stopped(&uart->port)) {
                bfin_serial_stop_tx(&uart->port);
                return;
        }
	
        UART_PUT_CHAR(uart,xmit->buf[xmit->tail]);
        xmit->tail = (xmit->tail + 1) & (UART_XMIT_SIZE - 1);
        uart->port.icount.tx++;

        if (uart_circ_chars_pending(xmit) < WAKEUP_CHARS)
                uart_write_wakeup(&uart->port);

        if (uart_circ_empty(xmit))
                bfin_serial_stop_tx(&uart->port);
}

static irqreturn_t bfin_serial_int(int irq, void *dev_id, struct pt_regs *regs)
{
	struct bfin_serial_port *uart = dev_id;
        unsigned short status;

	spin_lock(&uart->port.lock);
	status = UART_GET_IIR(uart);
	do{
		if((status & IIR_STATUS) == IIR_TX_READY)
			bfin_serial_tx_chars(uart);
		if((status & IIR_STATUS) == IIR_RX_READY)
			bfin_serial_rx_chars(uart,regs);
		status = UART_GET_IIR(uart);
	}while(status &(IIR_TX_READY | IIR_RX_READY));
	spin_unlock(&uart->port.lock);
        return IRQ_HANDLED;
}

/*
 * Return TIOCSER_TEMT when transmitter is not busy.
 */
static unsigned int bfin_serial_tx_empty(struct uart_port *port)
{
	struct bfin_serial_port *uart = (struct bfin_serial_port *)port;
	unsigned short lsr;
	lsr = UART_GET_LSR(uart);
	if(lsr & THRE)
		return TIOCSER_TEMT;
	else
		return 0;
}

static unsigned int bfin_serial_get_mctrl(struct uart_port *port)
{
	return TIOCM_CTS | TIOCM_DSR | TIOCM_CAR;
}

static void bfin_serial_set_mctrl(struct uart_port *port, unsigned int mctrl)
{
}

/*
 * Interrupts always disabled.
 */
static void bfin_serial_break_ctl(struct uart_port *port, int break_state)
{
}

int bfin_serial_startup(struct uart_port *port)
{
	struct bfin_serial_port *uart = (struct bfin_serial_port *)port;

	if (request_irq
            (uart->port.irq, bfin_serial_int, SA_INTERRUPT | SA_SHIRQ,
             "BFIN_UART0_RX", uart)) {
                printk("Unable to attach BlackFin UART RX interrupt\n");
                return -EBUSY;
        }

        if (request_irq
            (uart->port.irq+1, bfin_serial_int, SA_INTERRUPT | SA_SHIRQ,
             "BFIN_UART0_TX", uart)) {
                printk("Unable to attach BlackFin UART TX interrupt\n");
                return -EBUSY;
        }
	
	UART_PUT_IER(uart, ERBFI);
	return 0;
}

static void bfin_serial_shutdown(struct uart_port *port)
{
	struct bfin_serial_port *uart = (struct bfin_serial_port *)port;
	free_irq(uart->port.irq, uart);
	free_irq(uart->port.irq+1, uart);
}

static void
bfin_serial_set_termios(struct uart_port *port, struct termios *termios,
		   struct termios *old)
{
}

static const char *bfin_serial_type(struct uart_port *port)
{
	struct bfin_serial_port *uart = (struct bfin_serial_port *)port;
        return uart->port.type == PORT_BFIN ? "BFIN-UART" : NULL;
}

/*
 * Release the memory region(s) being used by 'port'.
 */
static void bfin_serial_release_port(struct uart_port *port)
{
}

/*
 * Request the memory region(s) being used by 'port'.
 */
static int bfin_serial_request_port(struct uart_port *port)
{
	return 0;
}

/*
 * Configure/autoconfigure the port.
 */
static void bfin_serial_config_port(struct uart_port *port, int flags)
{
	struct bfin_serial_port *uart = (struct bfin_serial_port *)port;

        if (flags & UART_CONFIG_TYPE &&
            bfin_serial_request_port(&uart->port) == 0)
                uart->port.type = PORT_BFIN;
}

/*
 * Verify the new serial_struct (for TIOCSSERIAL).
 * The only change we allow are to the flags and type, and
 * even then only between PORT_BFIN and PORT_UNKNOWN
 */
static int
bfin_serial_verify_port(struct uart_port *port, struct serial_struct *ser)
{
	return 0;
}

static struct uart_ops bfin_serial_pops = {
	.tx_empty	= bfin_serial_tx_empty,
	.set_mctrl	= bfin_serial_set_mctrl,
	.get_mctrl	= bfin_serial_get_mctrl,
	.stop_tx	= bfin_serial_stop_tx,
	.start_tx	= bfin_serial_start_tx,
	.stop_rx	= bfin_serial_stop_rx,
	.enable_ms	= bfin_serial_enable_ms,
	.break_ctl	= bfin_serial_break_ctl,
	.startup	= bfin_serial_startup,
	.shutdown	= bfin_serial_shutdown,
	.set_termios	= bfin_serial_set_termios,
	.type		= bfin_serial_type,
	.release_port	= bfin_serial_release_port,
	.request_port	= bfin_serial_request_port,
	.config_port	= bfin_serial_config_port,
	.verify_port	= bfin_serial_verify_port,
};

static int bfin_serial_calc_baud(unsigned int uartclk)
{
	int baud;
	baud = get_sclk()/(uartclk*8);
	if((baud & 0x1) == 1) {
		baud++;
	}
	return baud/2;
}

static void __init bfin_serial_init_ports(void)
{
	static int first = 1;
	int i;
	unsigned short val;
	int baud;

	if (!first)
		return;
	first = 0;
	bfin_serial_hw_init();

	for (i = 0; i < NR_PORTS; i++) {
		bfin_serial_ports[i].port.uartclk   = 57600;
		bfin_serial_ports[i].port.ops       = &bfin_serial_pops;
		bfin_serial_ports[i].port.line      = i;
		bfin_serial_ports[i].port.iotype    = UPIO_MEM;
		bfin_serial_ports[i].port.membase   = (void __iomem *)uart_base_addr[i];
                bfin_serial_ports[i].port.mapbase   = uart_base_addr[i];
                bfin_serial_ports[i].port.irq       = uart_irq[i];
                bfin_serial_ports[i].port.flags     = UPF_BOOT_AUTOCONF;
        	baud = bfin_serial_calc_baud(bfin_serial_ports[i].port.uartclk);

	        /* Enable UART */
		val = UART_GET_GCTL(&bfin_serial_ports[i]);
		val |= UCEN;
		UART_PUT_GCTL(&bfin_serial_ports[i], val);

	        /* Set DLAB in LCR to Access DLL and DLH */
		val = UART_GET_LCR(&bfin_serial_ports[i]);
		val |= DLAB;
		UART_PUT_LCR(&bfin_serial_ports[i], val);

		UART_PUT_DLL(&bfin_serial_ports[i], baud&0xFF);
		UART_PUT_DLH(&bfin_serial_ports[i], (baud>>8)&0xFF);

        	/* Clear DLAB in LCR to Access THR RBR IER */
		val = UART_GET_LCR(&bfin_serial_ports[i]);
                val &= ~DLAB;
                UART_PUT_LCR(&bfin_serial_ports[i], val);

        	/* Set LCR to Word Lengh 8-bit word select */
		val = WLS(8);
		UART_PUT_LCR(&bfin_serial_ports[i], val);
	}
}

#ifdef CONFIG_SERIAL_BFIN_CONSOLE
/*
 * Interrupts are disabled on entering
 */
static void
bfin_serial_console_write(struct console *co, const char *s, unsigned int count)
{
	struct bfin_serial_port *uart = &bfin_serial_ports[co->index];
        int flags = 0;
        unsigned short status, tmp;
	int i;

        local_irq_save(flags);
	
	for(i=0;i<count;i++){

	        do {
			status = UART_GET_LSR(uart);
	        } while (!(status & THRE));
		
		tmp = UART_GET_LCR(uart);
	        tmp &= ~DLAB;
        	UART_PUT_LCR(uart, tmp);

		UART_PUT_CHAR(uart,s[i]);
		if(s[i] == '\n'){
			do{
			status = UART_GET_LSR(uart);
			}while(!(status & THRE));
		UART_PUT_CHAR(uart,'\r');
		}
	}
        local_irq_restore(flags);
}

/*
 * If the port was already initialised (eg, by a boot loader),
 * try to determine the current setup.
 */
static void __init
bfin_serial_console_get_options(struct bfin_serial_port *uart, int *baud,
			   int *parity, int *bits)
{
	unsigned short status;

	status = UART_GET_IER(uart) & (ERBFI | ETBEI);
	if (status == (ERBFI | ETBEI)) {
		/* ok, the port was enabled */
		unsigned int lcr;

		lcr = UART_GET_LCR(uart);

		*parity = 'n';
		if (lcr & PEN) {
			if (lcr & EPS)
				*parity = 'e';
			else
				*parity = 'o';
		}

		*bits = 8;
		*baud = 57600;
	}
}

static int __init
bfin_serial_console_setup(struct console *co, char *options)
{
	struct bfin_serial_port *uart;
	int baud = 57600;
	int bits = 8;
	int parity = 'n';
	int flow = 'n';

	/*
	 * Check whether an invalid uart number has been specified, and
	 * if so, search for the first available port that does have
	 * console support.
	 */
	if (co->index == -1 || co->index >= NR_PORTS)
		co->index = 0;
	uart = &bfin_serial_ports[co->index];

	if (options)
		uart_parse_options(options, &baud, &parity, &bits, &flow);
	else
		bfin_serial_console_get_options(uart, &baud, &parity, &bits);

	return uart_set_options(&uart->port, co, baud, parity, bits, flow);
}

static struct uart_driver bfin_serial_reg;
static struct console bfin_serial_console = {
	.name		= "ttyS",
	.write		= bfin_serial_console_write,
	.device		= uart_console_device,
	.setup		= bfin_serial_console_setup,
	.flags		= CON_PRINTBUFFER,
	.index		= -1,
	.data		= &bfin_serial_reg,
};

static int __init bfin_serial_rs_console_init(void)
{
	bfin_serial_init_ports();
	register_console(&bfin_serial_console);
	return 0;
}
console_initcall(bfin_serial_rs_console_init);

#define BFIN_SERIAL_CONSOLE	&bfin_serial_console
#else
#define BFIN_SERIAL_CONSOLE	NULL
#endif

static struct uart_driver bfin_serial_reg = {
	.owner			= THIS_MODULE,
	.driver_name		= "bfin-uart",
	.dev_name		= "ttyS",
	.devfs_name		= "ttyS/",
	.major			= SERIAL_BFIN_MAJOR,
	.minor			= MINOR_START,
	.nr			= NR_PORTS,
	.cons			= BFIN_SERIAL_CONSOLE,
};

static int bfin_serial_suspend(struct platform_device *dev, pm_message_t state)
{
	struct bfin_serial_port *uart = platform_get_drvdata(dev);

	if (uart)
		uart_suspend_port(&bfin_serial_reg, &uart->port);

	return 0;
}

static int bfin_serial_resume(struct platform_device *dev)
{
	struct bfin_serial_port *uart = platform_get_drvdata(dev);

	if (uart)
		uart_resume_port(&bfin_serial_reg, &uart->port);

	return 0;
}

static int bfin_serial_probe(struct platform_device *dev)
{
	struct resource *res = dev->resource;
	int i;

	for (i = 0; i < dev->num_resources; i++, res++)
		if (res->flags & IORESOURCE_MEM)
			break;
	
	if (i < dev->num_resources) {
		for (i = 0; i < NR_PORTS; i++,res++) {
			if (bfin_serial_ports[i].port.mapbase != res->start)
				continue;
			bfin_serial_ports[i].port.dev = &dev->dev;
			uart_add_one_port(&bfin_serial_reg, &bfin_serial_ports[i].port);
			platform_set_drvdata(dev, &bfin_serial_ports[i]);
		}
	}

	return 0;
}

static int bfin_serial_remove(struct platform_device *pdev)
{
	struct bfin_serial_port *uart = platform_get_drvdata(pdev);

	platform_set_drvdata(pdev, NULL);

	if (uart)
		uart_remove_one_port(&bfin_serial_reg, &uart->port);

	return 0;
}

static struct platform_driver bfin_serial_driver = {
	.probe		= bfin_serial_probe,
	.remove		= bfin_serial_remove,
	.suspend	= bfin_serial_suspend,
	.resume		= bfin_serial_resume,
	.driver		= {
		.name	= "bfin-uart",
	},
};

static int __init bfin_serial_init(void)
{
	int ret;

	printk(KERN_INFO "Serial: Blackfin serial driver\n");
	
	bfin_serial_init_ports();

	ret = uart_register_driver(&bfin_serial_reg);
	if (ret == 0) {
		ret = platform_driver_register(&bfin_serial_driver);
		if (ret){
			DPRINTK("uart register failed\n");
			uart_unregister_driver(&bfin_serial_reg);
		}
	}
	return ret;
}

static void __exit bfin_serial_exit(void)
{
	platform_driver_unregister(&bfin_serial_driver);
	uart_unregister_driver(&bfin_serial_reg);
}

module_init(bfin_serial_init);
module_exit(bfin_serial_exit);

MODULE_AUTHOR("Aubrey.Li <aubrey.li@analog.com>");
MODULE_DESCRIPTION("Blackfin generic serial port driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS_CHARDEV_MAJOR(SERIAL_BFIN_MAJOR);
