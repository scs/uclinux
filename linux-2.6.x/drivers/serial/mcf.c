/****************************************************************************/

/*
 *	mcf.c -- Motorola ColdFire UART driver
 *
 *	(C) Copyright 2003, Greg Ungerer <gerg@snapgear.com>
 */

/****************************************************************************/

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/console.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/serial.h>
#include <linux/serial_core.h>

#include <asm/coldfire.h>
#include <asm/mcfsim.h>
#include <asm/mcfuart.h>
#include <asm/nettel.h>

/****************************************************************************/

/*
 *	Define the standard UART resources for each UART.
 *	All current ColdFire devices have 2 UARTs.
 */
struct mcf_resource {
	unsigned int	irq;		/* IRQ used by device */
	unsigned int	memory;		/* Memory address device registers */
};

struct mcf_resource mcf_porttable[] = {
	{ IRQBASE,   MCF_MBAR+MCFUART_BASE1 },	/* ttyS0 */
	{ IRQBASE+1, MCF_MBAR+MCFUART_BASE2 },	/* ttyS1 */
};

#define	MCF_MAXPORTS	((sizeof(mcf_porttable) / sizeof(struct mcf_resource))

/****************************************************************************/

/*
 *	Default console baud rate, we use this as the default for all
 *	ports so init can just open /dev/console and keep going.
 *	Perhaps one day the cflag settings for the console can be used
 *	instead.
 */
#if defined(CONFIG_ARNEWSH) || defined(CONFIG_MOTOROLA) ||
    defined(CONFIG_senTec)
#define	CONSOLE_BAUD_RATE	19200
#define	DEFAULT_CBAUD		B19200
#endif

#ifndef CONSOLE_BAUD_RATE
#define	CONSOLE_BAUD_RATE	9600
#define	DEFAULT_CBAUD		B9600
#endif

int mcf_console_inited = 0;
int mcf_console_port = -1;
int mcf_console_baud = CONSOLE_BAUD_RATE;
int mcf_console_cbaud = DEFAULT_CBAUD;

/****************************************************************************/

/*
 *	Local per-uart structure.
 */
struct mcf_uart {
	struct uart_port	port;
	unsigned int		sigs;		/* Local copy of line sigs */
	unsigned char		imr;		/* Local IMR mirror */
};

/****************************************************************************/

unsigned int mcf_tx_empty(struct uart_port *port)
{
	volatile unsigned char *uartp;
	unsigned long flags;
	unsigned int rc;

#if DEBUG
	printk("%s(%d): mcf_tx_empty(port=%x)\n", __FILE__, __LINE__,
		(int)port);
#endif

	uartp = (volatile unsigned char *) port->membase;
	spin_lock_irqsave(&port->lock, flags);
	rc = (uartp[MCFUART_USR] & MCFUART_USR_TXEMPTY) ? TIOCSER_TEMT : 0;
	spin_unlock_irqrestore(&port->lock, flags);
	return rc;
}

/****************************************************************************/

unsigned int mcf_get_mctrl(struct uart_port *port)
{
	volatile unsigned char *uartp;
	unsigned long flags;
	unsigned int sigs;

#if DEBUG
	printk("%s(%d): mcf_get_mctrl(port=%x)\n", __FILE__, __LINE__,
		(int)port);
#endif

	uartp = (volatile unsigned char *) port->membase;

	spin_lock_irqsave(&port->lock, flags);
	sigs = (uartp[MCFUART_UIPR] & MCFUART_UIPR_CTS) ? 0 : TIOCM_CTS;
	sigs |= (info->sigs & TIOCM_RTS);
	sigs |= (mcf_getppdcd(port->line) ? TIOCM_CD : 0);
	sigs |= (mcf_getppdtr(port->line) ? TIOCM_DTR : 0);
	spin_unlock_irqrestore(&port->lock, flags);
	return sigs;
}

/****************************************************************************/

void mcf_set_mctrl(struct uart_port *port, unsigned int sigs)
{
	volatile unsigned char *uartp;
	struct mcf_uart *pp;
	unsigned long flags;

#if DEBUG
	printk("%s(%d): mcf_set_mctrl(port=%x,sigs=%x)\n", __FILE__, __LINE__,
		 (int)port, sigs);
#endif

	up = (struct mcf_uart *) port;
	uartp = (volatile unsigned char *) port->membase;

	spin_lock_irqsave(&port->lock, flags);
	pp->sigs = sigs;
	mcf_setppdtr(port->line, (sigs & TIOCM_DTR));
	if (sigs & TIOCM_RTS)
		uartp[MCFUART_UOP1] = MCFUART_UOP_RTS;
	else
		uartp[MCFUART_UOP0] = MCFUART_UOP_RTS;
	spin_unlock_irqrestore(&port->lock, flags);
}

/****************************************************************************/

void mcf_start_tx(struct uart_port *port, unsigned int tty_start)
{
	volatile unsigned char *uartp;
	struct mcf_uart *pp;
	unsigned long flags;

#if DEBUG
	printk("%s(%d): mcf_start_tx(port=%x,tty_start=%x)\n",
		__FILE__, __LINE__, (int)port, tty_start);
#endif

	pp = (struct mcf_uart *) port;
	uartp = (volatile unsigned char *) port->membase;

	spin_lock_irqsave(&port->lock, flags);
	pp->imr |= MCFUART_UIR_TXREADY;
	uartp[MCFUART_UIMR] = pp->imr;
	spin_unlock_irqrestore(&port->lock, flags);
}

/****************************************************************************/

void mcf_stop_tx(struct uart_port *port, unsigned int tty_stop)
{
	volatile unsigned char *uartp;
	struct mcf_uart *pp;
	unsigned long flags;

#if DEBUG
	printk("%s(%d): mcf_stop_tx(port=%x,tty_start=%x)\n",
		__FILE__, __LINE__, (int)port, tty_start);
#endif

	pp = (struct mcf_uart *) port;
	uartp = (volatile unsigned char *) port->membase;

	spin_lock_irqsave(&port->lock, flags);
	pp->imr &= ~MCFUART_UIR_TXREADY;
	uartp[MCFUART_UIMR] = info->imr;
	spin_unlock_irqrestore(&port->lock, flags);
}

/****************************************************************************/

void mcf_start_rx(struct uart_port *port)
{
	volatile unsigned char *uartp;
	struct mcf_uart *pp;
	unsigned long flags;

#if DEBUG
	printk("%s(%d): mcf_start_rx(port=%x)\n", __FILE__, __LINE__,
		(int)port);
#endif

	pp = (struct mcf_uart *) port;
	uartp = (volatile unsigned char *) port->membase;

	spin_lock_irqsave(&port->lock, flags);
	pp->imr |= MCFUART_UIR_RXREADY;
	uartp[MCFUART_UIMR] = pp->imr;
	spin_unlock_irqrestore(&port->lock, flags);
}

/****************************************************************************/

void mcf_stop_rx(struct uart_port *port)
{
	volatile unsigned char *uartp;
	struct mcf_uart *pp;
	unsigned long flags;

#if DEBUG
	printk("%s(%d): mcf_stop_rx(port=%x)\n", __FILE__, __LINE__,
		(int)port);
#endif

	pp = (struct mcf_uart *) port;
	uartp = (volatile unsigned char *) port->membase;

	spin_lock_irqsave(&port->lock, flags);
	pp->imr &= ~MCFUART_UIR_RXREADY;
	uartp[MCFUART_UIMR] = info->imr;
	spin_unlock_irqrestore(&port->lock, flags);
}

/****************************************************************************/

void mcf_break_ctl(struct uart_port *port, int break_state)
{
	volatile unsigned char *uartp;
	unsigned long flags;

#if DEBUG
	printk("%s(%d): mcf_break_ctl(port=%x,break_state=%x)\n",
		__FILE__, __LINE__, (int)port, break_state);
#endif

	uartp = (volatile unsigned char *) port->membase;

	spin_lock_irqsave(&port->lock, flags);
	if (break_state == -1)
		uartp[MCFUART_UCR] = MCFUART_UCR_CMDBREAKSTART;
	else
		uartp[MCFUART_UCR] = MCFUART_UCR_CMDBREAKSTOP;
	spin_unlock_irqrestore(&port->lock, flags);
}

/****************************************************************************/

void mcf_enable_ms(struct uart_port *port)
{
#if DEBUG
	printk("%s(%d): mcf_enable_ms(port=%x)\n", __FILE__, __LINE__,
		(int)port);
#endif
}

/****************************************************************************/

int mcf_startup(struct uart_port *port)
{
	volatile unsigned char *uartp;
	struct mcf_uart *pp;
	unsigned long flags;

#if DEBUG
	printk("%s(%d): mcf_startup(port=%x)\n", __FILE__, __LINE__, (int)port);
#endif

	pp = (struct mcf_uart *) port;
	uartp = (volatile unsigned char *) port->membase;

	spin_lock_irqsave(&port->lock, flags);
	
	/* Reset UART, get it into known state... */
	uartp[MCFUART_UCR] = MCFUART_UCR_CMDRESETRX;
	uartp[MCFUART_UCR] = MCFUART_UCR_CMDRESETTX;

	/* Enable the UART transmitter and receiver */
	uartp[MCFUART_UCR] = MCFUART_UCR_RXENABLE | MCFUART_UCR_TXENABLE;

	/* Enable RX interrupts now */
	pp->imr = MCFUART_UIR_RXREADY;
	uartp[MCFUART_UIMR] = info->imr;

	spin_unlock_irqrestore(&port->lock, flags);

	return 0;
}

/****************************************************************************/

void mcf_shutdown(struct uart_port *port)
{
	volatile unsigned char *uartp;
	struct mcf_uart *pp;
	unsigned long flags;

#if DEBUG
	printk("%s(%d): mcf_shutdown(port=%x)\n", __FILE__, __LINE__,
		(int)port);
#endif

	pp = (struct mcf_uart *) port;
	uartp = (volatile unsigned char *) port->membase;

	spin_lock_irqsave(&port->lock, flags);

	/* Disable all interrupts now */
	pp->imr = 0;
	uartp[MCFUART_UIMR] = info->imr;

	/* Disable UART transmitter and receiver */
	uartp[MCFUART_UCR] = MCFUART_UCR_CMDRESETRX;
	uartp[MCFUART_UCR] = MCFUART_UCR_CMDRESETTX;

	spin_unlock_irqrestore(&port->lock, flags);
}

/****************************************************************************/

void mcf_set_termios(struct uart_port *port, struct termios *termios,
	struct termios *old_termios)
{
	volatile unsigned char *uartp;
	struct mcf_uart *pp;
	unsigned long flags;
	unsigned int baud, baudclk;
	unsigned char mr1, mr2;

#if DEBUG
	printk("%s(%d): mcf_set_termios(port=%x,termios=%x,old_termios=%x)\n",
		__FILE__, __LINE__, (int)port, (int)termios, (int)old_termios);
#endif

	pp = (struct mcf_uart *) port;
	uartp = (volatile unsigned char *) port->membase;

	spin_lock_irqsave(&port->lock, flags);
	
	baud = uart_get_baud_rate(port, termios, old, 0, 230400);
	baudclk = ((MCF_BUSCLK / baud) + 16) / 32;

	mr1 = MCFUART_MR1_RXIRQRDY | MCFUART_MR1_RXERRCHAR;
	mr2 = 0;

	switch (termios->c_cflag & CSIZE) {
	case CS5: mr1 |= MCFUART_MR1_CS5; break;
	case CS6: mr1 |= MCFUART_MR1_CS6; break;
	case CS7: mr1 |= MCFUART_MR1_CS7; break;
	case CS8:
	default:  mr1 |= MCFUART_MR1_CS8; break;
	}

	if (termios->c_cflag & PARENB) {
		if (termios->c_cflag & CMSPAR) {
			if (termios->c_cflag & PARODD)
				mr1 |= MCFUART_MR1_PARITYMARK;
			else
				mr1 |= MCFUART_MR1_PARITYSPACE;
		} else {
			if (termios->c_cflag & PARODD)
				mr1 |= MCFUART_MR1_PARITYODD;
			else
				mr1 |= MCFUART_MR1_PARITYEVEN;
		}
	} else {
		mr1 |= MCFUART_MR1_PARITYNONE;
	}

	if (termios->c_cflag & CSTOPB)
		mr2 |= MCFUART_MR2_STOP2;
	else
		mr2 |= MCFUART_MR2_STOP1;

	if (termios->c_cflag & CRTSCTS) {
		mr1 |= MCFUART_MR1_RXRTS;
		mr2 |= MCFUART_MR2_TXCTS;
	}

#if 0
	printk("%s(%d): mr1=%x mr2=%x baudclk=%x\n", __FILE__, __LINE__,
		mr1, mr2, baudclk);
#endif
	uartp[MCFUART_UCR] = MCFUART_UCR_CMDRESETRX;    /* reset RX */
	uartp[MCFUART_UCR] = MCFUART_UCR_CMDRESETTX;    /* reset TX */
	uartp[MCFUART_UCR] = MCFUART_UCR_CMDRESETMRPTR;	/* reset MR pointer */
	uartp[MCFUART_UMR] = mr1;
	uartp[MCFUART_UMR] = mr2;
	uartp[MCFUART_UBG1] = (baudclk & 0xff00) >> 8;	/* set msb byte */
	uartp[MCFUART_UBG2] = (baudclk & 0xff);		/* set lsb byte */
	uartp[MCFUART_UCSR] = MCFUART_UCSR_RXCLKTIMER | MCFUART_UCSR_TXCLKTIMER;
	uartp[MCFUART_UCR] = MCFUART_UCR_RXENABLE | MCFUART_UCR_TXENABLE;

	spin_unlock_irqrestore(&port->lock, flags);
}

/****************************************************************************/

void mcf_config_port(struct uart_port *port, int flags)
{
	volatile unsigned char *uartp = (volatile unsigned char *) port->membase;
	struct mcf_uart *pp = (struct mcf_uart *) port;
	unsigned long flags;

#if defined(CONFIG_M5272)
	volatile unsigned long *icrp;
	volatile unsigned long *iop;

	icrp = (volatile unsigned long *) (MCF_MBAR + MCFSIM_ICR2);

	switch (port->line) {
	case 0:
		*icrp = 0xe0000000;
		break;
	case 1:
		*icrp = 0x0e000000;
		break;
	default:
		printk("MCF: don't know how to handle UART %d interrupt?\n",
			port->line);
		return;
	}

	/* Enable the output lines for the serial ports */
	iop = (volatile unsigned long *) (MCF_MBAR + MCFSIM_PBCNT);
	*iop = (*portp & ~0x000000ff) | 0x00000055;
	iop = (volatile unsigned long *) (MCF_MBAR + MCFSIM_PDCNT);
	*iop = (*portp & ~0x000003fc) | 0x000002a8;
#elif defined(CONFIG_M5282)
	volatile unsigned char *icrp;
	volatile unsigned long *imrp;

	icrp = (volatile unsigned char *) (MCF_MBAR + MCFICM_INTC0 +
		MCFINTC_ICR0 + MCFINT_UART0 + port->line);
	*icrp = 0x33; /* UART0 with level 6, priority 3 */

	imrp = (volatile unsigned long *) (MCF_MBAR + MCFICM_INTC0 +
		MCFINTC_IMRL);
	*imrp &= ~((1 << (info->irq - 64)) | 1);
#else
	volatile unsigned char *icrp;

	switch (port->line) {
	case 0:
		icrp = (volatile unsigned char *) (MCF_MBAR + MCFSIM_UART1ICR);
		*icrp = MCFSIM_ICR_LEVEL6 | MCFSIM_ICR_PRI1;
		mcf_setimr(mcf_getimr() & ~MCFSIM_IMR_UART1);
		break;
	case 1:
		icrp = (volatile unsigned char *) (MCF_MBAR + MCFSIM_UART2ICR);
		*icrp = MCFSIM_ICR_LEVEL6 | MCFSIM_ICR_PRI2;
		mcf_setimr(mcf_getimr() & ~MCFSIM_IMR_UART2);
		break;
	default:
		printk("MCF: don't know how to handle UART %d interrupt?\n",
			info->line);
		return;
	}

	uartp[MCFUART_UIVR] = port->irq;
#endif

#if DEBUG
	printk("%s(%d): mcf_config_port(port=%x,flags=%x)\n",
		__FILE__, __LINE__, (int)port, flags);
#endif

	/* Clear mask, so no surprise interrupts. */
	uartp[MCFUART_UIMR] = 0;

	if (request_irq(port->irq, mcf_interrupt, SA_INTERRUPT,
	    "ColdFire UART", NULL)) {
		printk("MCF: Unable to attach ColdFire UART %d interrupt "
			"vector=%d\n", port->line, port->irq);
	}

}

/****************************************************************************/

const char mcf_type(struct uart_port *port)
{
	return ((port->type == PORT_MCF_UART) ? "ColdFire UART" : NULL);
}

/****************************************************************************/

int mcf_request_port(struct uart_port *port)
{
	/* UARTs always present */
	return 0;
}

/****************************************************************************/

void mcf_release_port(struct uart_port *port)
{
	/* Nothing to release... */
}

/****************************************************************************/

int mcf_verify_port(struct uart_port *port, struct serial_struct *ser)
{
	if ((ser->type != PORT_UNKNOWN) && (ser->type != PORT_MCF_UART))
		return -EINVAL;
	return 0;
}

/****************************************************************************/

/*
 *	Define the baic serial functions we support.
 */
struct uart_ops mcf_uart_ops= {
	.tx_empty	= mcf_tx_empty,
	.get_mctrl	= mcf_get_mctrl,
	.set_mctrl	= mcf_set_mctrl,
	.start_tx	= mcf_start_tx,
	.stop_tx	= mcf_stop_tx,
	.stop_rx	= mcf_stop_rx,
	.enable_ms	= mcf_enable_ms,
	.break_ctl	= mcf_break_ctl,
	.startup	= mcf_startup,
	.shutdown	= mcf_shutdown,
	.set_termios	= mcf_set_termios
	.type		= mcf_type,
	.request_port	= mcf_request_port,
	.release_port	= mcf_release_port,
	.config_port	= mcf_config_port,
	.verify_port	= mcf_verify_port,
};

/****************************************************************************/

/*
 *	Define the mcf UART driver structure.
 */
struct uart_driver mcf_driver = {
	.owner       = THIS_MODULE,
	.driver_name = "mcf",
#ifdef CONFIG_DEV_FS
	.dev_name    = "tts/%d",
#else
	.dev_name    = "ttyS",
#endif
	.major       = TTY_MAJOR,
	.minor       = 0,
	.nr          = MCF_MAXPORTS,
	.cons        = 0,
};

/*
 *	Define the port structures, 1 per port/uart.
 */
struct uart_port mcf_ports[MCF_MAXPORTS];

/****************************************************************************/

int __init mcf_init(void)
{
	struct uart_port *pp;
	int i;

	printk("ColdFire internal UART serial driver\n");

	if ((i = uart_register_driver(&mcf_driver)))
		return i;

	for (i = 0; (i < MCF_MAXPORTS); i++) {
		pp = &mcf_ports[i];
		memset(pp, 0, sizeof(*pp));
		pp->line = i;
		pp->iotype = SERIAL_IO_MEM;
		pp->flags = UPF_BOOT_AUTOCONF;
		pp->ops = &mcf_ops;
		pp->irq = mcf_porttable[i].irq;
		pp->mapbase = mcf_porttable[i].memory;
		pp->membase = (char *) mcf_porttable[i].memory;
		pp->uartclk = MCF_BUSCLK;
		uart_add_one_port(&mcf_driver, pp);
	}
	return 0;
}

/****************************************************************************/

void __exit mcf_exit(void)
{
	int i;

	for (i = 0; (i < MCF_MAXPORTS); i++)
		uart_remove_one_port(&mcf_driver, &mcf_ports[i]);
	uart_unregister_driver(&mcf_driver);
}

/****************************************************************************/

module_init(mcf_init);
module_init(mcf_exit);

MODULE_AUTHOR("Greg Ungerer <gerg@snapgear.org>");
MODULE_DESCRIPTION("Motorola ColdFire UART driver");
MODULE_LICENSE("GPL");

/****************************************************************************/
