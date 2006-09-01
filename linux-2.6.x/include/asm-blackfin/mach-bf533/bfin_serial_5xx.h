#include <linux/serial.h>
#include <asm/dma.h>

#define NR_PORTS                1

#define OFFSET_THR              0x00    /* Transmit Holding register            */
#define OFFSET_RBR              0x00    /* Receive Buffer register              */
#define OFFSET_DLL              0x00    /* Divisor Latch (Low-Byte)             */
#define OFFSET_IER              0x04    /* Interrupt Enable Register            */
#define OFFSET_DLH              0x04    /* Divisor Latch (High-Byte)            */
#define OFFSET_IIR              0x08    /* Interrupt Identification Register    */
#define OFFSET_LCR              0x0C    /* Line Control Register                */
#define OFFSET_MCR              0x10    /* Modem Control Register               */
#define OFFSET_LSR              0x14    /* Line Status Register                 */
#define OFFSET_MSR              0x18    /* Modem Status Register                */
#define OFFSET_SCR              0x1C    /* SCR Scratch Register                 */
#define OFFSET_GCTL             0x24    /* Global Control Register              */

#define UART_GET_CHAR(uart)     bfin_read16(((uart)->port.membase + OFFSET_RBR))
#define UART_GET_DLL(uart)	bfin_read16(((uart)->port.membase + OFFSET_DLL))
#define UART_GET_IER(uart)      bfin_read16(((uart)->port.membase + OFFSET_IER))
#define UART_GET_DLH(uart)	bfin_read16(((uart)->port.membase + OFFSET_DLH))
#define UART_GET_IIR(uart)      bfin_read16(((uart)->port.membase + OFFSET_IIR))
#define UART_GET_LCR(uart)      bfin_read16(((uart)->port.membase + OFFSET_LCR))
#define UART_GET_LSR(uart)      bfin_read16(((uart)->port.membase + OFFSET_LSR))
#define UART_GET_GCTL(uart)     bfin_read16(((uart)->port.membase + OFFSET_GCTL))

#define UART_PUT_CHAR(uart,v)   bfin_write16(((uart)->port.membase + OFFSET_THR),v)
#define UART_PUT_DLL(uart,v)    bfin_write16(((uart)->port.membase + OFFSET_DLL),v)
#define UART_PUT_IER(uart,v)    bfin_write16(((uart)->port.membase + OFFSET_IER),v)
#define UART_PUT_DLH(uart,v)    bfin_write16(((uart)->port.membase + OFFSET_DLH),v)
#define UART_PUT_LCR(uart,v)    bfin_write16(((uart)->port.membase + OFFSET_LCR),v)
#define UART_PUT_GCTL(uart,v)   bfin_write16(((uart)->port.membase + OFFSET_GCTL),v)

#define CTS_PORT	FIO_FLAG_D
#define CTS_PIN		7
#define CTS_PORT_DIR	FIO_DIR
#define CTS_PORT_INEN	FIO_INEN

#define RTS_PORT	FIO_FLAG_D
#define RTS_PIN		6
#define RTS_PORT_DIR	FIO_DIR
#define RTS_PORT_INEN	FIO_INEN

struct bfin_serial_port {
        struct uart_port        port;
        unsigned int            old_status;
#ifdef CONFIG_SERIAL_BFIN_DMA
	int			tx_done;
	int			tx_count;
	struct circ_buf		rx_dma_buf;
	struct timer_list       rx_dma_timer;
	int			rx_dma_nrows;
	unsigned int		tx_dma_channel;
	unsigned int		rx_dma_channel;
	struct work_struct	tx_dma_workqueue;
#else
	struct work_struct 	cts_workqueue;
#endif
};

struct bfin_serial_port bfin_serial_ports[NR_PORTS];
const unsigned long uart_base_addr[NR_PORTS] = {0xFFC00400};
const int uart_irq[NR_PORTS] = {IRQ_UART_RX};

#ifdef CONFIG_SERIAL_BFIN_DMA
unsigned int uart_tx_dma_channel[NR_PORTS] = {CH_UART_TX};
unsigned int uart_rx_dma_channel[NR_PORTS] = {CH_UART_RX};
#endif

static void bfin_serial_hw_init(void)
{

#ifdef CONFIG_SERIAL_BFIN_CTSRTS
	bfin_write16(CTS_PORT_DIR,bfin_read16(CTS_PORT_DIR)&(~1<<CTS_PIN));
	bfin_write16(CTS_PORT_INEN,bfin_read16(CTS_PORT_INEN)|(1<<CTS_PIN));
	
	bfin_write16(RTS_PORT_DIR,bfin_read16(RTS_PORT_DIR)|(1<<RTS_PIN));
#endif
}
