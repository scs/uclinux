/*
 * arch/bfinommu/asm/bf533_dma.h -  Major Data structures for BF533 DMA
 *   			 	
 * Copyright (C) 2004 LG Soft India.
 *
 */

#ifndef _BLACKFIN_DMA_H_
#define _BLACKFIN_DMA_H_

#include <asm/io.h>
#include <linux/slab.h>
#include <asm/irq.h>
#include <asm/board/bf533_irq.h>
#include <asm/signal.h>
#include <asm/semaphore.h>


#define LINUX_WORKAROUND

// #define BLACKFIN_DMA_DEBUG

#ifndef LINUX_WORKAROUND
#undef BLACKFIN_DMA_DEBUG
#else
#include <linux/kernel.h>
extern void prom_printf(char * fmt, ...);

#endif

#define BLACKFIN_DMA_DEBUG 0

#ifdef BLACKFIN_DMA_DEBUG
#define DMA_DBG(fmt, args...) do { printk("Blackfin DMA driver: "fmt, ##args);} while (0)
#else
#define DMA_DBG(fmt, args...) do {} while (0)
#endif

#define ESUCCESS 1
#define SSYNC() asm("ssync;")

/*****************************************************************************
*        Generic DMA  Declarations
*
****************************************************************************/

#define BASE_VALUE 	0x0000	
#define LOW_WORD 	0xFFFF	
#define HIGH_WORD 	0x0000FFFF	

typedef enum {
	DMA_SUCCESS		=  0,		/* Generic Success */
	DMA_FAIL		= -1,		/* Generic Failure */
	DMA_BAD_DEVICE 		= -2,		/* Bad Device Information */
	DMA_BAD_HANDLE		= -3,		/* Bad Channel Handle */
	DMA_BAD_DESCRIPTOR	= -4,		/* Bad Descriptor */
	DMA_BAD_MODE		= -5,		/* Bad channel mode */
	DMA_NO_SUCH_CHANNEL	= -6,		/* No channel with the given controller number and channel number */
	DMA_CHANNEL_IN_USE	= -7,		/* Channel is already in use */
	DMA_ALREAD_RUNNIG	= -8,		/* DMA  is already in running  */
	DMA_NO_BUFFER		= -9,		/* Channel has no Buffer */

} DMA_RESULT;

typedef enum {
	DMA_UNKNOWN_EVENT,			/* Unknown Event */
	DMA_DESCRIPTOR_PROCESSED,		/* Descriptor is processed */
	DMA_INNER_LOOP_PROCESSED,		/* Inner loop of the circular buffer is processed */
	DMA_OUTER_LOOP_PROCESSED,		/* Outer loop of the circular buffer is processed */
	DMA_ERROR_INTERRUPT,			/* DMA Error interrupt is occured */
}DMA_EVENT;

typedef enum{
	DMA_CHANNEL_AVAILABLE,
	DMA_CHANNEL_ALLOCATED
} DMA_CHANNEL_STATUS;


/*****************************************************************************
*        BF-533 Specific Declarations
*
****************************************************************************/

#define MAX_BLACKFIN_DMA_CHANNEL 12

#define CH_PPI 			0
#define CH_SPORT0_RX 		1
#define CH_SPORT0_TX 		2
#define CH_SPORT1_RX 		3
#define CH_SPORT1_TX 		4
#define CH_SPI 			5
#define CH_UART_RX 		6
#define CH_UART_TX 		7
#define CH_MEM_STREAM0_DEST	8	// TX	
#define CH_MEM_STREAM0_SRC  	9     	// RX
#define CH_MEM_STREAM1_DEST	10	// TX
#define CH_MEM_STREAM1_SRC 	11 	// RX

#define DATA_SIZE_8 		0
#define DATA_SIZE_16 		1
#define DATA_SIZE_32 		2

#define FLOW_STOP 		0
#define FLOW_AUTO 		1
#define FLOW_ARRAY 		5
#define FLOW_SMALL 		6
#define FLOW_LARGE 		7
#define EINVAL_FLOWTYPE 	-1

#define	DMAWNR			0x2
#define	DMAWDSIZE16		0x4
#define	DMAWDSIZE32		0x8
#define	DMARESTART		0x20
#define	DMASEL			0x40
#define	DMADI			0x80
#define DMASTOP			0x0
#define DMAAUTO			0x1000	
#define DMAARRAY		0x4000			
#define DMASMALL		0x6000			
#define DMALARGE		0x7000			

#define DMAERR			0x02

typedef enum {				/* DMA Compatible Devices in BF533 */
	DMA_DEVICE_PPI,
	DMA_DEVICE_SPORT_RX,
	DMA_DEVICE_SPORT_TX,
	DMA_DEVICE_SPI,
	DMA_DEVICE_UART_RX,
	DMA_DEVICE_UART_TX,
	DMA_DEVICE_MDMA_SOURCE,
	DMA_DEVICE_MDMA_DESTINATION,
} DMA_DEVICE_TYPE;

/*
typedef enum _DMA_DONE {
	DONE_NOT_DONE,
	DONE_DONE
}DMA_DONE;
*/
#pragma pack(2)
typedef struct _DMA_IRQ_STATUS
{
	unsigned short b_DMA_DONE:1;
	unsigned short b_DMA_ERR:1;
	unsigned short b_DFETCH:1;
	unsigned short b_DMA_RUN:1;
}DMA_IRQ_STATUS_REG;
#pragma pack()

typedef enum _DMA_FLOW {
	DMA_STOP	=0,
	DMA_AUTO	=1,
	DMA_ARRAY	=4,
	DMA_SMALL	=6,
	DMA_LARGE	=7,
} DMA_FLOW;

typedef enum _DMA_NDSIZE {
	NDSIZE_STOP	=0,
	NDSIZE_ARRAY	=7,
	NDSIZE_SMALL	=8,
	NDSIZE_LARGE	=9
} DMA_NDSIZE;

typedef enum _DMA_DI_EN {
	DI_EN_DISABLE,
	DI_EN_ENABLE
} DMA_DI_EN;

typedef enum _DMA_DI_SEL {
	DI_SEL_OUTER_LOOP,
	DI_SEL_INNER_LOOP
} DMA_DI_SEL;

typedef enum _DMA_RESTART {
	RESTART_RETAIN,
	RESTART_DISCARD
} DMA_RESTART;

typedef enum _DMA_DMA2D {
	DMA2D_LINEAR,
	DMA2D_2D
} DMA_DMA2D;

typedef enum _DMA_WDSIZE {
	WDSIZE_8BIT,
	WDSIZE_16BIT,
	WDSIZE_32BIT
} DMA_WDSIZE;


typedef enum _DMA_WNR {
	WNR_READ,
	WNR_WRITE
} DMA_WNR;

typedef enum _DMA_EN {
	DMA_DISABLE,
	DMA_ENABLE	
} DMA_EN;

#pragma pack(2)
typedef struct _DMA_CONFIG
{
	unsigned short b_DMA_EN:1;	//Bit 0 : DMA Enable
	unsigned short b_WNR:1;		//Bit 1 : DMA Direction
	unsigned short b_WDSIZE:2;	//Bit 2 & 3 : DMA Tranfer Word size
	unsigned short b_DMA2D:1;	//Bit 4 : DMA Mode 2D or 1D 
	unsigned short b_RESTART:1;	//Bit 5 : Retain the FIFO 
	unsigned short b_DI_SEL:1;	//Bit 6 : Data Interrupt Timing Select 
	unsigned short b_DI_EN:1;	//Bit 7 : Data Interrupt Enable 
	unsigned short b_NDSIZE:4;	//Bit 8 to 11 : Flex descriptor Size 
	unsigned short b_FLOW:3;	//Bit 12 to 14 : FLOW  
	
} DMA_CONFIG_REG;
#pragma pack()

typedef enum _DMA_PMAP {
	PMAP_PPI	= 0,	/* Controller 0 */
	PMAP_SPORT0_RX	= 1,	/* Controller 0 */
	PMAP_SPORT0_TX	= 2,	/* Controller 0 */
	PMAP_SPORT1_RX	= 3,	/* Controller 0 */
	PMAP_SPORT1_TX	= 4,	/* Controller 0 */
	PMAP_SPI	= 5,	/* Controller 0 */
	PMAP_UART_RX	= 6,	/* Controller 0 */
	PMAP_UART_TX	= 7	/* Controller 0 */
}DMA_PMAP;


typedef struct {				/* peripheral mapping */
	DMA_DEVICE_TYPE	DeviceType;		/* DMA_DEVICE_TYPE Value */
	unsigned int	DeviceNumber;		/* device number */
	unsigned int	ControllerNumber; 	/* controller number */
	DMA_PMAP	PeripheralMap;		/* Value of PMAP in the peripheral map register */
} DMA_MAPPING;

typedef enum _DMA_CTYPE {
	PERIPHERAL,
	MEMORY
} DMA_CTYPE;

#pragma pack(2)
typedef struct _DMA_PERIPHERAL_MAP
{
	unsigned short		:6;	/* 0:5 bits are reserved */
	unsigned short	b_CTYPE	:1;	/* 6	Channel type */
	unsigned short		:5;	/* 7:11 bits are Reserved */
	unsigned short	b_PMAP	:4;	/* 12:15 bits represents the Peripheral ID */
}DMA_PERIPHERAL_MAP_REG;
#pragma pack()

typedef struct 
{
	unsigned short next_desc_ptr_lsb;
	unsigned short next_desc_ptr_msb;
	unsigned long start_addr;
	unsigned short cfg;
#if 0
	DMA_CONFIG_REG cfg;
#endif
	unsigned short x_count;
	unsigned short x_modify;
	unsigned short y_count;
	unsigned short y_modify;
} dmasg_t;

typedef struct 
{
	//unsigned short start_addr_lo;
	//unsigned short start_addr_hi;
	unsigned long start_addr;
	unsigned short cfg;
#if 0
	DMA_CONFIG_REG cfg;
#endif
	unsigned short x_count;
	unsigned short x_modify;
	unsigned short y_count;
	unsigned short y_modify;
} dmasgarray_t;

typedef struct 
{
	unsigned short next_desc_addr_lo;
	//unsigned long start_addr;
	unsigned short start_addr_lo;
	unsigned short start_addr_hi;
	unsigned short cfg;
#if 0
	DMA_CONFIG_REG cfg;
#endif
	unsigned short x_count;
	unsigned short x_modify;
	unsigned short y_count;
	unsigned short y_modify;
} dmasgsmall_t;

typedef struct 
{
	unsigned long next_desc_addr;
	unsigned long start_addr;
	unsigned short cfg;
#if 0
	DMA_CONFIG_REG cfg;
#endif
	unsigned short x_count;
	unsigned short x_modify;
	unsigned short y_count;
	unsigned short y_modify;
} dmasglarge_t;

typedef struct
{
	unsigned long  next_desc_ptr; /* DMA Next Descriptor Pointer register */
	unsigned long  start_addr;	/* DMA Start address  register */

	unsigned short cfg;		/* DMA Configuration register */
#if 0
	DMA_CONFIG_REG cfg;
#endif
	unsigned short dummy1;		/* DMA Configuration register */

	unsigned long reserved;		

	unsigned short x_count;		/* DMA x_count register */
	unsigned short dummy2;		

	unsigned short x_modify;	/* DMA x_modify register */
	unsigned short dummy3;		

	unsigned short y_count;		/* DMA y_count register */
	unsigned short dummy4;		

	unsigned short  y_modify;	/* DMA y_modify register */
	unsigned short dummy5;		

	unsigned long  curr_desc_ptr;	/* DMA Current Descriptor Pointer register */
	unsigned short curr_addr_ptr_lo;	/* DMA Current Address Pointer register */
	unsigned short curr_addr_ptr_hi;	/* DMA Current Address Pointer register */
	unsigned short irq_status;	/* DMA irq status register */
#if 0
	volatile DMA_IRQ_STATUS_REG irq_status;	/* DMA irq status register */
#endif
	unsigned short dummy6;		

	unsigned short peripheral_map;	/* DMA peripheral map register */
	unsigned short dummy7;		

	unsigned short curr_x_count;	/* DMA Current x-count register */
	unsigned short dummy8;		

	unsigned long reserved2;		

	unsigned short curr_y_count;	/* DMA Current y-count register */
	unsigned short dummy9;		

	unsigned long reserved3;		

}DMA_register;

typedef union
{
	dmasglarge_t large_descriptor;
	dmasgsmall_t small_descriptor;
}generic_descriptor;

typedef void (*dma_callback_t)(DMA_EVENT event , void *data); 
typedef void (*dma_interrupt_t) (int irq, void *dev_id, struct pt_regs *pt_regs);

typedef struct
{
	int 			dma_channel_status;
	DMA_register 		*regs;
 	dmasglarge_t 		*L_last_descriptor;
 	dmasglarge_t 		*L_first_descriptor;
 	dmasglarge_t		*L_wait_last_descriptor;
 	dmasglarge_t 		*L_wait_first_descriptor;
 	dmasglarge_t 		*L_next_descriptor;
 	dmasgsmall_t 		*S_last_descriptor;
 	dmasgsmall_t 		*S_first_descriptor;
 	dmasgsmall_t 		*S_wait_last_descriptor;
 	dmasgsmall_t 		*S_wait_first_descriptor;
 	dmasgsmall_t 		*S_next_descriptor;

	unsigned short 		descr_base;			/* Descriptor Base used for Small flow mode */

	unsigned short 		flowmode;			/* Flow mode of the channel */

	unsigned int		ControllerNumber;	 	/* controller number */
	DMA_PERIPHERAL_MAP_REG 	*PeripheralMap;			/* Peripheral Map  */

	dma_callback_t		callback;

	const char		*device_id;

	unsigned int		LoopbackFlag;

}DMA_channel;

#if 0
DMA_channel 	dma_ch[MAX_BLACKFIN_DMA_CHANNEL];

static DMA_register* 	base_addr[MAX_BLACKFIN_DMA_CHANNEL] =
{
	(DMA_register *) 0xffc00c00,		
	(DMA_register *) 0xffc00c40,	
	(DMA_register *) 0xffc00c80,
	(DMA_register *) 0xffc00cc0,
	(DMA_register *) 0xffc00d00,
	(DMA_register *) 0xffc00d40,
	(DMA_register *) 0xffc00d80,
	(DMA_register *) 0xffc00dc0,
	(DMA_register *) 0xffc00e00,
	(DMA_register *) 0xffc00e40,
	(DMA_register *) 0xffc00e80,
	(DMA_register *) 0xffc00ec0,
};

static DMA_MAPPING Mapping[] = {
	{ DMA_DEVICE_PPI,	0,	0,	PMAP_PPI	},
	{ DMA_DEVICE_SPORT_RX,	0,	0,	PMAP_SPORT0_RX	},
	{ DMA_DEVICE_SPORT_TX,	0,	0,	PMAP_SPORT0_TX	},
	{ DMA_DEVICE_SPORT_RX,	1,	0,	PMAP_SPORT1_RX	},
	{ DMA_DEVICE_SPORT_TX,	1,	0,	PMAP_SPORT1_TX	},
	{ DMA_DEVICE_SPI,	0,	0,	PMAP_SPI	},
	{ DMA_DEVICE_UART_RX,	0,	0,	PMAP_UART_RX	},
	{ DMA_DEVICE_UART_TX,	0,	0,	PMAP_UART_TX	},
};
#endif

/**************************************************************************************
*	DMA API's 
**************************************************************************************/

#if 0
int get_dma_list(char * buf);
#endif

int __init blackfin_dma_init(void);
int 	request_dma(unsigned int channel, const char *device_id, dma_interrupt_t dma_interrupt, dma_callback_t callback);
int 	freedma(unsigned int channel);
int 	set_dma_descriptor_base(unsigned int channel, unsigned int base);
int  	disable_dma(unsigned int channel);
int  	enable_dma(unsigned int channel);
int  	set_dma_addr(unsigned int channel, unsigned long addr);
int 	set_dma_mode(unsigned int channel, char mode);
int 	set_dma_type(unsigned int channel, char type);
int 	set_dma_count(unsigned int channel, unsigned short count);
int 	get_dma_residue(unsigned int channel);
int 	set_dma_transfer_size(unsigned int channel, char size);
int 	get_dma_transfer_size(unsigned int channel);
int 	enable_dma_autobuffer(unsigned int channel);
int 	clear_dma_buffer(unsigned int channel);
int 	disable_dma_buffer_clear(unsigned int channel);
void 	dma_interrupt(int irq, void *dev_id, struct pt_regs *pt_regs);
void* 	create_descriptor(int flowtype);
int 	add_descriptor(void *newdescriptor, int  channel_number, int flowtype);
int 	set_desc_xcount(void *descriptor, unsigned short x_count, int flowtype);
int  	set_desc_startaddr(void *descriptor, unsigned long startaddr, int flowtype);
int  	set_desc_ycount(void *descriptor, unsigned short y_count, int flowtype);
int  	set_desc_ymodify(void *descriptor, unsigned short y_modify, int flowtype);
int  	set_desc_xmodify(void *descriptor, unsigned short x_modify, int flowtype);
int 	add_to_wait_descriptor(void *newdescriptor, int  channel_number, int flowtype);
int 	dma_m2m(unsigned long src_addr, unsigned long dest_addr, 
		unsigned char data_size, unsigned short count,
		unsigned long src_addr2, unsigned long dest_addr2, 
		unsigned char data_size2, unsigned short count2,
		unsigned long src_addr3, unsigned long dest_addr3,
		unsigned char data_size3, unsigned short count3);

int 	dma_m2m_bf533(unsigned long src_addr, unsigned long dest_addr, 
		unsigned char data_size, unsigned short x_count, unsigned short type);

int dma_m2p(unsigned int channel, unsigned long start_addr, 
		char dir, char data_size, unsigned short count);


#endif
