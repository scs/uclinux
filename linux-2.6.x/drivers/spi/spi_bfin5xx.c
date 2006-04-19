/************************************************************
*
* Copyright (C) 2004, Analog Devices. All Rights Reserved
*
* FILE bfin5xx_spi.c
* PROGRAMMER(S): Luke Yang (Analog Devices Inc.)
*
*
* DATE OF CREATION: March. 10th 2006
*
* SYNOPSIS:
*
* DESCRIPTION: SPI controller driver for Blackfin5xx.
**************************************************************

* MODIFICATION HISTORY:
* March 10, 2006  bfin5xx_spi.c Created. (Luke Yang)

************************************************************
*
* This program is free software; you can distribute it and/or modify it
* under the terms of the GNU General Public License (Version 2) as
* published by the Free Software Foundation.
*
* This program is distributed in the hope it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
* FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
* for more details.
*
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 59 Temple Place - Suite 330, Boston MA 02111-1307, USA.
*
************************************************************/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/ioport.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/dma-mapping.h>
#include <linux/spi/spi.h>
#include <linux/workqueue.h>
#include <linux/errno.h>
#include <linux/delay.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/delay.h>
#include <asm/dma.h>

#include <asm/bfin5xx_spi.h>

MODULE_AUTHOR("Luke Yang");
MODULE_DESCRIPTION("Blackfin5xx SPI Contoller");
MODULE_LICENSE("GPL");

#ifdef BFIN_SPI_DEBUG
#define PRINTK(args...) printk(args)
#else
#define PRINTK(args...)
#endif

#define IS_DMA_ALIGNED(x) (((u32)(x)&0x07)==0)

#define DEFINE_SPI_REG(reg, off) \
static inline u16 read_##reg(void) \
            { return *(volatile unsigned short*)(SPI0_REGBASE + off); } \
static inline void write_##reg(u16 v) \
            {*(volatile unsigned short*)(SPI0_REGBASE + off) = v;\
             __builtin_bfin_ssync();}

DEFINE_SPI_REG(CTRL, 0x00)
DEFINE_SPI_REG(FLAG, 0x04)
DEFINE_SPI_REG(STAT, 0x08)
DEFINE_SPI_REG(TDBR, 0x0C)
DEFINE_SPI_REG(RDBR, 0x10)
DEFINE_SPI_REG(BAUD, 0x14)
DEFINE_SPI_REG(SHAW, 0x18)

#define START_STATE ((void*)0)
#define RUNNING_STATE ((void*)1)
#define DONE_STATE ((void*)2)
#define ERROR_STATE ((void*)-1)

#define QUEUE_RUNNING 0
#define QUEUE_STOPPED 1

struct driver_data {
	/* Driver model hookup */
	struct platform_device *pdev;

	/* SPI framework hookup */
	struct spi_master *master;

	/* BFIN hookup */
	struct bfin5xx_spi_master *master_info;

	/* DMA setup stuff */
	u32 *null_dma_buf;  //

	/* Driver message queue */
	struct workqueue_struct	*workqueue;
	struct work_struct pump_messages;
	spinlock_t lock;
	struct list_head queue;
	int busy;
	int run;

	/* Message Transfer pump */
	struct tasklet_struct pump_transfers;

	/* Current message transfer state info */
	struct spi_message* cur_msg;
	struct spi_transfer* cur_transfer;
	struct chip_data *cur_chip;
	size_t len;
	void *tx;
	void *tx_end;
	void *rx;
	void *rx_end;
	int dma_mapped;
	dma_addr_t rx_dma;
	dma_addr_t tx_dma;
	size_t rx_map_len;
	size_t tx_map_len;
	u8 n_bytes;
	u32 dma_width;
	void (*write)(struct driver_data *drv_data);
	void (*read)(struct driver_data *drv_data);
};

struct chip_data {
	u16 ctl_reg;
	u16 baud;
	u16 flag;

	u8  n_bytes;
	u32 width;
	u32 dma_width;
	u8 enable_dma;
	u8 bits_per_word;
	void (*write)(struct driver_data *drv_data);
	void (*read)(struct driver_data *drv_data);
};

static void pump_messages(void *data);


void bfin_spi_enable(struct driver_data *drv_data)
{
	u16 cr;

	cr = read_CTRL();
	write_CTRL(cr | (CFG_SPI_ENABLE << 14));
	__builtin_bfin_ssync();

}

void bfin_spi_disable(struct driver_data *drv_data)
{
	u16 cr;

	cr = read_CTRL();
	write_CTRL(cr | (CFG_SPI_DISABLE << 14));
	__builtin_bfin_ssync();
}

static int flush(struct driver_data *drv_data)
{
	unsigned long limit = loops_per_jiffy << 1;

	/* wait for stop and clear stat */
	do {} while (!(read_STAT() & BIT_STAT_SPIF) && limit--);
	write_STAT(BIT_STAT_CLR);

	return limit;
}

/* stop controller and re-config current chip*/
static void restore_state(struct driver_data *drv_data)
{
	/* Clear status and disable clock */
	write_STAT(BIT_STAT_CLR);
	bfin_spi_disable(drv_data);

	/* Load the registers */
	write_CTRL(drv_data->cur_chip->ctl_reg);
	write_BAUD(drv_data->cur_chip->baud);
	write_FLAG(drv_data->cur_chip->flag);
}

/* used to kick off transfer in rx mode */
static unsigned short dummy_read(void)
{
	unsigned short tmp;

	tmp = read_RDBR();
	return tmp;
}

static void null_writer(struct driver_data *drv_data)
{
	u8 n_bytes = drv_data->n_bytes;

	while (drv_data->tx < drv_data->tx_end) {
		write_TDBR(0);
		do {} while ((read_STAT() & BIT_STAT_TXS));
		drv_data->tx += n_bytes;
	}
}

static void null_reader(struct driver_data *drv_data)
{
	u8 n_bytes = drv_data->n_bytes;
	dummy_read();

	while (drv_data->rx < drv_data->rx_end) {
		do {} while (!(read_STAT() & BIT_STAT_RXS));
		dummy_read();
		drv_data->rx += n_bytes;
	}
}

static void u8_writer(struct driver_data *drv_data)
{

	PRINTK("cr8-s is 0x%x\n",read_STAT());
	while (drv_data->tx < drv_data->tx_end) {
		write_TDBR(*(u8 *)(drv_data->tx));
		do {} while (read_STAT() & BIT_STAT_TXS);
		++drv_data->tx;
	}
}

static void u8_reader(struct driver_data *drv_data)
{
	PRINTK("cr-8 is 0x%x\n",read_STAT());
	dummy_read();

	while (drv_data->rx < drv_data->rx_end) {
		do {} while (!(read_STAT() & BIT_STAT_RXS));
		*(u8 *)(drv_data->rx) = read_RDBR();
		++drv_data->rx;
	}
}

static void u16_writer(struct driver_data *drv_data)
{
	PRINTK("cr16 is 0x%x\n",read_STAT());
	while (drv_data->tx < drv_data->tx_end) {
		write_TDBR(*(u16 *)(drv_data->tx));
		do {} while ((read_STAT() & BIT_STAT_TXS));
		drv_data->tx += 2;
	}
}

static void u16_reader(struct driver_data *drv_data)
{
	PRINTK("cr-16 is 0x%x\n",read_STAT());
	dummy_read();

	while (drv_data->rx < drv_data->rx_end) {
		do {} while (!(read_STAT() & BIT_STAT_RXS));
		*(u16 *)(drv_data->rx) = read_RDBR();
		drv_data->rx += 2;
	}
}

/* test if ther is more transfer to be done */
static void *next_transfer(struct driver_data *drv_data)
{
	struct spi_message *msg = drv_data->cur_msg;
	struct spi_transfer *trans = drv_data->cur_transfer;

	/* Move to next transfer */
	if (trans->transfer_list.next != &msg->transfers) {
		drv_data->cur_transfer =
			list_entry(trans->transfer_list.next,
					struct spi_transfer,
					transfer_list);
		return RUNNING_STATE;
	} else
		return DONE_STATE;
}


/* caller already set message->status; dma and pio irqs are blocked */
/* give finished message back */
static void giveback(struct spi_message *message, struct driver_data *drv_data)
{
	struct spi_transfer* last_transfer;

	last_transfer = list_entry(message->transfers.prev,
					struct spi_transfer,
					transfer_list);

	message->state = NULL;
	if (message->complete)
		message->complete(message->context);

	drv_data->cur_msg = NULL;
	drv_data->cur_transfer = NULL;
	drv_data->cur_chip = NULL;
	queue_work(drv_data->workqueue, &drv_data->pump_messages);
}

static irqreturn_t dma_irq_handler(int irq, void *dev_id, struct pt_regs *regs)
{
	struct driver_data *drv_data = (struct driver_data *)dev_id;
	struct spi_message *msg = drv_data->cur_msg;

	clear_dma_irqstat(CH_SPI);

	msg->actual_length += drv_data->len;

	bfin_spi_disable(drv_data);
	/* Move to next transfer */
	msg->state = next_transfer(drv_data);

	/* Schedule transfer tasklet */
	tasklet_schedule(&drv_data->pump_transfers);

	/* free the irq handler before next transfer */
	free_dma(CH_SPI);

	return IRQ_HANDLED;
}

static void pump_transfers(unsigned long data)
{
	struct driver_data *drv_data = (struct driver_data *)data;
	struct spi_message *message = NULL;
	struct spi_transfer *transfer = NULL;
	struct spi_transfer *previous = NULL;
	struct chip_data *chip = NULL;
	u16 cr,width,dma_config;
	u32 tranf_success = 1;

	/* Get current state information */
	message = drv_data->cur_msg;
	transfer = drv_data->cur_transfer;
	chip = drv_data->cur_chip;

	/* if msg is error or done, report it back using complete() callback */
	/* Handle for abort */
	if (message->state == ERROR_STATE) {
		message->status = -EIO;
		giveback(message, drv_data);
		return;
	}

	/* Handle end of message */
	if (message->state == DONE_STATE) {
		message->status = 0;
		giveback(message, drv_data);
		return;
	}

	/* Delay if requested at end of transfer */
	if (message->state == RUNNING_STATE) {
		previous = list_entry(transfer->transfer_list.prev,
					struct spi_transfer,
					transfer_list);
		if (previous->delay_usecs)
			udelay(previous->delay_usecs);
	}

	/* Setup the transfer state based on the type of transfer */
	if (flush(drv_data) == 0) {
		dev_err(&drv_data->pdev->dev, "pump_transfers: flush failed\n");
		message->status = -EIO;
		giveback(message, drv_data);
		return;
	}

	drv_data->dma_width = chip->dma_width;
	if (transfer->tx_buf != NULL) {
		drv_data->tx = (void *)transfer->tx_buf;
		drv_data->tx_end = drv_data->tx + transfer->len;
		PRINTK("tx_buf is 0x%x, tx_end is 0x%x\n",transfer->tx_buf, drv_data->tx_end);
	} else {
		drv_data->tx = NULL;
	}

	if (transfer->rx_buf != NULL) {
		drv_data->rx = transfer->rx_buf;
		drv_data->rx_end = drv_data->rx + transfer->len;
		PRINTK("rx_buf is 0x%x, rx_end is 0x%x\n",transfer->rx_buf, drv_data->rx_end);
	} else {
		drv_data->rx = NULL;
	}

	drv_data->rx_dma = transfer->rx_dma;
	drv_data->tx_dma = transfer->tx_dma;
	drv_data->len = transfer->len;
	drv_data->write = drv_data->tx ? chip->write : null_writer;
	drv_data->read = drv_data->rx ? chip->read : null_reader;
	PRINTK("SPI transfer: drv_data->write is 0x%x, chip->write is 0x%x, null_wr is 0x%x\n", drv_data->write, chip->write, null_writer);

	/* speed and width has been set on per message */

	message->state = RUNNING_STATE;
	width = chip->width;
	dma_config = 0;

	PRINTK("SPI: now pumping a transfer: width is %d, len is %d\n",width,transfer->len);
	/* Try to map dma buffer and do a dma transfer if successful */
	/* use different way to r/w according to drv_data->cur_chip->enable_dma */
	if (drv_data->cur_chip->enable_dma) {

		write_STAT(BIT_STAT_CLR);

		/* register dma irq handler */
		if(request_dma(CH_SPI, "BF53x_SPI_DMA") < 0)
		{
			PRINTK("Unable to request BlackFin SPI DMA channel\n");
			message->status = -EIO;
			giveback(message, drv_data);
			return;
		}
		set_dma_callback(CH_SPI, (void*)dma_irq_handler, drv_data);

		PRINTK("SPI: doing dma transfer\n");
		/* config dma channel */
		if(width == CFG_SPI_WORDSIZE16){
			set_dma_x_count(CH_SPI, ((drv_data->len)>>1));
			set_dma_x_modify(CH_SPI, 2);
		}
		else {
			set_dma_x_count(CH_SPI, drv_data->len);
			set_dma_x_modify(CH_SPI, 1);
		}

		/* Go baby, go */
		/* set transfer width,direction. And enable spi */
		cr = read_CTRL();

		/* In dma mode, rx or tx must be NULL in one transfer*/
		if ( drv_data->rx != NULL) {
			/* set transfer mode, and enable SPI */
			write_CTRL(cr | CFG_SPI_DMAREAD | (width << 8) | (CFG_SPI_ENABLE << 14));

			/* start dma*/
			dma_config |= ( WNR | RESTART | DI_EN );
			set_dma_config(CH_SPI, dma_config);
			set_dma_start_addr(CH_SPI, (unsigned long)drv_data->rx);
			enable_dma(CH_SPI);

		} else if (drv_data->tx != NULL) {

			write_CTRL(cr | CFG_SPI_DMAWRITE | (width << 8) | (CFG_SPI_ENABLE << 14));
			__builtin_bfin_ssync();

			/* start dma */
			dma_config |= ( RESTART | DI_EN );
			set_dma_config(CH_SPI, dma_config);
			set_dma_start_addr(CH_SPI, (unsigned long)drv_data->tx);
			enable_dma(CH_SPI);
		}
	} else {/* IO mode write then read */
		/* Go baby, go */
		PRINTK("SPI: doing IO transfer\n");

		write_STAT(BIT_STAT_CLR);

		/* write then read. TBD: is there any need of full duplex(read while writing)? */
		if (drv_data->tx != NULL) {
			cr = (read_CTRL() & 0xFFC0); /* clear the TIMOD bits */
			cr |= CFG_SPI_WRITE | (width << 8) | (CFG_SPI_ENABLE << 14);
			PRINTK("SPI IO write: cr is 0x%x\n",cr);

			write_CTRL(cr);

			drv_data->write(drv_data);

			if (drv_data->tx != drv_data->tx_end)
				tranf_success = 0;
		}
		if (drv_data->rx != NULL) {
			cr = (read_CTRL() & 0xFFC0); /* cleare the TIMOD bits */
			cr |= CFG_SPI_READ | (width << 8) | (CFG_SPI_ENABLE << 14);
			PRINTK("SPI IO read: cr is 0x%x\n",cr);

			write_CTRL(cr);

			drv_data->read(drv_data);
			if (drv_data->rx != drv_data->rx_end)
				tranf_success = 0;
		}

		if (!tranf_success) {
			message->state = ERROR_STATE;
		}
		else {
			/* Update total byte transfered */
			message->actual_length += drv_data->len;

			/* Move to next transfer of this msg*/
			message->state = next_transfer(drv_data);
		}

		bfin_spi_disable(drv_data);

		/* Schedule next transfer tasklet */
		tasklet_schedule(&drv_data->pump_transfers);

	}
}

/* pop a msg from queue and kick off real transfer */
static void pump_messages(void *data)
{
	struct driver_data *drv_data = data;
	unsigned long flags;

	/* Lock queue and check for queue work */
	spin_lock_irqsave(&drv_data->lock, flags);
	if (list_empty(&drv_data->queue) || drv_data->run == QUEUE_STOPPED) {
		/* pumper kicked off but work to do */
		drv_data->busy = 0;
		spin_unlock_irqrestore(&drv_data->lock, flags);
		return;
	}

	/* Make sure we are not already running a message */
	if (drv_data->cur_msg) {
		spin_unlock_irqrestore(&drv_data->lock, flags);
		return;
	}

	/* Extract head of queue */
	drv_data->cur_msg = list_entry(drv_data->queue.next,
					struct spi_message, queue);
	list_del_init(&drv_data->cur_msg->queue);
	drv_data->busy = 1;
	spin_unlock_irqrestore(&drv_data->lock, flags);

	/* Initial message state*/
	drv_data->cur_msg->state = START_STATE;
	drv_data->cur_transfer = list_entry(drv_data->cur_msg->transfers.next,
						struct spi_transfer,
						transfer_list);

	/* Setup the SSP using the per chip configuration */
	drv_data->cur_chip = spi_get_ctldata(drv_data->cur_msg->spi);
	restore_state(drv_data);
	PRINTK("SPI: got an message to pump, state is set to: baud %d, flag 0x%x, ctl 0x%x \n",\
	       drv_data->cur_chip->baud, drv_data->cur_chip->flag, drv_data->cur_chip->ctl_reg);
	PRINTK("SPI: the first transfer len is %d\n", drv_data->cur_transfer->len);

	/* Mark as busy and launch transfers */
	tasklet_schedule(&drv_data->pump_transfers);
}

/* got a msg to transfer, queue it in drv_data->queue. And kick off message pumper */
static int transfer(struct spi_device *spi, struct spi_message *msg)
{
	struct driver_data *drv_data = spi_master_get_devdata(spi->master);
	unsigned long flags;

	spin_lock_irqsave(&drv_data->lock, flags);

	if (drv_data->run == QUEUE_STOPPED) {
		spin_unlock_irqrestore(&drv_data->lock, flags);
		return -ESHUTDOWN;
	}

	msg->actual_length = 0;
	msg->status = -EINPROGRESS;
	msg->state = START_STATE;

	PRINTK("SPI: adding an msg in transfer() \n");
	list_add_tail(&msg->queue, &drv_data->queue);

	if (drv_data->run == QUEUE_RUNNING && !drv_data->busy)
		queue_work(drv_data->workqueue, &drv_data->pump_messages);

	spin_unlock_irqrestore(&drv_data->lock, flags);

	return 0;
}

/* first setup for new devices */
static int setup(struct spi_device *spi)
{
	struct bfin5xx_spi_chip *chip_info = NULL;
	struct chip_data *chip;
	struct driver_data *drv_data = spi_master_get_devdata(spi->master);
	u8 spi_flg;

	if (!spi->bits_per_word)
		spi->bits_per_word = 16;

	if (spi->bits_per_word != 8 && spi->bits_per_word != 16)
		return -EINVAL;

	/* Only alloc (or use chip_info) on first setup */
	chip = spi_get_ctldata(spi);
	if (chip == NULL) {
		chip = kzalloc(sizeof(struct chip_data), GFP_KERNEL);
		if (!chip)
			return -ENOMEM;

		chip->enable_dma = 0;
		chip_info = spi->controller_data;
	}

	/* chip_info isn't always needed */
	if (chip_info) {
		chip->enable_dma = chip_info->enable_dma != 0
					&& drv_data->master_info->enable_dma;
		chip->ctl_reg = chip_info->ctl_reg;
		chip->bits_per_word = chip_info->bits_per_word;
	}

	/* Notice: for blackfin, the speed_hz is the value of register
	   SPI_BAUD, not the real baudrate */
	chip->baud = spi->max_speed_hz;
	spi_flg = ~(1 << (spi->chip_select));
	chip->flag =  ((u16)spi_flg << 8 ) | (1 << (spi->chip_select));

	if (chip->bits_per_word <= 8) {
		chip->n_bytes = 1;
		chip->width = CFG_SPI_WORDSIZE8;
		chip->read = u8_reader;
		chip->write = u8_writer;
		PRINTK("SPI 8bit: chip->write is 0x%x, u8_writer is 0x%x\n",chip->write,u8_writer);
	} else if (spi->bits_per_word <= 16) {
		chip->n_bytes = 2;
		chip->width = CFG_SPI_WORDSIZE16;
		chip->read = u16_reader;
		chip->write = u16_writer;
		PRINTK("SPI 16bit: chip->write is 0x%x, u16_writer is 0x%x\n",chip->write,u16_writer);
	} else {
		dev_err(&spi->dev, "invalid wordsize\n");
		kfree(chip);
		return -ENODEV;
	}
	PRINTK("SPI: setup spi chip %s, width is %d, dma is %d, ctl_reg is 0x%x\n", \
	       spi->modalias, chip->width, chip->enable_dma, chip->ctl_reg);
	spi_set_ctldata(spi, chip);

	return 0;
}

/* callback for spi framework. clean driver specific data */
static void cleanup(const struct spi_device *spi)
{
	struct chip_data *chip = spi_get_ctldata((struct spi_device *)spi);

	kfree(chip);
}

static int init_queue(struct driver_data *drv_data)
{
	INIT_LIST_HEAD(&drv_data->queue);
	spin_lock_init(&drv_data->lock);

	drv_data->run = QUEUE_STOPPED;
	drv_data->busy = 0;

	/* init transfer tasklet */
	tasklet_init(&drv_data->pump_transfers,
			pump_transfers,	(unsigned long)drv_data);

	/* init messages workqueue */
	INIT_WORK(&drv_data->pump_messages, pump_messages, drv_data);
	drv_data->workqueue = create_singlethread_workqueue(
					drv_data->master->cdev.dev->bus_id);
	if (drv_data->workqueue == NULL)
		return -EBUSY;

	return 0;
}

static int start_queue(struct driver_data *drv_data)
{
	unsigned long flags;

	spin_lock_irqsave(&drv_data->lock, flags);

	if (drv_data->run == QUEUE_RUNNING || drv_data->busy) {
		spin_unlock_irqrestore(&drv_data->lock, flags);
		return -EBUSY;
	}

	drv_data->run = QUEUE_RUNNING;
	drv_data->cur_msg = NULL;
	drv_data->cur_transfer = NULL;
	drv_data->cur_chip = NULL;
	spin_unlock_irqrestore(&drv_data->lock, flags);

	queue_work(drv_data->workqueue, &drv_data->pump_messages);

	return 0;
}

static int stop_queue(struct driver_data *drv_data)
{
	unsigned long flags;
	unsigned limit = 500;
	int status = 0;

	spin_lock_irqsave(&drv_data->lock, flags);

	/* This is a bit lame, but is optimized for the common execution path.
	 * A wait_queue on the drv_data->busy could be used, but then the common
	 * execution path (pump_messages) would be required to call wake_up or
	 * friends on every SPI message. Do this instead */
	drv_data->run = QUEUE_STOPPED;
	while (!list_empty(&drv_data->queue) && drv_data->busy && limit--) {
		spin_unlock_irqrestore(&drv_data->lock, flags);
		msleep(10);
		spin_lock_irqsave(&drv_data->lock, flags);
	}

	if (!list_empty(&drv_data->queue) || drv_data->busy)
		status = -EBUSY;

	spin_unlock_irqrestore(&drv_data->lock, flags);

	return status;
}

static int destroy_queue(struct driver_data *drv_data)
{
	int status;

	status = stop_queue(drv_data);
	if (status != 0)
		return status;

	destroy_workqueue(drv_data->workqueue);

	return 0;
}

static int bfin5xx_spi_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct bfin5xx_spi_master *platform_info;
	struct spi_master *master;
	struct driver_data *drv_data = 0;
	int status = 0;

	platform_info = dev->platform_data;

	/* Allocate master with space for drv_data and null dma buffer */
	master = spi_alloc_master(dev, sizeof(struct driver_data) + 16);
	if (!master) {
		dev_err(&pdev->dev, "can not alloc spi_master\n");
		return -ENOMEM;
	}
	drv_data = spi_master_get_devdata(master);
	drv_data->master = master;
	drv_data->master_info = platform_info;
	drv_data->pdev = pdev;

	master->bus_num = pdev->id;
	master->num_chipselect = platform_info->num_chipselect;
	master->cleanup = cleanup;
	master->setup = setup;
	master->transfer = transfer;

#if defined(CONFIG_BF534)|defined(CONFIG_BF536)|defined(CONFIG_BF537)
	*pPORT_MUX |= PFS4E;
	__builtin_bfin_ssync();
	*pPORTF_FER |= 0x7c40;
	__builtin_bfin_ssync();
#endif

	/* Initial and start queue */
	status = init_queue(drv_data);
	if (status != 0) {
		dev_err(&pdev->dev, "problem initializing queue\n");
		goto out_error_queue_alloc;
	}
	status = start_queue(drv_data);
	if (status != 0) {
		dev_err(&pdev->dev, "problem starting queue\n");
		goto out_error_queue_alloc;
	}

	/* Register with the SPI framework */
	platform_set_drvdata(pdev, drv_data);
	status = spi_register_master(master);
	if (status != 0) {
		dev_err(&pdev->dev, "problem registering spi master\n");
		goto out_error_queue_alloc;
	}

	return status;

out_error_queue_alloc:
	destroy_queue(drv_data);

out_error_master_alloc:
	spi_master_put(master);
	return status;
}

/* stop hardware and remove the driver */
static int bfin5xx_spi_remove(struct platform_device *pdev)
{
	struct driver_data *drv_data = platform_get_drvdata(pdev);
	int status = 0;

	if (!drv_data)
		return 0;

	/* Remove the queue */
	status = destroy_queue(drv_data);
	if (status != 0)
		return status;

	/* Disable the SSP at the peripheral and SOC level */
        bfin_spi_disable(drv_data);

	/* Release DMA */
	if (drv_data->master_info->enable_dma) {
		free_dma(CH_SPI);
	}

	/* Disconnect from the SPI framework */
	spi_unregister_master(drv_data->master);

	/* Prevent double remove */
	platform_set_drvdata(pdev, NULL);

	return 0;
}


static void bfin5xx_spi_shutdown(struct platform_device *pdev)
{
	int status = 0;

	if ((status = bfin5xx_spi_remove(pdev)) != 0)
		dev_err(&pdev->dev, "shutdown failed with %d\n", status);
}

/* PM, do nothing now */
#ifdef CONFIG_PM
static int suspend_devices(struct device *dev, void *pm_message)
{
	pm_message_t *state = pm_message;

	if (dev->power.power_state.event != state->event) {
		dev_warn(dev, "pm state does not match request\n");
		return -1;
	}

	return 0;
}

static int bfin5xx_spi_suspend(struct platform_device *pdev, pm_message_t state)
{
	struct driver_data *drv_data = platform_get_drvdata(pdev);
	int status = 0;

	/* Check all childern for current power state */
	if (device_for_each_child(&pdev->dev, &state, suspend_devices) != 0) {
		dev_warn(&pdev->dev, "suspend aborted\n");
		return -1;
	}

	status = stop_queue(drv_data);
	if (status != 0)
		return status;

	/* stop hardware */
	bfin_spi_disable(drv_data);

	return 0;
}

static int bfin5xx_spi_resume(struct platform_device *pdev)
{
	struct driver_data *drv_data = platform_get_drvdata(pdev);
	int status = 0;

	/* Enable the SPI interface */
	bfin_spi_enable(drv_data);

	/* Start the queue running */
	status = start_queue(drv_data);
	if (status != 0) {
		dev_err(&pdev->dev, "problem starting queue (%d)\n", status);
		return status;
	}

	return 0;
}
#else
#define bfin5xx_spi_suspend NULL
#define bfin5xx_spi_resume NULL
#endif /* CONFIG_PM */


static struct platform_driver driver = {
	.driver = {
		.name = "bfin-spi-master",
		.bus = &platform_bus_type,
		.owner = THIS_MODULE,
	},
	.probe = bfin5xx_spi_probe,
	.remove = __devexit_p(bfin5xx_spi_remove),
	.shutdown = bfin5xx_spi_shutdown,
	.suspend = bfin5xx_spi_suspend,
	.resume = bfin5xx_spi_resume,
};

static int __init bfin5xx_spi_init(void)
{
	platform_driver_register(&driver);
	return 0;
}
module_init(bfin5xx_spi_init);

static void __exit bfin5xx_spi_exit(void)
{
	platform_driver_unregister(&driver);
}
module_exit(bfin5xx_spi_exit);
