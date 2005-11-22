
#include <linux/kernel.h> 
#include <linux/module.h> 
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <asm/blackfin.h>
#include <asm/dma.h>

#include "bfin_spi_channel.h"


struct semaphore spilock;


void spi_send_data(unsigned short data)
{
	*(unsigned short*)(SPI0_REGBASE + SPI_TXBUFF_OFF) = data;
	__builtin_bfin_ssync();
}


unsigned short spi_receive_data(void)
{
	unsigned short data;
	
	data = *(unsigned short*)(SPI0_REGBASE + SPI_RXBUFF_OFF);
	__builtin_bfin_ssync();
	return data;
}

void spi_enable(spi_device_t *spi_dev)
{
	unsigned short regdata;
	
	/* stop DMA channel if DMA mode enabled */
	if (spi_dev->dma)
		enable_dma(CH_SPI);

	regdata = *(unsigned short*)(SPI0_REGBASE + SPI_CTRL_OFF);
	regdata |= BIT_CTL_ENABLE;
	*(unsigned short*)(SPI0_REGBASE + SPI_CTRL_OFF) = regdata;
	__builtin_bfin_ssync();
}

void spi_disable(spi_device_t *spi_dev)
{
	unsigned short regdata;

	regdata = *(unsigned short*)(SPI0_REGBASE + SPI_CTRL_OFF);
	regdata &= ~BIT_CTL_ENABLE;
	*(unsigned short*)(SPI0_REGBASE + SPI_CTRL_OFF) = regdata;
	__builtin_bfin_ssync();

	if (spi_dev->dma)
		disable_dma(CH_SPI);
}

int spi_dma_read(spi_device_t *spi_dev, void *buffer, unsigned int count)
{

	unsigned short regdata;
	
	/* set transfer mode to DMA rx */
	regdata = *(unsigned short*)(SPI0_REGBASE + SPI_CTRL_OFF);
	regdata |= BIT_CTL_TIMOD_DMA_RX;
	*(unsigned short*)(SPI0_REGBASE + SPI_CTRL_OFF) = regdata;
	__builtin_bfin_ssync();
 
	/* config dma channel */
	spi_dev->dma_config |= ( WNR | RESTART | DI_EN );
	set_dma_config(CH_SPI, spi_dev->dma_config);
	set_dma_start_addr(CH_SPI, (unsigned long)buffer);
	set_dma_x_count(CH_SPI, count);
		
	if(spi_dev->size == CFG_SPI_WORDSIZE16)
		set_dma_x_modify(CH_SPI, 2);
	else 
    		set_dma_x_modify(CH_SPI, 1);
    	
	__builtin_bfin_ssync();

	/* enable spi and dma channel */
	spi_enable(spi_dev);

	return 0;
}

int spi_dma_write(spi_device_t *spi_dev, void *buffer, unsigned int count)
{
	unsigned short regdata;
	
	// configure spi port for DMA TIMOD 
	regdata = *(unsigned short*)(SPI0_REGBASE + SPI_CTRL_OFF);
	regdata |= BIT_CTL_TIMOD_DMA_RX;
	*(unsigned short*)(SPI0_REGBASE + SPI_CTRL_OFF) = regdata;
	__builtin_bfin_ssync();
	
	/* config dma channel */
	spi_dev->dma_config |= ( RESTART );
	set_dma_config(CH_SPI, spi_dev->dma_config);
	set_dma_start_addr(CH_SPI, (unsigned long) buffer);
	set_dma_x_count(CH_SPI, count);
	
	if(spi_dev->size == CFG_SPI_WORDSIZE16)
		set_dma_x_modify(CH_SPI, 2);
	else 
    		set_dma_x_modify(CH_SPI, 1);
	
	__builtin_bfin_ssync();
	
	/* enable spi and dma channel */
	spi_enable(spi_dev);

	return 0;
}

void spi_clear_irqstat(spi_device_t *spi_dev)
{
	if (spi_dev->dma)
		clear_dma_irqstat(CH_SPI);
}


void spi_set_ctl(spi_device_t *spi_dev)
{
	unsigned short control_reg;

	control_reg = ((spi_dev->out_opendrain << 13) | (spi_dev->master << 12) | (spi_dev->polar << 11) | (spi_dev->phase << 10) | (spi_dev->byteorder << 9) | (spi_dev->size << 8) | (spi_dev->emiso << 5) | (spi_dev->slave_sel << 4) | (spi_dev->more_data << 3) | (spi_dev->send_zero << 2) | (spi_dev->ti_mod));

	*(unsigned short*)(SPI0_REGBASE + SPI_BAUD_OFF) = spi_dev->bdrate;
	*(unsigned short*)(SPI0_REGBASE + SPI_FLAG_OFF) = spi_dev->flag;
	*(unsigned short*)(SPI0_REGBASE + SPI_CTRL_OFF) = control_reg;
	__builtin_bfin_ssync();
	
}


void spi_get_stat(unsigned short *data)
{
	*data = *(unsigned short*)(SPI0_REGBASE + SPI_STAU_OFF);
}

void spi_get_ctl(unsigned short *data)
{
	*data = *(unsigned short*)(SPI0_REGBASE + SPI_CTRL_OFF);
}


int spi_channel_request(spi_device_t *spi_dev)
{

	down(&(spilock));

	spi_set_ctl(spi_dev);

	/* clear status reg */
	*(unsigned short*)(SPI0_REGBASE + SPI_STAT_OFF) = 0xFFFF;

	if (spi_dev->irq_handler != NULL) {
		if (spi_dev->dma ) {
			/* DMA mode. Request DMA5 channel, and pass the interrupt handler */
			if(request_dma(CH_SPI, "BF533_SPI_DMA") < 0)
			{
				panic("Unable to attach BlackFin SPI DMA channel\n");
				return -EFAULT;
			}	
			else
				set_dma_callback(CH_SPI, (void*)spi_dev->irq_handler, spi_dev->priv_data);
		} else {
			/* IO mode */
			if(request_irq(SPI0_IRQ_NUM, spi_dev->irq_handler, SA_INTERRUPT, 
				       spi_dev->dev_name, spi_dev->priv_data) < 0)
			{
				printk("SPI: Can't register IRQ.\n");
				return -EFAULT;
			}
		}
	}
	
	return 0;
}


int spi_channel_release (spi_device_t *spi_dev)
{

	if (spi_dev->irq_handler != NULL) {
		if (spi_dev->dma) {
			free_dma(CH_SPI);
		} else {
			free_irq(SPI0_IRQ_NUM, spi_dev->priv_data);
		}
	}
    
	/* clear status reg */
	*(unsigned short*)(SPI0_REGBASE + SPI_STAT_OFF) = 0xFFFF;

	up(&(spilock));
	return 0;
}


int __init spi_channel_init(void)
{

#if defined(CONFIG_BF534)|defined(CONFIG_BF536)|defined(CONFIG_BF537)
	*pPORT_MUX |= PFS4E;
	__builtin_bfin_ssync();
	*pPORTF_FER |= 0x7c40;
	__builtin_bfin_ssync();
#endif

	init_MUTEX(&(spilock));
	
	return 0;
}   

arch_initcall(spi_channel_init);


EXPORT_SYMBOL(spi_send_data);
EXPORT_SYMBOL(spi_receive_data);
EXPORT_SYMBOL(spi_enable);
EXPORT_SYMBOL(spi_disable);
EXPORT_SYMBOL(spi_dma_read);
EXPORT_SYMBOL(spi_dma_write);
EXPORT_SYMBOL(spi_clear_irqstat);
EXPORT_SYMBOL(spi_set_ctl);
EXPORT_SYMBOL(spi_get_ctl);
EXPORT_SYMBOL(spi_get_stat);
EXPORT_SYMBOL(spi_channel_request);
EXPORT_SYMBOL(spi_channel_release);




