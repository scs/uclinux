/****************************************************************
 * $ID: i2c-bfin-twi.c      12 Aug 2005 13:29:10 -0800        $ *
 *                                                              *
 * Description:                                                 *
 *                                                              *
 * Maintainer:  sonicz  <sonic.zhang@analog.com>                *
 *                                                              *
 * CopyRight (c)  2005  Analog Device                           *
 * All rights reserved.                                         *
 *                                                              *
 * This file is free software;                                  *
 *   you are free to modify and/or redistribute it   	        *
 *   under the terms of the GNU General Public Licence (GPL).   *
 *                                                              *
 ****************************************************************/

#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/i2c.h>
#include <linux/mm.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/completion.h>
#include <linux/interrupt.h>

#include <asm/blackfin.h>
#include <asm/irq.h>

#define I2C_BFIN_TWI 0x00
#define POLL_TIMEOUT		(2*HZ)
#ifndef CONFIG_TWICLK_KHZ
#define CONFIG_TWICLK_KHZ	400
#endif


struct bfin_twi_iface
{
	struct semaphore 	twi_lock;
	int			irq;
	spinlock_t		lock;
	char			read_write;
	u8			*transPtr;
	int			result;
	int			timeout_count;
	struct timer_list	timeout_timer;
	struct i2c_adapter	adap;
	struct completion	complete;
};

static struct bfin_twi_iface twi_iface;

static void bfin_twi_handle_interrupt(struct bfin_twi_iface *iface)
{
	unsigned short twi_int_stat;
	twi_int_stat = *pTWI_INT_STAT;
	 
	if ( RCVSERV & twi_int_stat ){
		/* Receive next data */
		*(iface->transPtr++) = *pTWI_RCV_DATA8;
		/* Clear interrupt source */
		*pTWI_INT_STAT = RCVSERV;
		__builtin_bfin_ssync();
	}
	if ( XMTSERV & twi_int_stat ){
		/* Transmit next data */
		*pTWI_XMT_DATA8 = *(iface->transPtr++);
		/* Clear status */
		*pTWI_INT_STAT = XMTSERV;
		__builtin_bfin_ssync();
	}
	if ( MCOMP & twi_int_stat ){
		*pTWI_INT_STAT = MCOMP;
		__builtin_bfin_ssync();
		iface->result = 1;
	}
	if( MERR & twi_int_stat ) {
		*pTWI_INT_STAT = MERR;
		__builtin_bfin_ssync();
		iface->result = -1;
	}
	if( twi_int_stat & (MERR|MCOMP))
		complete(&iface->complete);
}


/* Interrupt handler */
static irqreturn_t bfin_twi_interrupt_entry(int irq, void *dev_id, struct pt_regs *regs)
{
	struct bfin_twi_iface *iface = (struct bfin_twi_iface *)dev_id;
	unsigned long flags;

	spin_lock_irqsave(&iface->lock, flags);
	del_timer(&iface->timeout_timer);
	bfin_twi_handle_interrupt(iface);
	spin_unlock_irqrestore(&iface->lock, flags);
	return IRQ_HANDLED;
}

static void bfin_twi_timeout(unsigned long data)
{
	struct bfin_twi_iface *iface = (struct bfin_twi_iface *)data;
	unsigned long flags;

	spin_lock_irqsave(&iface->lock, flags);
	bfin_twi_handle_interrupt(iface);
	if (iface->result == 0) {
		iface->timeout_count--;
		if(iface->timeout_count>0) {
			iface->timeout_timer.expires = jiffies + POLL_TIMEOUT;
			add_timer(&iface->timeout_timer);
		}
		else {
			iface->result = -1;
			complete(&iface->complete);
		}
	}
	spin_unlock_irqrestore(&iface->lock, flags);
}


/*
 * Generic i2c master transfer entrypoint
 */
static int bfin_twi_xfer(struct i2c_adapter *adap, struct i2c_msg msgs[], int num)
{
	struct bfin_twi_iface* iface = (struct bfin_twi_iface*)adap->algo_data;
	struct i2c_msg *pmsg;
	int i, ret;
	int rc = 0;

	if ( !(*pTWI_CONTROL & TWI_ENA) )
		return -ENXIO;

	down(&iface->twi_lock);

	ret = 0;
	for (i = 0; rc >= 0 && i < num;) {
		pmsg = &msgs[i++];
		if (pmsg->flags & I2C_M_TEN) {
			printk(KERN_ERR "i2c-bfin-twi: 10 bits addr not supported !\n");
			rc = -EINVAL;
			break;
		}

		iface->transPtr = pmsg->buf;
		iface->result = 0;
		iface->timeout_count = 10;
		if (pmsg->flags & I2C_M_RD)
			iface->read_write = I2C_SMBUS_READ;
		else
			iface->read_write = I2C_SMBUS_WRITE;

		/* Set Transmit device address */
		*pTWI_MASTER_ADDR = (pmsg->addr)>>1;

		/* Set Transmit device address */
		*pTWI_XMT_DATA8 = *(iface->transPtr++);
		__builtin_bfin_ssync();

		iface->timeout_timer.expires = jiffies + POLL_TIMEOUT;
		add_timer(&iface->timeout_timer);

		/* Master enable, Issue Tx */
		*pTWI_MASTER_CTL = MEN | ( pmsg->len << 6 ) | ((iface->read_write == I2C_SMBUS_READ) ? MDIR : 0);
		__builtin_bfin_ssync();

		wait_for_completion(&iface->complete);	

		rc = iface->result;
		if (rc == 1)
			ret++;
		else if(rc == -1)
			break;
	}

	/* Release sem */
	up(&iface->twi_lock);

	return ret;
}

/*
 * Return what the adapter supports
 */
static u32 bfin_twi_functionality(struct i2c_adapter *adap)
{
	if(adap->id == I2C_BFIN_TWI)
		return I2C_FUNC_SMBUS_EMUL;
	return 0;
}


static struct i2c_algorithm bfin_twi_algorithm = {
	.name		= "BFIN TWI I2C",
	.id		= I2C_BFIN_TWI,
	.master_xfer	= bfin_twi_xfer,
	.smbus_xfer     = NULL,
	.functionality  = bfin_twi_functionality,
};

static int __init i2c_bfin_twi_init(void)
{
	struct i2c_adapter *p_adap;
	int rc;

	init_MUTEX(&(twi_iface.twi_lock));
	spin_lock_init(&twi_iface.lock);
	init_completion(&twi_iface.complete);
	twi_iface.irq = IRQ_TWI;

	init_timer(&twi_iface.timeout_timer);
	twi_iface.timeout_timer.function = bfin_twi_timeout;
	twi_iface.timeout_timer.data = (unsigned long)&twi_iface;

	p_adap = &twi_iface.adap;
	p_adap->id = I2C_BFIN_TWI;
	p_adap->algo = &bfin_twi_algorithm;
	p_adap->algo_data = &twi_iface;
	p_adap->client_register = NULL;
	p_adap->client_unregister = NULL;

	rc = request_irq(twi_iface.irq, bfin_twi_interrupt_entry, SA_INTERRUPT, "bfin twi i2c", &twi_iface);
	if (rc) {
		printk(KERN_ERR "i2c-bfin-twi: can't get IRQ %d !\n", twi_iface.irq);
		return -ENODEV;
	}

	/* Set TWI internal clock as 10MHz */
	*pTWI_CONTROL = (get_sclk() / 10 / 1024 / 1024 ) & 0x7F;

	/* Set Twi interface clock as specified */
	*pTWI_CLKDIV = (( 5*1024 / CONFIG_TWICLK_KHZ ) << 8) | (( 5*1024 / CONFIG_TWICLK_KHZ ) & 0xFF);

	/* FIFO Initiation */
	*pTWI_FIFO_CTL = 0;
	
	/* Interrupt mask . Enable XMT, RCV interrupt */
	*pTWI_INT_MASK = RCVSERV | XMTSERV | MCOMP | MERR;
	__builtin_bfin_ssync();

	/* Enable TWI */
	*pTWI_CONTROL |= TWI_ENA;
	__builtin_bfin_ssync();


	return i2c_add_adapter(p_adap);
}

static void __exit i2c_bfin_twi_exit(void)
{
	i2c_del_adapter(&twi_iface.adap);
}

MODULE_AUTHOR("Sonic Zhang <sonic.zhang@analog.com>");
MODULE_DESCRIPTION("I2C-Bus adapter routines for Blackfin TWI");
MODULE_LICENSE("GPL");

module_init(i2c_bfin_twi_init);
module_exit(i2c_bfin_twi_exit);

