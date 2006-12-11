/*
 * File:        drivers/input/touchscreen/ad7877.c
 *
 * Based on: 	ads7846.c
 *
 *		Copyright (C) 2006 Michael Hennerich, Analog Devices Inc.
 *
 * Author:	Michael Hennerich, Analog Devices Inc.
 *
 * Created:	Nov, 10th 2006
 * Description:	AD7877 based touchscreen, sensor (ADCs), DAC and GPIO driver
 *
 * Rev:         $Id$
 *
 * Modified:
 *              Copyright 2004-2006 Analog Devices Inc.
 *
 * Bugs:        Enter bugs at http://blackfin.uclinux.org/
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
 * along with this program; if not, see the file COPYING, or write
 * to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * History:
 * Copyright (c) 2005 David Brownell
 * Copyright (c) 2006 Nokia Corporation
 * Various changes: Imre Deak <imre.deak@nokia.com>
 *
 * Using code from:
 *  - corgi_ts.c
 *	Copyright (C) 2004-2005 Richard Purdie
 *  - omap_ts.[hc], ads7846.h, ts_osk.c
 *	Copyright (C) 2002 MontaVista Software
 *	Copyright (C) 2004 Texas Instruments
 *	Copyright (C) 2005 Dirk Behme
 */


#include <linux/device.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/input.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/spi/spi.h>
#include <linux/spi/ad7877.h>
#include <asm/irq.h>

#ifdef	CONFIG_BFIN
#include <asm/blackfin.h>
#endif

#define	TS_PEN_UP_TIMEOUT	msecs_to_jiffies(50)

/*--------------------------------------------------------------------------*/

#define MAX_SPI_FREQ_HZ			20000000
#define	MAX_12BIT			((1<<12)-1)

#define AD7877_REG_ZEROS			0
#define AD7877_REG_CTRL1			1
#define AD7877_REG_CTRL2			2
#define AD7877_REG_ALERT			3
#define AD7877_REG_AUX1HIGH			4
#define AD7877_REG_AUX1LOW			5
#define AD7877_REG_BAT1HIGH			6
#define AD7877_REG_BAT1LOW			7
#define AD7877_REG_BAT2HIGH			8
#define AD7877_REG_BAT2LOW			9
#define AD7877_REG_TEMP1HIGH			10
#define AD7877_REG_TEMP1LOW			11
#define AD7877_REG_SEQ0				12
#define AD7877_REG_SEQ1				13
#define AD7877_REG_DAC				14
#define AD7877_REG_NONE1			15
#define AD7877_REG_EXTWRITE			15
#define AD7877_REG_XPLUS			16
#define AD7877_REG_YPLUS			17
#define AD7877_REG_Z2				18
#define AD7877_REG_aux1				19
#define AD7877_REG_aux2				20
#define AD7877_REG_aux3				21
#define AD7877_REG_bat1				22
#define AD7877_REG_bat2				23
#define AD7877_REG_temp1			24
#define AD7877_REG_temp2			25
#define AD7877_REG_Z1				26
#define AD7877_REG_GPIOCTRL1			27
#define AD7877_REG_GPIOCTRL2			28
#define AD7877_REG_GPIODATA			29
#define AD7877_REG_NONE2			30
#define AD7877_REG_NONE3			31

#define AD7877_SEQ_YPLUS_BIT			(1<<11)
#define AD7877_SEQ_XPLUS_BIT			(1<<10)
#define AD7877_SEQ_Z2_BIT			(1<<9)
#define AD7877_SEQ_AUX1_BIT			(1<<8)
#define AD7877_SEQ_AUX2_BIT			(1<<7)
#define AD7877_SEQ_AUX3_BIT			(1<<6)
#define AD7877_SEQ_BAT1_BIT			(1<<5)
#define AD7877_SEQ_BAT2_BIT			(1<<4)
#define AD7877_SEQ_TEMP1_BIT			(1<<3)
#define AD7877_SEQ_TEMP2_BIT			(1<<2)
#define AD7877_SEQ_Z1_BIT			(1<<1)

enum {
	AD7877_SEQ_YPOS  = 0,
	AD7877_SEQ_XPOS  = 1,
	AD7877_SEQ_Z2    = 2,
	AD7877_SEQ_AUX1  = 3,
	AD7877_SEQ_AUX2  = 4,
	AD7877_SEQ_AUX3  = 5,
	AD7877_SEQ_BAT1  = 6,
	AD7877_SEQ_BAT2  = 7,
	AD7877_SEQ_TEMP1 = 8,
	AD7877_SEQ_TEMP2 = 9,
	AD7877_SEQ_Z1    = 10,

	AD7877_NR_SENSE  = 11,
};


/* DAC Register Default RANGE 0 to Vcc, Volatge Mode, DAC On */
#define AD7877_DAC_CONF			0x1

/* If gpio3 is set AUX3/GPIO3 acts as GPIO Output */
#define AD7877_EXTW_GPIO_3_CONF		0x1C4
#define AD7877_EXTW_GPIO_DATA		0x200

/* Control REG 2 */
#define AD7877_TMR(x)			((x & 0x3) << 0)
#define AD7877_REF(x)			((x & 0x1) << 2)
#define AD7877_POL(x)			((x & 0x1) << 3)
#define AD7877_FCD(x)			((x & 0x3) << 4)
#define AD7877_PM(x)			((x & 0x3) << 6)
#define AD7877_ACQ(x)			((x & 0x3) << 8)
#define AD7877_AVG(x)			((x & 0x3) << 10)

/* Control REG 1 */
#define	AD7877_SER			(1 << 11)	/* non-differential */
#define	AD7877_DFR			(0 << 11)	/* differential */

#define AD7877_MODE_NOC  (0)	/* Do not convert */
#define AD7877_MODE_SCC  (1)	/* Single channel conversion */
#define AD7877_MODE_SEQ0 (2)	/* Sequence 0 in Slave Mode */
#define AD7877_MODE_SEQ1 (3)	/* Sequence 1 in Master Mode */

#define AD7877_CHANADD(x)		((x&0xF)<<7)
#define AD7877_READADD(x)		((x)<<2)
#define AD7877_WRITEADD(x)		((x)<<12)


#define AD7877_READ_CHAN(x) (AD7877_WRITEADD(AD7877_REG_CTRL1) | AD7877_SER | \
		AD7877_MODE_SCC | AD7877_CHANADD(AD7877_REG_ ## x) | \
		AD7877_READADD(AD7877_REG_ ## x))


#define AD7877_MM_SEQUENCE (AD7877_SEQ_YPLUS_BIT | AD7877_SEQ_XPLUS_BIT | AD7877_SEQ_Z2_BIT | AD7877_SEQ_Z1_BIT)
/*--------------------------------------------------------------------------*/


struct ad7877 {
	struct input_dev	*input;
	char			phys[32];

	struct spi_device	*spi;
	u16			model;
	u16			vref_delay_usecs;
	u16			x_plate_ohms;
	u16			pressure_max;

	u16			cmd_crtl1;
	u16			cmd_crtl2;
	u16			dac;

	u8			stopacq_polarity;
	u8			first_conversion_delay;
	u8			acquisition_time;
	u8			averaging;
	u8			pen_down_acc_interval;

	u16 conversion_data[AD7877_NR_SENSE];

	struct spi_transfer	xfer[3];
	struct spi_message	msg;


	int intr_flag;

	spinlock_t		lock;
	struct timer_list	timer;		/* P: lock */
	unsigned		pendown:1;	/* P: lock */
	unsigned		pending:1;	/* P: lock */

	unsigned		irq_disabled:1;	/* P: lock */
	unsigned		disabled:1;
	unsigned		gpio3:1;
	unsigned		gpio4:1;

};

/*
 * Non-touchscreen sensors only use single-ended conversions.
 */

static int gpio3 = 0;

struct ser_req {
	u16			ref_on;
	u16			command;
	u16			sample;
	struct spi_message	msg;
	struct spi_transfer	xfer[5];
};

static struct task_struct *ad7877_task;
static DECLARE_WAIT_QUEUE_HEAD(ad7877_wait);

static void ad7877_enable(struct ad7877 *ts);
static void ad7877_disable(struct ad7877 *ts);

static int device_suspended(struct device *dev)
{
	struct ad7877 *ts = dev_get_drvdata(dev);
	return dev->power.power_state.event != PM_EVENT_ON || ts->disabled;
}

static int ad7877_read(struct device *dev, u16 reg)
{
	struct spi_device	*spi = to_spi_device(dev);
	struct ser_req		*req = kzalloc(sizeof *req, SLAB_KERNEL);
	int			status;

	if (!req)
		return -ENOMEM;

	spi_message_init(&req->msg);


	req->command = (u16) (AD7877_WRITEADD(AD7877_REG_CTRL1) | AD7877_READADD(reg));
	req->xfer[0].tx_buf = &req->command;
	req->xfer[0].len = 2;

	req->xfer[1].rx_buf = &req->sample;
	req->xfer[1].len = 2;

	spi_message_add_tail(&req->xfer[0], &req->msg);
	spi_message_add_tail(&req->xfer[1], &req->msg);

	status = spi_sync(spi, &req->msg);

	if (req->msg.status)
		status = req->msg.status;

	kfree(req);
	return status ? status : req->sample;
}

static int ad7877_write(struct device *dev, u16 reg, u16 val)
{
	struct spi_device	*spi = to_spi_device(dev);
	struct ser_req		*req = kzalloc(sizeof *req, SLAB_KERNEL);
	int			status;

	if (!req)
		return -ENOMEM;

	spi_message_init(&req->msg);


	req->command = (u16) (AD7877_WRITEADD(reg) | (val & MAX_12BIT));
	req->xfer[0].tx_buf = &req->command;
	req->xfer[0].len = 2;


	spi_message_add_tail(&req->xfer[0], &req->msg);

	status = spi_sync(spi, &req->msg);

	if (req->msg.status)
		status = req->msg.status;

	kfree(req);

	return status;
}

static int ad7877_read_adc(struct device *dev, unsigned command)
{
	struct spi_device	*spi = to_spi_device(dev);
	struct ad7877		*ts = dev_get_drvdata(dev);
	struct ser_req		*req = kzalloc(sizeof *req, SLAB_KERNEL);
	int			status;
	int			sample;
	int			i;

	if (!req)
		return -ENOMEM;

	spi_message_init(&req->msg);

	/* activate reference, so it has time to settle; */
	req->ref_on = AD7877_WRITEADD(AD7877_REG_CTRL2) | AD7877_POL(ts->stopacq_polarity) |\
			 AD7877_AVG(0) | AD7877_PM(2) | AD7877_TMR(0) |\
			 AD7877_ACQ(ts->acquisition_time) | AD7877_FCD(0);

	req->command = (u16) command;

	req->xfer[0].tx_buf = &req->ref_on;
	req->xfer[0].len = 2;
	req->xfer[0].delay_usecs = ts->vref_delay_usecs;

	req->xfer[1].tx_buf = &req->command;
	req->xfer[1].len = 2;
	req->xfer[1].delay_usecs = ts->vref_delay_usecs;

	req->xfer[2].rx_buf = &req->sample;
	req->xfer[2].len = 2;

	req->xfer[3].tx_buf = &ts->cmd_crtl2;	/*REF OFF*/
	req->xfer[3].len = 2;

	req->xfer[4].tx_buf = &ts->cmd_crtl1;	/*DEFAULT*/
	req->xfer[4].len = 2;


	/* group all the transfers together, so we can't interfere with
	 * reading touchscreen state; disable penirq while sampling
	 */
	for (i = 0; i < 5; i++)
		spi_message_add_tail(&req->xfer[i], &req->msg);


	ts->irq_disabled = 1;
	disable_irq(spi->irq);
	status = spi_sync(spi, &req->msg);
	ts->irq_disabled = 0;
	enable_irq(spi->irq);

	if (req->msg.status)
		status = req->msg.status;


	sample = req->sample;

	kfree(req);
	return status ? status : sample;
}

#define SHOW(name) static ssize_t \
name ## _show(struct device *dev, struct device_attribute *attr, char *buf) \
{ \
	ssize_t v = ad7877_read_adc(dev, \
			AD7877_READ_CHAN(name)); \
	if (v < 0) \
		return v; \
	return sprintf(buf, "%u\n", (unsigned) v); \
} \
static DEVICE_ATTR(name, S_IRUGO, name ## _show, NULL);

SHOW(aux1)
SHOW(aux2)
SHOW(aux3)
SHOW(bat1)
SHOW(bat2)
SHOW(temp1)
SHOW(temp2)


static ssize_t ad7877_disable_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	struct ad7877	*ts = dev_get_drvdata(dev);

	return sprintf(buf, "%u\n", ts->disabled);
}

static ssize_t ad7877_disable_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct ad7877 *ts = dev_get_drvdata(dev);
	char *endp;
	int i;

	i = simple_strtoul(buf, &endp, 10);
	spin_lock_irq(&ts->lock);

	if (i)
		ad7877_disable(ts);
	else
		ad7877_enable(ts);

	spin_unlock_irq(&ts->lock);

	return count;
}

static DEVICE_ATTR(disable, 0664, ad7877_disable_show, ad7877_disable_store);

static ssize_t ad7877_dac_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	struct ad7877	*ts = dev_get_drvdata(dev);

	return sprintf(buf, "%u\n", ts->dac);
}

static ssize_t ad7877_dac_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct ad7877 *ts = dev_get_drvdata(dev);
	char *endp;
	int i;

	i = simple_strtoul(buf, &endp, 10);

	ts->dac = i & 0xFF;

	ad7877_write(dev, AD7877_REG_DAC, (ts->dac << 4) | AD7877_DAC_CONF);

	return count;
}

static DEVICE_ATTR(dac, 0664, ad7877_dac_show, ad7877_dac_store);

static ssize_t ad7877_gpio3_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	struct ad7877	*ts = dev_get_drvdata(dev);

	return sprintf(buf, "%u\n", ts->gpio3);
}

static ssize_t ad7877_gpio3_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct ad7877 *ts = dev_get_drvdata(dev);
	char *endp;
	int i;

	i = simple_strtoul(buf, &endp, 10);
	spin_lock_irq(&ts->lock);

	if (i) {
		ts->gpio3=1;
	} else {
		ts->gpio3=0;
	}

	ad7877_write(dev, AD7877_REG_EXTWRITE, AD7877_EXTW_GPIO_DATA | (ts->gpio4 << 4) | (ts->gpio3 << 5));

	spin_unlock_irq(&ts->lock);

	return count;
}

static DEVICE_ATTR(gpio3, 0664, ad7877_gpio3_show, ad7877_gpio3_store);

static ssize_t ad7877_gpio4_show(struct device *dev,
				     struct device_attribute *attr, char *buf)
{
	struct ad7877	*ts = dev_get_drvdata(dev);

	return sprintf(buf, "%u\n", ts->gpio4);
}

static ssize_t ad7877_gpio4_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	struct ad7877 *ts = dev_get_drvdata(dev);
	char *endp;
	int i;

	i = simple_strtoul(buf, &endp, 10);
	spin_lock_irq(&ts->lock);

	if (i) {
		ts->gpio4=1;
	} else {
		ts->gpio4=0;
	}

	ad7877_write(dev, AD7877_REG_EXTWRITE, AD7877_EXTW_GPIO_DATA | (ts->gpio4 << 4) | (ts->gpio3 << 5));
	spin_unlock_irq(&ts->lock);

	return count;
}

static DEVICE_ATTR(gpio4, 0664, ad7877_gpio4_show, ad7877_gpio4_store);

/*--------------------------------------------------------------------------*/

/*
 * /DAV Data available Interrupt only kicks the kthread.
 * The kthread kicks the timer only to issue the Pen Up Event if
 * no new data is available
 *
 */

static void ad7877_rx(void *ads)
{
	struct ad7877		*ts = ads;
	struct input_dev	*input_dev = ts->input;
	unsigned		Rt;
	unsigned		sync = 0;
	u16			x, y, z1, z2;

	x = ts->conversion_data[AD7877_SEQ_XPOS] & MAX_12BIT;
	y = ts->conversion_data[AD7877_SEQ_YPOS]& MAX_12BIT;
	z1 = ts->conversion_data[AD7877_SEQ_Z1] & MAX_12BIT;
	z2 = ts->conversion_data[AD7877_SEQ_Z2] & MAX_12BIT;

	/* range filtering */
	if (x == MAX_12BIT)
		x = 0;

	if (likely(x && z1 && !device_suspended(&ts->spi->dev))) {
		/* compute touch pressure resistance using equation #2 */
		Rt = z2;
		Rt -= z1;
		Rt *= x;
		Rt *= ts->x_plate_ohms;
		Rt /= z1;
		Rt = (Rt + 2047) >> 12;
	} else
		Rt = 0;

	if (Rt) {
		input_report_abs(input_dev, ABS_X, x);
		input_report_abs(input_dev, ABS_Y, y);
		sync = 1;
	}

	if (sync) {
		input_report_abs(input_dev, ABS_PRESSURE, Rt);
		input_sync(input_dev);
	}

#ifdef	VERBOSE
	if (Rt)
		pr_debug("%s: %d/%d/%d%s\n", ts->spi->dev.bus_id,
			x, y, Rt, Rt ? "" : " UP");
#endif

}


static inline void ad7877_ts_event_release(struct ad7877 *ts)
{
	struct input_dev *input_dev = ts->input;
	input_report_abs(input_dev, ABS_PRESSURE, 0);
	input_sync(input_dev);
}

static void ad7877_timer(unsigned long handle)
{
	struct ad7877	*ts = (void *)handle;

	spin_lock_irq(&ts->lock);

	ad7877_ts_event_release(ts);

	spin_unlock_irq(&ts->lock);
}


static irqreturn_t ad7877_irq(int irq, void *handle, struct pt_regs *regs)
{
	struct ad7877 *ts = handle;
	unsigned long flags;

	spin_lock_irqsave(&ts->lock, flags);

		if (!ts->irq_disabled) {
			ts->irq_disabled = 1;
			disable_irq(ts->spi->irq);
			ts->pending = 1;
		}

	ts->intr_flag = 1;

	spin_unlock_irqrestore(&ts->lock, flags);

	wake_up_interruptible(&ad7877_wait);

	return IRQ_HANDLED;
}


static int ad7877_thread(void *_ts)
{
	struct ad7877 *ts = _ts;
	int status;
	unsigned long flags;

        do {
		wait_event_interruptible(ad7877_wait, kthread_should_stop() || (ts->intr_flag!=0));

		if(ts->intr_flag) {
			status = spi_sync(ts->spi, &ts->msg);
			if (status)
				dev_err(&ts->spi->dev, "spi_sync --> %d\n", status);
	
			ad7877_rx(ts);
	
			spin_lock_irqsave(&ts->lock, flags);
	
	                ts->intr_flag = 0;
			ts->pending = 0;
	
			if (!device_suspended(&ts->spi->dev)) {
				ts->irq_disabled = 0;
				enable_irq(ts->spi->irq);
				mod_timer(&ts->timer, jiffies + TS_PEN_UP_TIMEOUT);
			}
	
			spin_unlock_irqrestore(&ts->lock, flags);
	}
        	try_to_freeze();
        } while (!kthread_should_stop());
        printk(KERN_DEBUG "ad7877: ktsd kthread exiting\n");
        return 0;
}


/*--------------------------------------------------------------------------*/

/* Must be called with ts->lock held */
static void ad7877_disable(struct ad7877 *ts)
{
	if (ts->disabled)
		return;

	ts->disabled = 1;

	if (!ts->pending) {
		ts->irq_disabled = 1;
		disable_irq(ts->spi->irq);
	} else {
		/* the kthread will run at least once more, and
		 * leave everything in a clean state, IRQ disabled
		 */
		while (ts->pending) {
			spin_unlock_irq(&ts->lock);
			msleep(1);
			spin_lock_irq(&ts->lock);
		}
	}

	/* we know the chip's in lowpower mode since we always
	 * leave it that way after every request
	 */

}

/* Must be called with ts->lock held */
static void ad7877_enable(struct ad7877 *ts)
{
	if (!ts->disabled)
		return;

	ts->disabled = 0;
	ts->irq_disabled = 0;
	enable_irq(ts->spi->irq);
}

static int ad7877_suspend(struct spi_device *spi, pm_message_t message)
{
	struct ad7877 *ts = dev_get_drvdata(&spi->dev);

	spin_lock_irq(&ts->lock);

	spi->dev.power.power_state = message;
	ad7877_disable(ts);

	spin_unlock_irq(&ts->lock);

	return 0;

}

static int ad7877_resume(struct spi_device *spi)
{
	struct ad7877 *ts = dev_get_drvdata(&spi->dev);

	spin_lock_irq(&ts->lock);

	spi->dev.power.power_state = PMSG_ON;
	ad7877_enable(ts);

	spin_unlock_irq(&ts->lock);

	return 0;
}

static int __devinit ad7877_probe(struct spi_device *spi)
{
	struct ad7877			*ts;
	struct input_dev		*input_dev;
	struct ad7877_platform_data	*pdata = spi->dev.platform_data;
	struct spi_message		*m;
	int				err;
	u16				verify;


	if (!spi->irq) {
		dev_dbg(&spi->dev, "no IRQ?\n");
		return -ENODEV;
	}


	if (!pdata) {
		dev_dbg(&spi->dev, "no platform data?\n");
		return -ENODEV;
	}


	/* don't exceed max specified SPI CLK frequency */
	if (spi->max_speed_hz > MAX_SPI_FREQ_HZ) {
		dev_dbg(&spi->dev, "SPI CLK %d Hz?\n",spi->max_speed_hz);
		return -EINVAL;
	}

	ts = kzalloc(sizeof(struct ad7877), GFP_KERNEL);
	input_dev = input_allocate_device();
	if (!ts || !input_dev) {
		err = -ENOMEM;
		goto err_free_mem;
	}


	dev_set_drvdata(&spi->dev, ts);
	spi->dev.power.power_state = PMSG_ON;

	ts->spi = spi;
	ts->input = input_dev;
	ts->intr_flag = 0;
	init_timer(&ts->timer);
	ts->timer.data = (unsigned long) ts;
	ts->timer.function = ad7877_timer;

	spin_lock_init(&ts->lock);

	ts->model = pdata->model ? : 7877;
	ts->vref_delay_usecs = pdata->vref_delay_usecs ? : 100;
	ts->x_plate_ohms = pdata->x_plate_ohms ? : 400;
	ts->pressure_max = pdata->pressure_max ? : ~0;


	ts->stopacq_polarity = pdata->stopacq_polarity;
	ts->first_conversion_delay = pdata->first_conversion_delay;
	ts->acquisition_time = pdata->acquisition_time;
	ts->averaging = pdata->averaging;
	ts->pen_down_acc_interval = pdata->pen_down_acc_interval;

	snprintf(ts->phys, sizeof(ts->phys), "%s/input0", spi->dev.bus_id);

	input_dev->name = "AD7877 Touchscreen";
	input_dev->phys = ts->phys;
	input_dev->cdev.dev = &spi->dev;

        set_bit(EV_KEY, input_dev->evbit);
        set_bit(EV_ABS, input_dev->evbit);
	set_bit(ABS_X, input_dev->absbit);
	set_bit(ABS_Y, input_dev->absbit);
	set_bit(ABS_PRESSURE, input_dev->absbit);

	input_set_abs_params(input_dev, ABS_X,
			pdata->x_min ? : 0,
			pdata->x_max ? : MAX_12BIT,
			0, 0);
	input_set_abs_params(input_dev, ABS_Y,
			pdata->y_min ? : 0,
			pdata->y_max ? : MAX_12BIT,
			0, 0);
	input_set_abs_params(input_dev, ABS_PRESSURE,
			pdata->pressure_min, pdata->pressure_max, 0, 0);

	ad7877_write((struct device *) spi, AD7877_REG_SEQ1, AD7877_MM_SEQUENCE);


	verify = ad7877_read((struct device *) spi, AD7877_REG_SEQ1);

	if (verify != AD7877_MM_SEQUENCE){
		printk(KERN_ERR "%s: Failed to probe %s\n", spi->dev.bus_id, input_dev->name);
		err = -ENODEV;
		goto err_free_mem;
	}

	if(gpio3)
		ad7877_write((struct device *) spi, AD7877_REG_EXTWRITE, AD7877_EXTW_GPIO_3_CONF);


	ts->cmd_crtl2 =  AD7877_WRITEADD(AD7877_REG_CTRL2) | AD7877_POL(ts->stopacq_polarity) |\
			AD7877_AVG(ts->averaging) | AD7877_PM(1) |\
			AD7877_TMR(ts->pen_down_acc_interval) | AD7877_ACQ(ts->acquisition_time) |\
			AD7877_FCD(ts->first_conversion_delay);

	ad7877_write((struct device *) spi, AD7877_REG_CTRL2, ts->cmd_crtl2);

	ts->cmd_crtl1 =  AD7877_WRITEADD(AD7877_REG_CTRL1) | AD7877_READADD(AD7877_REG_XPLUS) |\
			 AD7877_MODE_SEQ1 | AD7877_DFR;

	ad7877_write((struct device *) spi, AD7877_REG_CTRL1, ts->cmd_crtl1);

	m = &ts->msg;

	spi_message_init(m);

	ts->xfer[0].tx_buf = &ts->cmd_crtl1;
	ts->xfer[0].len = 2;

	spi_message_add_tail(&ts->xfer[0], m);

	ts->xfer[1].rx_buf = &ts->conversion_data[AD7877_SEQ_YPOS];
	ts->xfer[1].len = AD7877_NR_SENSE * sizeof(u16);

	spi_message_add_tail(&ts->xfer[1], m);

	/* Request AD7877 /DAV GPIO interrupt */

	if (request_irq(spi->irq, ad7877_irq, IRQF_TRIGGER_LOW,
			spi->dev.driver->name, ts)) {
		dev_dbg(&spi->dev, "irq %d busy?\n", spi->irq);
		err = -EBUSY;
		goto err_free_mem;
	}

	dev_info(&spi->dev, "touchscreen, irq %d\n", spi->irq);

	device_create_file(&spi->dev, &dev_attr_temp1);
	device_create_file(&spi->dev, &dev_attr_temp2);
	device_create_file(&spi->dev, &dev_attr_aux1);
	device_create_file(&spi->dev, &dev_attr_aux2);
	device_create_file(&spi->dev, &dev_attr_bat1);
	device_create_file(&spi->dev, &dev_attr_bat2);
	device_create_file(&spi->dev, &dev_attr_disable);
	device_create_file(&spi->dev, &dev_attr_dac);
	device_create_file(&spi->dev, &dev_attr_gpio4);

	if(gpio3)
		device_create_file(&spi->dev, &dev_attr_gpio3);
	else
		device_create_file(&spi->dev, &dev_attr_aux3);

	err = input_register_device(input_dev);
	if (err)
		goto err_remove_attr;

	ts->intr_flag = 0;

	ad7877_task = kthread_run(ad7877_thread, ts, "ad7877_ktsd");

        if (IS_ERR(ad7877_task)) {
                printk(KERN_ERR "ts: Failed to start ad7877_task\n");
                goto err_remove_attr;
        }

	return 0;

 err_remove_attr:
	device_remove_file(&spi->dev, &dev_attr_disable);
	device_remove_file(&spi->dev, &dev_attr_dac);
	device_remove_file(&spi->dev, &dev_attr_temp1);
	device_remove_file(&spi->dev, &dev_attr_temp2);
	device_remove_file(&spi->dev, &dev_attr_aux1);
	device_remove_file(&spi->dev, &dev_attr_aux3);
	device_remove_file(&spi->dev, &dev_attr_bat1);
	device_remove_file(&spi->dev, &dev_attr_bat2);
	device_remove_file(&spi->dev, &dev_attr_gpio4);

	if(gpio3)
		device_remove_file(&spi->dev, &dev_attr_gpio3);
	else
		device_remove_file(&spi->dev, &dev_attr_aux3);


	free_irq(spi->irq, ts);
 err_free_mem:
	input_free_device(input_dev);
	kfree(ts);
	return err;
}

static int __devexit ad7877_remove(struct spi_device *spi)
{
	struct ad7877		*ts = dev_get_drvdata(&spi->dev);

	input_unregister_device(ts->input);

	ad7877_suspend(spi, PMSG_SUSPEND);

	kthread_stop(ad7877_task);

	device_remove_file(&spi->dev, &dev_attr_disable);
	device_remove_file(&spi->dev, &dev_attr_dac);
	device_remove_file(&spi->dev, &dev_attr_temp1);
	device_remove_file(&spi->dev, &dev_attr_temp2);
	device_remove_file(&spi->dev, &dev_attr_aux1);
	device_remove_file(&spi->dev, &dev_attr_aux2);
	device_remove_file(&spi->dev, &dev_attr_bat1);
	device_remove_file(&spi->dev, &dev_attr_bat2);
	device_remove_file(&spi->dev, &dev_attr_gpio4);

	if(gpio3)
		device_remove_file(&spi->dev, &dev_attr_gpio3);
	else
		device_remove_file(&spi->dev, &dev_attr_aux3);

	free_irq(ts->spi->irq, ts);

	kfree(ts);

	dev_dbg(&spi->dev, "unregistered touchscreen\n");
	return 0;
}

static struct spi_driver ad7877_driver = {
	.driver = {
		.name	= "ad7877",
		.bus	= &spi_bus_type,
		.owner	= THIS_MODULE,
	},
	.probe		= ad7877_probe,
	.remove		= __devexit_p(ad7877_remove),
	.suspend	= ad7877_suspend,
	.resume		= ad7877_resume,
};

static int __init ad7877_init(void)
{

	return spi_register_driver(&ad7877_driver);
}
module_init(ad7877_init);

static void __exit ad7877_exit(void)
{
	spi_unregister_driver(&ad7877_driver);

}
module_exit(ad7877_exit);

module_param(gpio3, int, 0);
MODULE_PARM_DESC(gpio3,
	"If gpio3 is set to 1 AUX3 acts as GPIO3");

MODULE_DESCRIPTION("ad7877 TouchScreen Driver");
MODULE_LICENSE("GPL");
