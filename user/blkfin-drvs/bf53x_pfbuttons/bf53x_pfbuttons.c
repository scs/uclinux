/*
 * File:         drivers/input/misc/bf53x_pfbuttons.c
 * Based on:
 * Author:       Michele d'Amico
 *
 * Created:
 * Description:
 *
 * Rev:          $Id: bf53x_pfbuttons.c 3552 2007-08-13 06:45:25Z cooloney $
 *
 * Modified:     Copyright 2006 Michele d'Amico
 *               Copyright 2006 Analog Devices Inc.
 *		 Copyright 2007 Michael Hennerich, Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * This program is free software ;  you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation ;  either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY ;  without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program ;  see the file COPYING.
 * If not, write to the Free Software Foundation,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/input.h>
#include <linux/major.h>
#include <asm/uaccess.h>
#include <asm/blackfin.h>
#include <asm/irq.h>
#include <asm/gpio.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>
#include <linux/interrupt.h>

MODULE_AUTHOR("Michele d'Amico <michele.damico@fitre.it>");
MODULE_DESCRIPTION("PFButton input driver");
MODULE_LICENSE("GPL");

#if defined(CONFIG_BFIN533_TASVOIP)
#define BUTTONS 4
#define PF_BUTTON1 11
#define PF_BUTTON2 12
#define PF_BUTTON3 13
#define PF_BUTTON4 14

static unsigned short bf53xPFbuttons_btn_gpios[BUTTONS] = {
	PF_BUTTON1,
	PF_BUTTON2,
	PF_BUTTON3,
	PF_BUTTON4
};

static unsigned short bf53xPFbuttons_btncode[BUTTONS] = {
	(unsigned short)BTN_0,
	(unsigned short)BTN_1,
	(unsigned short)BTN_2,
	(unsigned short)BTN_3
};

#define LEDS 1
#define PF_LED1 9

static unsigned short bf53xPFbuttons_led_gpios[LEDS] = {
	PF_LED1
};

static unsigned short bf53xPFbuttons_ledcode[LEDS] = {
	(unsigned short)LED_MISC
};

#define BELLS 1
#define PF_BELL1 10

static unsigned short bf53xPFbuttons_snd_gpios[BELLS] = {
	PF_BELL1
};

static unsigned short bf53xPFbuttons_sndcode[BELLS] = {
	(unsigned short)SND_BELL
};

#elif defined(CONFIG_BFIN533_STAMP)
#define BUTTONS 3
#define PF_BUTTON1 5
#define PF_BUTTON2 6
#define PF_BUTTON3 8

static unsigned short bf53xPFbuttons_btn_gpios[BUTTONS] = {
	PF_BUTTON1,
	PF_BUTTON2,
	PF_BUTTON3
};

static unsigned short bf53xPFbuttons_btncode[BUTTONS] = {
	(unsigned short)BTN_0,
	(unsigned short)BTN_1,
	(unsigned short)BTN_2
};

#define LEDS 3
#define PF_LED1 2
#define PF_LED2 3
#define PF_LED3 4

static unsigned short bf53xPFbuttons_led_gpios[LEDS] = {
	PF_LED1,
	PF_LED2,
	PF_LED3
};

static unsigned short bf53xPFbuttons_ledcode[LEDS] = {
	(unsigned short)LED_MISC,
	(unsigned short)LED_MUTE,
	(unsigned short)LED_SUSPEND
};

#define BELLS 0

#define PF_BELLS_MASK 0

#elif defined(CONFIG_BFIN533_EZKIT)
#define BUTTONS 4
#define PF_BUTTON1 7
#define PF_BUTTON2 8
#define PF_BUTTON3 9
#define PF_BUTTON4 10

static unsigned short bf53xPFbuttons_btn_gpios[BUTTONS] = {
	PF_BUTTON1,
	PF_BUTTON2,
	PF_BUTTON3,
	PF_BUTTON4
};

static unsigned short bf53xPFbuttons_btncode[BUTTONS] = {
	(unsigned short)BTN_0,
	(unsigned short)BTN_1,
	(unsigned short)BTN_2,
	(unsigned short)BTN_3
};

/* I don't know where the leds are routed on EZKIT (Michele) */
#define LEDS 0
#define PF_LEDS_MASK 0

#define BELLS 0
#define PF_BELLS_MASK 0

#elif defined(CONFIG_BFIN537_STAMP)
#define BUTTONS 4
#define PF_BUTTON1 2
#define PF_BUTTON2 3
#define PF_BUTTON3 4
#define PF_BUTTON4 5

static unsigned short bf53xPFbuttons_btn_gpios[BUTTONS] = {
	PF_BUTTON1,
	PF_BUTTON2,
	PF_BUTTON3,
	PF_BUTTON4
};

static unsigned short bf53xPFbuttons_btncode[BUTTONS] = {
	(unsigned short)BTN_0,
	(unsigned short)BTN_1,
	(unsigned short)BTN_2,
	(unsigned short)BTN_3
};

#define LEDS 3
#define PF_LED1 6
#define PF_LED2 7
#define PF_LED3 8

static unsigned short bf53xPFbuttons_led_gpios[LEDS] = {
	PF_LED1,
	PF_LED2,
	PF_LED3
};

static unsigned short bf53xPFbuttons_ledcode[LEDS] = {
	(unsigned short)LED_MISC,
	(unsigned short)LED_MUTE,
	(unsigned short)LED_SUSPEND
};

#define BELLS 0

#define PF_BELLS_MASK 0
#else
#error "ONLY Tasvoip, STAMP and EZKIT are supported"
#endif

struct bf53xPFbuttons {
#if BUTTONS
	unsigned short *btncode;
	unsigned short *btn_gpios;
#endif
#if LEDS
	unsigned short *ledcode;
	unsigned short *led_gpios;
#endif
#if BELLS
	unsigned short *sndcode;
	unsigned short *snd_gpios;
#endif
	struct input_dev *dev;
	char name[64];
	char phys[32];
	short laststate[BUTTONS];
	short statechanged[BUTTONS];
	unsigned long irq_handled;
	unsigned long events_sended;
	unsigned long events_processed;
};

static irqreturn_t bf53xPFbuttons_irq_handler(int irq, void *dev_id);
static int bf53xPFbuttons_proc_output(struct bf53xPFbuttons *bf53xPFbuttons,
				      char *buf);
static int bf53xPFbuttons_read_proc(char *page, char **start, off_t off,
				    int count, int *eof, void *data);

static struct bf53xPFbuttons chip = {
#if BUTTONS
	.btncode = bf53xPFbuttons_btncode,
	.btn_gpios = bf53xPFbuttons_btn_gpios,
#endif
#if LEDS
	.ledcode = bf53xPFbuttons_ledcode,
	.led_gpios = bf53xPFbuttons_led_gpios,
#endif
#if BELLS
	.sndcode = bf53xPFbuttons_sndcode,
	.snd_gpios = bf53xPFbuttons_snd_gpios,
#endif
	.irq_handled = 0,
	.events_sended = 0,
	.events_processed = 0,
};

static irqreturn_t bf53xPFbuttons_irq_handler(int irq, void *dev_id)
{
	struct bf53xPFbuttons *bf53xPFbuttons = (struct bf53xPFbuttons *)dev_id;

	u16 i = 0;

	pr_debug("bf53xPFbuttons_irq_handler PF%d\n", (irq - IRQ_PF0));

	while (i < BUTTONS) {
		if (bf53xPFbuttons->btn_gpios[i] == irq - IRQ_PF0)
			break;
		i++;
	}

	bf53xPFbuttons->statechanged[i] = 1;
	bf53xPFbuttons->laststate[i] ^= bf53xPFbuttons->statechanged[i];

	input_report_key(bf53xPFbuttons->dev, bf53xPFbuttons->btncode[i],
			 bf53xPFbuttons->laststate[i] ? 0 : 1);
	bf53xPFbuttons->events_sended++;
	input_sync(bf53xPFbuttons->dev);

	bf53xPFbuttons->irq_handled++;
	return IRQ_HANDLED;
}

static int bf53xPFbuttons_dev_event(struct input_dev *dev, unsigned int type,
				    unsigned int code, int value)
{
	struct bf53xPFbuttons *bf53xPFbuttons =
	    (struct bf53xPFbuttons *)dev->private;
	int i;

	switch (type) {

	case EV_LED:
#if LEDS
		for (i = 0; i < LEDS; ++i) {
			if (bf53xPFbuttons->ledcode[i] == code) {
				gpio_set_value(bf53xPFbuttons->led_gpios[i],
					       value);
				bf53xPFbuttons->events_processed++;
				return 0;
			}
		}
		break;
#endif
	case EV_SND:
#if BELLS
		for (i = 0; i < BELLS; ++i) {
			if (bf53xPFbuttons->sndcode[i] == code) {
				gpio_set_value(bf53xPFbuttons->snd_gpios[i],
					       value);
				bf53xPFbuttons->events_processed++;
				return 0;
			}
		}
#endif
		break;
	}

	return -1;
}

static void inline bf53xPFbuttons_remove_IRQ(struct bf53xPFbuttons
					     *bf53xPFbuttons)
{

	u16 i;

	for (i = 0; i < BUTTONS; i++) {
		free_irq(IRQ_PF0 + bf53xPFbuttons->btn_gpios[i],
			 bf53xPFbuttons_irq_handler);
	}

}

static int inline bf53xPFbuttons_init_IRQ(struct bf53xPFbuttons *bf53xPFbuttons)
{

	u16 i;

	for (i = 0; i < BUTTONS; i++) {
		pr_debug("bf53xPFbuttons_init_IRQ PF%d configured\n",
			 IRQ_PF0 + bf53xPFbuttons->btn_gpios[i]);
		if (request_irq
		    (IRQ_PF0 + bf53xPFbuttons->btn_gpios[i],
		     bf53xPFbuttons_irq_handler,
		     IRQF_TRIGGER_RISING | IRQF_TRIGGER_FALLING,
		     "bf53xPFbuttons", bf53xPFbuttons)) {
			/* Rollback */
			printk(KERN_WARNING
			       "bf53xPFbuttons: IRQ %d is not free. Roolback to the previos configuration\n",
			       IRQ_PF0 + i);
			bf53xPFbuttons_remove_IRQ(bf53xPFbuttons);
			return -EIO;
		}

	}

	return 0;
}

static int bf53xPFbuttons_request_gpio(unsigned short *gpios,
				       unsigned short nr_gpios)
{
	u16 i;

	for (i = 0; i < nr_gpios; i++)
		if (gpio_request(gpios[i], NULL)) {
			printk(KERN_WARNING
			       "bf53xPFbuttons: Failed to request GPIO_%d\n",
			       gpios[i]);
		} else {
			gpio_direction_output(gpios[i]);
		}

	return 0;
}

static int bf53xPFbuttons_release_gpio(unsigned short *gpios,
				       unsigned short nr_gpios)
{
	u16 i;

	for (i = 0; i < nr_gpios; i++)
		gpio_free(gpios[i]);

	return 0;
}

static int __init bf53xPFbuttons_init(void)
{
	struct bf53xPFbuttons *bf53xPFbuttons = &chip;
	int i;
	int ret = 0;

	bf53xPFbuttons->dev = input_allocate_device();

	if (!bf53xPFbuttons->dev)
		return -1;

	bf53xPFbuttons->dev->evbit[0] = 0;
#if BUTTONS
	{
		bf53xPFbuttons->dev->evbit[0] |= BIT(EV_KEY);
		bf53xPFbuttons->dev->keycode = bf53xPFbuttons->btncode;
		bf53xPFbuttons->dev->keycodesize =
		    sizeof(bf53xPFbuttons->btncode);
		bf53xPFbuttons->dev->keycodemax =
		    ARRAY_SIZE(bf53xPFbuttons_btncode);

		for (i = 0; i < BUTTONS; i++) {
			set_bit(bf53xPFbuttons->btncode[i],
				bf53xPFbuttons->dev->keybit);
		}
	}
#endif
#if LEDS
	{
		bf53xPFbuttons->dev->evbit[0] |= BIT(EV_LED);
		for (i = 0; i < LEDS; i++) {
			set_bit(bf53xPFbuttons->ledcode[i],
				bf53xPFbuttons->dev->ledbit);
		}
	}
#endif
#if BELLS
	{
		bf53xPFbuttons->dev->evbit[0] |= BIT(EV_SND);
		for (i = 0; i < BELLS; i++) {
			set_bit(bf53xPFbuttons->sndcode[i],
				bf53xPFbuttons->dev->sndbit);
		}
	}
#endif

	if (LEDS || BELLS) {
		bf53xPFbuttons->dev->event = bf53xPFbuttons_dev_event;
		bf53xPFbuttons->dev->private = bf53xPFbuttons;
	}

	sprintf(bf53xPFbuttons->name, "BF5xx PFButtons");
	sprintf(bf53xPFbuttons->phys, "pfbuttons/input0");
	bf53xPFbuttons->dev->name = bf53xPFbuttons->name;
	bf53xPFbuttons->dev->phys = bf53xPFbuttons->phys;
	bf53xPFbuttons->dev->id.bustype = BUS_HOST;
	bf53xPFbuttons->dev->id.vendor = 0x0001;
	bf53xPFbuttons->dev->id.product = 0x0001;
	bf53xPFbuttons->dev->id.version = 0x0100;

	input_register_device(bf53xPFbuttons->dev);

	printk(KERN_INFO "input: %s at %s\n", bf53xPFbuttons->name,
	       bf53xPFbuttons->dev->phys);

	create_proc_read_entry("driver/bf53xPFbuttons", 0, 0,
			       bf53xPFbuttons_read_proc, bf53xPFbuttons);

#if LEDS
	bf53xPFbuttons_request_gpio(bf53xPFbuttons->led_gpios, LEDS);
#endif

#if BELLS
	bf53xPFbuttons_request_gpio(bf53xPFbuttons->snd_gpios, BELLS);
#endif

#if BUTTONS

	ret = bf53xPFbuttons_init_IRQ(bf53xPFbuttons);

#endif	 /*BUTTONS*/
	    pr_debug("bf53xPFbuttons_init IRQ restored\n");
	return ret;
}

void __exit bf53xPFbuttons_exit(void)
{
	struct bf53xPFbuttons *bf53xPFbuttons = &chip;

#if LEDS
	bf53xPFbuttons_release_gpio(bf53xPFbuttons->led_gpios, LEDS);
#endif

#if BELLS
	bf53xPFbuttons_release_gpio(bf53xPFbuttons->snd_gpios, BELLS);
#endif

	bf53xPFbuttons_remove_IRQ(bf53xPFbuttons);
	input_free_device(bf53xPFbuttons->dev);
	remove_proc_entry("driver/bf53xPFbuttons", NULL);
}

module_init(bf53xPFbuttons_init);
module_exit(bf53xPFbuttons_exit);

/*
 * Info exported via "/proc/driver/bf53xPFbuttons".
 * TODO: convert this to debugfs
 */
static int bf53xPFbuttons_proc_output(struct bf53xPFbuttons *bf53xPFbuttons,
				      char *buf)
{
	char *p;
	u16 i;
	p = buf;

	p += sprintf(p, "PIN\t:DATA DIR INEN EDGE BOTH POLAR MASKA MASKB\n");
	p += sprintf(p, "   \t:H/L  O/I D/E  E/L  B/S   L/H   S/C   S/C\n");
	for (i = 0; i < MAX_BLACKFIN_GPIOS; i++)
		p += sprintf(p,
			     "PF%d\t: %d....%d....%d....%d....%d....%d.....%d.....%d \n",
			     i, get_gpio_data(i), get_gpio_dir(i),
			     get_gpio_inen(i), get_gpio_edge(i),
			     get_gpio_both(i), get_gpio_polar(i),
			     get_gpio_maska(i), get_gpio_maskb(i));
	p += sprintf(p,
		     "Interrupt: %ld\nEvents sended: %ld\nEvents processed: %ld\n",
		     bf53xPFbuttons->irq_handled, bf53xPFbuttons->events_sended,
		     bf53xPFbuttons->events_processed);

	return p - buf;
}

static int bf53xPFbuttons_read_proc(char *page, char **start, off_t off,
				    int count, int *eof, void *data)
{
	struct bf53xPFbuttons *bf53xPFbuttons = (struct bf53xPFbuttons *)data;
	int len = bf53xPFbuttons_proc_output(bf53xPFbuttons, page);
	if (len <= off + count)
		*eof = 1;
	*start = page + off;
	len -= off;
	if (len > count)
		len = count;
	if (len < 0)
		len = 0;
	return len;
}
