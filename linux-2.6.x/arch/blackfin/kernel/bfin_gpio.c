/*
 * File:         arch/blackfin/kernel/bfin_gpio.c
 * Based on:
 * Author:	 Michael Hennerich (hennerich@blackfin.uclinux.org)
 *
 * Created:
 * Description:
 *
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright 2004-2006 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
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
 */



/*
*  Number     BF537/6/4    BF561    BF533/2/1
*
*  GPIO_0       PF0         PF0        PF0
*  GPIO_1       PF1         PF1        PF1
*  GPIO_2       PF2         PF2        PF2
*  GPIO_3       PF3         PF3        PF3
*  GPIO_4       PF4         PF4        PF4
*  GPIO_5       PF5         PF5        PF5
*  GPIO_6       PF6         PF6        PF6
*  GPIO_7       PF7         PF7        PF7
*  GPIO_8       PF8         PF8        PF8
*  GPIO_9       PF9         PF9        PF9
*  GPIO_10      PF10        PF10       PF10
*  GPIO_11      PF11        PF11       PF11
*  GPIO_12      PF12        PF12       PF12
*  GPIO_13      PF13        PF13       PF13
*  GPIO_14      PF14        PF14       PF14
*  GPIO_15      PF15        PF15       PF15
*  GPIO_16      PG0         PF16
*  GPIO_17      PG1         PF17
*  GPIO_18      PG2         PF18
*  GPIO_19      PG3         PF19
*  GPIO_20      PG4         PF20
*  GPIO_21      PG5         PF21
*  GPIO_22      PG6         PF22
*  GPIO_23      PG7         PF23
*  GPIO_24      PG8         PF24
*  GPIO_25      PG9         PF25
*  GPIO_26      PG10        PF26
*  GPIO_27      PG11        PF27
*  GPIO_28      PG12        PF28
*  GPIO_29      PG13        PF29
*  GPIO_30      PG14        PF30
*  GPIO_31      PG15        PF31
*  GPIO_32      PH0         PF32
*  GPIO_33      PH1         PF33
*  GPIO_34      PH2         PF34
*  GPIO_35      PH3         PF35
*  GPIO_36      PH4         PF36
*  GPIO_37      PH5         PF37
*  GPIO_38      PH6         PF38
*  GPIO_39      PH7         PF39
*  GPIO_40      PH8         PF40
*  GPIO_41      PH9         PF41
*  GPIO_42      PH10        PF42
*  GPIO_43      PH11        PF43
*  GPIO_44      PH12        PF44
*  GPIO_45      PH13        PF45
*  GPIO_46      PH14        PF46
*  GPIO_47      PH15        PF47
*/

#include <linux/config.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/ptrace.h>
#include <linux/sysdev.h>
#include <linux/err.h>
#include <linux/clk.h>

#include <asm/irq.h>
#include <asm/io.h>
#include <asm/blackfin.h>
#include <asm/gpio.h>

#undef BFIN_gpioDEBUG

#ifdef BFIN_gpioDEBUG
#define assert(expr) do {} while(0)
#else
#define assert(expr) 						\
	if (!(expr)) {						\
	printk(KERN_INFO "Assertion failed! %s, %s, %s, line=%d \n",	\
	#expr, __FILE__,__FUNCTION__,__LINE__); 		\
	}
#endif

#define gpio_bank(x) (x >> 4)
#define gpio_bit(x)  (1<<(x & 0xFF))
#define gpio_sub_n(x) (x & 0xFF)


#ifdef BF533_FAMILY
static struct gpio_port_t *gpio_bankb[gpio_bank(MAX_BLACKFIN_GPIOS)] = {
	(struct gpio_port_t *) FIO_FLAG_D,
};
#endif

#ifdef BF537_FAMILY
static struct gpio_port_t *gpio_bankb[gpio_bank(MAX_BLACKFIN_GPIOS)] = {
	(struct gpio_port_t *) PORTFIO,
	(struct gpio_port_t *) PORTGIO,
	(struct gpio_port_t *) PORTHIO,
};

static unsigned short *port_fer[gpio_bank(MAX_BLACKFIN_GPIOS)] = {
	(unsigned short *) PORTF_FER,
	(unsigned short *) PORTG_FER,
	(unsigned short *) PORTH_FER,
};
#endif

#ifdef BF561_FAMILY
static struct gpio_port_t *gpio_bankb[gpio_bank(MAX_BLACKFIN_GPIOS)] = {
	(struct gpio_port_t *) FIO0_FLAG_D,
	(struct gpio_port_t *) FIO1_FLAG_D,
	(struct gpio_port_t *) FIO2_FLAG_D,
};
#endif


static unsigned short reserved_map[gpio_bank(MAX_BLACKFIN_GPIOS)];


int check_gpio(unsigned short gpio)
{
	if(gpio>MAX_BLACKFIN_GPIOS)
		return -EINVAL;
  return 0;
}

#ifdef BF537_FAMILY
void port_setup(unsigned short gpio, unsigned short usage)
{

if (usage == GPIO_USAGE) {
  if (*port_fer[gpio_bank(gpio)] & gpio_bit(gpio))
	printk(KERN_WARNING "bfin-gpio: Possible Conflict with Peripheral"
	 "usage and GPIO %d detected!\n", gpio);

	*port_fer[gpio_bank(gpio)] &= ~gpio_bit(gpio);
	__builtin_bfin_ssync();
 } else {

	*port_fer[gpio_bank(gpio)] |= gpio_bit(gpio);
	__builtin_bfin_ssync();

 }
}
#else
#define port_setup(...)  do { } while (0)
#endif


void default_gpio(unsigned short gpio)
{
  unsigned short bank,bitmask;

  bank = gpio_bank(gpio);
  bitmask = gpio_bit(gpio);

	gpio_bankb[bank]->maska_clear = bitmask;
	gpio_bankb[bank]->maskb_clear = bitmask;
	__builtin_bfin_ssync();
	gpio_bankb[bank]->inen &= ~bitmask;
	gpio_bankb[bank]->dir &= ~bitmask;
	gpio_bankb[bank]->polar &= ~bitmask;
	gpio_bankb[bank]->both &= ~bitmask;
	gpio_bankb[bank]->edge &= ~bitmask;
}


int __init bfin_gpio_init(void)
{
	int i;

	printk(KERN_INFO "Blackfin GPIO Controller\n");

	for (i = 0; i < MAX_BLACKFIN_GPIOS; i+=16) {
		reserved_map[gpio_bank(i)] = 0;
	}

#ifdef CONFIG_BFIN_MAC
		reserved_map[PORT_H] = 0xFFFF;
#endif

	return 0;
}

arch_initcall(bfin_gpio_init);

void set_gpio_dir(unsigned short gpio, unsigned short arg)
{

  unsigned long flags;

  assert(reserved_map[gpio_bank(gpio)] & gpio_bit(gpio));

  local_irq_save(flags);
	if(arg) {
	  gpio_bankb[gpio_bank(gpio)]->dir |= gpio_bit(gpio);
		} else {
	  gpio_bankb[gpio_bank(gpio)]->dir &= ~gpio_bit(gpio);
	}

  local_irq_restore(flags);


}

void set_gpio_inen(unsigned short gpio, unsigned short arg)
{

  unsigned long flags;

  assert(reserved_map[gpio_bank(gpio)] & gpio_bit(gpio));

  local_irq_save(flags);

	if(arg) {
	  gpio_bankb[gpio_bank(gpio)]->inen |= gpio_bit(gpio);
		} else {
	  gpio_bankb[gpio_bank(gpio)]->inen &= ~gpio_bit(gpio);
	}

  local_irq_restore(flags);


}

void set_gpio_polar(unsigned short gpio, unsigned short arg)
{

  unsigned long flags;

  assert(reserved_map[gpio_bank(gpio)] & gpio_bit(gpio));

  local_irq_save(flags);

	if(arg) {
	  gpio_bankb[gpio_bank(gpio)]->polar |= gpio_bit(gpio);
		} else {
	  gpio_bankb[gpio_bank(gpio)]->polar &= ~gpio_bit(gpio);
	}

  local_irq_restore(flags);

}

void set_gpio_edge(unsigned short gpio, unsigned short arg)
{

  unsigned long flags;

  assert(reserved_map[gpio_bank(gpio)] & gpio_bit(gpio));

  local_irq_save(flags);

	if(arg) {
	  gpio_bankb[gpio_bank(gpio)]->edge |= gpio_bit(gpio);
		} else {
	  gpio_bankb[gpio_bank(gpio)]->edge &= ~gpio_bit(gpio);
	}

  local_irq_restore(flags);

}

void set_gpio_both(unsigned short gpio, unsigned short arg)
{

  unsigned long flags;

  assert(reserved_map[gpio_bank(gpio)] & gpio_bit(gpio));

  local_irq_save(flags);

	if(arg) {
	  gpio_bankb[gpio_bank(gpio)]->both |= gpio_bit(gpio);
		} else {
	  gpio_bankb[gpio_bank(gpio)]->both &= ~gpio_bit(gpio);
	}

  local_irq_restore(flags);

}

void set_gpio_data(unsigned short gpio, unsigned short arg)
{

  assert(reserved_map[gpio_bank(gpio)] & gpio_bit(gpio));

	if(arg) {
	  gpio_bankb[gpio_bank(gpio)]->set = gpio_bit(gpio);
		} else {
	  gpio_bankb[gpio_bank(gpio)]->clear = gpio_bit(gpio);
	}
}


void set_gpio_maska(unsigned short gpio, unsigned short arg)
{

  assert(reserved_map[gpio_bank(gpio)] & gpio_bit(gpio));

	if(arg) {
	  gpio_bankb[gpio_bank(gpio)]->maska_set = gpio_bit(gpio);
		} else {
	  gpio_bankb[gpio_bank(gpio)]->maska_clear = gpio_bit(gpio);
	}
}

void set_gpio_maskb(unsigned short gpio, unsigned short arg)
{

  assert(reserved_map[gpio_bank(gpio)] & gpio_bit(gpio));

	if(arg) {
	  gpio_bankb[gpio_bank(gpio)]->maskb_set = gpio_bit(gpio);
		} else {
	  gpio_bankb[gpio_bank(gpio)]->maskb_clear = gpio_bit(gpio);
	}
}

void set_gpio_toggle(unsigned short gpio)
{

  assert(reserved_map[gpio_bank(gpio)] & gpio_bit(gpio));

	  gpio_bankb[gpio_bank(gpio)]->toggle = gpio_bit(gpio);

}


unsigned short get_gpio_dir(unsigned short gpio)
{

	return (0x01 & (gpio_bankb[gpio_bank(gpio)]->dir >> gpio_sub_n(gpio)));

}

unsigned short get_gpio_inen(unsigned short gpio)
{

	return (0x01 & (gpio_bankb[gpio_bank(gpio)]->inen >> gpio_sub_n(gpio)));

}

unsigned short get_gpio_polar(unsigned short gpio)
{

	return (0x01 & (gpio_bankb[gpio_bank(gpio)]->polar >> gpio_sub_n(gpio)));

}

unsigned short get_gpio_edge(unsigned short gpio)
{

	return (0x01 & (gpio_bankb[gpio_bank(gpio)]->edge >> gpio_sub_n(gpio)));

}

unsigned short get_gpio_both(unsigned short gpio)
{

	return (0x01 & (gpio_bankb[gpio_bank(gpio)]->both >> gpio_sub_n(gpio)));

}

unsigned short get_gpio_maska(unsigned short gpio)
{

	return (0x01 & (gpio_bankb[gpio_bank(gpio)]->maska >> gpio_sub_n(gpio)));

}

unsigned short get_gpio_maskb(unsigned short gpio)
{

	return (0x01 & (gpio_bankb[gpio_bank(gpio)]->maskb >> gpio_sub_n(gpio)));

}

unsigned short get_gpio_data(unsigned short gpio)
{
	return (0x01 & (gpio_bankb[gpio_bank(gpio)]->data >> gpio_sub_n(gpio)));

}


unsigned short get_gpiop_dir(unsigned short gpio)
{

	return (gpio_bankb[gpio_bank(gpio)]->dir);

}

unsigned short get_gpiop_inen(unsigned short gpio)
{

	return (gpio_bankb[gpio_bank(gpio)]->inen);

}

unsigned short get_gpiop_polar(unsigned short gpio)
{

	return (gpio_bankb[gpio_bank(gpio)]->polar);

}

unsigned short get_gpiop_edge(unsigned short gpio)
{

	return (gpio_bankb[gpio_bank(gpio)]->edge);

}

unsigned short get_gpiop_both(unsigned short gpio)
{

	return (gpio_bankb[gpio_bank(gpio)]->both);

}

unsigned short get_gpiop_maska(unsigned short gpio)
{

	return (gpio_bankb[gpio_bank(gpio)]->maska);

}

unsigned short get_gpiop_maskb(unsigned short gpio)
{

	return (gpio_bankb[gpio_bank(gpio)]->maskb);

}

unsigned short get_gpiop_data(unsigned short gpio)
{
	return (gpio_bankb[gpio_bank(gpio)]->data);

}

int request_gpio(unsigned short gpio,unsigned short opt)
{
	unsigned long flags;

	if (check_gpio(gpio) < 0)
		return -EINVAL;

	local_irq_save(flags);

	if (unlikely(reserved_map[gpio_bank(gpio)] & gpio_bit(gpio))) {
		printk(KERN_ERR "bfin-gpio: GPIO %d is already reserved!\n", gpio);
		dump_stack();
		local_irq_restore(flags);
		
		return -EBUSY;
	}
	reserved_map[gpio_bank(gpio)] |= gpio_bit(gpio);

	local_irq_restore(flags);

	if(opt & REQUEST_ALT_FUNCT) {
	  port_setup(gpio, PERIPHERAL_USAGE);
	} else { 
	  default_gpio(gpio);
	  port_setup(gpio, GPIO_USAGE);
	  
		if(opt & GPIO_INV_POLAR)
		   set_gpio_polar(gpio, GPIO_POLAR_AL_FE);
		  
		if (opt & GPIO_INPUT) {
			set_gpio_inen(gpio, GPIO_INPUT_ENABLE);
		} else 
		if (opt & GPIO_OUTPUT) {
			set_gpio_dir(gpio, GPIO_DIR_OUTPUT);
		}
	}

  return 0;

}


void free_gpio(unsigned short gpio)
{
	unsigned long flags;

	if (check_gpio(gpio) < 0)
		return;


	local_irq_save(flags);


	if (unlikely(!(reserved_map[gpio_bank(gpio)] & gpio_bit(gpio)))) {
		printk(KERN_ERR "bfin-gpio: GPIO %d wasn't reserved!\n", gpio);
		dump_stack();
		local_irq_restore(flags);
		return;
	}

	port_setup(gpio, GPIO_USAGE);
	default_gpio(gpio);

	reserved_map[gpio_bank(gpio)] &= ~gpio_bit(gpio);

	local_irq_restore(flags);

}

EXPORT_SYMBOL(request_gpio);
EXPORT_SYMBOL(free_gpio);

EXPORT_SYMBOL(set_gpio_dir);
EXPORT_SYMBOL(set_gpio_inen);
EXPORT_SYMBOL(set_gpio_polar);
EXPORT_SYMBOL(set_gpio_edge);
EXPORT_SYMBOL(set_gpio_both);
EXPORT_SYMBOL(set_gpio_data);
EXPORT_SYMBOL(set_gpio_toggle);
EXPORT_SYMBOL(set_gpio_maska);
EXPORT_SYMBOL(set_gpio_maskb);
EXPORT_SYMBOL(get_gpio_dir);
EXPORT_SYMBOL(get_gpio_inen);
EXPORT_SYMBOL(get_gpio_polar);
EXPORT_SYMBOL(get_gpio_edge);
EXPORT_SYMBOL(get_gpio_both);
EXPORT_SYMBOL(get_gpio_maska);
EXPORT_SYMBOL(get_gpio_maskb);
EXPORT_SYMBOL(get_gpio_data);

EXPORT_SYMBOL(get_gpiop_dir);
EXPORT_SYMBOL(get_gpiop_inen);
EXPORT_SYMBOL(get_gpiop_polar);
EXPORT_SYMBOL(get_gpiop_edge);
EXPORT_SYMBOL(get_gpiop_both);
EXPORT_SYMBOL(get_gpiop_maska);
EXPORT_SYMBOL(get_gpiop_maskb);
EXPORT_SYMBOL(get_gpiop_data);
