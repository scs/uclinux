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

#include <linux/module.h>
#include <linux/err.h>
#include <asm/blackfin.h>
#include <asm/gpio.h>

#if 1
#define assert(expr) do {} while(0)
#else
#define assert(expr) 						\
	if (!(expr)) {						\
	printk(KERN_INFO "Assertion failed! %s, %s, %s, line=%d \n",	\
	#expr, __FILE__,__FUNCTION__,__LINE__); 		\
	}
#endif


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


inline int check_gpio(unsigned short gpio)
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

# if defined(BF537_FAMILY) && (defined(CONFIG_BFIN_MAC) || defined(CONFIG_BFIN_MAC_MODULE))
		reserved_map[PORT_H] = 0xFFFF;
#endif

	return 0;
}

arch_initcall(bfin_gpio_init);


/***********************************************************
*
* FUNCTIONS: Blackfin General Purpose Ports Access Functions
*
* INPUTS/OUTPUTS:
* gpio - GPIO Number between 0 and MAX_BLACKFIN_GPIOS
* 
*
* DESCRIPTION: These functions abstract direct register access
*              to Blackfin processor General Purpose 
*              Ports Regsiters 
*              
* CAUTION: These functions do not belong to the GPIO Driver API
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/

/* Set a specific bit */

#define SET_GPIO(name) void \
set_gpio_ ## name (unsigned short gpio, unsigned short arg) \
{ \
  unsigned long flags;\
  assert(reserved_map[gpio_bank(gpio)] & gpio_bit(gpio));\
  local_irq_save(flags);\
	if(arg) {\
	  gpio_bankb[gpio_bank(gpio)]->name |= gpio_bit(gpio);\
		} else {\
	  gpio_bankb[gpio_bank(gpio)]->name &= ~gpio_bit(gpio);\
	}\
  local_irq_restore(flags);\
} \
EXPORT_SYMBOL(set_gpio_ ## name);

SET_GPIO(dir)
SET_GPIO(inen)
SET_GPIO(polar)
SET_GPIO(edge)
SET_GPIO(both)


#define SET_GPIO_SC(name) void \
set_gpio_ ## name (unsigned short gpio, unsigned short arg) \
{ \
  assert(reserved_map[gpio_bank(gpio)] & gpio_bit(gpio));\
	if(arg) {\
	  gpio_bankb[gpio_bank(gpio)]->name ## _set |= gpio_bit(gpio);\
		} else {\
	  gpio_bankb[gpio_bank(gpio)]->name ## _clear |= gpio_bit(gpio);\
	}\
} \
EXPORT_SYMBOL(set_gpio_ ## name);

SET_GPIO_SC(data)
SET_GPIO_SC(maska)
SET_GPIO_SC(maskb)


void set_gpio_toggle(unsigned short gpio)
{

  assert(reserved_map[gpio_bank(gpio)] & gpio_bit(gpio));

	  gpio_bankb[gpio_bank(gpio)]->toggle = gpio_bit(gpio);

}
EXPORT_SYMBOL(set_gpio_toggle);

/* Get a specific bit */

#define GET_GPIO(name) unsigned short  \
get_gpio_ ## name (unsigned short gpio) \
{ \
	return (0x01 & (gpio_bankb[gpio_bank(gpio)]->name >> gpio_sub_n(gpio)));\
} \
EXPORT_SYMBOL(get_gpio_ ## name);

GET_GPIO(dir)
GET_GPIO(inen)
GET_GPIO(polar)
GET_GPIO(edge)
GET_GPIO(both)
GET_GPIO(maska)
GET_GPIO(maskb)
GET_GPIO(data)

/*Get current PORT date (16-bit word)*/

#define GET_GPIO_P(name) unsigned short  \
get_gpiop_ ## name (unsigned short gpio) \
{ \
	return (gpio_bankb[gpio_bank(gpio)]->name);\
} \
EXPORT_SYMBOL(get_gpiop_ ## name);

GET_GPIO_P(dir)
GET_GPIO_P(inen)
GET_GPIO_P(polar)
GET_GPIO_P(edge)
GET_GPIO_P(both)
GET_GPIO_P(maska)
GET_GPIO_P(maskb)
GET_GPIO_P(data)


/***********************************************************
*
* FUNCTIONS: Blackfin GPIO Driver 
*
* INPUTS/OUTPUTS:
* gpio - GPIO Number between 0 and MAX_BLACKFIN_GPIOS
* 
*
* DESCRIPTION: Blackfin GPIO Driver API
*               
* CAUTION: 
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/

int gpio_request(unsigned short gpio, const char *label)
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
 
	port_setup(gpio, GPIO_USAGE);
	  
  return 0;

}


void gpio_free(unsigned short gpio)
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

	default_gpio(gpio);

	reserved_map[gpio_bank(gpio)] &= ~gpio_bit(gpio);

	local_irq_restore(flags);

}


void gpio_direction_input(unsigned short gpio)
{
  unsigned long flags;

  assert(reserved_map[gpio_bank(gpio)] & gpio_bit(gpio));

  local_irq_save(flags);
	  gpio_bankb[gpio_bank(gpio)]->dir &= ~gpio_bit(gpio);
	  gpio_bankb[gpio_bank(gpio)]->inen |= gpio_bit(gpio);
  local_irq_restore(flags);
}


void gpio_direction_output(unsigned short gpio)
{
  unsigned long flags;

  assert(reserved_map[gpio_bank(gpio)] & gpio_bit(gpio));

  local_irq_save(flags);
	  gpio_bankb[gpio_bank(gpio)]->inen &= ~gpio_bit(gpio);
	  gpio_bankb[gpio_bank(gpio)]->dir |= gpio_bit(gpio);
  local_irq_restore(flags);
}

EXPORT_SYMBOL(gpio_request);
EXPORT_SYMBOL(gpio_free);
EXPORT_SYMBOL(gpio_direction_input);
EXPORT_SYMBOL(gpio_direction_output);
