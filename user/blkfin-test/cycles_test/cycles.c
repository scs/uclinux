/*
 * File:         cycles.c
 * Based on:
 * Author:       Mike Frysinger
 *
 * Created:      Aug 2006
 * Description:  Example module for playing with the cycle counters
 *
 * Rev:          $Id: cycles.c 3342 2006-08-09 20:32:43Z vapier $
 *
 * Modified:
 *               Copyright 2006 Analog Devices Inc.
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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/delay.h>

#define PRINTK(x...) printk(KERN_DEBUG "cycles: " x);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mike Frysinger");
MODULE_DESCRIPTION("Example Blackfin cycles code");

/*
 * Return the 64bit cycle counter
 */
static inline unsigned long long cycles_get(void)
{
	unsigned long ret_high, ret_low;
	__asm__(
		"%0 = CYCLES;"
		"%1 = CYCLES2;"
		: "=d" (ret_low), "=d" (ret_high)
	);
	return ((unsigned long long)ret_high << 32) + ret_low;
}

/*
 * Reset the 64bit cycle counter to 0
 */
static inline void cycles_clear(void)
{
	__asm__(
		"R1 = 0;"
		"CYCLES = R1;"
		"CYCLES2 = R1;"
		: : : "R1"
	);
}

/*
 * Turn off the cycle counter completely
 */
static inline void cycles_turn_off(void)
{
	__asm__(
		"R1 = SYSCFG;"
		"BITCLR(R1,1);"
		"SYSCFG = R1;"
		"CSYNC;"
		: : : "R1"
	);
}

/*
 * Turn on the cycle counter
 */
static inline void cycles_turn_on(void)
{
	__asm__(
		"R1 = SYSCFG;"
		"BITSET(R1,1);"
		"SYSCFG = R1;"
		"CSYNC;"
		: : : "R1"
	);
}

/*
 * Some cheesy example code
 */
static int __init cycles_module_init(void)
{
	int cnt;

	PRINTK("turned off:\n");
	cycles_turn_off();
	cycles_clear();
	for (cnt=0; cnt<10; ++cnt) {
		mdelay(100);
		PRINTK(" %llu\n", cycles_get());
	}

	PRINTK("turned on:\n");
	cycles_turn_on();
	for (cnt=0; cnt<10; ++cnt) {
		mdelay(100);
		PRINTK(" %llu\n", cycles_get());
	}

	return 0;
}
module_init(cycles_module_init);

/*
 * Need this in order to unload the module
 */
static void __exit cycles_module_cleanup(void)
{
	return;
}
module_exit(cycles_module_cleanup);
