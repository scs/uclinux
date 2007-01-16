/*
 * File:         timer_test.c
 * Based on:
 * Author:       Mike Frysinger
 *
 * Created:      Jan 2007
 * Description:  Example module for playing with kernel timers
 *
 * Rev:          $Id: timer_test.c 3342 2006-08-09 20:32:43Z vapier $
 *
 * Modified:
 *               Copyright 2007 Analog Devices Inc.
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
#include <linux/timer.h>
#include <linux/types.h>

#define PRINTK(x...) printk(KERN_DEBUG "timer_test: " x)

static struct timer_list timer_test;

static ulong delay = 5;
module_param(delay, ulong, 0);
MODULE_PARM_DESC(delay, "number of seconds to delay before firing; default = 5 seconds");

void timer_test_func(unsigned long data)
{
	PRINTK("timer_test_func: here i am with my data '%li'!\n", data);
}

static int __init timer_test_init(void)
{
	int ret;
	PRINTK("timer module init\n");
	setup_timer(&timer_test, timer_test_func, 1234);
	PRINTK("arming timer to fire %lu seconds from now\n", delay);
	ret = mod_timer(&timer_test, jiffies + msecs_to_jiffies(delay * 1000));
	PRINTK("mod_timer() returned %i\n", ret);
	return 0;
}

static void __exit timer_test_cleanup(void)
{
	PRINTK("timer module cleanup\n");
	if (del_timer(&timer_test))
		PRINTK("timer is still in use!\n");
}

module_init(timer_test_init);
module_exit(timer_test_cleanup);

MODULE_DESCRIPTION("example kernel timer driver");
MODULE_LICENSE("GPL");
