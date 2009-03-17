/**
 *   @ingroup hal
 *   @file
 *
 *   Adeos-based Real-Time Abstraction Layer for x86.
 *
 *   Copyright &copy; 2005 Gilles Chanteperdrix.
 *
 *   Xenomai is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License as
 *   published by the Free Software Foundation, Inc., 675 Mass Ave,
 *   Cambridge MA 02139, USA; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   Xenomai is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 *   02111-1307, USA.
 */

/**
 * @addtogroup hal
 *
 * Generic NMI watchdog services.
 *
 *@{*/

#include <linux/version.h>
#include <linux/module.h>
#include <asm/system.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>
#include <asm/xenomai/hal.h>
#ifdef CONFIG_PROC_FS
#include <linux/proc_fs.h>
#endif /* CONFIG_PROC_FS */

unsigned long rthal_maxlat_tsc;

unsigned rthal_maxlat_us = CONFIG_XENO_HW_NMI_DEBUG_LATENCY_MAX;

void rthal_nmi_init(void (*emergency) (struct pt_regs *))
{
    rthal_maxlat_tsc = rthal_llimd(rthal_maxlat_us * 1000ULL,
                                   RTHAL_NMICLK_FREQ, 1000000000);
    rthal_nmi_release();

    if (rthal_nmi_request(emergency))
        printk("Xenomai: NMI watchdog not available.\n");
    else
        printk("Xenomai: NMI watchdog started (threshold=%u us).\n",
               rthal_maxlat_us);
}

#ifdef CONFIG_PROC_FS

#include <linux/ctype.h>

static int maxlat_read_proc(char *page,
                            char **start,
                            off_t off, int count, int *eof, void *data)
{
    int len;

    len = sprintf(page, "%u\n", rthal_maxlat_us);
    len -= off;
    if (len <= off + count)
        *eof = 1;
    *start = page + off;
    if (len > count)
        len = count;
    if (len < 0)
        len = 0;

    return len;
}

static int maxlat_write_proc(struct file *file,
                             const char __user * buffer,
                             unsigned long count, void *data)
{
    char *end, buf[16];
    int val;
    int n;

    n = (count > sizeof(buf) - 1) ? sizeof(buf) - 1 : count;

    if (copy_from_user(buf, buffer, n))
        return -EFAULT;

    buf[n] = '\0';
    val = simple_strtol(buf, &end, 0);

    if (((*end != '\0') && !isspace(*end)) || (val < 0))
        return -EINVAL;

    rthal_maxlat_us = val;
    rthal_maxlat_tsc = rthal_llimd(rthal_maxlat_us * 1000ULL,
                                   RTHAL_NMICLK_FREQ, 1000000000);

    return count;
}

void rthal_nmi_proc_register(void)
{
    __rthal_add_proc_leaf("nmi_maxlat",
                          &maxlat_read_proc,
                          &maxlat_write_proc, NULL, rthal_proc_root);
}

void rthal_nmi_proc_unregister(void)
{
    remove_proc_entry("nmi_maxlat", rthal_proc_root);
}

#endif /* CONFIG_PROC_FS */

/*@}*/

EXPORT_SYMBOL(rthal_maxlat_tsc);
EXPORT_SYMBOL(rthal_maxlat_us);
