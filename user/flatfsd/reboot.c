/* Borrowed from busybox */

#include <stdio.h>
#include <signal.h>
#include <syslog.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <paths.h>
#include <config/autoconf.h>
#include <linux/version.h>
#include <linux/autoconf.h>
#ifdef CONFIG_LEDMAN
#include <linux/ledman.h>
#include <sys/ioctl.h>
#endif

#if (__GNU_LIBRARY__ > 5) || defined(__dietlibc__) 
  #include <sys/reboot.h>
  #define init_reboot(magic) reboot(magic)
#else
  #define init_reboot(magic) reboot(0xfee1dead, 672274793, magic)
#endif

#ifndef RB_AUTOBOOT
static const int RB_AUTOBOOT = 0x01234567;
#endif
#ifndef RB_HALT_SYSTEM
static const int RB_HALT_SYSTEM = 0xcdef0123;
#endif

static int shutdown_now(int rb_which)
{
	/**
	 * Write the current date/time to the RTC
	 */
#ifdef CONFIG_USER_HWCLOCK_HWCLOCK
	system("hwclock --systohc --utc");
#elif defined(CONFIG_USER_RTC_M41T11) || defined (CONFIG_USER_RTC_DS1302)
	system("rtc -w");
#else
	/* We need to sleep for just a little to allow the CGI's to finish
	 * The RTC commands above already take a little while, so 
	 * only sleep if we don't have any RTC command to run
	 */
	sleep(1);
#endif

	/* Don't kill ourself */
	signal(SIGTERM,SIG_IGN);
	signal(SIGHUP,SIG_IGN);
	setpgrp();

	sync();

#ifdef CONFIG_USER_INIT_INIT
	/* Stop init from respawning daemons */
	kill(1, SIGTSTP);
#endif

	/* Send signals to every process _except_ pid 1 */
	kill(-1, SIGTERM);
	sleep(1);
	sync();

	kill(-1, SIGKILL);
	sleep(1);

#if defined(CONFIG_USER_MOUNT_UMOUNT) || defined (CONFIG_USER_BUSYBOX_UMOUNT)
	system("/bin/umount -a -r");
#endif

	sync();
#if !defined(__UC_LIBC__) && (LINUX_VERSION_CODE <= KERNEL_VERSION(2,2,11))
{
	extern int bdflush(int func, long data);
	/* bdflush, kupdate not needed for kernels >2.2.11 */
	bdflush(1, 0);
	sync();
}
#endif

#ifdef CONFIG_LEDMAN
	/* Turn off all LEDs so it is clear that we are shut down */
	ledman_cmd(LEDMAN_CMD_OFF, LEDMAN_ALL);
#endif
#ifdef CONFIG_SNAPDOG
	/* Turn off user servicing of the watchdog */
	/*write(open("/dev/watchdog", O_WRONLY), "V", 1);*/
	write(open("/dev/watchdog", O_WRONLY), "V", 1);
#endif

	init_reboot(rb_which);

	return -1; /* Shrug */
}

int reboot_now(void)
{
	return shutdown_now(RB_AUTOBOOT);
}

int halt_now(void)
{
	return shutdown_now(RB_HALT_SYSTEM);
}
