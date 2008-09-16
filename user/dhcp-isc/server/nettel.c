/* nettel.c -- NETtel specific functions for the DHCP server */

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <signal.h>
#include <sys/types.h>
#include <config/autoconf.h>
#include "dhcpd.h"
#include "nettel.h"

#ifdef CONFIG_USER_FLATFSD_FLATFSD

#if defined(CONFIG_USER_BUSYBOX_REBOOT) && !defined(__uClinux__)
#define	REBOOT_BIN				"/sbin/reboot"
#elif defined(CONFIG_USER_BUSYBOX_REBOOT) || defined(CONFIG_USER_SASH_REBOOT)
#define	REBOOT_BIN				"/bin/reboot"
#else
#error No way to reboot
#endif

static void rebootDevice(void)
{
	if (system("exec flatfsd -b") == -1) {
		/* If, for some reason, there is no flatfsd, or the kill fails,
		 * we will just go ahead and reboot
		 */
		system(REBOOT_BIN);
	}
	exit(10);
}

int commitChanges(void)
{
	static TIME commit_time;
	static int initted = 0;

	if (!initted) {
		initted = 1;
		commit_time = cur_time;
	}

	if (cur_time - commit_time > 3600) {
		commit_time = cur_time;
		return (system("exec flatfsd -s") == -1 ? -1 : 0);
	}
	return 0;
}

void config_exhausted(void)
{
	syslog(LOG_EMERG,
		"Configuration filesystem full while writing leases -- rebooting\n");
	sleep(5);
	rebootDevice();
}

#endif /* CONFIG_USER_FLATFSD_FLATFSD */
