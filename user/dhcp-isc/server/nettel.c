/* nettel.c -- NETtel specific functions for the DHCP server */

#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <signal.h>
#include <sys/types.h>
#include <config/autoconf.h>
#include "nettel.h"

#ifdef CONFIG_USER_FLATFSD_FLATFSD
static const char flatfsd_pidfile[] = "/var/run/flatfsd.pid";

#if defined(CONFIG_USER_BUSYBOX_REBOOT) && !defined(CONFIG_UCLINUX)
#define	REBOOT_BIN				"/sbin/reboot"
#elif defined(CONFIG_USER_BUSYBOX_REBOOT) || defined(CONFIG_USER_SASH_REBOOT)
#define	REBOOT_BIN				"/bin/reboot"
#else
#error No way to reboot
#endif

static int killProcess(const char *filename, int sig)
{
        char value[16];
        pid_t pid;
        FILE *in;

        /* get the pid of flatfsd */
        if ((in = fopen(filename, "r")) == NULL) {
                return -1;
        }

        if (fread(value, 1, sizeof(value), in) <= 0) {
                fclose(in);
                return -1;
        }
        fclose(in);

        pid = atoi(value);

        if (pid == 0 || kill(pid, sig) == -1) {
                return -1;
        }
        return 0;
}

static void rebootDevice(void)
{
        if (killProcess("/var/run/flatfsd.pid", SIGHUP) != 0) {
                /* If, for some reason, there is no flatfsd, or the kill fails,
                 * we will just go ahead and reboot
                 */
                system(REBOOT_BIN);
        }
        exit(10);
}

int commitChanges(void)
{
        return(killProcess(flatfsd_pidfile, SIGUSR1));
}

void config_exhausted(void)
{
        syslog(LOG_EMERG, "Configuration filesystem full while writing leases -- rebooting\n");
        sleep(5);
        rebootDevice();
}

#endif /* CONFIG_USER_FLATFSD_FLATFSD */
