/*****************************************************************************/

/*
 *	flatfsd.c -- Flat file-system daemon.
 *
 *	(C) Copyright 1999-2006, Greg Ungerer <gerg@snapgear.com>
 *	(C) Copyright 2000-2001, Lineo Inc. (www.lineo.com)
 *	(C) Copyright 2001-2002, SnapGear (www.snapgear.com)
 *	(C) Copyright 2004-2006, CyberGuard (www.cyberguard.com)
 *	(C) Copyright 2002-2005, David McCullough <davidm@snapgear.com>
 */

/*****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <linux/autoconf.h>
#include <config/autoconf.h>
#if defined(CONFIG_LEDMAN)
#include <linux/ledman.h>
#endif

#include "flatfs.h"
#include "reboot.h"

/*****************************************************************************/

/*
 * By default create version 3 flat fs files (compressed/duplicated).
 * Allow it to be overriden on the command line with args though.
 */
int fsver = 3;

/*****************************************************************************/

/*
 * Temporary marker file.
 */
#define	IGNORE_FLASH_WRITE_FILE	"/tmp/.flatfsd_ignore_write"

/*****************************************************************************/

/*
 * Globals for file and byte count.
 * This is a kind of ugly way to do it, but we are using LCP
 * (Least Change Principle)
 */
int numfiles;
int numbytes;
int numdropped;
int numversion;

/*****************************************************************************/

/*
 * The code to do Reset/Erase button menus.
 */
static int current_cmd = 0;
static void no_action(void) { }
static void reset_config_fs(void);

#define MAX_LED_PATTERN 4
#define	ACTION_TIMEOUT 5		/* timeout before action in seconds */

#ifndef CONFIG_LEDMAN
#define LEDMAN_RESET 0
#endif

static struct {
	void		(*action)(void);
	unsigned long	led;
	unsigned long	timeout;
} cmd_list[] = {
	{ no_action, 0, 0 },
	{ no_action, 0, 2 },
	{ reset_config_fs, LEDMAN_RESET, 0 },
	{ NULL,	0, 0 }
};

/*****************************************************************************/

static int recv_hup = 0;	/* SIGHUP = reboot device */
static int recv_usr1 = 0;	/* SIGUSR1 = write config to flash */
static int recv_usr2 = 0;	/* SIGUSR2 = erase flash and reboot */
static int recv_pwr = 0;	/* SIGPWR = halt device */
static int exit_flatfsd = 0;  /* SIGINT, SIGTERM, SIGQUIT */
static int nowrite = 0;

static void block_sig(int blp)
{
	sigset_t sigs;

	sigemptyset(&sigs);
	sigaddset(&sigs, SIGUSR1);
	sigaddset(&sigs, SIGUSR2);
	sigaddset(&sigs, SIGHUP);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGINT);
	sigaddset(&sigs, SIGQUIT);
	sigaddset(&sigs, SIGPWR);
	sigprocmask(blp?SIG_BLOCK:SIG_UNBLOCK, &sigs, NULL);
}

static void sigusr1(int signr)
{
	recv_usr1 = 1;
}

static void sigusr2(int signr)
{
	recv_usr2 = 1;
}

static void sighup(int signr)
{
	recv_hup = 1;
}

static void sigpwr(int signr)
{
	recv_pwr = 1;
}

static void sigexit(int signr)
{
	exit_flatfsd = 1;
}

/*****************************************************************************/

/*
 * Save the filesystem to flash in flat format for retrieval later.
 */

static void save_config_to_flash(void)
{
	if (!nowrite) {
#if !defined(USING_FLASH_FILESYSTEM)
		int	rc;
#endif
		block_sig(1);

#ifdef LOGGING
		system("/bin/logd writeconfig");
#endif
#if !defined(USING_FLASH_FILESYSTEM)
		if ((rc = flat_savefs(fsver)) < 0)
			syslog(LOG_ERR, "Failed to write flatfs (%d): %m", rc);
#endif
#ifdef LOGGING
		system("/bin/logd write-done");
		system("flatfsd -c");
#endif
		block_sig(0);
	}
}

/*****************************************************************************/

/*
 * Default the config filesystem.
 */

static void reset_config_fs(void)
{
	int rc;

	block_sig(1);

	printf("Resetting configuration\n");
#ifdef LOGGING
	system("/bin/logd resetconfig");
#endif

	/*
	 * Don't actually clean out the filesystem.
	 * That will be done when we reboot
	 */
	if ((rc = flat_clean(0)) < 0) {
		syslog(LOG_ERR, "Failed to prepare flatfs for reset (%d): %m", rc);
		exit(1);
	}
	save_config_to_flash();

	reboot_now();
	block_sig(0);
}

/*****************************************************************************/

int creatpidfile(void)
{
	FILE	*f;
	pid_t	pid;
	char	*pidfile = "/var/run/flatfsd.pid";

	pid = getpid();
	if ((f = fopen(pidfile, "w")) == NULL) {
		syslog(LOG_ERR, "Failed to open %s: %m", pidfile);
		return -1;
	}
	fprintf(f, "%d\n", pid);
	fclose(f);
	return 0;
}

int readpidfile(void)
{
	FILE	*f;
	pid_t	pid;
	char	*pidfile = "/var/run/flatfsd.pid";
	int	nread;

	pid = getpid();
	if ((f = fopen(pidfile, "r")) == NULL) {
		syslog(LOG_ERR, "Failed to open %s: %m", pidfile);
		return -1;
	}
	nread = fscanf(f, "%d\n", &pid);
	fclose(f);
	if (nread)
		return pid;
	return -1;
}

/*****************************************************************************/

/*
 * Lodge ourselves with the kernel LED manager. If it gets an
 * interrupt from the reset switch it will send us a SIGUSR2.
 */

int register_resetpid(void)
{
#if defined(CONFIG_LEDMAN) && defined(LEDMAN_CMD_SIGNAL)
	int	fd;

	if ((fd = open("/dev/ledman", O_RDONLY)) < 0) {
		syslog(LOG_ERR, "Failed to open /dev/ledman: %m");
		return -1;
	}
	if (ioctl(fd, LEDMAN_CMD_SIGNAL, 0) < 0) {
		syslog(LOG_ERR, "Failed to register pid: %m");
		return -2;
	}
	close(fd);
#endif
	return 0;
}

/*****************************************************************************/

#if defined(CONFIG_LEDMAN) && defined(LEDMAN_CMD_SIGNAL)
#define CHECK_FOR_SIG(x) \
	do { usleep(x); if (recv_usr1 || recv_usr2 || recv_pwr || recv_hup) goto skip_out; } while(0)
#else
#define CHECK_FOR_SIG(x) \
	do { usleep(x); if (recv_usr1 || recv_usr2 || recv_pwr || recv_hup) return; } while(0)
#endif

static void led_pause(void)
{
	unsigned long start = time(0);

#if defined(CONFIG_LEDMAN) && defined(LEDMAN_CMD_SIGNAL)
	ledman_cmd(LEDMAN_CMD_ALT_ON, LEDMAN_ALL); /* all leds on */
	ledman_cmd(LEDMAN_CMD_ON | LEDMAN_CMD_ALTBIT, LEDMAN_ALL); /* all leds on */
	CHECK_FOR_SIG(100000);
	ledman_cmd(LEDMAN_CMD_OFF | LEDMAN_CMD_ALTBIT, LEDMAN_ALL); /* all leds off */
	CHECK_FOR_SIG(100000);
	ledman_cmd(LEDMAN_CMD_ON | LEDMAN_CMD_ALTBIT, cmd_list[current_cmd].led);
	CHECK_FOR_SIG(250000);
#endif

	while (time(0) - start < cmd_list[current_cmd].timeout) {
		CHECK_FOR_SIG(250000);
	}

	block_sig(1);
#if defined(CONFIG_LEDMAN) && defined(LEDMAN_CMD_SIGNAL)
	ledman_cmd(LEDMAN_CMD_ON | LEDMAN_CMD_ALTBIT, LEDMAN_ALL); /* all leds on */
#endif
	(*cmd_list[current_cmd].action)();
	block_sig(0);

	current_cmd = 0;

#if defined(CONFIG_LEDMAN) && defined(LEDMAN_CMD_SIGNAL)
skip_out:
	ledman_cmd(LEDMAN_CMD_RESET | LEDMAN_CMD_ALTBIT, LEDMAN_ALL);
	ledman_cmd(LEDMAN_CMD_ALT_OFF, LEDMAN_ALL); /* all leds on */
#endif
}

/*****************************************************************************/

void usage(int rc)
{
	printf("usage: flatfsd [-bcrwnis123vh?]\n"
		"\t-b safely reboot the system\n"
		"\t-H safely halt the system\n"
		"\t-c check that the saved flatfs is valid\n"
		"\t-r read from flash, write to config filesystem\n"
		"\t-w read from default, write to config filesystem\n"
		"\t-n with -r or -w, do not write to flash\n"
		"\t-i initialise from default, reboot\n"
		"\t-s save config filesystem to flash\n"
		"\t-1 force use of version 1 flash layout\n"
		"\t-2 force use of version 2 flash layout\n"
		"\t-3 force use of version 3 flash layout (default)\n"
		"\t-v print version\n"
		"\t-h this help\n");
	exit(rc);
}

/*****************************************************************************/

static void version(void)
{
	printf("flatfsd " FLATFSD_VERSION "\n");
}

/*****************************************************************************/

static int saveconfig(void)
{
	/* Query PID file, and send USR1 to the running daemon */
	int pid = readpidfile();
	if(pid > 0) {
		printf("Saving configuration\n");
		kill(pid, SIGUSR1);
	} else {
		struct stat st_buf;
		/* No daemon running, so save the config ourselves */
		if (stat(IGNORE_FLASH_WRITE_FILE, &st_buf) < 0) {
			save_config_to_flash();
		} else {
			syslog(LOG_INFO, "Not writing to flash because %s exists",
				IGNORE_FLASH_WRITE_FILE);
		}
	}
	return 0;
}

/*****************************************************************************/

static int reboot_system(void)
{
	/* Query PID file, and send USR1 to the running daemon */
	int pid = readpidfile();
	if (pid > 0) {
		printf("Rebooting system\n");
		kill(pid, SIGHUP);
	} else {
		reboot_now();
		/*notreached*/
		return 1;
	}
	return 0;
}

static int halt_system(void)
{
	/* Query PID file, and send USR1 to the running daemon */
	int pid = readpidfile();
	if (pid > 0) {
		printf("Halting system\n");
		kill(pid, SIGPWR);
	} else {
		halt_now();
		/*notreached*/
		return 1;
	}
	return 0;
}

/*****************************************************************************/

/*
 * Remote reset of config.
 *
 * We cannot use the button signals to do this as we need to send two and
 * they may be locked during a save (resulting on only one signal).
 * So we do the clean ourselves, which is safe, then send a save followed by
 * reboot signal to flatfsd, of which none will be lost.
 */

static int reset_config(void)
{
	/* Query PID file, and send USR1 to the running daemon */
	int rc, pid = readpidfile();
	if (pid > 0) {
		printf("Reset config\n");
#ifdef LOGGING
		system("/bin/logd resetconfig");
#endif
		/*
		 * Don't actually clean out the filesystem.
		 * That will be done when we reboot.
		 */
		if ((rc = flat_clean(0)) < 0) {
			syslog(LOG_ERR, "Failed to prepare flatfs for reset (%d): %m", rc);
			exit(1);
		}
		kill(pid, SIGUSR1);
		sleep(1);
		kill(pid, SIGHUP);
	} else {
		reset_config_fs();
	}
	return 0;
}

/*****************************************************************************/

static void log_caller(char *prefix)
{
#ifdef LOGGING
	char	procname[64];
	char	cmd[64];
	pid_t	pp = getppid();
	FILE	*fp;

	procname[0] = '\0';

	snprintf(cmd, sizeof(cmd), "/proc/%d/cmdline", pp);
	if ((fp = fopen(cmd, "r"))) {
		fgets(procname, sizeof(procname), fp);
		fclose(fp);
	}

	if (procname[0] == '\0')
		strcpy(procname, "???");

	snprintf(cmd, sizeof(cmd), "%s %d: %s", prefix, (int) pp, procname);
	system(cmd);
#endif
}

/*****************************************************************************/

int main(int argc, char *argv[])
{
	struct sigaction act;
	int rc, rc1, rc2, readonly, clobbercfg;

	clobbercfg = readonly = 0;

	openlog("flatfsd", LOG_PERROR, LOG_DAEMON);

	while ((rc = getopt(argc, argv, "vcnribwH123hs?")) != EOF) {
		switch (rc) {
		case 'w':
			clobbercfg++;
			readonly++;
			break;

		case 'r':
			readonly++;
			break;
		case 'n':
			nowrite = 1;
			break;
		case 'c':
#if !defined(USING_FLASH_FILESYSTEM)
			rc = flat_check();
			if (rc < 0) {
#ifdef LOGGING
				char ecmd[64];
				sprintf(ecmd, "/bin/logd chksum-bad %d", -rc);
				system(ecmd);
#endif
				printf("Flash filesystem is invalid %d - check syslog\n", rc);
			} else {
				printf("Flash filesystem is valid\n");
#ifdef LOGGING
				system("/bin/logd chksum-good");
#endif
			}
			exit(rc);
#else
			exit(0);
#endif
			break;
		case 'v':
			version();
			exit(0);
			break;
		case 's':
			log_caller("/bin/logd flatfsd-s");
			exit(saveconfig());
			break;
		case 'b':
			log_caller("/bin/logd flatfsd-b");
			exit(reboot_system());
			break;
		case 'H':
			log_caller("/bin/logd flatfsd-h");
			exit(halt_system());
			break;
		case 'i':
			log_caller("/bin/logd flatfsd-i");
			exit(reset_config());
			break;
		case '1':
			fsver = 1;
			break;
		case '2':
			fsver = 2;
			break;
		case '3':
			fsver = 3;
			break;
		case 'h':
		case '?':
			usage(0);
			break;
		default:
			usage(1);
			break;
		}
	}

	if (readonly) {
		rc1 = rc2 = 0;

		if (clobbercfg ||
#if !defined(USING_FLASH_FILESYSTEM)
			((rc = flat_restorefs()) < 0) ||
#endif
			(rc1 = flat_filecount()) <= 0 ||
			(rc2 = flat_needinit())
		) {
#ifdef LOGGING
			char ecmd[64];

			/* log the reason we have for killing the flatfs */
			if (clobbercfg)
				sprintf(ecmd, "/bin/logd newflatfs clobbered");
			else if (rc < 0)
				sprintf(ecmd, "/bin/logd newflatfs recreate=%d", rc);
			else if (rc1 <= 0)
				sprintf(ecmd, "/bin/logd newflatfs filecount=%d", rc1);
			else if (rc2)
				sprintf(ecmd, "/bin/logd newflatfs needinit");
			else
				sprintf(ecmd, "/bin/logd newflatfs unknown");

			system(ecmd);
#endif
			syslog(LOG_ERR, "Nonexistent or bad flatfs (%d), creating new one...", rc);
			flat_clean(1);
			if ((rc = flat_new(DEFAULTDIR)) < 0) {
				syslog(LOG_ERR, "Failed to create new flatfs, err=%d errno=%d",
					rc, errno);
				exit(1);
			}
			save_config_to_flash();
		}
		syslog(LOG_INFO, "Created %d configuration files (%d bytes)",
			numfiles, numbytes);
		exit(0);
	}

	creatpidfile();

	act.sa_handler = sighup;
	memset(&act.sa_mask, 0, sizeof(act.sa_mask));
	act.sa_flags = SA_RESTART;
	act.sa_restorer = 0;
	sigaction(SIGHUP, &act, NULL);

	act.sa_handler = sigusr1;
	memset(&act.sa_mask, 0, sizeof(act.sa_mask));
	act.sa_flags = SA_RESTART;
	act.sa_restorer = 0;
	sigaction(SIGUSR1, &act, NULL);

	act.sa_handler = sigusr2;
	memset(&act.sa_mask, 0, sizeof(act.sa_mask));
	act.sa_flags = SA_RESTART;
	act.sa_restorer = 0;
	sigaction(SIGUSR2, &act, NULL);

	act.sa_handler = sigpwr;
	memset(&act.sa_mask, 0, sizeof(act.sa_mask));
	act.sa_flags = SA_RESTART;
	act.sa_restorer = 0;
	sigaction(SIGPWR, &act, NULL);

	/* Make sure we don't suddenly exit while we are writing */
	act.sa_handler = sigexit;
	memset(&act.sa_mask, 0, sizeof(act.sa_mask));
	act.sa_flags = SA_RESTART;
	act.sa_restorer = 0;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
	sigaction(SIGQUIT, &act, NULL);

	register_resetpid();

	/*
	 * Spin forever, waiting for a signal to write...
	 */
	for (;;) {
		if (recv_usr1) {
			struct stat st_buf;
			recv_usr1 = 0;
			/* Don't write out config if temp file  exists. */
			if (stat(IGNORE_FLASH_WRITE_FILE, &st_buf) == 0) {
				syslog(LOG_INFO, "Not writing to flash "
					"because %s exists",
					IGNORE_FLASH_WRITE_FILE);
				continue;
			}
			save_config_to_flash();
			continue;
		}

		if (recv_hup) {
			/*
			 * Make sure we do the check above first so that we
			 * commit to flash before rebooting.
			 */
			recv_hup = 0;
			reboot_now();
			/*notreached*/
			exit(1);
		}

		if (recv_pwr) {
			/*
			 * Ditto for halt
			 */
			recv_pwr = 0;
			halt_now();
			/*notreached*/
			exit(1);
		}

		if (recv_usr2) {
#ifdef LOGGING
			system("/bin/logd button");
#endif
			recv_usr2 = 0;
			current_cmd++;
			if (cmd_list[current_cmd].action == NULL) /* wrap */
				current_cmd = 0;
		}

		if (exit_flatfsd)
			break;

		if (current_cmd)
			led_pause();
		else if (!recv_hup && !recv_usr1 && !recv_usr2 && !recv_pwr)
			pause();
	}

	return 0;
}

/*****************************************************************************/
