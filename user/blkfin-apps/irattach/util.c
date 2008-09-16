#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <getopt.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <sys/file.h>
#include <sys/kd.h>

extern char *pidfile;

int be_quiet = 1;
int caught_signal = 0;

/*
 * Function beep (ms, freq)
 *
 *    
 *
 */
void beep(unsigned int ms, unsigned int freq)
{
	int fd, arg;
	
	if (be_quiet)
		return;
	fd = open("/dev/console", O_RDWR);
	if (fd < 0)
		return;
	arg = (ms << 16) | freq;
	ioctl(fd, KDMKTONE, arg);
	close(fd);
	usleep(ms*1000);
}

#if 0	/* Unused ??? */
/*
 * Function open_dev (dev, mode)
 *
 *    Open a device
 *
 */
int open_dev(dev_t dev, int mode)
{
	char *fn;
	int fd;
	if ((fn = tmpnam(NULL)) == NULL)
		return -1;
	if (mknod(fn, mode, dev) != 0)
		return -1;
	fd = open(fn, (mode & S_IWRITE) ? O_RDWR: O_RDONLY);
	unlink(fn);
	return fd;
}
#endif

/*
 * Function lookup_dev (name)
 *
 *    Look up the minor number of the IrDA device
 *
 */
int lookup_dev(char *name)
{
	FILE *f;
	int n;
	char s[32], t[32];
	
	f = fopen("/proc/misc", "r");
	if (f == NULL)
		return -errno;
	while (fgets(s, 32, f) != NULL) {
		if (sscanf(s, "%d %s", &n, t) == 2)
			if (strcmp(name, t) == 0)
				break;
	}
	fclose(f);
	if (strcmp(name, t) == 0)
		return n;
	else
		return -ENODEV;
}

int execute(char *msg, char *cmd)
{
	int ret;
	FILE *f;
	char line[256];

	syslog(LOG_INFO, "executing: '%s'", cmd);
	strcat(cmd, " 2>&1");
	f = popen(cmd, "r");
	while (fgets(line, 255, f)) {
		line[strlen(line)-1] = '\0';
		syslog(LOG_INFO, "+ %s", line);
	}
	ret = pclose(f);
	if (WIFEXITED(ret)) {
		if (WEXITSTATUS(ret))
			syslog(LOG_INFO, "%s exited with status %d",
			       msg, WEXITSTATUS(ret));
		return WEXITSTATUS(ret);
	} else
		syslog(LOG_INFO, "%s exited on signal %d",
		       msg, WTERMSIG(ret)); 
	return -1;
}

int execute_on_dev(char *action, char *class, char *dev, int minor)
{
	char msg[128], cmd[512];

	sprintf(msg, "%s cmd", action);
	sprintf(cmd, "./%s %s %s %d", class, action, dev, minor);

	return execute(msg, cmd);
}

/*
 * Function set_sysctl_param (name, value)
 *
 *    Set parameter <name> to <value> in /proc/sys/net/irda
 *
 */
int set_sysctl_param(char *name, char *value)
{
	char msg[128], cmd[512];

	sprintf(msg, "Setting %s to %s", name, value);
	sprintf(cmd, "echo %s > /proc/sys/net/irda/%s", value, name);

	return execute(msg, cmd);
}


void write_pid(void)
{
    FILE *f;
    f = fopen(pidfile, "w");
    if (f == NULL)
        syslog(LOG_INFO, "could not open %s: %m", pidfile);
    else {
        fprintf(f, "%d\n", getpid());
        fclose(f);
    }
}

void fork_now(int ttyfd)
{
	int ret;
	int i;

	if ((ret = fork()) > 0)
		exit(0);
	
	if (ret == -1)
		syslog(LOG_INFO, "forking: %m");
	if (setsid() < 0)
		syslog(LOG_INFO, "detaching from tty: %m");

	if ((ret = fork()) > 0) {
		/* cleanup_files = 0; */
		exit(0);
	}

	/* Close all open inherited files! Except for ttyfd! */
	for (i = 0; i < 64; i++)
		if(i != ttyfd)
			close(i);

	write_pid();
} 



