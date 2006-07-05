/*********************************************************************
 *                
 * Filename:      irattach.c
 * Version:       
 * Description:   
 * Status:        Experimental.
 * Author:        Dag Brattli <dagb@cs.uit.no>
 * Created at:    Sun Dec  7 23:21:05 1997
 * Modified at:   Mon Apr  8 11:30:28 2002
 * Modified by:   Ronny Arild <ronny.arild@thalesgroup.no>
 * Sources:       
 *
 *     Copyright (c) 1997, 1999-2000 Dag Brattli <dagb@cs.uit.no>, 
 *     All Rights Reserved.
 *     
 *     This program is free software; you can redistribute it and/or 
 *     modify it under the terms of the GNU General Public License as 
 *     published by the Free Software Foundation; either version 2 of 
 *     the License, or (at your option) any later version.
 *
 *     Neither Dag Brattli nor University of Troms admit liability nor
 *     provide warranty for any of this software. This material is 
 *     provided "AS-IS" and at no charge.
 *
 ********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <syslog.h>
#include <termios.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/utsname.h>

#include "irda.h"

#ifndef N_IRDA
#define N_IRDA 11 /* This one should go in .../asm/termio.h */
#endif /* N_IRDA */

#ifndef AF_IRDA
#define AF_IRDA 23
#endif

/* External prototypes */
extern void fork_now(int ttyfd);
extern int set_sysctl_param(char *name, char *value);
extern int execute(char *msg, char *cmd);
/* Internal prototypes */

#define VERSION "0.9.17 (19.02.2006) Dag Brattli/Jean Tourrilhes"

extern char *optarg;
extern int optind;

static int devfd = -1;		/* File descriptor for the tty device */
static int fdflags = -1;	/* Current file descriptor flags */
static int initfdflags = -1;	/* Initial file descriptor flags */
static int initdisc = -1;	/* Initial line discipline */
static struct termios termsave;	/* Saved tty termios */
static int termvalid = -1;	/* If termsave is valid */

/* Default path for pid file */
char *pidfile = "/var/run/irattach.pid";

/* Used by ioctl to the tty to obtain the network device name */
struct irtty_info {
	char name[6];
};

#define IRTTY_IOC_MAGIC 'e'
#define IRTTY_IOCTDONGLE  _IO(IRTTY_IOC_MAGIC, 1)
#define IRTTY_IOCGNAME   _IOR(IRTTY_IOC_MAGIC, 2, struct irtty_info)
#define IRTTY_IOC_MAXNR  2  

struct irtty_info info;
/* IrDA Device Name of the device we manage */
char device[20];

struct dongle_list_s {
	int   id;
	char *dongle;
};
struct dongle_list_s dongle_list[] = {
	{ IRDA_ESI_DONGLE,		"esi" },
	{ IRDA_TEKRAM_DONGLE,		"tekram" },
	{ IRDA_ACTISYS_DONGLE,		"actisys" },
	{ IRDA_ACTISYS_PLUS_DONGLE,	"actisys+" },
	{ IRDA_GIRBIL_DONGLE,		"girbil" },
	{ IRDA_LITELINK_DONGLE,		"litelink" },
	{ IRDA_AIRPORT_DONGLE,		"airport" },
	{ IRDA_OLD_BELKIN_DONGLE,	"old_belkin" },
	{ IRDA_EP7211_IR,		"ep7211" },
	{ IRDA_MCP2120_DONGLE,		"mcp2120" },
	{ IRDA_ACT200L_DONGLE,		"act200l" },
	{ IRDA_MA600_DONGLE,		"ma600" },
	{ IRDA_TOIM3232_DONGLE,		"toim3232" },
	{ -1,				NULL }
};

/* Where to read device names */
#define PROC_NET_DEV	"/proc/net/dev"

/************************ COMMON SUBROUTINES ************************/

/*
 * Function modify_flags (set, clear)
 *
 *    Modify the flags of an interface
 *
 */
static int modify_flags(char *dev, int set, int clear)
{
	struct ifreq ifr;
	int sockfd;

	/* Create socket */
        sockfd = socket(AF_IRDA, SOCK_STREAM, 0);
        if (sockfd < 0) {
                syslog (LOG_WARNING, "socket(AF_IRDA): %m");
		return(-1);
		/* Can't clean_exit(), will recurse - Jean II */
        }

	/* Try to read flags. Will fail if device doesn't exist */
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
		syslog (LOG_WARNING, "ioctl(SIOCGIFFLAGS): %m");
		close (sockfd);
		return -1;
	}

	/* Modify flags according to arguments */
        ifr.ifr_flags |= set;
	ifr.ifr_flags &= ~clear;

	/* Not, set the modified flags */
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);
        if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
		syslog (LOG_WARNING, "ioctl(SIOCSIFFLAGS): %m");
		close (sockfd);
                return -1;
        }
	close(sockfd);
        return 0;	
}

/*
 * Function ifup (name)
 *
 *    Start device
 *
 */
static inline int ifup(char *dev)
{
	syslog(LOG_INFO, "Starting device %s", dev);
	return(modify_flags(dev, IFF_UP|IFF_RUNNING, 0));
}

/*
 * Function ifdown (name)
 *
 *    Stop device
 *
 */
static inline int ifdown(char *dev)
{
	syslog(LOG_INFO, "Stopping device %s", dev);
	return(modify_flags(dev, 0, IFF_UP));
}

/********************* SIGNAL & ERROR HANDLING *********************/

/*
 * Put everything back in the state we found it
 */
void cleanup(int signo)
{
	switch (signo) {
	case SIGTERM:
	case SIGINT:
	        syslog(LOG_INFO, "got SIGTERM or SIGINT\n");
		break;
	case SIGHUP:
	        syslog(LOG_INFO, "got SIGHUP\n");
		break;
	default:
		break;
	}
	ifdown(device);

	/* Reset the fd termios struct ++ */
	if (devfd != -1) {
		fdflags &= ~O_NONBLOCK;
		if (fcntl (devfd, F_SETFL, fdflags) != 0) {
			syslog (LOG_ERR, "fcntl: fdflags: %m");
		}
		if (initdisc != -1)
			if (ioctl(devfd, TIOCSETD, &initdisc) < 0){
				fprintf(stderr, "Oups ! Can't set back original link discipline...\n");
				syslog(LOG_ERR, "ioctl: set_inidisc: %m");
			}
		if (termvalid != -1)
			if (tcsetattr(devfd, TCSANOW, &termsave) != 0) {
				syslog (LOG_ERR, "tcsetattr: %m");
			}
		if (fcntl (devfd, F_SETFL, initfdflags) != 0) {
			syslog (LOG_ERR, "fcntl: initfdflags: %m");
		}
		close(devfd);
		devfd = -1;
	}

	/* Delete pid file */
	unlink(pidfile);

	syslog(LOG_INFO, "exiting ...\n");

	if (signo == -1)
		exit(1);
	else
		exit(0);
}

/* To avoid recursion, clean_exit() should no be used above this
 * point - Jean II */
static inline void clean_exit(int status)
{
	cleanup(status);
	//exit(-1); /* should not get here */
}

static void print_usage(void)
{
	int i;
	fprintf(stderr, "Usage: irattach <dev> [-d dongle] [-s] [-b] [-v] [-h]\n");
	fprintf(stderr, "       <dev> is tty name, device name or module name\n");
	fprintf(stderr, "Dongles supported :\n");
	for (i = 0; dongle_list[i].dongle != NULL; i++)
		fprintf(stderr, "\t%s\n", dongle_list[i].dongle);
	fprintf(stderr, "\n");
}

/************************ MODULES MANAGEMENT ************************/

/*
 * Function load_module (name)
 *
 *    Tries to load (modprobe) the module with the given name
 *
 */
static int load_module(char *name)
{
	char msg[128], cmd[512];
	int ret;
	
	sprintf(msg, "Trying to load module %s", name);
	sprintf(cmd, "/sbin/modprobe %s", name);

	ret = execute(msg, cmd);

	return ret;
}

/*
 * Extract an interface name out of /proc/net/irda
 * Important note : this procedure suppose that you don't alias irda devices
 */
static char *
get_irdevname(char *	name,	/* Where to store the name */
	      int	nsize,	/* Size of name buffer */
	      char *	buf)	/* Current position in buffer */
{
	char *	end;

	/* Skip leading spaces */
	while(isspace(*buf))
		buf++;

	/* Check if it's irda */
	if(strncmp(buf, "irda", 4))
		return(NULL);
	/* End of name (no alias) */
	end = strchr(buf, ':');

	/* Not found ??? To big ??? */
	if((end == NULL) || (((end - buf) + 1) > nsize))
		return(NULL);

	/* Copy */
	memcpy(name, buf, (end - buf));
	name[end - buf] = '\0';

	return(end + 2);
}

/*
 * Function get_devlist ()
 *
 *    Get list of irda device on the system
 *
 */
static int get_devlist(char ifnames[][IFNAMSIZ + 1],
		       int maxchars, int maxnames)
{
	char		buff[1024];
	FILE *		fh;
	int		ifnum;
	
	/* Check if /proc/net/dev is available */
	fh = fopen(PROC_NET_DEV, "r");

	if(fh == NULL)
		return(-1);

	/* Success : use data from /proc/net/dev */
	ifnum = 0;

	/* Eat 2 lines of header */
	fgets(buff, sizeof(buff), fh);
	fgets(buff, sizeof(buff), fh);

	/* Read each device line */
	while(fgets(buff, sizeof(buff), fh)) {
		/* Get an irda name */
		if(get_irdevname(ifnames[ifnum], maxchars, buff)) {
			ifnum++;
		}
		if(ifnum > maxnames) {
			fclose(fh);
			return(-1);
		}
	}
	fclose(fh);
	return(ifnum);
}

/*
 * Function get_module_devices(char *	modname)
 *
 *    Load a module and figure out which IrDA interfaces were created.
 *
 */
static inline int get_module_devices(char *	modname)
{
	char	before_names[10][IFNAMSIZ + 1];
	int	before_num;
	char	after_names[15][IFNAMSIZ + 1];
	int	after_num;
	int	firstone = -1;
	int	pid;
	int	i, j;
	int	ret;

	/* Get list of devices before */
	before_num = get_devlist(before_names, IFNAMSIZ + 1, 10);
	if(before_num < 0) {
		fprintf(stderr, "Could not get device name list.\n");
		exit(-1);
	}

	/* Load the module */
	ret = load_module(modname);
	if(ret) {
		fprintf(stderr, "Invalid module name [%s] !\n", device);
		print_usage();
		exit(-1);
	}

	/* Get list of devices after */
	after_num = get_devlist(after_names, IFNAMSIZ + 1, 15);
	if(after_num <= 0) {
		fprintf(stderr, "Could not get device name list.\n");
		exit(-1);
	}

	/* Loop on all found names */
	for(i = 0; i < after_num; i++) {
		/* Check if it was here before */
		for(j = 0; j < before_num; j++) {
			if(!strcmp(before_names[j], after_names[i]))
				break;
		}
		/* If not found, it's a new interface */
		if(j == before_num) {
			/* Already got one ??? */
			if(firstone >= 0) {
				fprintf(stderr,
					"Found additional interface [%s]\n",
					after_names[i]);
				/* Create a new instance for this other
				 * interface */
				pid = fork();
				/* If in the child */
				if(!pid) {
					/* Get the interface name */
					strcpy(device, after_names[i]);
					/* Exit so we manage this guy */
					return(0);
				}
				/* In parent : continue looking at interface
				 * list, spawn childs, and eventually
				 * go back to manage the first one found */
			} else {
				/* Get the interface name */
				firstone = i;
				strcpy(device, after_names[i]);
				fprintf(stderr, "Found interface [%s]\n",
					device);
			}
		}
	}
	return(0);
}

/************************** TTY MANAGEMENT **************************/

/*
 * Function establish_irda (ttyfd)
 * 
 *    Turn the serial port into a irda interface.
 */
static void establish_irda (int ttyfd) 
{
	int irdadisc = N_IRDA;
	
	if (ioctl(ttyfd, TIOCEXCL, 0) < 0) {
		syslog (LOG_WARNING, "ioctl(TIOCEXCL): %m");
	}
	
	if (ioctl(ttyfd, TIOCGETD, &initdisc) < 0) {
		syslog(LOG_ERR, "ioctl(TIOCGETD): %m");
		clean_exit(-1);
	}
	
	if (ioctl(ttyfd, TIOCSETD, &irdadisc) < 0){
		fprintf(stderr,  
			 "Maybe you don't have IrDA support in your kernel?\n");
		syslog(LOG_ERR, "irattach: tty: set_disc(%d): %s\n", 
			irdadisc, strerror(errno));
		clean_exit(-1);
	}
}

/*
 * Function tty_configure (tios)
 *
 *    Put a IrDA line discipline in a transparent mode. 
 *
 */
static int tty_configure(struct termios *tios) 
{
	tios->c_cflag     = CS8|CREAD|B9600|CLOCAL;
	
	/* Ignore break condition and parity errors */
 	tios->c_iflag     = IGNBRK | IGNPAR;
	tios->c_oflag     = 0;
	tios->c_lflag     = 0; /* set input mode (non-canonical, no echo,..) */
	tios->c_cc[VMIN]  = 1; /* num of chars to wait for, before delivery */
	tios->c_cc[VTIME] = 0; /* timeout before delivery */
	
	return(0);
}

/*
 * Function init_irda (ttyfd)
 *
 *    Initialize IrDA line discipline
 *
 */
static void init_irda_ldisc(int ttyfd) 
{
	struct termios tios;
	
	/* Get TTY configuration */
	if (tcgetattr(ttyfd, &tios) != 0) {
		syslog (LOG_ERR, "tcgetattr: %m");
		clean_exit(-1);
	}
	/* Save the original values */
	memcpy(&termsave, &tios, sizeof(struct termios));
	termvalid = 0;

	tty_configure(&tios);
	
	/* tcflush(ttyfd, TCIFLUSH); */
	if (tcsetattr(ttyfd, TCSAFLUSH, &tios) < 0) {
		syslog(LOG_ERR, "tcsetattr: %m");
		clean_exit(-1);
	}
}

/*
 * Function start_tty(ttyfd)
 *
 *    Set up the serial device to be the irda interface.
 *
 * This needs to be called after the fork.
 */
static void start_tty(int ttyfd) 
{
	int cloexec;

	/* Set new flags -> blocking mode while we configure */
	fdflags &= ~O_NONBLOCK;
	if (fcntl(ttyfd, F_SETFL, fdflags) == -1) {
		syslog(LOG_WARNING, "Couldn't set device fd flags: %m");
	}
		
	/* We need to make sure the devfd/ttyfd will not be inherited by the
	 * shells which get vfork'ed when we use popen(3) to execute commands
	 * like sysctl and modprobe on behalf of irattach. In the daemon mode
	 * we got most likely fd=0 which would be reused for stdin by /bin/sh
	 * otherwise!
	 * F_SETFD belongs to the fd, not file: no need to save and restore
	 * later.
	 * Martin
	 */
	if ((cloexec = fcntl(devfd, F_GETFD)) == -1) {
		syslog(LOG_ERR,
		       "Couldn't get device fd close-on-exec flag: %m");
		clean_exit(-1);
	}
	cloexec |= FD_CLOEXEC;
	if (fcntl(devfd, F_SETFD, cloexec) == -1) {
		syslog(LOG_ERR,
		       "Couldn't set device fd close-on-exec flag: %m");
		clean_exit(-1);
	}

	/* Set up the serial device as a irda interface */	
	init_irda_ldisc(ttyfd);
	establish_irda(ttyfd);

	/* Give it time to set up its terminal */
	sleep(1);
	
	/*
	 *  Set device for non-blocking reads.
	 */
	if (fcntl(ttyfd, F_SETFL, fdflags | O_NONBLOCK) == -1) {
		syslog(LOG_ERR, 
		       "Couldn't set device to non-blocking mode: %m");
		clean_exit(-1);
	}
}

/*
 * Function open_tty(ttyfd)
 *
 *    Open the desired tty, save its state.
 *
 * This needs to be called before the fork.
 */
static int open_tty(char *dev) 
{
	int ttyfd;

	/* Open the serial device */
	ttyfd = open(dev, O_NONBLOCK | O_RDWR, 0);
	if (ttyfd < 0) {
		fprintf(stderr, "Failed to open device %s: %s\n",
			dev, strerror(errno));
		exit(-1);
	}

	/* Save old flags
	 * Need to happen first, because we need to restore them when leaving
	 * via clean_exit() */
	if ((fdflags = fcntl(ttyfd, F_GETFL)) == -1) {
		fprintf(stderr, "Couldn't get device %s flags: %s\n",
			dev, strerror(errno));
		close(ttyfd);
		exit(-1);
	}
	initfdflags = fdflags;

	return(ttyfd);
}

/************************ DONGLE MANAGEMENT ************************/

/*
 * Function attach_dongle (name)
 *
 *    Tries to load the dongle and attach it to the specified device
 *
 */
static inline void attach_dongle(int ttyfd, char *dev, int dongle)
{

	/* If we have a tty channel, use it */
	if(ttyfd != -1) {
		/* Attach dongle */
		ioctl(ttyfd, IRTTY_IOCTDONGLE, dongle);
	} else {
		/* irport case (or maybe FIR drivers) */
		int	sockfd;
		struct ifreq ifr;

		/* Create socket */
		sockfd = socket(AF_IRDA, SOCK_STREAM, 0);
		if (sockfd < 0) {
			perror("socket");
			clean_exit(-1);
		}

		/* Attach dongle */
		ifr.ifr_data = (void *) dongle;
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
		if (ioctl(sockfd, SIOCSDONGLE, &ifr) < 0) {
			perror("ioctl");
			close(sockfd);
			clean_exit(-1);
		}

		/* Cleanup */
		close(sockfd);
	}
}

/*
 * Function get_dongle (dongle)
 *
 *    Find the dongle id corresponding to the name
 *
 */
static inline int get_dongle(char *dongle)
{
	int i;
	for (i = 0; dongle_list[i].dongle != NULL; i++) {
		if (strcmp(dongle_list[i].dongle, dongle) == 0)
		       	return dongle_list[i].id;
	}
	return -1;
}

/******************************* MAIN *******************************/

/*
 * Function main (argc, )
 *
 *    Main function
 *
 */
int main(int argc, char *argv[]) 
{
	struct utsname buf;
	int	tty = 0;	/* True if first arg is a tty */
	int	modname = 0;	/* True is first arg is a module name */
	int	dongle = -1;	/* Dongle type requested */
	int	discovery = -1;	/* True if discovery requested */
	int	c;
	int	ret;
	int     daemonize = 1;  /* Go to background by default */

	//printf("%s\n", VERSION);
	if ((argc < 2) || (argc > 5)) {
		print_usage();
		exit(-1);
	}

	/* First arg is device name. Save it now, because in some cases
	 * getopt() will remove it... */
	strncpy(device, argv[1], 20);
	device[20] = '\0';

	/* Look for options */
	/* Do this before processing device, to handle "-h" and -v"
	 * properly. Jean II */
	while ((c = getopt(argc, argv, "d:hsvb")) != -1) {
		switch (c) {
		case 's':
		       	/* User wants to start discovery */
			discovery = 1;
			break;
		case 'd':
			dongle = get_dongle(optarg);
			if (dongle == -1) {
				fprintf(stderr,
				       "Sorry, dongle not supported yet!\n");
				print_usage();
				exit(-1);
			}	
			break;
		case 'v':
			printf("Version: %s\n", VERSION);
			exit(0);
		case 'h':
			print_usage();
			exit(0);
		case 'b':
		       	/* Do not fork to background */
			daemonize = 0;
			break;
		default:
			print_usage();
			exit(-1);
		}
	}

	/* Check if the device is a tty */
	if(strncmp("/dev", device, 4) == 0) {
		/* We are managing a tty ! */
		tty = 1;

		/* Create tty channel and make it exist */
		devfd = open_tty(device);
	} else {
		/* Check for a irda device name */
		if((strncmp("irda", device, 4) == 0) &&
		   (isdigit(device[4]))) {
			/* May fail if no alias in /etc/modules.conf.
			 * Ignore, because the user may load module by hand.
			 * Jean II */
			load_module(device);
		} else {
			/* This is a module name - currently experimental */
			modname = 1;

			/* Get list of devices associated with module */
			/* This may fork as needed - Jean II */
			get_module_devices(device);
		}
	}

	if(daemonize) {
	  	/* Go as a background daemon */
		fork_now(devfd);
	}

	/* --- Deamon mode --- */
	/* We can no longer print out directly to the terminal, we
	 * now must use the syslog facility.
	 * Jean II */

	/* Trap signals */
	if (signal(SIGHUP, cleanup) == SIG_ERR)
		syslog(LOG_INFO, "signal(SIGHUP): %m");
	if (signal(SIGTERM, cleanup) == SIG_ERR)
		syslog(LOG_INFO, "signal(SIGTERM): %m");
	if (signal(SIGINT, cleanup) == SIG_ERR)
		syslog(LOG_INFO, "signal(SIGINT): %m");

	/* If device is a tty */
	/* We may want to move that before the fork(), except for the sleep */
	if (tty) {
		/* Setup tty channel */
		start_tty(devfd);

		/* Get device name corresponding to the tty */
		if (ioctl(devfd, IRTTY_IOCGNAME, &info) < 0) {
			syslog(LOG_ERR, "Are you using an old kernel?");
			clean_exit(-1);
		}
		strncpy(device, info.name, 20);
	}

	/* --- IrDA stack and IrDA port loaded loaded --- */
	/* We can not assume that the IrDA stack is present before
	 * this point, so all sysctl/ioctl must be done after here.
	 * The real name of the device is also only known at this point.
	 * Jean II */

	/* If dongle is chosen -> bind dongle driver to the irda port */
	if (dongle != -1) {
		attach_dongle(devfd, device, dongle);
  	}

	/* Use hostname as device name */
	if (uname(&buf) == 0)
		set_sysctl_param("devname", strtok(buf.nodename, "."));

	/* User may want to start discovery */
	if(discovery > 0)
		set_sysctl_param("discovery", "1");

	/* Start the network interface */
	ret = ifup(device);
	if(ret < 0)
		clean_exit(-1);

	/*
	 *  Loop forever and wait for kill or ctrl-C since closing this 
	 *  process will also close all open files for this process
	 *  which will in turn close the tty used for IrDA which is not
	 *  really what we want :-)
	 */
	while (1)
		pause();

	return 0;
}
