/*
    rsh.c - remote shell client
    Copyright (C) 2003  Guus Sliepen <guus@sliepen.eu.org>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as published
	by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>

#define BUFLEN 0x10000

#ifndef BINDIR
#define BINDIR "/usr/bin"
#endif

static char *argv0;

static void usage(void) {
	fprintf(stderr, "Usage: %s [-46vn] [-l user] [-p port] [user@]host command...\n", argv0);
}

/* Make sure everything gets written */

static ssize_t safewrite(int fd, const void *buf, size_t count) {
	int written = 0, result;
	
	while(count) {
		result = write(fd, buf, count);
		if(result == -1) {
			if(errno == EINTR)
				continue;
			else
				return result;
		}
		written += result;
		buf += result;
		count -= result;
	}
	
	return written;
}

/* Safe and fast string building */

static void safecpy(char **dest, int *len, const char *source, bool terminate) {
	while(*source && *len) {
		*(*dest)++ = *source++;
		(*len)--;
	}

	if(terminate && *len) {
		*(*dest)++ = 0;
		(*len)--;
	}
}

static void closestdin(void) {
	int fd;

	close(0);

	if((fd = open("/dev/null", O_RDONLY)) < 0) {
		fprintf(stderr, "%s: Error opening /dev/null: %s\n", argv0, strerror(errno));
		exit(1);
	}

	if(fd != 0) {
		dup2(fd, 0);
		close(fd);
	}
}

int main(int argc, char **argv) {
	char *user = NULL;
	char *luser = NULL;
	char *host = NULL;
	char *port = "shell";
	char *p;
	char lport[5];
	
	struct passwd *pw;
	
	int af = AF_UNSPEC;
	struct addrinfo hint, *ai, *aip, *lai;
	int err, sock = -1, lsock = -1, esock = -1, i;
	
	int opt;

	bool verbose = false;

	char hostaddr[NI_MAXHOST];
	char portnr[NI_MAXSERV];

	char buf[3][BUFLEN], *bufp[3];
	int len[3], wlen;
	
	fd_set infd, outfd, infdset, outfdset, errfd;
	int maxfd;
	
	int flags;
	
	argv0 = argv[0];
	
	/* Lookup local username */
	
	if (!(pw = getpwuid(getuid()))) {
		fprintf(stderr, "%s: Could not lookup username: %s\n", argv0, strerror(errno));
		return 1;
	}
	user = luser = pw->pw_name;
	
	/* if we were called with something else from rsh use the name as host */
	host = basename(argv0);

	if(!strcmp(host, "rsh") || !strcmp(host, "rsh-redone-rsh"))
		host = NULL;

	/* Process options */
			
	while((opt = getopt(argc, argv, "-l:p:46vn")) != -1) {
		switch(opt) {
			case 1:
				if(!host) {
					host = optarg;
					break;
				} else {
					optind--;
					goto done;
				}
			case 'l':
				user = optarg;
				break;
			case 'p':
				port = optarg;
				break;
			case '4':
				af = AF_INET;
				break;
			case '6':
				af = AF_INET6;
				break;
			case 'v':
				verbose = true;
				break;
			case 'n':
				closestdin();
				break;
			default:
				fprintf(stderr, "%s: Unknown option!\n", argv0);
				usage();
				return 1;
		}
	}

done:
	if(!host) {
		fprintf(stderr, "%s: No host specified!\n", argv0);
		usage();
		return 1;
	}
	
	if(optind == argc) {
		execv(BINDIR "/rlogin", argv);
		fprintf(stderr, "%s: Could not execute " BINDIR "/rlogin: %s\n", argv0, strerror(errno));
		return 1;
	}

	if((p = strchr(host, '@'))) {
		user = host;
		*p = '\0';
		host = p + 1;
	}
	
	/* Resolve hostname and try to make a connection */
	
	memset(&hint, '\0', sizeof hint);
	hint.ai_family = af;
	hint.ai_socktype = SOCK_STREAM;
	
	err = getaddrinfo(host, port, &hint, &ai);
	
	if(err) {
		fprintf(stderr, "%s: Error looking up host: %s\n", argv0, gai_strerror(err));
		return 1;
	}
	
	hint.ai_flags = AI_PASSIVE;
	
	for(aip = ai; aip; aip = aip->ai_next) {
		if(getnameinfo(aip->ai_addr, aip->ai_addrlen, hostaddr, sizeof hostaddr, portnr, sizeof portnr, NI_NUMERICHOST | NI_NUMERICSERV)) {
			fprintf(stderr, "%s: Error resolving address: %s\n", argv0, strerror(errno));
			return 1;
		}
		if(verbose) fprintf(stderr, "Trying %s port %s...", hostaddr, portnr);
		
		if((sock = socket(aip->ai_family, aip->ai_socktype, aip->ai_protocol)) == -1) {
			if(verbose) fprintf(stderr, " Could not open socket: %s\n", strerror(errno));
			continue;
		}

		hint.ai_family = aip->ai_family;

		/* Bind to a privileged port */
				
		for(i = 1023; i >= 512; i--) {
			snprintf(lport, sizeof lport, "%d", i);
			err = getaddrinfo(NULL, lport, &hint, &lai);
			if(err) {
				fprintf(stderr, " Error looking up localhost: %s\n", gai_strerror(err));
				return 1;
			}
			
			err = bind(sock, lai->ai_addr, lai->ai_addrlen);
			
			freeaddrinfo(lai);
			
			if(err)
				continue;
			else
				break;
		}
		
		if(err) {
			if(verbose) fprintf(stderr, " Could not bind to privileged port: %s\n", strerror(errno));
			continue;
		}
		
		if(connect(sock, aip->ai_addr, aip->ai_addrlen) == -1) {
			if(verbose) fprintf(stderr, " Connection failed: %s\n", strerror(errno));
			continue;
		}
		if(verbose) fprintf(stderr, " Connected.\n");
		break;
	}
	
	if(!aip) {
		fprintf(stderr, "%s: Could not make a connection.\n", argv0);
		return 1;
	}
	
	/* Create a socket for the incoming connection for stderr output */
	
	if((lsock = socket(aip->ai_family, aip->ai_socktype, aip->ai_protocol)) == -1) {
		fprintf(stderr, "%s: Could not open socket: %s\n", argv0, strerror(errno));
		return 1;
	}
	
	hint.ai_family = aip->ai_family;
	
	freeaddrinfo(ai);
	
	for(i--; i >= 512; i--) {
		snprintf(lport, sizeof lport, "%d", i);
		err = getaddrinfo(NULL, lport, &hint, &lai);
		if(err) {
			fprintf(stderr, "%s: Error looking up localhost: %s\n", argv0, gai_strerror(err));
			return 1;
		}

		err = bind(lsock, lai->ai_addr, lai->ai_addrlen);

		freeaddrinfo(lai);

		if(err)
			continue;
		else
			break;
	}
	
	if(err) {
		fprintf(stderr, "%s: Could not bind to privileged port: %s\n", argv0, strerror(errno));
		return 1;
	}
	
	if(listen(lsock, 10)) {
		fprintf(stderr, "%s: Could not listen: %s\n", argv0, strerror(errno));
		return 1;
	}
	
	/* Drop privileges */
	
	if(setuid(getuid())) {
		fprintf(stderr, "%s: Unable to drop privileges: %s\n", argv0, strerror(errno));
		return 1;
	}
	
	/* Send required information to the server */
	
	bufp[0] = buf[0];
	len[0] = sizeof buf[0];
	safecpy(&bufp[0], &len[0], lport, 1);
	safecpy(&bufp[0], &len[0], luser, 1);
	safecpy(&bufp[0], &len[0], user, 1);

	for(; optind < argc; optind++) {
		safecpy(&bufp[0], &len[0], argv[optind], 0);
		if(optind < argc - 1)
			safecpy(&bufp[0], &len[0], " ", 0);
	}
	safecpy(&bufp[0], &len[0], "", 1);
	
	if(!len[0]) {
		fprintf(stderr, "%s: Arguments too long!\n", argv0);
		return 1;
	}
	
	if(safewrite(sock, buf[0], bufp[0] - buf[0]) == -1) {
		fprintf(stderr, "%s: Unable to send required information: %s\n", argv0, strerror(errno));
		return 1;
	}

	/* Wait for acknowledgement from server */
	
	errno = 0;
	
	if(read(sock, buf[0], 1) != 1 || *buf[0]) {
		fprintf(stderr, "%s: Didn't receive NULL byte from server: %s\n", argv0, strerror(errno));
		return 1;
	}

	/* Wait for incoming connection from server */
	
	if((esock = accept(lsock, NULL, 0)) == -1) {
		fprintf(stderr, "%s: Could not accept stderr connection: %s\n", argv0, strerror(errno));
		return 1;
	}
	
	close(lsock);
	
	/* Process input/output */

	flags = fcntl(sock, F_GETFL);
	fcntl(sock, F_SETFL, flags | O_NONBLOCK);
	flags = fcntl(esock, F_GETFL);
	fcntl(esock, F_SETFL, flags | O_NONBLOCK);
	
	bufp[0] = buf[0];
	bufp[1] = buf[1];
	bufp[2] = buf[2];
	
	FD_ZERO(&infdset);
	FD_ZERO(&outfdset);
	FD_SET(0, &infdset);
	FD_SET(sock, &infdset);
	FD_SET(esock, &infdset);
	
	maxfd = (sock>esock?sock:esock) + 1;
	
	for(;;) {
		errno = 0;
		infd = infdset;
		outfd = outfdset;
		errfd = infdset;
	
		if(select(maxfd, &infd, &outfd, &errfd, NULL) <= 0) {
			if(errno == EINTR)
				continue;
			else
				break;
		}


		if(FD_ISSET(esock, &infd)) {
			len[2] = read(esock, buf[2], BUFLEN);
			if(len[2] <= 0) {
				if(errno != EINTR) {
					if(FD_ISSET(sock, &infdset) || FD_ISSET(1, &outfdset))
						FD_CLR(esock, &infdset);
					else
						break;
				}
			} else {
				FD_SET(2, &outfdset);
				FD_CLR(esock, &infdset);
			}
		}

		if(FD_ISSET(2, &outfd)) {
			wlen = write(2, bufp[2], len[2]);
			if(wlen <= 0) {
				if(errno != EINTR) {
					if(FD_ISSET(sock, &infdset) || FD_ISSET(1, &outfdset))
						FD_CLR(esock, &infdset);
					else
						break;
				}
			} else {
				len[2] -= wlen;
				bufp[2] += wlen;
				if(!len[2]) {
					FD_CLR(2, &outfdset);
					FD_SET(esock, &infdset);
					bufp[2] = buf[2];
				}
			}
		}

		if(FD_ISSET(sock, &infd)) {
			len[1] = read(sock, buf[1], BUFLEN);
			if(len[1] <= 0) {
				if(errno != EINTR) {
					if(FD_ISSET(esock, &infdset) || FD_ISSET(2, &outfdset))
						FD_CLR(sock, &infdset);
					else
						break;
				}
			} else {
				FD_SET(1, &outfdset);
				FD_CLR(sock, &infdset);
			}
		}

		if(FD_ISSET(1, &outfd)) {
			wlen = write(1, bufp[1], len[1]);
			if(wlen <= 0) {
				if(errno != EINTR) {
					if(FD_ISSET(esock, &infdset) || FD_ISSET(2, &outfdset))
						FD_CLR(sock, &infdset);
					else
						break;
				}
			} else {
				len[1] -= wlen;
				bufp[1] += wlen;
				if(!len[1]) {
					FD_CLR(1, &outfdset);
					FD_SET(sock, &infdset);
					bufp[1] = buf[1];
				}
			}
		}

		if(FD_ISSET(0, &infd)) {
			len[0] = read(0, buf[0], BUFLEN);
			if(len[0] <= 0) {
				if(errno != EINTR) {
					FD_CLR(0, &infdset);
					shutdown(sock, SHUT_WR);
				}
			} else {
				FD_SET(sock, &outfdset);
				FD_CLR(0, &infdset);
			}
		}

		if(FD_ISSET(sock, &outfd)) {
			wlen = write(sock, bufp[0], len[0]);
			if(wlen <= 0) {
				if(errno != EINTR)
					break;
			} else {
				len[0] -= wlen;
				bufp[0] += wlen;
				if(!len[0]) {
					FD_CLR(sock, &outfdset);
					FD_SET(0, &infdset);
					bufp[0] = buf[0];
				}
			}
		}

		
	}
		
	if(errno) {
		fprintf(stderr, "%s: %s\n", argv0, strerror(errno));
		return 1;
	}
	
	close(sock);
	close(esock);
	
	return 0;
}
