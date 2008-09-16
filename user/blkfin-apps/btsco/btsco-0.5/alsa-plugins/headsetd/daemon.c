/*
 *
 *  Headset Profile support for Linux
 *
 *  Copyright (C) 2006  Fabien Chevalier
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <syslog.h>
#include <assert.h>

#include <bluetooth/bluetooth.h>
#include <bluetooth/rfcomm.h>
#include <bluetooth/sdp.h>
#include <bluetooth/sdp_lib.h>

#include <config.h>
#include "daemon.h"
#include "sdp.h"
#include "volctl.h"

/* Local defines */
#define PCM_SERVER_SOCKET "\0bluez-headset-pcm"
#define CTL_SERVER_SOCKET "\0bluez-headset-ctl"

/* Local data */
volatile sig_atomic_t terminate = 0;
static   sdp_session_t *sdp_session;

/* Local functions declaration */
static void daemon_checkNewState  (struct Daemon *this);
static int  daemon_dispatchEvents (struct Daemon *this, const short revents[], int pollrvalue);

static void sig_term(int sig);

/* Functions definitions */

int createDaemon(struct Daemon* this)
{
	this->_cur_state     = &HeadsetIdleState;

	openlog("headsetd", LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_DAEMON);
	syslog(LOG_INFO, "Bluetooth headset daemon version " VERSION);

	/* Initialising Applicative PCM server socket */
	int _appl_srv_sockfd = socket(PF_LOCAL, SOCK_STREAM, 0);  
  	if(_appl_srv_sockfd < 0)
  	{
    		syslog(LOG_ERR, "socket(_appl_srv_sockfd): %s", strerror(errno));
    		return -1;
  	}

	struct sockaddr_un  pcm_srv_sock = {
		AF_UNIX, PCM_SERVER_SOCKET
	};
	if(bind(_appl_srv_sockfd, (struct sockaddr *)&pcm_srv_sock, sizeof(pcm_srv_sock)) != 0) {
    		syslog(LOG_ERR, "bind(_appl_srv_sockfd): %s", strerror(errno));
		goto error;	
	}
  
	/* Set socket as non blocking */
	if(fcntl(_appl_srv_sockfd, F_SETFL, O_NONBLOCK) < 0) {
    		syslog(LOG_ERR, "fcntl(_appl_srv_sockfd): %s", strerror(errno));
		goto error;	
	}
	listen(_appl_srv_sockfd, 1);

	/* Initialising Applicative CTL server socket */
	int _appl_ctlsrv_sockfd = socket(PF_LOCAL, SOCK_DGRAM, 0);  
  	if(_appl_ctlsrv_sockfd < 0)
  	{
    		syslog(LOG_ERR, "socket(_appl_ctlsrv_sockfd): %s", strerror(errno));
    		goto error;
  	}

	struct sockaddr_un  ctl_srv_sock = {
		AF_UNIX, CTL_SERVER_SOCKET
	};
	if(bind(_appl_ctlsrv_sockfd, (struct sockaddr *)&ctl_srv_sock, sizeof(ctl_srv_sock)) != 0) {
    		syslog(LOG_ERR, "bind(_appl_ctlsrv_sockfd): %s", strerror(errno));
		goto error2;	
	}
  
	/* Set socket as non blocking */
	if(fcntl(_appl_ctlsrv_sockfd, F_SETFL, O_NONBLOCK) < 0) {
    		syslog(LOG_ERR, "fcntl(_appl_srv_sockfd): %s", strerror(errno));
		goto error2;	
	}
	listen(_appl_ctlsrv_sockfd, 1);

	/* Initialising RFCOMM server socket */
	int _rfcomm_srv_sockfd = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);
  	if(_rfcomm_srv_sockfd < 0)
  	{
    		syslog(LOG_ERR, "socket(_rfcomm_srv_sockfd): %s", strerror(errno));
		goto error2;	
  	}

	struct sockaddr_rc socka;
	socka.rc_family  = AF_BLUETOOTH;
	socka.rc_channel = 1;
	socka.rc_bdaddr  = *BDADDR_ANY;
	/* We loop until we find a free channel to bind to */
	int rfcomm_channel;
	for(rfcomm_channel = 0; (rfcomm_channel == 0) && (socka.rc_channel <= 31); socka.rc_channel += 2) {
		if(bind(_rfcomm_srv_sockfd, (struct sockaddr *)&socka, sizeof(socka)) == 0) {
			rfcomm_channel = socka.rc_channel;
		}
		else if(errno != EADDRINUSE) {
			syslog(LOG_ERR, "bind(_rfcomm_srv_sockfd): %s", strerror(errno));
			goto error3;	
		}
	}
  
	/* Set socket as non blocking */
	if(fcntl(_rfcomm_srv_sockfd, F_SETFL, O_NONBLOCK) < 0) {
    		syslog(LOG_ERR, "fcntl(_rfcomm_srv_sockfd): %s", strerror(errno));
		goto error3;	
	}
	listen(_rfcomm_srv_sockfd, 1);

	/* registering sdp record */
	if((sdp_session = sdp_headset_register(rfcomm_channel)) == 0) {
		goto error3;
	}

	/* FROM THIS POINT WE KNOW WE ARE GOOD */
	hspd_sockets[IDX_PCM_APPL_SRV_SOCK] = _appl_srv_sockfd;
	hspd_sockets[IDX_CTL_APPL_SRV_SOCK] = _appl_ctlsrv_sockfd;
	hspd_sockets[IDX_RFCOMM_SRV_SOCK] = _rfcomm_srv_sockfd;

	/* enter idle state */
	HeadsetIdleState.enter(&HeadsetIdleState);

	/* Initialising signal handlers */
	struct sigaction sa;
	/* setup sigterm handler. we must make sure to do a clean disconnect */
	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sig_term;
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);

	return 0;	

error3:
	close(_rfcomm_srv_sockfd);
error2:
	close(_appl_ctlsrv_sockfd);
error:
	close(_appl_srv_sockfd);
	return -1;
}

static int daemon_dispatchEvents (struct Daemon *this, const short revents_tbl[], int pollrvalue)
{
	short revents;
	const int USLEEP_VALUE = 100000;

	/* Checking if we have been interrupted */
	if(terminate) {
		/* exit from loop */
		return 1;
	}

	/* Checking if timeout */
	if (pollrvalue == 0) {
		struct State *s = this->_cur_state;
		if(s->timedout) {
			s->timedout(s);
			daemon_checkNewState(this);
		}
		else {
	    		syslog(LOG_ERR, "unexpected Timeout happened in state %s", s->name);
		}
		return 0;
	}

	revents = revents_tbl[IDX_CTL_APPL_SRV_SOCK];
	if(revents) {
		struct State *s = this->_cur_state;
		s->readCtlAppl(s, revents);
		return 0;
	}
	revents = revents_tbl[IDX_PCM_APPL_SRV_SOCK];
	if(revents) {
		struct State *s = this->_cur_state;
		if(s->handleApplConnReq) {
			s->handleApplConnReq(s);
			daemon_checkNewState(this);
		}
		else {
	    		syslog(LOG_ERR, "unexpected event handleApplConnReq received in state %s", s->name);
			/* Ending up here means there is a bug, and we have a very high chance
			to end up looping on this forever. So we sleep a bit to avoid eating
			100 % CPU */
			usleep(USLEEP_VALUE);
		}
		return 0;
	}
	revents = revents_tbl[IDX_RFCOMM_SOCK];
	if(revents) {
		struct State *s = this->_cur_state;
		if(s->readRfcomm) {
			s->readRfcomm(s, revents);
			daemon_checkNewState(this);
		}
		else {
			syslog(LOG_ERR, "unexpected event readRfcomm received in state %s",
				s->name);
			/* Ending up here means there is a bug, and we have a very high chance
			to end up looping on this forever. So we sleep a bit to avoid eating
			100 % CPU */
			usleep(USLEEP_VALUE);
		}
		return 0;
	}
	revents = revents_tbl[IDX_PCM_APPL_SOCK];
	if(revents) {
		struct State *s = this->_cur_state;
		if(s->readPcmAppl) {
			s->readPcmAppl(s, revents);
			daemon_checkNewState(this);
		}
		else {
			syslog(LOG_ERR, "unexpected event readPcmAppl received in state %s",
				s->name);
			/* Ending up here means there is a bug, and we have a very high chance
			to end up looping on this forever. So we sleep a bit to avoid eating
			100 % CPU */
			usleep(USLEEP_VALUE);
		}
		return 0;
	}
	revents = revents_tbl[IDX_SCO_SOCK];
	if(revents) {
		struct State *s = this->_cur_state;
		if(s->readSco) {
			s->readSco(s, revents);
			daemon_checkNewState(this);
		}
		else {
			syslog(LOG_ERR, "unexpected event readSco received in state %s",
				s->name);
			/* Ending up here means there is a bug, and we have a very high chance
			to end up looping on this forever. So we sleep a bit to avoid eating
			100 % CPU */
			usleep(USLEEP_VALUE);
		}
		return 0;
	}
	revents = revents_tbl[IDX_RFCOMM_SRV_SOCK];
	if(revents) {
		struct State *s = this->_cur_state;
		if(s->handleRfcommConnReq) {
			s->handleRfcommConnReq(s);
			daemon_checkNewState(this);
		}
		else {
			syslog(LOG_ERR, "unexpected event handleRfcommConnReq received in state %s",
				s->name);
			/* Ending up here means there is a bug, and we have a very high chance
			to end up looping on this forever. So we sleep a bit to avoid eating
			100 % CPU */
			usleep(USLEEP_VALUE);
		}
		return 0;
	}
	revents = revents_tbl[IDX_SDP_SOCK];
	if(revents) {
		struct State *s = this->_cur_state;
		if(s->readSdp) {
			s->readSdp(s, revents);
			daemon_checkNewState(this);
		}
		else {
			syslog(LOG_ERR, "unexpected event handleRfcommConnReq received in state %s",
				s->name);
			/* Ending up here means there is a bug, and we have a very high chance
			to end up looping on this forever. So we sleep a bit to avoid eating
			100 % CPU */
			usleep(USLEEP_VALUE);
		}
		return 0;
	}

	return 0;
}

void daemon_checkNewState  (struct Daemon *this)
{
	struct State *s = this->_cur_state;
	struct State *new = s->getNextState(s);
	this->_cur_state = new;
	if(new != s) {
		syslog(LOG_INFO, "Changing state: %s-->%s", s->name, new->name);
		if(new->enter) {
			new->enter(new);
			/* Transitionnal states may change their state in enter method,
			   so we have to check recursively */
			daemon_checkNewState(this);
		}
	}
}

void daemon_enterLoop(struct Daemon *this)
{
	int done;
	int timeout;
	int ret;
	int i;
	nfds_t poll_nfds;
	struct pollfd pollfds[DAEMON_NUM_SOCKS];
	short revents[DAEMON_NUM_SOCKS];
	do {
		struct State *s = this->_cur_state;
		/* Getting timeout */
		if(s->getTimeout) {
			timeout = s->getTimeout(s);
		}
		else {
			timeout = -1;
		}
		/* Getting file descriptors to poll on */
		poll_nfds = 0;
		for(i = 0; i < DAEMON_NUM_SOCKS; i++) {
		#ifndef NDEBUG	
			/* This may indicate an error, but not always - as such, we disable this
			   warning for release */
			if(hspd_sockets[i] == 0 && s->pollEvents[i] != 0) {
				fprintf(stderr, "WARNING: polling on non existent socket idx=%d\n", i);
			}
		#endif
			if(s->pollEvents[i] != 0) {
				pollfds[poll_nfds].fd     = hspd_sockets[i];
				pollfds[poll_nfds].events = s->pollEvents[i];
				poll_nfds++;
			}
		}

		ret  = poll(pollfds, poll_nfds, timeout);

		/* Putting return events in order */
		poll_nfds = 0;
		for(i = 0; i < DAEMON_NUM_SOCKS; i++) {
			if(s->pollEvents[i] == 0) {
				revents[i] = 0;
			}
			else {
				revents[i] = pollfds[poll_nfds].revents;
				poll_nfds++;
			}
		}

		done = daemon_dispatchEvents(this, revents, ret);
	} while (!done);
}

void daemon_destroy(struct Daemon *this)
{
	syslog(LOG_INFO, "exiting cleanly");
	if(hspd_sockets[IDX_PCM_APPL_SOCK] > 0 ) {
		close(hspd_sockets[IDX_PCM_APPL_SOCK]);
		hspd_sockets[IDX_PCM_APPL_SOCK] = 0;
	}
	if(hspd_sockets[IDX_SCO_SOCK] > 0 ) {
		close(hspd_sockets[IDX_SCO_SOCK]);
		hspd_sockets[IDX_SCO_SOCK] = 0;
	}
	if(hspd_sockets[IDX_RFCOMM_SOCK] > 0 ) {
		close(hspd_sockets[IDX_RFCOMM_SOCK]);
		hspd_sockets[IDX_RFCOMM_SOCK] = 0;
	}
	close(hspd_sockets[IDX_PCM_APPL_SRV_SOCK]);
	hspd_sockets[IDX_PCM_APPL_SRV_SOCK] = 0;
	close(hspd_sockets[IDX_CTL_APPL_SRV_SOCK]);
	hspd_sockets[IDX_CTL_APPL_SRV_SOCK] = 0;
	close(hspd_sockets[IDX_RFCOMM_SRV_SOCK]);
	hspd_sockets[IDX_RFCOMM_SRV_SOCK] = 0;
	sdp_close(sdp_session);
	sdp_session = 0;
	volctl_release();
}

static void sig_term(int sig)
{
	terminate = 1;
}
