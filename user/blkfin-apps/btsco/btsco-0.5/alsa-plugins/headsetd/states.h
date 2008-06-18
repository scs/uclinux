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

#ifndef STATES_H
#define STATES_H

#include <bluetooth/bluetooth.h>

#include <sockets.h>

struct events {
	short ev[DAEMON_NUM_SOCKS];
};

struct State {
	/* private data */
	struct State    *_next_state;
	/* Mandatory public interface */
	const short      pollEvents[DAEMON_NUM_SOCKS];
	struct State *  (*getNextState)(struct State *s);
	const char       *const name;
	void            (*readCtlAppl)(struct State *s, short revents);
	/* Optionnal public interface */
	void            (*enter)(struct State *s);
	int             (*getTimeout)(struct State *s);
	void            (*timedout)(struct State *s);
	void            (*readPcmAppl)(struct State *s, short revents);
	void            (*readSco)(struct State *s, short revents);
	void            (*readRfcomm)(struct State *s, short revents);
	void            (*readSdp)(struct State *s, short revents);
	void            (*handleApplConnReq)(struct State *s);
	void            (*handleRfcommConnReq)(struct State *s);
};

extern struct State HeadsetIdleState;
extern struct State HeadsetPagingState;
extern struct State HeadsetConnectingState;
extern struct State HeadsetReadyState;
extern struct State HeadsetOpeningState;
extern struct State HeadsetStreamingState;
extern struct State HeadsetConnectedState;
extern struct State HeadsetClosewaitingState;

#endif /* STATES_H */
