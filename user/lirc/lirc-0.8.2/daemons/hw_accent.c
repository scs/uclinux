/****************************************************************************
 ** hw_accent.c *************************************************************
 ****************************************************************************
 *
 * LIRC driver for Kanam/Accent serial port remote control.
 *
 * The Kanam/Accent is a remote control with an IR receiver 
 * connecting to the serial port. The receiver communicate with the 
 * host system at 1200 8N1, so the standard serial driver provided 
 * by the Linux kernel is used.
 *
 * For each keypress on the remote control, a sequence of 13 or 14 
 * bytes is transmitted. We can consider just the first 8 bytes as 
 * significative. Each sequence begins with the three bytes: 0x90 
 * 0x46 0x42. If a key is held-down, a sequence of zeroes is 
 * transmitted. The gap between two different full codes is about 
 * 188500 microseconds. The gap between each zero on a key-hold is 
 * about 56000 microseconds.
 *
 * Sometimes the receiver jams, especially on very short key press. 
 * In this case a uninterrupted stream of zeroes is transmitted, 
 * without the gap of 56000 us. The stream is interrupted if 
 * another key is pressed on the remote or if the driver closes and 
 * reopen the serial port.
 *
 * Unfortunately the LIRC source code is not well documented, so I 
 * hope to have guessed well the workflow of lircd. Please, contact 
 * me if the comments in this source code are not accurate or 
 * clear.
 *
 * Author:	Niccolo Rigacci <niccolo@rigacci.org>
 *
 * Version:	1.1	2007-02-12
 *
 * Original routines from hw_pixelview.c and hw_pinsys.c.
 * First working code for this remote from Leandro Dardini.
 * 
 * Christoph Bartelmus <lirc@bartelmus.de>
 * Bart Alewijnse <scarfboy@yahoo.com>
 * Leandro Dardini <ldardini@tiscali.it>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

/* Functions available for logging (see tools/lircrcd.c).
 *
 * NOTE: if compiled without the DEBUG option and with SYSLOG,
 * you cannot control the amount of debug info sent to syslog,
 * even the LOG_DEBUG messages will be logged.
 *
 * void logprintf(int priority, char *format, ...)
 * 	Calls the syslog(3) function.
 *
 * void logperror(int priority, char *s)
 *	Uses the syslog(3) to print a message followed by the error message
 *	strerror (%m) associated to the present errno.
 *
 * void LOGPRINTF(int priority, char *format, ...)
 *	Calls logprintf(), but only if compiled with DEBUG option.
 *
 * void LOGPERROR(int priority, char *s)
 *	Calls logperror(), but only if compiled with DEBUG option.
*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include "ir_remote.h"
#include "hardware.h"
#include "lircd.h"
#include "serial.h"

#include "hw_accent.h"

// Max number of bytes received in a sequence.
#define ACCENT_MAX_READ_BYTES 16
// Only the first bytes of the sequence are meaning.
#define ACCENT_MEANING_BYTES 8
// The meaning bytes are packed into an integer of this length.
#define ACCENT_CODE_LENGTH 64
// Baud rate for the serial port.
#define ACCENT_BAUD_RATE 1200
#define ACCENT_BAUD_RATE_CONST B1200

static unsigned char b[ACCENT_MAX_READ_BYTES];

// Timestamps of keypress start, keypress end and last pressed key.
static struct timeval start, end, last; 

// Time gap (us) between a keypress on the remote control and the next one.
static lirc_t gap;
// Time (us) of a signal received from the remote control.
static lirc_t signal_length;

// The code of the pressed key and the previous one.
// Type ir_code is unsigned long or unsigned long long.
static ir_code code, last_code = 0;


struct hardware hw_accent = {
	LIRC_DRIVER_DEVICE,       /* default device */
	-1,                       /* fd */
	LIRC_CAN_REC_LIRCCODE,    /* features */
	0,                        /* send_mode */
	LIRC_MODE_LIRCCODE,       /* rec_mode */
	ACCENT_CODE_LENGTH,       /* code_length */
	accent_init,              /* init_func */
	NULL,                     /* config_func */
	accent_deinit,            /* deinit_func */
	NULL,                     /* send_func */
	accent_rec,               /* rec_func */
	accent_decode,            /* decode_func */
	NULL,                     /* ioctl_func */
	NULL,                     /* readdata */
	"accent"
};


//-------------------------------------------------------------------------
// This function is called by the LIRC daemon during the transform of a
// received code into an lirc event.
//
// It gets the global variable code (remote keypress code).
//
// It returns:
//	prep		Code prefix (zero for this LIRC driver)
//      codep		Code of keypress
//	postp		Trailing code (zero for this LIRC dirver)
//      repeat_flagp	True if the keypress is a repeated keypress
//      remaining_gapp	Extimated time gap remaining before next code?
//-------------------------------------------------------------------------
int accent_decode (struct ir_remote *remote,
		   ir_code *prep,
		   ir_code *codep,
		   ir_code *postp,
		   int *repeat_flagp,
		   lirc_t *remaining_gapp)
{
	LOGPRINTF(LOG_DEBUG, "Entering accent_decode(), code = %016llx\n",
		  code);
	
	LOGPRINTF(LOG_DEBUG, "accent_decode() is calling map_code()");
	if (!map_code(remote, prep, codep, postp,
		      0, 0, ACCENT_CODE_LENGTH, code, 0, 0))
	{
		return(0);
	}

	// Check the time gap between the last keypress and this one.
	if (start.tv_sec - last.tv_sec >= 2) {
		// Gap of 2 or more seconds: this is not a repeated keypress.
		*repeat_flagp = 0;
		gap = 0;
	} else {
		// Calculate the time gap in microseconds.
		gap = (start.tv_sec - last.tv_sec) * 1000000 +
			(start.tv_usec - last.tv_usec);
		if(expect_at_most(remote, gap, remote->remaining_gap))
		{
			// The gap is shorter than a standard gap
			// (with relative or aboslute tolerance): this
			// is a repeated keypress.
			*repeat_flagp = 1;
		}
		else
		{
			// Standard gap: this is a new keypress.
			*repeat_flagp = 0;
		}
	}
	
	// Calculate extimated time gap remaining for the next code.
	if (is_const(remote)) {
		// The sum (signal_length + gap) is always constant
		// so the gap is shorter when the code is longer.
		if (remote->gap > signal_length) {
			*remaining_gapp = remote->gap - signal_length;
		} else {
			*remaining_gapp = 0;
		}
	} else {
		// The gap after the signal is always constant.
		// This is the case of Kanam Accent serial remote.
		*remaining_gapp = remote->gap;
	}
	
	LOGPRINTF(LOG_DEBUG, "Exiting accent_decode()");
	LOGPRINTF(LOG_DEBUG, "prep:                   %016llx\n", *prep);
	LOGPRINTF(LOG_DEBUG, "codep:                  %016llx\n", *codep);
	LOGPRINTF(LOG_DEBUG, "postp:                  %016llx\n", *postp);
	LOGPRINTF(LOG_DEBUG, "repeat_flagp:           %d\n",
		  *repeat_flagp);
	LOGPRINTF(LOG_DEBUG, "code:                   %016llx\n", code);
	LOGPRINTF(LOG_DEBUG, "is_const(remote):       %d\n",
		  is_const(remote));
	LOGPRINTF(LOG_DEBUG, "remote->gap:            %lu\n",
		  (unsigned long) remote->gap);
	LOGPRINTF(LOG_DEBUG, "remote->remaining_gap:  %lu\n",
		  (unsigned long) remote->remaining_gap);
	LOGPRINTF(LOG_DEBUG, "signal length:          %lu\n",
		  (unsigned long) signal_length);
	LOGPRINTF(LOG_DEBUG, "gap:                    %lu\n",
		  (unsigned long) gap);
	LOGPRINTF(LOG_DEBUG, "extim. remaining_gap:   %lu\n",
		  (unsigned long) *remaining_gapp);
	
	return(1);
}

//-------------------------------------------------------------------------
// Lock and initialize the serial port.
// This function is called by the LIRC daemon when the first client
// registers itself.
// Return 1 on success, 0 on error.
//-------------------------------------------------------------------------
int accent_init(void)
{
	
	LOGPRINTF(LOG_DEBUG, "Entering accent_init()");
	
	// Calculate the time length of a remote signal (in microseconds):
	// (bits + total_stop_bits) * 1000000 / bitrate
	signal_length = (hw.code_length + (hw.code_length / 8)) * 1000000
		/ ACCENT_BAUD_RATE;
	
	if (!tty_create_lock(hw.device)) {
		logprintf(LOG_ERR,   "Could not create the lock file");
		LOGPRINTF(LOG_EMERG, "Could not create the lock file");
		return(0);
	}
	if ((hw.fd = accent_open_serial_port(hw.device)) < 0) {
		logprintf(LOG_ERR,   "Could not open the serial port");
		LOGPRINTF(LOG_EMERG, "Could not open the serial port");
		accent_deinit();
		return(0);
	}
	return(1);
}

//-------------------------------------------------------------------------
// Close and release the serial line.
//-------------------------------------------------------------------------
int accent_deinit(void)
{
	LOGPRINTF(LOG_DEBUG, "Entering accent_deinit()");
	close(hw.fd);
	tty_delete_lock();
	return(1);
}

//-------------------------------------------------------------------------
// Receive a code (bytes sequence) from the remote.
// This function is called by the LIRC daemon when I/O is pending
// from a registered client, e.g. irw.
//-------------------------------------------------------------------------
char *accent_rec(struct ir_remote *remotes)
{
	char *m;
	int i, j;
	
	LOGPRINTF(LOG_DEBUG, "Entering accent_rec()");
	
	// Timestamp of the last pressed key.
	last = end;
	// Timestamp of key press start.
	gettimeofday(&start, NULL);
	
	// Loop untill read ACCENT_MAX_READ_BYTES or sequence timeout.
	for (i = 0; i < ACCENT_MAX_READ_BYTES; i++) {
		// The function accent_rec() is called when some data
		// is already available to read, so we don't wait on
		// the first byte.
		if (i > 0) {
			// Each of the following bytes must be
			// received within some timeout.  7500 us is
			// the standard time for receiving a byte
			// (wait at least this time) 56000 us is the
			// min time gap between two code sequences
			// (don't wait so much)
			if (waitfordata(45000) == 0) {
				// waitfordata() timed out: the
				// sequence is complete.
				LOGPRINTF(LOG_INFO, "waitfordata() timeout "
					  "waiting for byte %d", i);
				break;
			}
		}
		// Some data available to read.
		if (read(hw.fd, &b[i], 1) == -1) {
			logprintf(LOG_ERR, "read() failed at byte %d", i);
			logperror(LOG_ERR, "read() failed");
			return(NULL);
		} else {
			LOGPRINTF(LOG_INFO, "read() byte %d: %02x", i, b[i]);
		}
	} // End for
	
	// Timestamp of key press end.	
	gettimeofday(&end, NULL);
	
	// The bytes sequence is complete, check its validity.
	LOGPRINTF(LOG_INFO, "Received a sequence of %d bytes", i);
	
	// Just one byte with zero value: repeated keypress?
	if (i == 1 && b[0] == 0) {
		if (last_code && (start.tv_sec - last.tv_sec < 2)) {
			// A previous code exists and the time gap is
			// lower than 2 seconds.
			logprintf(LOG_INFO, "Received repeated key");
			code = last_code;
			tcflush(hw.fd, TCIFLUSH);
			m = decode_all(remotes);
			return(m);
		} else {
			LOGPRINTF(LOG_INFO, "Previos code not set, "
				  "invalid repeat key");
			last_code = 0;
			return(NULL);
		}
	}
	
	// Sequence too short?
	if (i < ACCENT_MEANING_BYTES) {
		logprintf(LOG_NOTICE, "Invalid sequence: too short");
		last_code = 0;
		return(NULL);
	}
	
	// A valid code begins with bytes 0x90 0x46 0x42
	// and it is long not more than ACCENT_MEANING_BYTES.
	if (b[0] == 0x90 && b[1] == 0x46 && b[2] == 0x42) {
		code = 0;
		if (sizeof(code) >= ACCENT_MEANING_BYTES) {
			// We have plenty of space to store the full sequence.
			code |= b[0]; code <<= 8;
			code |= b[1]; code <<= 8;
			code |= b[2]; code <<= 8;
			code |= b[3]; code <<= 8;
			code |= b[4]; code <<= 8;
			code |= b[5]; code <<= 8;
			code |= b[6]; code <<= 8;
			code |= b[7];
		} else {
			// No much space, keep only the differentiating part.
			code |= b[3]; code <<= 8;
			code |= b[4]; code <<= 8;
			code |= b[5]; code <<= 8;
			code |= b[6];
		}
		LOGPRINTF(LOG_INFO, "sizeof(code) = %d", sizeof(code));
		logprintf(LOG_INFO, "Received code -> 0x%016llx", code);
		last_code = code;
		tcflush(hw.fd, TCIFLUSH);
		m = decode_all(remotes);
		return(m);
	}
	
	// Sometimes the receiver goes crazy, it starts to send to the
	// serial line a sequence of zeroes with no pauses at all.
	// This jam terminates only if the user press a new button on
	// the remote or if we close and re-open the serial port.
	if (i == ACCENT_MAX_READ_BYTES) {
		for (j = 0; j < ACCENT_MAX_READ_BYTES; j++)
		{
			if (b[j] != 0) break;
		}
		if (j == ACCENT_MAX_READ_BYTES) {
			// All the received bytes are zeroes, without gaps.
			logprintf(LOG_WARNING, "Receiver jam! "
				  "Reopening the serial port");
			close(hw.fd);
			if ((hw.fd = accent_open_serial_port(hw.device)) < 0) {
				logprintf(LOG_ERR, "Could not reopen the "
					  "serial port");
				raise(SIGTERM);
			}
			last_code = 0;
			return(NULL);
		}
	}
	
	// Should never reach this point.
	logprintf(LOG_NOTICE, "Received an invalid sequence");
	for (j = 0; j < i; j++)
	{
		LOGPRINTF(LOG_NOTICE, " b[%d] = %02x", j, b[j]);
	}
	last_code = 0;
	return(NULL);
}

//-------------------------------------------------------------------------
// Open the serial line and set the discipline (do the low level work).
// Return the file descriptor or -1 on error.
//-------------------------------------------------------------------------
int accent_open_serial_port(char *device) 
{
	int fd;
	struct termios options;
	
	logprintf(LOG_DEBUG, "Entering accent_open_serial_port(), device = %s",
		  device);
	
	// Open the serial device.
	if ((fd = open(device, O_RDWR | O_NONBLOCK | O_NOCTTY | O_SYNC)) < 0) {
		logprintf(LOG_ERR, "Could not open the serial port");
		logperror(LOG_ERR, "open() failed");
		return(-1);
	}
	// Get the parameters associated with the serial line.
	if (tcgetattr(fd, &options) < 0) {
		logprintf(LOG_ERR, "Could not get serial port attributes");
		logperror(LOG_ERR, "tcgetattr() failed");
		return(-1);
	}
	// Set the line in raw mode (no control chars, etc.)
	cfmakeraw(&options);
	// Apply the changes after all the output has been transmitted.
	// Discard input before the change is made.
	if (tcsetattr(fd, TCSAFLUSH, &options) < 0) {
		logprintf(LOG_ERR,
			  "Could not set serial port with cfmakeraw()");
		logperror(LOG_ERR, "tcsetattr() failed");
		return(-1);
	}
	
	// Gets the parameters associated with the serial line.
	if (tcgetattr(fd, &options) < 0) {
		logprintf(LOG_ERR, "Could not get serial port attributes");
		logperror(LOG_ERR, "tcgetattr() failed");
		return(-1);
	}
	// Set input and output baud rate to 1200.
	cfsetispeed(&options, ACCENT_BAUD_RATE_CONST);
	cfsetospeed(&options, ACCENT_BAUD_RATE_CONST);
	// Disable RTS/CTS (hardware) flow control.
	options.c_cflag &= ~CRTSCTS;
	// Set one stop bit.
	options.c_cflag &= ~CSTOPB;
	// Ignore modem control lines.
	options.c_cflag |= CLOCAL;
	// Enable receiver.
	options.c_cflag |= CREAD;
	// Disable parity checking for input.
	options.c_cflag &= ~PARENB;
	if (tcsetattr(fd, TCSAFLUSH, &options) < 0) {
		logprintf(LOG_ERR,
			  "Could not set serial port line discipline");
		logperror(LOG_ERR, "tcsetattr() failed");
		return(-1);
	}
	
	// Discards data received but not read.
	if (tcflush(fd, TCIFLUSH) < 0) {
		logprintf(LOG_ERR, "Could not flush input buffer");
		logperror(LOG_ERR, "tcflush() failed");
		return(-1);
	}
	
	return(fd);
}
