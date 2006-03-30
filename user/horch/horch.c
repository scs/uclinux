/*
*++ horch - simple CAN bus analyzer
*-- horch - einfacher CAN Bus Analyzer
 *
 * Copyright (c) 1999-2005 port GmbH, Halle
 *------------------------------------------------------------------
 * $Header$
 *
 *--------------------------------------------------------------------------
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 *
 *
 * modification history
 * --------------------
 * $Log$
 * Revision 1.3  2006/03/30 15:40:47  hennerich
 * Apply horch user application patch/update form port GmbH
 *
 * Revision 1.40.2.2  2006/02/27 11:12:40  hae
 * add GPL header
 * delete old cvs log messages
 * check for valid port number (> 1024)
 * show GPL version in version string
 *
 * Revision 1.40.2.1  2005/08/02 13:49:49  oe
 * - added 'o' interactive command
 *
 *
 * old log information deleted 2005/08/02 oe
 *
*/

/*
* SYNOPSIS
*
* \fBhorch\fR [dtSTV] [-D dev][[-a] -b baud][-C -c id][-l file][-p port][-s time]
*++ Command line options
*++     -a        - advanced - use >baud< as BTR0/1 value
*++     -b baud   - use this baud rate at CAN (in KBit/s, Standard 125)
*++     -C        - interpret message id given with -c as debug message
*++     -c<id>    - use id as debug id
*++     -d        - debug mode, useful for program developer
*++     -l<file>  - Logfilename, logging is enabled/disabled with 'l'
*++     -p<n>     - use portnumber in Servermode, default 7235
*++     -s<time>  - cyclic state (ms)
*++     -t        - show time stamp at start up
*++     -D device - CAN device Name, (z.B can1 (LINUX); 0..2 (Level-X Channel))
*++     -S        - TCP/IP Server Mode
*++     -T        - use OS time not drivers time stamp
*++     -V        - Version
*++.\"additional for EtherCAN
*++.\"    -C        - occupy console focus
*++ additional for LevelX 
*++     -B        - board name (see horch -h) 
*++     -U        - board number (e.g. 1..4 COM port)
*++ OPTIONS
* -a
*++ If specified, the baud value given with -b is used to set directly
*++ the bit-timing registers BTR0 and BTR1.
*++ Low byte is used for BTR0.
* .CS
* horch -ab 0x13c
* .CE
*--Im Moment nur für can4linux implementiert.
*
* -b baud
*++ used baud rate in kbaud.
*++ Without this option
*++ the driver is opened with the value from the file
*++ .I /proc/sys/Can/Baud
*++ (LINUX can4linux)
* .IP -d
*++ Switch debug mode on
*++ Messages about internal states and program flow
*++ are printed to
*++ .B stderr .
*
* -C
* -c CAN-ID
*++ The CAN message ID given as an argument to the -c option
*++ gets a special interpretation if the option -C is set.
*++ It's content is interpretet and displayed as an ASCII character stream.
*++ CAN applications gets the opportunity to send text messages,
*++ e.g. debugging messages via CAN.
*-- Den Debug-Meldungen wird ein \"DEBUG:\" vorangestellt. 
*
* -l filename
*++ The formatted display output can be saved in a local file.
*++ It's default name is
*++ .B logfile .
*++ With this option it is possible to set a new log-file name.
*++ Logging is activated sending a interactive command (see there) to
*++ .B horch .
*++ .br
*++ Logfiles are not created in Server mode.
*
* -p port
*++ The internet protocol uses the
*++ .B "port number"
*++ to address a specific service on an server host.
*++ This is port number 7235 for
*++ .B horch .
*++ The port number can be set at at start time with this option.
*
* -s time
*++ Display CAN controller status information every <time> ms.
*
* -t
*++ By default displaying of the time stamp is disabled at start up.
*++ It can be enabled interactively.
*++ With this option given, it is enabled at start up.
*
*.\" .TP
*.\" -C
*--.\" Belege Console.
*--.\" .br
*--.\" Beim Start auf dem EtherCAN Modul bekommt
*--.\" .B horch
*--.\" die Konsole für Ein-Ausgaben zugeteil.
*++.\" occupy console focus
*++.\" .br
*++.\" When starting
*++.\" .B horch
*++.\" on the EtherCAN
*++.\" the console in/output is occupied by
*++.\" .B horch .
*
* -D dev
*-- Auswahl des verwendeten CAN Kanals (LINUX und Windows Treiber).
*-- .B dev
*-- ist der verwendete Devicename.
*-- Unter Linux wird dieser als /dev/<\fBdev\fR> verwendet.
*-- Voraussetzung ist ein installierter LINUX CAN-Devicetreiber
*-- (can4linux, cpc).
*-- Für CPC unter Windows wird dev entsprechend der Einstellung
*--  in <windir>/cpcconf.ini interpretiert. 
*-- Default ist CHAN00.
*-- Für Level-X unter Windows sind zusätzlich die Optionen 
*
* -B board
* -U unit
*-- notwendig.
*
*-- Bsp. PCI-IntelliCAN unter WinXP:
*-- -BLXN4pi2j -U0 -D0
*
*-- Der richtige Board-Name ist vom verwendeten Treiber 
*-- und vom benutzten Betriebssystem abhängig und 
*-- kann mit der Option -h abgefragt werden. 
*-- Die Unit 0 ist die erste Karte. 
*-- Das Device 0 ist CAN0 der zweikanaligen PCI-IntelliCAN Karte.
*
*++ Select the CAN channel to be used (LINUX).
*++ .B dev
*++ is the device name and is used as /dev/<\fBdev\fR> .
*++ Precondition is a installed LINUX CAN device driver.
*
* -S
*++ Using
*++ .B horch
*++ in the TCP/IP server mode.
*
*++  This server is reachable within the local host as
*++ .I localhost ,
*++ or within a TCP/IP network with the name of the
*++ hosted computer and the port number 7235.
*++ All commands to
*++ .B horch
*++ can be given over socket streams.
*++ For the command mode
*++ the server can also be reached 
*++ with the common
*++ .B telnet
*++ application.
*
* telnet host 7235
*
*++ Telnet should be used with "charcter mode".
*++ In this mode commands are getting immediately effective.
* .CS
* telnet> mode character
* .CE
*
* -T
*++ use operating system time as time stamp.
*++ .br
*++ By default
*++ .B horch
*++ uses the time stamp provided by the driver at receive time.
*++ If the driver does not support time stamps,
*++ the opearting system time can be used.
*++ Usualy this time is not the receive time, rather the display time.
*
* -V
*++ prints the version number to
* .B stdout
*
*++ DISPLAY FORMAT
*++ Received CAN Messages are displayed as ASCII text strings.
*++ The basic format description is:
*
*[timestamp] <id-dec>/0x<id-hex> : <type> : 0{<data>}8
*
*type:	<frametype> + <datatype>
*datatype:	D|R
*frametype	x|s
*
*example:
*  991330039.943806  12/0x00c : sD : 80 12 34 0d 
*  991330039.944806  12/0x00c : xD : 80 12 34 0d 
*  991330039.945806  4660/0x1234 : xR : (length=0)
*  991330039.946806  4660/0x1234 : xD : 01 02 03 04 05 06
*  991330039.947806  4660/0x1234 : xR : (length=4)
*
*++ The message ID is always displayed in decimal and hexa-decimal.
*++ The leading time stamp value is optional and can be activated
*++ by an interactive command.
*++ The format of the displayed data bytes 
*++ can be selected by interactive commands
*++ from decimal, hexa-decimal or ascii characters.
*-- Weitere Meldungen beginnen mit:
*
*-- ERROR:         Fehler
*-- DEBUG:         über CAN empfangene String-Streams
*-- INFO:          Informationen
*
*++ INTERACTIVE COMMANDS
*.B horch
*++ can be controlled through commands from it's stdin channel
*++ (console or TCP/IP).
*++ Most commans consist of one letter
*++ and are used to change formatting of CAN messages.
*++ In the case stdin comes from the console
*++ .B horch
*++ uses the command
*++ .I stty (1)
*++ to switch the console int the
*++ .B "raw, noecho"
*++ mode.
*
* ?
*++ On-line help, command overview
.-- Den Zeilen wird \"INFO:\" vorangestellt.
*
* a
*++ Formatting of data bytes as ASCII characters
*
* b
*++ change bit rate on-line
* .CS
* b 125
* .CE
*-- Jeder gültige CANopen Wert ist zulässig
*++ Every valid CANopen bit rate value is allowed
*
* c
*++ print cut-mark to stdout
*
* d
*++ Formatting of data bytes as decimal numbers
*
* f
*-- Installiert ein Filter für Empfangs Nachrichten
*-- Die Filter-Format Spezifikation ist im Kapitel Filter beschrieben.
*++ Installes a filter for receive messages.
*++ For the format of filter specification see command option -f.
*
* h
*++ Formattting of data bytes as hexa-decimal numbers
*
* i
*++ On LINUX Systems a interpreter program can be startet
*++ which interprets and displays the content of the actual
*++ .B logfile .
*
* l 
*++ toggles state of local file logging.
*++ Logfiles are not created in Server mode.
*
* m acc_code acc_mask
*++ Set the content of acceptance and mask register of the SJA1000 CAN 
*++ controller chip.
*++ With the help of this command a message filter based on the CAN chip
*++ hardware is possible.
*++ (see SJA1000 documentation)
*-- Dieses Kommando ist momentan nur für can4linux verfügbar.
*
*++ acc_code and acc_mask
*++ can be a 32 bit value as decimal or hexadecimal number.
*
* q
* Quit
*++ quit program
*
* R
*++ Reset the CAN controller, e.g. after a Error Busoff.
*
* r
*++ reset the values of
*++ .B horch
*++ statistic variables.
*
* s
*++ display statistic informations
*-- Es gibt hier kein allgemeingültiges Format.
*-- Die Statusinformationen sind vom verwendeten CAN Controller im 
*-- Layer-2 Treiber abhängig.
*-- Die erste Spalte gibt im Klartext den Namen des CAN-Controllers an,
*-- es folgen, als Dezimalzahlen, die Inhalte verschiedener Register.
*-- Für den am meisten verwendeten SJA1000
*-- sieht eine Statistikzeile folgendermasssen aus:
*++ For the most often used CAN controller SJA1000
*++ a statistic line looks like this:
* .LS
* :: sja1000 <act baud rate> <status register> <error_warning limit> <rx errors> <tx errors> <error code> <buslast>
* .LE
*
* t
*++ activate display of time stamps.
*
* T
*++ deactivate display of time stamps.
*
* y
*-- aktivieren des Triggers
*-- Vor der Benutzung dieses Kommandos sollten gültige
*--  Triggereinstellungen vorgenommen werden.
*++ start the trigger
*
* Y
*++ stop the trigger
*
* x
*++ change trigger settings
*++ Format: x idx mask [r] id [data] 
*
* w
* W
*++ send a CAN message
* .br
*-- Eine CAN Message kann gesendet werden.
*-- Nach diesem Kommando werden alle folgenden Zeichen bis zu einem NewLine
*-- als Argumente ausgewertet.
*-- Das Kommando mit Großbuchstaben \fBW\fP wird zum Senden von Nachrichten
*-- im extended Format (29 Bit) benutzt.
*-- Folgt dem Kommandobuchstaben als erstes Argument der Buchstabe \fBr\fP
*-- wird eine RTR Message versendet.
*++ A CAN message is sent.
*++ All of the letters following the command letter are interpreted
*++ as arguments.
*++ The capital command letter \fBW\fP is used to send in extended message
*++ format (using 29 bits)
*++ If the letter \fBr\fP is following the command letter as first argument,
*++ an RTR message is sent.
* .sp
* .CS
* w [r] id  0{data}8
* 
* w 222 0xaa 0x55 100   ; standard message with three data bytes
* w r 0x100 0 0 0       ; standard rtr message with data length code 3
* W 0x100 1 2           ; extended  message with two data bytes
* .CE
*
* H
*++ Formattting of data bytes as hexa-decimal numbers
*++ Opposite to the
*++ .B h
*++ command letter,
*++ CAN message data are stored as binary data as canmsg_t structure
*++ if local file logging is enabled (-l).
*++ All other formats are stored as ASCII character lines.
*
* 
* FILTER
* 
* Format: f1,100-200,555,1200-
* <id>             <id> soll empfangen werden
* <id 1>-<id 2>    <id 1> bis <id 2> sollen empfangen werden 
* <id>-            ab <id> sollen alle Message IDs empfangen werden
* -<id>            bis <id> sollen alle Message IDs empfangen werden
* 
* <id>,<id 1>,<id 2> gehören zum entsprechenden Bereich (einschließlich)
* 
* TRIGGER
* 
* Format: x idx mask [r] id [data] 
*-- .B idx
*-- ist ein Wert zwischen 0 und 2 und spezifiziert einen Triggerpuffer,
*-- Mask ist eine Bitmaske
*-- womit don't care-Bytes in der CAN_Nachricht angegeben
*-- werden.
*-- Ein gesetztes Bit meint, das Datenbyte vom Trigger und von der Message
*-- müssen übereinstimmen.
*-- Ein gelöschtes Bit meint, wenn ein Datenbyte vorhanden ist,
*-- die Message-Länge muß übereinstimmen. 
*-- Der Inhalt des entsprechenden Datenbytes soll ignoriert werden.
*-- 
*-- Ist der 3 Parameter ein \fBr\fP
*-- so wird auf eine RTR-Nachricht hin getriggert,
+-- id ist die gewünschte CAN-ID
*-- .B data
*-- sind optionale Datenbytes der Nachricht 
*++ .B idx
*++ is a value between 0 and 2 and specifies a trigger buffer.
*++ Mask specifies which bytes are don't care bytes.
*++ Is the 2nd parameter a r, so the trigger waits for a RTR Message
*++ id is the wanted CAN-ID,
*++ .B data
*++ are the optional data bytes of the message

*++ CAN ERRORS
*++ Errors recognized  by the driver are displayed at the console
*++ as text messages.
*++ The following messages are known:
*
*"ERROR: OVERRUN"          CAN chip overrun
*"ERROR: PASSIVE"	   Error passive
*"ERROR: BUSOFF"	   Error Busoff (use command R for Bus on)
*"ERROR: Buffer OVERRUN"   Software buffer overrun
*/

#include "horch_cfg.h"

#define MAX_TRIGGER_MESSAGES 3 /* 0,1,2 */


#ifdef TARGET_LX_WIN_BC
# include <canopen.h>
# include <target.h>
# include <conio.h>
#endif /* TARGET_LX_WIN_BC */

#include <string.h>

#include "filter/filter.h"
#include "socklib/socklib.h"

#include <horch.h>

/* global program options, typical o_ but debug */
int debug            = FALSE;
char *log_file       = LOGFILE;
FILE *log_fp         = NULL;
char *fmt            = "%02x ";
unsigned int testCOB = TESTCOB;
int o_debugmessage   = FALSE;
int o_timestamp[HORCH_MAX_CLIENTS]      = {FALSE};
int save_binary      = FALSE;
int show_time        = TRUE;
int o_use_drivers_time = TRUE;
int o_server	     = FALSE;		/* TCP/IP Server */
int o_udpserver	     = FALSE;		/* UDP/IP Server */
int o_focus	     = FALSE;		/* dont switch console if IPC */
long o_period        = 1000000; /* bus load period in us, default 1 sec */
int o_show_status    = FALSE;
#if defined(TARGET_LINUX)
int o_bitrate	     = 0;		/* use /proc/sys/Can/Baud */
#else
int o_bitrate	     = 125;		/* default 125kBit */
#endif
int o_btr            = 0;		/* if set, use o_bitrate as BTR value */
int o_portnumber     = 7235;
char device[40];			/* Device */
#ifdef TARGET_LX_WIN_BC
int board_nr	     = 0;		/* number of device */
extern int o_Device;
#endif /* TARGET_LX_WIN_BC */
#ifdef TARGET_NRAY_WIN_BC
unsigned char canLine;
#endif
#if defined(TARGET_LX_WIN_BC)
extern char *o_boardname_ptr;
#elif defined(TARGET_CPC_ECO) || defined(TARGET_CPC_LINUX)
/* same for unix and Windows - not used for ARM */
/* extern char o_boardname_ptr[]; */
extern char * o_boardname_ptr;
#elif defined(TARGET_NRAY_WIN_BC)
extern char * o_boardname_ptr;
#endif


/* other globals */
#ifdef CONFIG_SK 
unsigned long  lifecount;
#endif

/* Trigger */
unsigned char 	 care_mask[HORCH_MAX_CLIENTS][MAX_TRIGGER_MESSAGES];
char 	 trigger[HORCH_MAX_CLIENTS];
canmsg_t triggermessage[HORCH_MAX_CLIENTS][MAX_TRIGGER_MESSAGES];

/* verbundene Clients */
CLIENT_FD_T client_fd[HORCH_MAX_CLIENTS]; /* socket file descriptor   */

/* Buslast Messung */
float f_busload = 0;        /* global bus load variable */
unsigned int u32_bits = 0;  /* number of received bits within a period */

/* flag to send status information */
static unsigned int flag_show_status[HORCH_MAX_CLIENTS];

/***************************************************************************
* interpreted String buffer
* 
* ro: Die Puffer sind momentan sehr reichlich ausgelegt,
*     da die genaue maximal-Größe unbekannt ist.

* TCPIP_BUFFER_MAX 
*     Momentan werden max. 20 CAN-Nachrichten in den
*     Puffer gepackt. Eine Nachricht hat eine maximale Länge
*     von ca. 60 Byte.
*     Zusätzlich können noch Error-Strings hinzukommen.
*     Damit dürften es nicht mehr als 1200+x Byte werden.
*
* DEBUGMSG_BUFFER_MAX 
*     Der horch kann Debugstrings interpretieren.
*     Er sammelt die Daten bis zu einem Zeilenumbruch.
*     Dann packt er den String in send_line[client][].
*     Normalerweise sollte ein String nicht länger als 60 Zeichen
*     sein, sonst ist er nicht mehr ordentlich darstellbar.
*     Eine Begrenzung existiert aber nicht.
*
*/
char send_line[HORCH_MAX_CLIENTS][TCPIP_BUFFER_MAX];	/* formatted message */
char debug_line[DEBUGMSG_BUFFER_MAX]; /* formatted CAN debug message */

char * buffer_ptr[HORCH_MAX_CLIENTS]; /* pointer to the end of send_line[] */
int buffer_len[HORCH_MAX_CLIENTS];     /* filled buffer len */	

/***************************************************************************/

/* functions */
static char	*sbuf(const unsigned char *s, const int n, const char *fmt,
			char *dest);
static void	usage(char *s);
static void	online_help(unsigned char);
/* static void	clean(void); */
static int	cut_mark(unsigned char);
void 		quit(char *line);
void 		set_trigger( unsigned char client, char *);
char  		compare_msg(const unsigned char, const canmsg_t * const,
			const canmsg_t * const);
int		getopt(int, char * const *, const char *);
void    	add_bits(unsigned char, unsigned char);
static void 	alarmhandler (int signo); 
int		set_bitrate(char *line);


#ifdef DEBUGCODE
/**********************************************************************
* only for internal debugging
*
* add_debugstring
*
* add a line with system time and additional string to the 
* buffer of client 0
*/
void add_debugstring(char *s)
{
char x[100];

return;
    if(client_fd[0] != -1) {
	show_system_time(x);
	strcat(send_line[0], x);
	strcat(send_line[0], s);
    }
}
#endif


/***********************************************************************
* TCPIP Buffer Commands
*
* buffer_ptr .. pointer to the end of send_line[]
* buffer_len .. filled buffer len 	
*/

/*
* buffer_add - String anhängen 
*
* Im Moment wird niemals der Rückgabewert ausgewertet
* Könnte also void sein ??
*
*/
int buffer_add(
	const unsigned char client,
	const char * s 
	)
{
int len = strlen(s);

    /* Overflow Error */
    if (buffer_len[client] + len > TCPIP_BUFFER_MAX) {
	return buffer_len[client];
    }

    strcat(&send_line[client][buffer_len[client]], s);
    buffer_len[client] += len;

    return buffer_len[client];

#if 0
    /* How looks this with using pointers ? */




#endif    
}

/* 
* buffer_remove - (Teil-)String löschen
*
* count == BUFFER_REMOVE_ALL .. ganzen String löschen 
*
*/
int buffer_remove(
	const unsigned char client,
	const int count
	)
{
int len;

    if( count == BUFFER_REMOVE_ALL ) {
    	send_line[client][0] = '\0';
	buffer_len[client] = 0;
    }
    else if( send_line[client][count] == '\0' ) {
    	/* häufiger Fall, gesamter String wurde übertragen und 
    	 * kann gelöscht werden.
    	 */
	send_line[client][0] = '\0';
	buffer_len[client] = 0;
    }
    else 
    {
	if (count >= buffer_len[client]) {
	    /* dieser Fall sollte bereits früher rausfallen */
	    send_line[client][0] = '\0';
	    buffer_len[client] = 0;
	} else {
	    /* Länge des Reststrings ermitteln */
	    len = buffer_len[client] - count;
	    memmove(&send_line[client][0], &send_line[client][count], len);
	    send_line[client][len] = '\0';
	    buffer_len[client] = len;
	}
    }

    return buffer_len[client];
}

/* 
* buffer_size 
*
* Wieviele Zeichen sind im Buffer 
*
*
* is called often, use macro in horch.h
*/

#if 0
int buffer_size(
	const unsigned char client
	)
{
    return buffer_len[client];
}
#endif

/* z.B. add_time() und sbuf() arbeitet direkt im Puffer,
 * daher manchmal resyncronisation notwendig
 * An dieser Stelle aber unbekannt, ob Puffer länger oder kürzer geworden
 * ist.
 *
 * Diese Funktion sollte irgendwann rausfallen.
 */
int buffer_recalc(
	unsigned char client
	)
{
    buffer_len[client] = strlen(send_line[client]);
    return buffer_len[client];
}


/***********************************************************************
* termination_handler
*
*/
void termination_handler(
	int signum		/* signal to handle */
	)
{
    /* avoid warnings */
    signum = signum;

    /* remove the file containing the process id */
#ifdef  LINUX_ARM
    if( -1 == unlink(PIDFILE)) {
	  perror("remove pid file");
    }
#endif
    clean_up();
}

/***************************************************************************
*
* main - main entrypoint
*
*/
int  main(int argc, char * argv[])
{
int i;	/* for-loop variable */
int c,which;
char *options;				/* getopt options string */
extern char *optarg;
#if !defined(TARGET_LINUX)
extern int optind, opterr, optopt;
#endif
char *pname;

#if defined(TARGET_LINUX) 
#  if CAN4LINUXVERSION < 0x0301		/* defined in can4linux.h */
CanSja1000Status_par_t status;
#  else
CanStatusPar_t status;
#  endif
#endif /* TARGET_LINUX */

#if    defined(TARGET_LINUX) \
    || defined(TARGET_CPC_LINUX) \
    || defined(TARGET_LINUX_ARM)
struct itimerval value1, ovalue;
int can_fd;
#endif

/* ÄNDERN */
int client = 0;

    /* var initialization 
     *--------------------------------------------------------------*/
    o_server = TRUE; /* in Servermode weniger Ausgaben erzeugen */
    for(i = 0; i < HORCH_MAX_CLIENTS; i++) {
	client_fd[i] = NO_CLIENT;
	reset_send_line(i, BUFFER_REMOVE_ALL);
	o_timestamp[i] = FALSE; /* default */
	flag_show_status[i] = 0;

	/* MAX_TRIGGER_MESSAGES muss noch genutzt werden */
	/* set trigger messages to 0x000 0x00 0x00 0x00 0x00 ... */
	trigger[i] = 0;
	set_trigger(i," 0 0xff 0x000 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00");
	set_trigger(i," 1 0xff 0x000 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00");
	set_trigger(i," 2 0xff 0x000 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00");
    }
    
    /* Filter auf Defaultwerte setzen */
    filter_init(FILTER_REMOVE);
    o_server = FALSE; /* Defaultvalue */

    
    
    /*--------------------------------------------------------------*/

    pname = *argv;
    sprintf(device, "%s", STDDEV);

    /* common options for all versions */
    options = "CSTVab:c:dhf:l:p:s:tu"
#if defined(TARGET_LINUX)
    		"D:"		/* Driver selection */
#endif
#if defined(TARGET_NRAY_WIN_BC)
    		"D:"		/* Driver selection */
#endif
#if defined(TARGET_CPC_LINUX)
    		"D:"		/* Driver selection */
#endif
#if defined(TARGET_LX_WIN_BC)
    		"D:U:B:"	/* Driver/DriverPort selection */
#endif
#if defined(TARGET_CPC_ECO) && defined(__WIN32__)
    		"D:"	/* Driver/DriverPort selection */
#endif
    ;

    while ((c = getopt(argc, argv, options)) != EOF) {
	switch (c) {
	    case 'C':
		o_debugmessage = TRUE;
		break;
#if defined(TARGET_LINUX) && !defined(TARGET_CPC_ECO)
	    case 'D':
		/* can4linux */
		if (
		    /* path ist starting with '.' or '/', use it as it is */
			optarg[0] == '.'
			|| 
			optarg[0] == '/'
			) {
		    sprintf(device, "%s", optarg);

	        } else {
		    sprintf(device, "/dev/%s", optarg);
		}
		break;
#endif
#if defined(TARGET_LX_WIN_BC)
	    case 'D':
	    	o_Device = atoi(optarg); /* Device number */
	    	break;
	    case 'B':
		o_boardname_ptr = optarg; 	/* Boardname */
		break;
	    case 'U':
		board_nr = atoi(optarg); 	/* Board number */
		break;
#endif
#if defined(TARGET_CPC_ECO) && defined(__WIN32__)
	    case 'D':
	    	/* Win32 version of CPC driver */
	    	/* Device name must be found at cpcconf.ini */
		o_boardname_ptr = optarg;
	    	break;
#endif
#ifdef TARGET_NRAY_WIN_BC
	    case 'D':
	    	canLine = atoi(optarg);
	    	break;
#endif 
#ifdef TARGET_CPC_LINUX
	    case 'D':
		/* Linux version of CPC driver */
		sprintf(device, "/dev/%s", optarg);
		o_boardname_ptr = device;
		break;
#endif
#ifdef TARGET_LINUX_ARM
	    case 'D': /* ignore */
		sprintf(device, "/dev/%s", optarg);
		o_boardname_ptr = device;
		break;
#endif
	    case 'S':
		o_server = TRUE;
		break;
	    case 'T':
		o_use_drivers_time = FALSE;
		break;
	    case 'u':
		o_udpserver = TRUE;
		break;
	    case 'a':
		o_btr |= 1;
		break;
	    case 'b':
		o_bitrate = (int)strtol(optarg, NULL, 0);
		o_btr |= 2;
		break;
	    case 'f':
		read_fp_string(client, optarg);
		break;
	    case 'l':
		log_file = optarg;
		break;
	    case 'd':
		debug = TRUE;
		break;
	    case 'c':
		testCOB =  (int)strtol(optarg, NULL, 0);
		break;
#ifndef CONFIG_SK 
	    case 'p':
		o_portnumber = (int)strtol(optarg, NULL, 0);
		if (o_portnumber < 1024) {
		    fprintf(stderr, "ERROR: Port number %d is not valid.", o_portnumber);
		    fprintf(stderr, "Using default port 7235\n");
		    fflush(stderr);
		}
		break;
	    case 's':
		o_period =  1000 * atoi(optarg);
		o_show_status    = TRUE;
		break;
#endif
	    case 't':
	    	for( i = 0; i < HORCH_MAX_CLIENTS; i++) {
		    o_timestamp[i] = TRUE; /* new default */
		}
		break;
	    case 'V':
		printf("\"horch GPL\""
#ifdef CONFIG_SK
		" SK"
#endif
#if HORCH_MAX_CLIENTS > 1
		" MC(max. %d Clients)"
#endif
		" Revision: %s, %s\n",
#if HORCH_MAX_CLIENTS > 1
		     HORCH_MAX_CLIENTS, 
#endif
		     horch_revision, __DATE__);
	        exit(0);
		break;
	    case 'h':
	    default: usage(pname); exit(0);
	}
    }

    if (debug != 0) {
    	fprintf(stderr, "found Options:\n"); 
    	fprintf(stderr, "  Bitrate: %dkBit/s\n", o_bitrate); 
# ifdef __WIN32__
    	fprintf(stderr, "  Device: %s\n", o_boardname_ptr); 
# endif
	fflush(stderr);
    }

    /* if -a, also -b should be used */ 
    if((o_btr & 1) && (o_btr != 3)) {
	fprintf(stderr, "use always -b baud when specifying -a\n\n");
	usage(pname); exit(0);
    }

#if defined(TARGET_LINUX)
    if(debug) {
	printf("using CAN device %s\n", device);
	if(o_btr & 1) {
	    printf(" use BTR0 = 0x%02x, BTR1 = 0x%02x\n",
			    o_bitrate & 0xff, o_bitrate >> 8);
	} else {
	    printf(" use bitrate %d\n", o_bitrate);
	}
    }
#endif

#if defined(TARGET_LINUX) || defined(TARGET_CPC_LINUX) || defined(TARGET_LINUX_ARM)
     /* Installing Signal handler */
    if (signal (SIGINT, termination_handler) == SIG_IGN)
	signal (SIGINT, SIG_IGN);
    if (signal (SIGHUP, termination_handler) == SIG_IGN)
	signal (SIGHUP, SIG_IGN);
    if (signal (SIGTERM, termination_handler) == SIG_IGN)
	signal (SIGTERM, SIG_IGN);
   /* SIGALRM is used to call cyclic bus load calculation */
    if (signal(SIGALRM, alarmhandler) == SIG_ERR){
        fprintf(stderr,"can't catch SIGALARM");
    }
#endif    
#if defined(TARGET_LINUX)
    /* reading baud rate out of /proc/sys/can/Baud, if o_bitrate == 0; */
    if (o_bitrate == 0) {
        can_fd = open (device,O_RDWR);
	ioctl(can_fd, CAN_IOCTL_STATUS, &status);
	o_bitrate = status.baud;
	close(can_fd);
    } 	
#endif


#if defined(TARGET_LINUX) || defined(TARGET_CPC_LINUX) || defined(TARGET_LINUX_ARM)
    which = ITIMER_REAL;
    value1.it_interval.tv_sec = 0;
    value1.it_interval.tv_usec = o_period;
    value1.it_value.tv_sec = 0;
    value1.it_value.tv_usec = o_period;
    which = setitimer(which, &value1, &ovalue);
#endif /* defined(TARGET_LINUX) */


#ifdef CONFIG_SK
    /* calculate time to life */
    /*           min          */
    lifecount = (60 * 60 * 1000000UL) / o_period; 
#endif

    /* now we are running, put our process id into /var/run */
#if defined(TARGET_LINUX_ARM) || defined(__uClinux__)
    {
    FILE *fp;
    int pid;

    	pid = getpid();
    	fp = fopen(PIDFILE, "w");
    	if( fp == NULL) {
	      perror("open pid file");
    	} else {
	    fprintf(fp, "%d", pid);
	    fclose(fp);
    	}
    }
#endif

    /* configure terminal mode */
    set_up(); /* Hardware- und Umgebungsspezifische Initialisierung */

    if(o_server) {
        if(o_udpserver) {
	    udp_event_loop();
        } else {
	    server_event_loop();
	}
    } else {
	event_loop();
    }

    /* close files and devices, restore terminal settings ,... */
    termination_handler(0);
    return 0;
}



/***************************************************************************
*
* sbuf - show(write in the dest. Buffer) an byte array with format spec
*
* formats n databytes as specified in fmt.
*
* RETURNS
*   pointer to start of the destination string
*
* ro: Warum wird der Anfang des Strings zurückgegeben??
*     -> früher wurde der String ausserhalb der Funktion umkopiert
*/
static char *sbuf(
	const unsigned char *s,	/* pointer to byte array */
	const int n,		/* number of conversions  */
	const char *fmt,	/* printf() format string */
	char *dest		/* destination String buffer  */
	)
{
int i;
int ascii = 0;			/* flag for ascii char display */
char *ptr;


    *dest = 0;
    ptr = dest;
    if( *(fmt+1) == 'c') ascii = 1;
    for(i = 0; i < n; i++) {
        if(ascii) {
	    ptr += sprintf(ptr, fmt, (*s < ' ' || *s > 0x7e) ? '.' : *s);
	    s++;
	} else {
	    ptr += sprintf(ptr, fmt, *s++);
	}
    }

    *(ptr++) = '\r';
    *(ptr++) = '\n';
    *ptr     = '\0';
    return(dest);
}

/***************************************************************************
*
* reset_send_line - Sendepuffer zurücksetzen
*
* Es werden die bereits gesendeten Zeichen aus dem Sendepuffer
* gelöscht. Der Rest des Puffers wird an den Anfang geschoben.
*
* \param decLen
*	um wieviel Zeichen soll gekürzt werden
*	-1 = komplett löschen
*
* RETURNS
*   nothing
*
*/
void reset_send_line(
	const unsigned char client, /* client number */
	const int decLen 	
	)
{
    buffer_remove(client, decLen);
}


/***************************************************************************
*
* add_time - display(write in the buffer) the timestamp 
*
* RETURNS
*   The buffer pointer is going increment.
*/
void add_time( 
	char **pl_ptr,	/* pointer to buffer pointer */
	const canmsg_t *m	/* pointer to message structur */
    )
{
    if ((show_time == TRUE) /*&& (o_timestamp)*/)
    {
	/* first add the timestamp to the line */
	if(o_use_drivers_time) {
	    *pl_ptr += sprintf(*pl_ptr, "%12lu.%06lu  ",
		m->timestamp.tv_sec,
		m->timestamp.tv_usec);
	} else {
	    *pl_ptr += show_system_time(*pl_ptr);
	}

    } /* show_time */
}

/***************************************************************************
*
* show_message - display the formatted CAN message
*
* formats the CAN message according to many flags
*
* RETURNS
* .TP
* nothing
*/
int show_message(
	const canmsg_t * const m	/* pointer to CAN message struct */
	)
{
int j;
#if 0
char *t_ptr;		/* temporärer Zeiger for normal can formatting*/
char **pl_ptr;		/* show to the l_ptr (normal) or d_ptr (debug) */
#endif
char *l_ptr;
static char *d_ptr = &debug_line[0];	/* temporärer Zeiger for debug message*/
int trig_c,trig_f;	/* variables for the trigger */

int len;		/* Stringlänge */

/* for address calculation */
char * ptmp;
int cnt;

register unsigned client;

int fCreated = 0;	/* 1 .. message in String gewandelt */
char pBuffer[100];	/* wenn fCreated == 1, dann wird hier die Nachricht
			   gepuffert */
char pTime[30];		/* wenn fCreated == 1, dann wird hier die Zeit
			   gepuffert */

int fTrigger;		/* ==1 Trigger aktiv - Msg nicht die richtige */ 

    if( (int)(m->id) != -1 ) {
	/* Bus load messurement routines */
	add_bits(m->flags,m->length); 
    }

    /* check for debug message id */
    /* Bei der Debug Message wird Text Angezeigt, und nur bei
     * der ersten eine Timestamp, d.h. wenn kein newline in der message
     * folgt offensichtlich text,
     * und die Timestampanzeige wird unterdrückt.
     * Besser Text in einem sep Puffer sammeln, 
     * und bei der letzten Message, mit Newline, ausgeben.
     */
    if ((o_debugmessage == TRUE) && (testCOB == m->id))  {
    	/* if it is the first CAN Message of the string, add time */
	if (d_ptr == &debug_line[0]) {
	    add_time( &d_ptr, m);
	    strcat(d_ptr, "DEBUG: ");
	    d_ptr = strchr( &debug_line[0], '\0');
	}

#ifdef xxx
	/* Borland-C doesn't know strnlen() */
	/* search linefeed/Carrage return or temporary string end */
	cnt = strnlen((void*)&(m->data[0]), (size_t)(m->length)); 

#else
	cnt = 0;
	while((cnt < 8) && (m->data[cnt] != 0)) {
	    cnt++;
	}
#endif

#if 0
	the glibc strnlen function is very expensive.
	should we therfore better use the while() loop above 
	or the following (uClinux-dist/user/mysql/strings/strnlen.c)
	memchr() is POSIX

	memchr is used anyway later in this function.

    uint strnlen(register const char *s, register uint maxlen)
    {
      const char *end= (const char *)memchr(s, '\0', maxlen);
      return end ? (uint) (end - s) : maxlen;
    }

	Todo:
	combining the two searches for \0 or \n in one loop ?


#endif
	ptmp = memchr((void*)&(m->data[0]), (int)'\n', cnt);
	if (ptmp != NULL) {
		/* Linefeed before String end */
	    cnt = ptmp - ((char*)&(m->data[0])) + 1;
	}
	/* now we have the number of bytes to append from the
	   message (m->data) to the current string (d_ptr)
	 */

	memcpy( d_ptr, m->data, cnt);
	d_ptr += cnt;
	*d_ptr = '\0';
	/*  test for an Carriage return */
	j = cnt - 1;
	if (m->data[j] == '\n')  {
	    /* send Debugmessage to all clients  */
	    for(client = 0; client < HORCH_MAX_CLIENTS; client++) {
		if (client_fd[client] == -1) {
		    continue;
		}

		/* add debugmessage to the send buffer */
		buffer_add(client, &debug_line[0]);
	    }
	    d_ptr = &debug_line[0]; /* reset line */
	}
    } /* Debug Messages */

/* als erstes ganz simpler Fall mit Schleife über alles 
 * -> noch optimieren
 */
    for(client = 0; client < HORCH_MAX_CLIENTS; client++) {
        if (client_fd[client] == NO_CLIENT) {
            continue;
        }
#ifdef DEBUGCODE
	BDEBUG("Bearbeite Client %d bisheriger PufferInhalt %d Zeichen\n",
				client, buffer_size(client));
#endif

	/*--------------------------------------------*/
	/* minimaler Schutz vor TCPIP Buffer Overflow */
	/*--------------------------------------------*/
	/* nochmal versuchen ein paar Zeichen loszuwerden */
	len = buffer_size(client);
	if(len > TCPIP_BUFFER_TRANSMIT ) {
	    display_line(client);
	    /* display_line change the buffer */
	    len = buffer_size(client);
	}

	if(len > TCPIP_BUFFER_STOP) {
	    if( len < TCPIP_BUFFER_MAX - 10) {
	    	buffer_add(client,"ERR\r\n");
	    }
	    continue;
	}

	/* detect special driver flags */
	if( m->flags & MSG_ERR_MASK ) {
	    if( m->flags & MSG_OVR ) {
		if( o_timestamp[client] == TRUE) {
		    l_ptr = &send_line[client][buffer_size(client)];
		    add_time(&l_ptr, m); /* Mmh, arbeitet direkt im Puffer */
		    buffer_recalc(client);
		}

		buffer_add(client, "ERROR: OVERRUN\r\n");
		/* Call skip if message at all is not useful.
		* but continue else. Than we have two lines:
		* 1. overrun
		* 2. message
		*/
		/* goto skip; */
	    }
	    if( m->flags & MSG_PASSIVE ) {
		if( o_timestamp[client] == TRUE) {
		    l_ptr = &send_line[client][buffer_size(client)];
		    add_time(&l_ptr, m); /* Mmh, arbeitet direkt im Puffer */
		    buffer_recalc(client);
		}
		buffer_add(client, "ERROR: PASSIVE\r\n");
	    }
	    if( m->flags & MSG_BUSOFF ) {
		if( o_timestamp[client] == TRUE) {
		    l_ptr = &send_line[client][buffer_size(client)];
		    add_time(&l_ptr, m); /* Mmh, arbeitet direkt im Puffer */
		    buffer_recalc(client);
		}
		buffer_add(client,"ERROR: BUSOFF\r\n");
	    }
	    if( m->flags & MSG_BOVR ) {
		if( o_timestamp[client] == TRUE) {
		    l_ptr = &send_line[client][buffer_size(client)];
		    add_time(&l_ptr, m); /* Mmh, arbeitet direkt im Puffer */
		    buffer_recalc(client);
		}
		buffer_add(client, "ERROR: Buffer OVERRUN\r\n");
	    }
	} /* CAN Errors */

	/* count display lines for statistical and debugging  reasons */


	/* Msg-ID == -1 bedeutet Error Message statt CAN Message */
	/* Debugmessages ignorieren */
	if ((o_debugmessage == TRUE) && (testCOB == m->id))  {}
	else if (m->id == (unsigned long)-1) {}
	else {

#ifdef _DEBUGCODE
	/*--------------------------------------------*/


		printf("-------------------------------------\n");
		printf("Bearbeite Msg für client %d\n", client);
#endif	

	    if( filter(client, m->id) == TRUE ) {
		/*--------------------------------------------*/
		/* Datenstring wird nur einmal generiert und an weitere 
		 * Clients weitergegeben. 
		 * fCreated == 0 : erster Client
		 * fCreated == 1 : folgende Clients
		 */
		if( fCreated == 0) {
		    fCreated = 1;

		    pTime[0] = '\0';
		    l_ptr = &pTime[0];
		    add_time(&l_ptr, m); /* Zeit puffern */
		    
		    pBuffer[0] = '\0';
		    l_ptr = &pBuffer[0]; /* Message puffern */
		/*--------------------------------------------*/

		    /* No debug message, display message ID */
		    show_time = TRUE; /* ?????????? */

		    l_ptr += sprintf(l_ptr, "%4ld/0x%03lx : ", m->id, m->id);
		    if( m->flags & MSG_EXT ) {
			/* if message is in extended format, flag it */
			/* l_ptr += sprintf(l_ptr, "x"); */
			strcat(l_ptr, "x");
			l_ptr++;
		    } else {
			/* if message is in standard format, flag it */
			/* l_ptr += sprintf(l_ptr, "s"); */
			strcat(l_ptr, "s");
			l_ptr++;
		    }

		    if( m->flags & MSG_RTR ) {
			l_ptr += sprintf(l_ptr, "R : (length=%d)\r\n",
			                              (int)m->length);
			/* don't format data bytes, was RTR */
		    } else {
/* fprintf(stderr, "Bitval=%x, f=%x, Test=%x\n",  MSG_SELF, */
	/* m->flags, m->flags & MSG_SELF); */
		        if( m->flags & MSG_SELF) {
			    strcat(l_ptr, "d : ");
		        }
		        else {
			    strcat(l_ptr, "D : ");
		        }
			l_ptr += 4;
			/* format the data bytes */
			sbuf(m->data , m->length, fmt, l_ptr);
		    }
		} /* fCreated */

		/* check for trigger */
		fTrigger = 0;

    		/* ERROR Messages should pass the Trigger */
		if (((m->flags & MSG_ERR_MASK) == 0) && (trigger[client] == 1))
		{
		    fTrigger = 1;
		    trig_f = 0; /* Trigger Flag */
		    for (trig_c = 0; (trig_c < MAX_TRIGGER_MESSAGES)\
		    			&& (trig_f == 0); trig_c ++) 
		    {
			/* returns != 0, if the m the message, 
			 * the we want to receive 			*/
			trig_f |= compare_msg(care_mask[client][trig_c], m,
					    &triggermessage[client][trig_c]);
		    }

		    if (trig_f != 0 )  {
			/* Triggermessage found, disable Trigger */
			trigger[client] = 0;
			fTrigger = 0;
#ifdef DEBUGCODE
			printf("Trigger client %d found\n", client);
#endif
		    } else {
#ifdef DEBUGCODE
			printf("not the Trigger message client %d\n", client);
#endif
		    }
		}

		if( fTrigger == 0) {
		    /* Clients Messages schicken */
		    if( o_timestamp[client] == TRUE) {
			buffer_add(client, &pTime[0]);
		    }
		    buffer_add(client, &pBuffer[0]);
		}
	    } /* filter */

	} /* CAN Message */	


/* skip: */
    

	if(!o_server) {
	    /* in local mode only save to logfile */
	    /* in local mode, sending to stdout, print each line */
	    if(log_fp) {
		/* log data to file */
		if(save_binary) {
		    /* log data to file */
		    /* src, length count, fp */
		    fwrite((void *)m, sizeof(canmsg_t), 1, log_fp);
		} else {
		    fprintf(log_fp, "%s", &send_line[0][0]);
		}
	    }

	    /* Console more -> Client 0 */	
	    display_line(0);
	} /* !o_server */
    } /* client loop */

    for(client = 0; client < HORCH_MAX_CLIENTS; client++) {
        if (client_fd[client] == -1) {
            continue;
        }
#if 0 && (defined(TARGET_LINUX_ARM) || defined(__uClinux__))
/* search for better algorithm */
	/* nicht alle Puffer gleichzeitig senden */
	/* Gilt an dieser Stelle nur, wenn viele CAN Messages zu verarbeiten
	 * sind. Wenn alle CAN Messages bearbeitet sind, werden sowieso
	 * alle Puffer gesendet.
	 *
	 * Bei nur einem Client kein positiver oder negativer Effekt.
	 */
	{
	static unsigned char tcpcnt = 0;
	int len = buffer_size(client);
	
	    if( len > 2 * TCPIP_BUFFER_TRANSMIT ) {
	    	/* Schutz, damit der Puffer nicht zu voll wird */
	        tcpcnt = 0;
	    }
	    
	    if( tcpcnt-- == 0) {
	    	/* Puffer der verschiedenen Clients möglichst 
	    	 * zu unterschiedlichen Zeiten verschicken */
		if( len > TCPIP_BUFFER_TRANSMIT )
		{ 
		    /* transmit buffer */
		    display_line(client);
		    tcpcnt = 5; /* nicht zu gross wählen */
		}
	    } 
	}
#else	/* TARGET_LINUX_ARM */
	/* Prüfen, ob der Puffer fast voll ist, dann zusätzlich hier leeren */
	if( buffer_size(client) > TCPIP_BUFFER_TRANSMIT )
	{ 
	    /* transmit buffer */
	    display_line(client);
	}
#endif /* TARGET_LINUX_ARM */
    } /* client loop */
    
    return 0;
}

/*******************************************************************

Interpretation der Eingaben
es werden Kommandobuchstaben ausgewertet.
Die meisten Funktionen ändern das Ausgabeformat der CAN Nachricht.

Kommando 'c'
gibt eine Begrenzungslinie aus.
Bei der Ausgabe zum Socket stream kann ein Schreibfehler vorkommen.

RETURNS
.TP
OK
.TP
-1
Error while sending to socket

-->
ACHTUNG:
--------

In späteren Versionen wird es keine Tastenkommandos mehr geben.
Dann muß jedes Kommando mit einen '\n' beendet werden.
**********************************************************************/
int change_format(unsigned char client, char c)
{
static unsigned char line[MAX_CLINE];/* command line buffer		*/
static char command = 0;	/* collect data for a complete line	*/
static int cnt = 0;		/* count input chars			*/

# ifdef CONFIG_DRIVER_TEST
    if (debug != 0) {
    	if((c >= 32) && (c < 0x7F)) {
	    printf("change_format 0x%02x/%c\n", (int)c, c);
	} else {
	    printf("change_format 0x%02x\n", (int)c);
	}
    }
# endif

/* =================================================================*/
/* Fehlerprüfung */
    {
    static int oldclient;
	if(cnt == 0) {
	    oldclient = client;
	} else {
	    if( oldclient != client) {
		fprintf(stderr,"ERROR: change_format() " \
					    "command mix of two clients!\n");
		return -1;
	    }
	}
    }
/* Fehlerprüfung end */
/* =================================================================*/

    if(command != '\0') {
    /* =================================================================*/
    	/* add character to command line */
    	if(c != '\n' && c != '\r') {
    	    if(cnt == MAX_CLINE) {
		command = '\0';
		cnt = 0;
		return 0;
	    }
	    line[cnt++] = c;
    	} else {
	    /*
	     * end of line, give it to a function.
	     * Line does not start with the command letter
	     * and does not end with Newline
	     */
	    line[cnt] = '\0';
	    /* first select function which has requested a line  */
	    switch(command) {
		case 'w':	/* write */
		    write_message(0, &line[0]);
		    break;
		case 'W':	/* write */
		    write_message(1, &line[0]);
		    break;
		case 'f':	/* filter */
		    read_fp_string(client, &line[0]);
		    break;
		case 'b':	/* bit rate */
		    set_bitrate(&line[0]);
		    break;
		case 'm':	/* acceptance mask */
		    set_acceptance(&line[0]);
		    break;
	        case 'o':	/* set various option parmeters */
		    set_options(&line[0]);
		    break;
	        case 'x':	/*set Trigger parameter  */
	            set_trigger(client,&line[0]);
	            break;
	        case 'Q':	
	            quit(&line[0]);
	            break;
		default: break;
	    }
	    command = '\0';	/* reset command -- finished */
	    cnt = 0;		/* and char counter */
    	}
    } else {
    /* =================================================================*/
        /* interpret character as command */
	switch(c) {
	/* define letters for commands which are collecting a line      */
	    case 'f':		/* filter command, collects line        */
	    case 'w':		/* write command, collects line         */
	    case 'W':
	    case 'o':		/* collects option parameter            */	
	    case 'x':		/* collects line for trigger settings   */
	    case 'Q':		/* collects line for Quit command       */
/* #if defined(TARGET_LINUX) || defined(__WIN32__) */
#if defined(linux) || defined(__WIN32__)
	    case 'm':
	    /* set acceptance and mask register in case of SJA1000 */
	    case 'b': 		/* set bit rate */
#endif
	    	command = c;
		break;
	/*--------------------------------------------------------------*/
	    case 'a':		/* ASCII format */
		fmt = "%c";
		break;
	    case 'c':
		/* put 'cut'-mark at display */
		return(cut_mark(client));
	    case 'd':		/* decimal format */
		fmt = "%03d ";
		break;
	    case 'h':		/* hex format */
		fmt = "%02x ";
		save_binary = FALSE;
		break;
#ifdef TARGET_LINUX
	    case 'i':
		system("konvert -L -x std.int -n std.nam logfile | less");
		break;
#endif
	    case 'l':
		if(log_fp) {
		    /* log file already opened */
		    fprintf(stderr, "close log file: %s\n",
						    log_file);
		    fclose(log_fp);
		    log_fp = NULL;
		} else {
		    /* must open log file 
		     * doing this with deleting the old file
		     */
		    if( (log_fp = fopen(log_file, "w")) == NULL ) {
			fprintf(stderr, "open log file error %d;",
							    errno);
			perror("");
		    }
		    fprintf(stderr, "opened log file: %s (%s)\n",
			    log_file,
			    (save_binary ? "binary" : "Ascii"));
		}
		break;
	    case 'R':
	    /* Reset the CAN controller */
	        sprintf(line, "%d", o_bitrate);
		set_bitrate(&line[0]);
		break;
	    case 'q':
	        if(o_server) {
		    /* only for test purposes a client can finish the server */
		    /* clean_up(); */
		    return -1;
	        } else {
		    clean_up();
		}
		break;
	    case 'r':			/* toggle self reception */
		break;
	    case 's':		/* show statistik */
		{
		    flag_show_status[client] = 1;
		    sendStatisticInformation(client); /* remove later */
		}
		break;
	    case 't':		/* activate time stamp display */
#ifdef DEBUGCODE
		BDEBUG("Client %d Timestamp on\n", client);
#endif	
		o_timestamp[client] = TRUE;
		break;
	    case 'T':		/* de-activate time stamp display */
#ifdef DEBUGCODE
		BDEBUG("Client %d Timestamp off\n", client);
#endif	
		o_timestamp[client] = FALSE;
		break;
	    case 'H':		/* Hex format and binary log */
		fmt = "%02x ";
		save_binary = TRUE;
		break;
	    case '?':
		online_help(client);
		break;
	    case 'y':		/* start trigger */
	    	trigger[client] = 1;
	    	if((!o_server) || (debug != 0)) {
	    	    printf("Start Trigger\n");
	    	}
	    	break;
	    case 'Y':		/* stop trigger */
	        trigger[client] = 0;
	    	if((!o_server) || (debug != 0)) {
	    	    printf("Stop Trigger\n");
	    	}
	        break;
	    case 'V':		/* Version Information */
	    	{
		    sendVersionInformation(client);
		}
	    	break;
	    case 'F':		/* Last Filter String */
		sendFilterInformation(client);
	        break;
	    default:
		break;
	}
    }

    return 0;
}


/***********************************************************************
*
* usage - print usage of the command to stderr
*
* RETURN: N/A
*
*/
static void usage(
	char *s			/* program name */
	)
{
static char *usage_text  = "\
"
#ifdef TARGET_LINUX
"\
-D<device>   - name use CAN device name /dev/<device>, default is %s\n\
"
#endif
#ifdef TARGET_CPC_LINUX
"\
-D<device>   - name use CAN device name /dev/<device>, default is %s\n\
"
#endif
#ifdef TARGET_LX_WIN_BC
"\
-D<channel>  - Channel number from Level-X Board\n\
-B<board>    - Board name of the Level-X Board\n\
-U<number>   - Board number of the selected Board(only for registry use)\n\
"
#endif
#if defined(TARGET_CPC_ECO) && defined(__WIN32__)
"\
-D<channel>  - Channel name from EMS Board found in cpcconf.ini\n\
"
#endif
"\
-C           - enable debug message\n\
-c<id>       - use id as debug id, default %d\n\
-S           - TCP/IP Server mode\n\
-T           - dont use drivers timestamp, use OS time\n\
-a           - advanced - use \"baudrate\" as BTR0/1 value\n\
             - (Bit 0..7 BTR0 // Bit 8..15 BTR1)\n\
-b<baudrate> - CAN Baudrate (Standard 125)\n\
-d           - debug On\n\
"
/* -f<spec>  - specification for receive message filter\n\ */
"-l<file>    - Logfilename, logging is enabled/disabled with 'l'\n\
-p<n>        - use portnumber in Servermode, default %d\n\
-s<time>     - send status information every <time> ms\n\
-t           - activate time stamp at start up\n\
"
/* -u    - use UDP\n\ */
"-V          - Version\n\
\n\
for interactive commands press \'?\'\n\
";
    fprintf(stderr, "usage: %s options\n", s);
    /* fprintf(stderr, usage_text, STDDEV, testCOB, o_portnumber); */
#ifdef TARGET_LINUX
    fprintf(stderr, usage_text, STDDEV, testCOB, o_portnumber);
#elif defined(TARGET_CPC_LINUX)
    fprintf(stderr, usage_text, STDDEV, testCOB, o_portnumber);
#elif defined(TARGET_LX_WIN_BC)
    fprintf(stderr, usage_text, testCOB, o_portnumber);
    /* erstmal auf die Schnelle */
    fprintf(stderr,"<wait>\n");
    while( !kbhit() ){};
    scan_lx_ini("board.ini", NULL, 0, 0);
#elif defined(TARGET_CPC_WIN_BC) || defined(TARGET_AC2_WIN_BC)
    fprintf(stderr, usage_text, testCOB, o_portnumber);
#elif defined(TARGET_LINUX_ARM)
    fprintf(stderr, usage_text, testCOB, o_portnumber);
#else
    fprintf(stderr, usage_text, STDDEV, testCOB, o_portnumber);
#endif
}

/***********************************************************************/
static void online_help(unsigned char client)
{
static char usage_text[][100]  = {
"\t\tOn-line help\r\n",
"\t\t============\r\n",
"?        - show On-line help\r\n",
"V        - Version Information\r\n",
"l        - switch file logging to \"%s\" %s\r\n",
"i        - start data interpreter\r\n",
"\r\n",
"a/d/h/H  - show data in ascii/dec/hex/hex\r\n",
"s        - statistic\r\n",
"o <val>  - set or reset option flags\r\n",
"t/T      - activate/deactivate timestamp display\r\n",
"w/W      - write message (Std/Ext)\r\n",
"F/f <range>     - get/set receive message filter\r\n",
"m <code> <mask> - change acceptance mask\r\n",
"x <trigger>     - set a trigger\r\n",
"y/Y      - set/stop trigger\r\n",
"b <baud> - change bit rate\r\n",
"R        - reset CAN\r\n",
"\r\n",
"c - put 'cut'-mark at display\r\n",
"^Q/^S start/stop; q - Quit\r\n",
};
char helpbuf[2048]; /* erst einmal */
char * phelp = &helpbuf[0];

char timebuf[20]; /* erst einmal */
int cnt;
int max = sizeof(usage_text)/sizeof(usage_text[0]); /* Zeilenzahl */

    cut_mark(client);

    if( o_timestamp[client] == TRUE) {
	show_system_time(&timebuf[0]);
    } else {
    	timebuf[0] = '\0';
    }

    for (cnt = 0; cnt < max; cnt++) {
	phelp += sprintf(phelp, "%s INFO: ", timebuf);
	phelp += sprintf(phelp, usage_text[cnt],
		    log_file, (log_fp) ? "Off" : "On"	/* -l */
		    );
	
    }

    buffer_add(client, helpbuf);
    cut_mark(client);
}


/***********************************************************************
* cut_mark - Linie darstellen
*
*/
static int cut_mark(
	unsigned char client
	)
{
static char line[70] =  "----------------------------------------\r\n";


    buffer_add(client, line);
    if(display_line(client) == -1) {
	return -1;
    } 
    return 0;
}

/******************************************
* quit - check for quit condition
* 
* RETURNS:
*
* nothing
********************************************/
void quit(		
        char *line	/* parameter line */
    ) /* idx dont_care RTR id data */
{
    if(strcmp(line, "uit") == 0) {
	clean_up();
    }
}


void	set_options(
	char *line
	)
{
char *endptr = 0;			/* unsigned char **endptr; */
unsigned char *lptr;
unsigned int flag;
    
    lptr = &line[0];
    skip_space(lptr);

    flag = strtoul(lptr, &endptr, 0);
    /* flag = strtoul(lptr, &endptr, 0); */

    if(debug) {
	printf(" Called Options with Flag=%x\n", flag);
    }


    if (flag & OPTION_SELF) {
	set_selfreception(1);
    } else {
	set_selfreception(0);
    }
    /* --------- */
    if (flag & OPTION_LISTENONLY) {
	;
    } else {
	;
    }
    if (flag & OPTION_TIMESTAMP) {
	set_timestamp(1);
    } else {
	set_timestamp(0);
    }
    /* --------- */
}
/**************************************************************************/
/**
*
* \brief display_line - displays the formatted CAN message 
*
* \param client
*	client number
*
* \param line
*	line to display on the client
*	display/sent characters will remove from the line
*
* \retval >=0
* 	number of sent characters
* 
* \retval <0
* 	error
*
*/
int display_line(
	const unsigned char client 	/* client number */
	)
{
int len;
int retval;

char *line;		/* string to send to the client */

    line = &send_line[client][0];

#ifdef DEBUGCODE
    if( buffer_size(client) != 0 ) {
	BDEBUG("display_line fd %d client %d len %d\n", 
    		client_fd[client], client, buffer_size(client));
    }
#endif    


    /* nothing to display/send */
    if(*line == '\0') return 0;

    len = buffer_size(client);

    if(o_server) {

	if(o_udpserver) {
	    retval = sendto(client_fd[client], (void *)line, len, 0,
	    		(struct sockaddr *)&fsin, sizeof(fsin) );
	} else {

#ifdef __WIN32__	    
	    retval = send(client_fd[client], (void *)line,\
					    len , 0);
#else /* __WIN32__ */	    
	    retval = send(client_fd[client], (void *)line,\
					len , MSG_NOSIGNAL);
/* printf("display_line ret %d\n", retval); */
#endif /* __WIN32__ */

	}
    } else {

	fprintf(stdout, line); 
	fflush(stdout);

	retval = len;
    }

    /* remove displayed/sent characters */
    if(retval > 0) {
	reset_send_line(client, retval);
    }

    return(retval);
}


/**************************************************************************/
/**
* sendStatisticInformation
*
* send statistic information, if possible
*/

void sendStatisticInformation(int client)
{
    /* send Status/Statistic information */
    if(flag_show_status[client] == 1) {

	    /* '::' start statistic info */
	char line[400], templine[400];
	char line2[40];

	getStat(&line[0]); /* fills line !! */

	if (memchr( line, '%', strlen(line)) == NULL) {
	    sprintf(line2," %.1f\r\n",f_busload);
	    strcat(line,line2);
	    buffer_add(client,line);
	} else {
	    /* need better solution! */
	    sprintf(line2," %.1f ",f_busload);
	    sprintf(templine, line, line2);
	    strcat(templine, "\r\n");
	    buffer_add(client,templine);
	}

	display_line(client);
    
	flag_show_status[client] = 0;
    }
}

/**************************************************************************/
/**
* sendVersionInformation
*
* send Version information 
* about horch and driver/Hardware
*
*/
void sendVersionInformation(int client)
{
char s[400];
    /* ':V' start Version info */
#if defined(TARGET_CPC_ECO) && defined(__WIN32__)
    buffer_add(client, ":V CPC Win32;"); 
#elif defined(TARGET_LINUX)
    buffer_add(client, ":V can4linux;"); 
#else
    /* later Hardwareinterface */
    buffer_add(client, ":V horch;"); 
#endif
    sprintf(s, " horch GPL V%s; %d Clients;",
	    horch_revision, HORCH_MAX_CLIENTS);
    buffer_add(client, s);
    buffer_add(client, getLayer2Version());
    buffer_add(client, ";\r\n");
    display_line(client);
}


/**************************************************************************/
/**
* sendFilterInformation
*
* send current Software Filter settings
*/
void sendFilterInformation(int client)
{
    buffer_add(client, ":F ");
    getFilterParams( client, &send_line[client][buffer_len[client]], 0);
    buffer_recalc(client);
    buffer_add(client, "\r\n");
    display_line(client);
}



/* ***********************************************************
*
* The function compare_msg compares two CAN-Messages
* If message2.length == 0, only the ID and the RTR-flag are compared
*
* ret=compare_msg(msg1,msg2);
*
* At the Moment:
* 	Message 'eins' - received Message
*	Message 'zwei' - Trigger Message
*
* return: 
* 0 if messages are unequal , not 0 if messages are equal
************************************************************/

char compare_msg(
      const unsigned char     dont_care, /* select don't care bytes in the message */
      const canmsg_t * const eins,  /* first message */
      const canmsg_t * const zwei   /* second message */
      )
{
register int temp2;

    /* compare id */
    if (eins->id != zwei->id) {
        return(0);
    }

    /* compare flags , only RTR */
    if ((eins->flags & MSG_RTR) != (zwei->flags & MSG_RTR)) 
    {
        return(0);
    }
    
    /* compare length 
     * ID is the same and the triggermessage(zwei) say, 
     * that we anly want to check the Message ID */
    if (zwei->length == 0) {
        return (1);
    } 

    if (eins->length != zwei->length) {
        return (0);
    }
    
    /* compare data - length is the same 
     * Data Frames - only bytes without set 'don't care' bit are compared
     * RTR Frames - all 'don't care' bits must se
     */ 
    for(temp2 = 0; temp2 < zwei->length; temp2++ ){
	if ( ((dont_care >> temp2) & 0x01) == 1 ) {
	    if (eins->data[temp2] != zwei->data[temp2]) {
	       return(0);
	    }
	}
    }

#ifdef DEBUGCODE 
    if (debug == TRUE) {
    	printf("compare\n");
	for(temp2 = 0; temp2 < zwei->length; temp2++ ){
	    printf("%x", eins->data[temp2]);
	}
	printf("\n");
	for(temp2 = 0; temp2 < zwei->length; temp2++ ){
	    printf("%x", zwei->data[temp2]);
	}
	printf("\n");
    }
#endif 	/* DEBUGCODE */
    
    return(2);
} /* end of function compare_msg */

/******************************************
* set_trigger - sets the trigger messages
* 
* interpret the line-String for a Trigger Message
*
* Example:
*
*    set_trigger(" 0 0xff 0x000 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00");
*
*    1.param: Number of Trigger buffer /Trigger Message
*    2.param: don't care bytes - bit coded
*    optional: 'R' or 'RTR' for Remote Frames
*    3.param: Message ID
*    4..11.param: Data bytes
*
* RETURNS:
*
* nothing
********************************************/
void set_trigger(
	unsigned char client,
        char *line	/* set_trigger parameter line */
    ) /* idx dont_care RTR id data */
{
char *lptr;
char *endptr;
int len = 0;
int idx = 0;

#ifndef DEBUGCODE
    if ((debug == TRUE) || (!o_server)) 
    {
	printf("set_trigger client %d\n", client);
	printf("%s\n", line);
    }
#endif

    /* May be some check is needed if we have a valid and useful message */
    lptr = &line[0];
    skip_space(lptr);
    idx = (unsigned char) strtoul(lptr, &endptr,0);
    if (idx > (MAX_TRIGGER_MESSAGES - 1)) { 
       return;
    }
    skip_word(lptr);
    skip_space(lptr);
    
   /* don't care byte */
    care_mask[client][idx] = 
    		(unsigned char) strtol(lptr, &endptr,0);
    skip_word(lptr);
    skip_space(lptr);
  
   /* RTR */
   if(*lptr == 'r' || *lptr == 'R') {
	triggermessage[client][idx].flags = MSG_RTR;
	skip_word(lptr);
   } else {
	triggermessage[client][idx].flags = 0;
   }

   skip_space(lptr);

   /* ID */ 
   triggermessage[client][idx].id = (unsigned int)strtoul(
   				(char*)lptr, (char**)&endptr, 0);
   while( lptr != endptr ) {
        lptr = endptr;
        triggermessage[client][idx].data[len] = 
			(unsigned char)strtol((char*)lptr, (char**)&endptr, 0);
	if(lptr != endptr) { 
	    len++;
	}    
        if(len == 8) { 
            break; /* only 8 data bytes! */
        }
    }
    triggermessage[client][idx].length = len;
}

/*************************************************************
*
* add_bits -  add the message's bits to the global bit counter
*
* returns: nothing 
*
**************************************************************/
void add_bits (unsigned char u8_flags, unsigned char u8_dlc)
{

    if ((u8_flags & MSG_EXT) == 1) {
	 u32_bits += 65; /* 47 + 18 */ 
    } else {
	 u32_bits += 47; /* Source for 47: User Manual CANChat */
    }

    if ((u8_flags & MSG_RTR) == 0) {
	u32_bits += 8 * u8_dlc;
    }
}    

/*************************************************************
* alarmhandler - calculates the bus load and set the global bus load
*		variable to the latest value
*
* this function is called by sigalrm every sample period ( o_period)
*
* Für Windows wird diese Funktion von der Applikation aufgerufen.
**********************************************************/
#if defined(TARGET_LINUX) || defined(TARGET_CPC_LINUX) \
|| defined(TARGET_LINUX_ARM)
void alarmhandler (int signo) 
# endif /* TARGET_LINUX */
#ifdef __WIN32__
void alarmhandler_win32 (int signo)
#endif
{
unsigned int client;
    /* avoid warnings */
    signo = signo;

    if (((o_btr & 1) == 0) && (o_bitrate != 0)) {
	f_busload = (float) u32_bits * 100 / 
			(float) (1000000 / o_period * o_bitrate * 1000);
    }
    u32_bits = 0;
#ifdef CONFIG_SK
    if( !lifecount--) exit();
#endif

    /* generate cyclic statusinformation */
    if(o_show_status) {
	for(client = 0; client < HORCH_MAX_CLIENTS; client++) {
	    if (client_fd[client] == -1) {
		continue;
	    }

	    flag_show_status[client] = 1; /* send status */
	}
    }
}

