/*
* Configuration for horch
*
*/


/* maximale Anzahl von Clients, die sich mit dem horch verbinden können 
 * --------------------------------------------------------------------*/
#ifndef HORCH_MAX_CLIENTS 
# define HORCH_MAX_CLIENTS 10
#endif /* HORCH_MAX_CLIENTS  */

/* Buffer Größen - Stringbuffer je Client
 * --------------------------------------------------------------------*/
#ifndef TCPIP_BUFFER_MAX 
# if MAX_CANMESSAGES_PER_FRAME > 20
    /* CPC Win32 test with more buffers */
#  define TCPIP_BUFFER_MAX 300000
# else
   /* default */
#  define TCPIP_BUFFER_MAX 30000
# endif
#endif

/* Wenn der Puffer diesen Füllgrad erreicht, 
 * schonmal versuchen zu verschicken */
#ifdef TARGET_LINUX_ARM 
#  define TCPIP_BUFFER_TRANSMIT	(10000)
#else
#  define TCPIP_BUFFER_TRANSMIT	(TCPIP_BUFFER_MAX - 500)
#endif

/* Anzahl von Bytes, ab der nichts mehr in den Buffer geschrieben werden soll */
#define TCPIP_BUFFER_STOP	(TCPIP_BUFFER_MAX - 160)

/* Buffer Größe für Debugmessages, 80 sollten reichen, aber... 
 * -------------------------------------------------------------------*/
#define DEBUGMSG_BUFFER_MAX 2056

