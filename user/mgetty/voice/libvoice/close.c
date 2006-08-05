/*
 * close.c
 *
 * Close the voice device.
 *
 * $Id$
 *
 */

#include "../include/voice.h"

int voice_close_device(void)
     {
     lprintf(L_MESG, "closing voice modem device");

     if (voice_fd == NO_VOICE_FD)
          {
          lprintf(L_WARN, "no voice modem device open");
          return(FAIL);
          };

     close(voice_fd);
     voice_fd = NO_VOICE_FD;
     rmlocks();
     return(OK);
     }
