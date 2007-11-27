/* simpleinit.c - poe@daimi.aau.dk */
/* Version 1.21 */

/* gerg@snapgear.com -- modified for direct console support DEC/1999 */

#define _GNU_SOURCE	/* For crypt() and termios defines */

#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/termios.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <linux/version.h>
#include <utmp.h>
#include <errno.h>
#include <termios.h>
#ifdef SHADOW_PWD
#include <shadow.h>
#endif

#if __GNU_LIBRARY__ > 5
#include <sys/reboot.h>
#endif
#include <asm/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/soundcard.h>

int main(int argc, char *argv[])
{
  int file_adc, file_dac;
  #define BUF_SIZE 1536
  static int buffer[BUF_SIZE];
  static int count = 0;
  int ret;
#define STEREO

#ifdef STEREO

  file_adc = open("/dev/dsp", O_RDONLY, 0);
  file_dac = open("/dev/dsp", O_WRONLY, 0);
  if(file_adc == 0 || file_dac == 0){
    perror("/dev/dsp");
    printf("problem in sound\n");
  }
  else{
    // setup stereo mode
    int mode;
    // reset the sound to start the DMA engine
    ioctl(file_adc, SNDCTL_DSP_RESET, &ret);
    mode = 2;
    ioctl(file_adc, SNDCTL_DSP_STEREO, &mode);
    mode = 2;
    ioctl(file_dac, SNDCTL_DSP_STEREO, &mode);
  
    while(1){
      int size;
      int wsize;
      size = read(file_adc, buffer, BUF_SIZE);
      if(size != 0){
        wsize = write(file_dac, buffer, size);
      }
    }
  }

#else
  // Basic working
  file_adc = open("/dev/dsp", O_RDONLY, 0);
  file_dac = open("/dev/dsp", O_WRONLY, 0);
  if(file_adc == 0 || file_dac == 0){
    perror("/dev/dsp");
    printf("problem in sound\n");
  }
  else{
    ioctl(file_adc, SNDCTL_DSP_RESET, &ret);
    while(1){
      int size;
      int wsize;
      size = read(file_adc, buffer, BUF_SIZE);
      if(size != 0){
        wsize = write(file_dac, buffer, size);
      }
    }
  }
#endif
}
