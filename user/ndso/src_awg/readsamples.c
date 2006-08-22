
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <errno.h>
#include <string.h>
#include <termios.h>
#include <ctype.h>
#include <fcntl.h>

#include "readsamples.h"
#include "parse.h"

static int read_config_lines(FILE *cfp,unsigned short *ptr)
{
  char **args;
  int cntr;


  for (cntr = 0;; cntr++) {
    if (!(args = cfgread(cfp))) break;

	if(ptr) ptr[cntr]= (unsigned short)atoi(args[1]);
  }


return (cntr);
}

int read_config(const char *pFile_parse, unsigned short *ptr)
{
  FILE *cfp;
  int ret;	
  if (!(cfp = fopen(pFile_parse,"r"))) {
  return (-1);
  }
  ret = read_config_lines(cfp,ptr);
  fclose(cfp);
  return (ret);
}



