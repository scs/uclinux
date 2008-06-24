#include <stdio.h>
#include <stdlib.h>

#include "parse.h"

static int read_config_lines(FILE *cfp,unsigned short *ptr)
{
  char **args;
  int cntr;


  for (cntr = 0;; cntr++) {
    if (!(args = cfgread(cfp))) break;

	if(ptr) ptr[cntr]= (unsigned short)atoi(args[0]);
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
