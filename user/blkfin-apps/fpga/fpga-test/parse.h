#ifndef __CFGFILE_H__
#define __CFGFILE_H__

#include <stdio.h>
char ** cfgread(FILE *fp);
char ** cfgfind(FILE *fp, char *var);

int read_config(const char *pFile_parse, unsigned short *ptr);

#endif /* __CFGFILE_H__ */
