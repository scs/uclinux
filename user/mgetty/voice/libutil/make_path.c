/*
 * make_path.c
 *
 * Builds a complete file path from a directory name and a filename.
 *
 * $Id$
 *
 */

#include "../include/voice.h"

void make_path(char *result, char *path, char *name)
     {

     if (name[0] == '/')
          {
          strcpy(result, name);
          }
     else
          {
          strcpy(result, path);
          strcat(result, "/");
          strcat(result, name);
          };

     }
