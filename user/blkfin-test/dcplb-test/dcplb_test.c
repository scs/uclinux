/*
 *
 *    Rev:          $Id$
 *    Revision:     $Revision$
 *    Source:       $Source$
 *    Created:      12.09.2006 14:45
 *    Author:       Michael Hennerich
 *    mail:         hennerich@blackfin.uclinux.org
 *    Description:  DCPLB Replacement test code
 *
 *   Copyright (C) 2006 Michael Hennerich
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 ****************************************************************************
 * MODIFICATION HISTORY:
 ***************************************************************************/

#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <strings.h>
#include <limits.h>


#define VERSION         "0.1"

#define ACCESS(addr) (void)((*(volatile unsigned char *) (addr)))

void
usage (FILE * fp, int rc)
{
  fprintf (fp,
     "Usage: dcplb_test [-h?v] [-s Start] -e End [-i Increment] \n");
  fprintf (fp, "        -h?            this help\n");
  fprintf (fp, "        -v             print version info\n");
  fprintf (fp, "        -s             Start Address\n");
  fprintf (fp, "        -e             End Address\n");
  fprintf (fp, "        -i             Increment\n");
  fprintf (fp, "\nExample: dcplb_test -s 0 -e 33554432 -i 4096 \n");
  exit (rc);
}

unsigned long
str2long (char *str, char *opt)
{
  int base;
  char *endptr;
  long val;

  base = (str[1] == 'x' || str[1] == 'X') ? 16 : 10;

  errno = 0;    /* To distinguish success/failure after call */
  val = strtoul(str, &endptr, base);

  if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) || (errno != 0 && val == 0)) {
    fprintf(stderr, "error when parsing -%s\n", opt);
    perror("strtol");
    exit(EXIT_FAILURE);
  }

  if (endptr == str) {
    fprintf(stderr, "No digits were found when parseing -%s\n", opt);
    exit(EXIT_FAILURE);
  }

  return val;
}
int
main (int argc, char *argv[])
{
  int c;
  unsigned long start,end,inc,x;

  printf ("Data CPLB replacement Test\n\n");

    /* Check the passed arg */

  start = 0x4000;
  inc = 0x1000;
  end = 0x8000;

    while ((c = getopt (argc, argv, "vch?s:e:i:")) > 0)
     {
      switch (c)
      {
      case 'v':
        printf ("%s: version %s\n", argv[0], VERSION);
        exit (0);
      case 's':
        start = str2long(optarg, "s");
        break;
      case 'e':
        end = str2long(optarg, "e");
        break;
      case 'i':
        inc = str2long(optarg, "i");
        break;
      case 'h':
      case '?':
        usage (stdout, 0);
        break;
      default:
        fprintf (stderr, "ERROR: unkown option '%c'\n", c);
        usage (stderr, 1);
        break;
      }
     }

  printf ("Start:\t 0x%X\n",start);
  printf ("End:\t 0x%X\n",end);
  printf ("Incr:\t 0x%X\n\n",inc);

  if(start >= end ){
    usage (stdout, 0);
    return 0;
  }

  for(x=start; x<=end; x+=inc){
    ACCESS(x);
  }

  printf ("Test Success\n\n");
  system("cat /proc/cplbinfo");

exit (0);
}
