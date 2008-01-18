/*
 *
 *    Rev:          $Id: twilcd_test.c 2174 2006-03-15 16:36:12Z hennerich $
 *    Revision:     $Revision: 2174 $
 *    Source:       $Source$
 *    Created:      15.03.2006 14:45
 *    Author:       Michael Hennerich
 *    mail:         hennerich@blackfin.uclinux.org
 *    Description:  TWI LCD test code
 *
 *   Copyright (C) 2005 Michael Hennerich
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

#include "twi_lcd.h"

#define LCD_DEVICE      "/dev/lcd"
#define VERSION         "0.1"

void
usage (FILE * fp, int rc)
{
  fprintf (fp,
	   "Usage: twilcd_test [-h?v] [-c] [-d CONTROLLER] [-p POSITION] [Message String]\n");
  fprintf (fp, "        -h?            this help\n");
  fprintf (fp, "        -v             print version info\n");
  fprintf (fp, "        -c             Clear Display\n");
  fprintf (fp, "        -d Number      use 1,2,3 for CONTROLLER 1,2,BOTH\n");
  fprintf (fp, "        -p Char POS    Position where to put the string \n");
  fprintf (fp, "\nExample: twilcd_test -p 0 \"Hello World !\"\n");
  exit (rc);
}

int
main (int argc, char *argv[])
{

  int fd;
  int c = 0;
  int clear = 0;
  int setpos = 0;
  int pos = 0;
  int contr = 0;
  int cont_num = 0;
  char *string;

  printf (" TWI LCD Test Application\n\n");

  /* Check the passed arg */

  while ((c = getopt (argc, argv, "vch?d:p:")) > 0)
    {
      switch (c)
	{
	case 'v':
	  printf ("%s: version %s\n", argv[0], VERSION);
	  exit (0);
	case 'c':
	  clear++;
	  break;
	case 'd':
	  contr++;
	  cont_num = atoi (optarg);
	  break;
	case 'p':
	  setpos++;
	  pos = atoi (optarg);
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


  fd = open ("/dev/lcd", O_RDWR);
  if (fd < 0)
    {
      printf ("Can't open dev lcd.\n");
      return -1;
    }

  if (contr)
    {
      ioctl (fd, LCD_Curr_Controller, cont_num);
      printf (" Selected Controller\t: %d \n", cont_num);
    }

  if (clear)
    {
      ioctl (fd, LCD_Clear, 1);
      printf (" Clearing Display\t: \n");
      sleep (1);		/* Clearing take tong */
    }

  if (setpos)
    {
      ioctl (fd, LCD_Set_Cursor_Pos, pos);
      printf (" Position\t\t: %d \n", pos);
    }

  string = argv[optind];

  if (string)
    {
      printf (" Message\t\t: %s \n", string);
      write (fd, string, strlen (string));
    }

  close (fd);

  exit (0);
}
