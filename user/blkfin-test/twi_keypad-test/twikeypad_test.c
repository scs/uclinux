/*
 *
 *    Rev:          $Id$
 *    Revision:     $Revision$
 *    Source:       $Source$
 *    Created:      15.03.2006 18:12
 *    Author:       Michael Hennerich
 *    mail:         hennerich@blackfin.uclinux.org
 *    Description:  TWI Keypad test code
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
#include <sys/poll.h>
#include <linux/input.h>

#define VERSION         "0.1"

#define LINE_MAX_LEN 	80

void
usage (FILE * fp, int rc)
{
  fprintf (fp, "Usage: twikeypad_test [-h?v] \n");
  fprintf (fp, "        -h?            this help\n");
  fprintf (fp, "        -v             print version info\n");
  fprintf (fp, "        -r             repeate\n");
  fprintf (fp, "        -q             quiet mode\n");
  exit (rc);
}

int
keypad_fgets (char *input, unsigned short len)
{
  int run = 1;
  unsigned short pos = 0;
  char l_input[LINE_MAX_LEN];
  char rx[16];
  struct pollfd p_fd[1];
  int p_res;
  struct input_event ie;


  p_fd[0].fd = open ("/dev/input/event0", O_RDWR | O_NONBLOCK, 0);
  if (p_fd[0].fd == -1)
    {
      printf ("open error %d\n", errno);
      exit (1);
    }
  l_input[0] = '\0';


  while (run && (pos < len))
    {
      p_fd[0].revents = 0;
      p_fd[0].events = POLLIN | POLLERR;
      p_res = poll (p_fd, 1, 10);
      if (p_res < 0)
	{
	  perror ("read!");
	  exit (1);
	}
      if (p_res > 0)
	{
	  if (p_fd[0].revents & POLLIN)
	    {
	      while (read (p_fd[0].fd, &ie, sizeof (ie)) > 0)
		{

		  if ((ie.type == EV_KEY) && (ie.value == 1))
		    {

		      switch (ie.code)
			{

			case KEY_ENTER:
			  sprintf (input, "%s\n", l_input);
			  run = 0;
			  break;
			case KEY_BACKSLASH:
			  sprintf (rx, "#");
			  strncat (l_input, rx, 1);
			  pos++;
			  break;
			case KEY_0:
			  sprintf (rx, "0");
			  strncat (l_input, rx, 1);
			  pos++;
			  break;
			case KEY_RIGHTBRACE:
			  sprintf (rx, "*");
			  strncat (l_input, rx, 1);
			  pos++;
			  break;
			case KEY_C:
			  sprintf (rx, "c");
			  strncat (l_input, rx, 1);
			  pos++;
			  break;
			case KEY_9:
			  sprintf (rx, "9");
			  strncat (l_input, rx, 1);
			  pos++;
			  break;
			case KEY_8:
			  sprintf (rx, "8");
			  strncat (l_input, rx, 1);
			  pos++;
			  break;
			case KEY_7:
			  sprintf (rx, "7");
			  strncat (l_input, rx, 1);
			  pos++;
			  break;
			case KEY_B:
			  sprintf (rx, "t");
			  strncat (l_input, rx, 1);
			  pos++;
			  break;
			case KEY_6:
			  sprintf (rx, "6");
			  strncat (l_input, rx, 1);
			  pos++;
			  break;
			case KEY_5:
			  sprintf (rx, "5");
			  strncat (l_input, rx, 1);
			  pos++;
			  break;
			case KEY_4:
			  sprintf (rx, "4");
			  strncat (l_input, rx, 1);
			  pos++;
			  break;
			case KEY_A:
			  sprintf (rx, "a");
			  strncat (l_input, rx, 1);
			  pos++;
			  break;
			case KEY_3:
			  sprintf (rx, "3");
			  strncat (l_input, rx, 1);
			  pos++;
			  break;
			case KEY_2:
			  sprintf (rx, "2");
			  strncat (l_input, rx, 1);
			  pos++;
			  break;
			case KEY_1:
			  sprintf (rx, "1");
			  strncat (l_input, rx, 1);
			  pos++;
			  break;

			}
		    }
		}
	    }
	  else if (p_fd[0].revents & POLLERR)
	    {
	      break;
	    }
	}
    }

  close (p_fd[0].fd);
  return 0;
}

int
main (int argc, char *argv[])
{

  int c;
  int quiet = 0;
  int repeate = 0;
  char input[LINE_MAX_LEN];

  /* Check the passed arg */

  while ((c = getopt (argc, argv, "vqrh?")) > 0)
    {
      switch (c)
	{
	case 'v':
	  printf ("%s: version %s\n", argv[0], VERSION);
	  exit (0);
	case 'q':
	  quiet++;
	  break;
	case 'r':
	  repeate++;
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


	  if (!quiet)
	    printf (" TWI Keypad Test Application\n\n");

  do {	
	  keypad_fgets (input, LINE_MAX_LEN);
	
	  if (!quiet)
	    printf ("Entry was: %s \n", input);
	  else
	    printf ("%s", input);
	
	  fflush(stdout);
	
    }while(repeate);

  exit (0);
}
