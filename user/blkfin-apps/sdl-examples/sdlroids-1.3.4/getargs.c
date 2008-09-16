/* 
 * SDLRoids - An Astroids clone.
 * 
 * Copyright (c) 2000 David Hedbor <david@hedbor.org>
 * 	based on xhyperoid by Russel Marks.
 * 	xhyperoid is based on a Win16 game, Hyperoid by Edward Hutchins 
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 * 
 */

/*
 * getargs.c - Get / parse command line arguments.
 */

#include "config.h"
RCSID("$Id: getargs.c,v 1.4 2000/10/25 07:55:34 neotron Exp $");

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "getargs.h"
#include "petopt.h"

/* Storage for boolean variables */
int flagargs[NUMARGS];

static PETOPTS pov[] =
{
  { 'f', POF_NONE,	"fullscreen", 	NULL,
    "Start in fullscreen mode." },
  { 'g', POF_STR,	"geometry", 	NULL,
    "Open a window of the specified size. ARG\n"
    "                                    is specified as HEIGHTxWIDTH." },
  { 'b', POF_INT,	"benchmark", 	&ARG_BENCH,
    "Run in benchmark mode. Display ARG frames\n"
    "                                    without delay and quit." },
  { 's', POF_NONE,	"nosound",	NULL,
    "Don't initialize the sound." },
  { 'l', POF_NONE,	"list-joysticks",NULL,
    "Exit after listing all the joysticks." },
  { 'n', POF_INT,	"joynr", 	&ARG_JOYNUM,
    "The index of the joystick to use. All\n"
    "                                    available joysticks are listed\n"
    "                                    SDLRoids starts." },
  { 'j', POF_STR,	"joystick", 	NULL,
    "Force the use of this joystick device. If\n"
    "                                    valid, it will become joystick 0." },
  { '0', POF_INT,	"fire", 	&ARG_JFIRE,
    "Button for firing main guns. Default = 0."},
  { '1', POF_INT,	"shields", 	&ARG_JSHIELD,
    "Button for enabling shields. Default=1." },
  { '2', POF_INT,	"bomb", 	&ARG_JBOMB,
    "Button for firing smartbomb. Default=2." },
  { 'h', POF_NONE,	"help", 	NULL,
    "Print usage information and exit." },
  { 'v', POF_NONE,	"version", 	NULL,
    "Print version number and exit." },
  { -1,  0, NULL, NULL, NULL }
};


/*
 * Parse individual options. 
 * Valid return values:
 *   <0. ...... Some error occured
 *    0 ....... Option parsed and stored ok
 *    1 ....... Option parsed, use builtin store function
*/
static int parse_option(PETOPT *pp, PETOPTS *pov, const char *arg)
{
  switch (pov->s)
  {
   case 'h':
    printf("Usage: %s [options]\n\n", pp->argv[0]);
    petopt_print_usage(pp, stdout);
    printf("\nShip control keys:\n"
           "  Cursor Left/Right                 Spin the ship left or right.\n"
           "  Cursor Up/Down                    Forward or reverse thrust.\n"
           "  Space                             Fire guns.\n"
           "  Tab                               Use shields.\n"
           "  s                                 Use smartbomb (kill all enemy ships).\n"
           "\nOther keys:\n"
           "  Esc or q                          Quit the game.\n"
           "  Pause                             Pause / unpause the game.\n"
           "  F1                                Start a new game.\n");
	  
    exit(0);

   case 'l':
    ARG_JLIST=1;
    return 0;
   case 'f':
    ARG_FSCRN=1;
    return 0;
   case 's':
    ARG_NOSND=1;
    return 0;
    
   case 'b':
    printf("Running in benchmark mode (%s frames)\n", arg);
    return 1;

   case 'v':
    printf("SDLRoids "VERSION" by David Hedbor <david@hedbor.org>.\n\n"
	   "Based on xhyperoid 1.2 by Russel Marks <russell.marks@ntlworld.com>\n"
	   "which is based on hyperoid 1.1 by Edward Hutchins.\n");
    exit(0);
   case 'j':
#ifdef HAVE_SETENV
    setenv("SDL_JOYSTICK_DEVICE", arg, 1);
#else
    fprintf(stderr,
	    "*** setenv() function missing. To change the device\n"
	    "*** set the environment variable SDL_JOYSTICK_DEVICE\n"
	    "*** to the path to your joystick.\n");
#endif
    break;
   case 'g':
    if(sscanf(arg, "%dx%d", &ARG_WIDTH, &ARG_HEIGHT) != 2)
    {
      fprintf(stderr,
	      "%s: Invalid geometry specification. Should be WIDTHxHEIGHT.\n",
	      pp->argv[0]);
      exit(2);
    } else {
      if(ARG_WIDTH < 30 || ARG_HEIGHT < 30)
      {
	fprintf(stderr,
		"%s: Too small window. Minimum size is 30x30.\n",
		pp->argv[0]);
	exit(2);
      }
      return 0;
    }
   default:
    return 1;
  }

  return 0;
}

static int print_error(PETOPT *pop, PETOPTS *pov, int err,  FILE *fp)
{
  char buf[3];
  const char *arg;


  if (pop->saved_ci > 0)
  {
    buf[0] = '-';
    buf[1] = pop->argv[pop->saved_ai][pop->saved_ci];
    buf[2] = '\0';
    arg = buf;
  } else {
    arg = pop->argv[pop->saved_ai];
    if (arg == NULL)
      arg = "";
  }
    
  switch (err)
  {
  case POE_EOF:
    return 0;

  case POE_OPTION:
    fprintf(fp, "Unrecognized option: %s.\n"
	    "Run '%s -h' for more information.\n",
	    arg, pop->argv[0]);
    break;

  case POE_MULTI:
    fprintf(fp, "%s: Ambiguous option: %s\n",
	    pop->argv[0], arg);
    break;
	
  case POE_MISSING:
    fprintf(fp, "Missing argument for option: %s\n"
	    "Run '%s -h' for more information.\n",
	    arg, pop->argv[0]);
    break;

  case POE_INVALID:
    fprintf(fp, "%s: Invalid argument for option: %s\n",
	    pop->argv[0], arg);
    break;

  case POE_INTERNAL:
    fprintf(fp, "%s: Internal error parsing option: %s\n",
	    pop->argv[0], arg);
    break;

  default:
    fprintf(fp, "%s: Internal options parsing error: #%d\n",
	    pop->argv[0], err);
  }
  return -1;
}

/* Get all command line options using petopt */
void getargs(int argc, char *argv[])
{
  int err;
  PETOPT *pop;
  memset(flagargs, 0, sizeof(flagargs));
  ARG_JSHIELD = 1; /* Default shield button */
  ARG_JBOMB = 2;   /* Default smartbomb button */
  err = petopt_setup(&pop, 0, argc, argv, pov, parse_option, print_error);
  if (err)
  {
    if (err > 0) fprintf(stderr, "petopt_setup: %s\n", strerror(err));
    exit(1);
  }
  err = petopt_parse(pop, &argc, &argv);
  if (err)
  {
    if (err > 0) fprintf(stderr, "petopt_parse: %s\n", strerror(err));
    exit(1);
  }
  
  err = petopt_cleanup(pop);
  if (err)
  {
    if (err > 0)
      fprintf(stderr, "petopt_cleanup: %s\n", strerror(err));
    exit(1);
  }  
}
