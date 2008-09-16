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
 * roidsupp.c - SDLRoids support functions
 */

#include "config.h"
RCSID("$Id: roidsupp.c,v 1.5 2001/03/23 23:54:23 neotron Exp $");

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#include "misc.h"
#include "hyperoid.h"

#include "roidsupp.h"

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

static char datafile[PATH_MAX+1];

/* these parts map to "abcdefghijklm" */
POINT LetterPart[] =
{
  {83, 572}, {64, 512}, {45, 572}, {96, 362}, {32, 362},
  {128, 256}, {0, 0}, {0, 256},
  {160, 362}, {224, 362}, {173, 572}, {192, 512}, {211, 572}
};

/* here's the vector font */
char *NumberDesc[] =
{
  "cakmck",       /* 0 */
  "dbl",          /* 1 */
  "abekm",        /* 2 */
  "abegjlk",      /* 3 */
  "mcfh",         /* 4 */
  "cbfgjlk",      /* 5 */
  "bdiljgi",      /* 6 */
  "acgl",         /* 7 */
  "bdjlieb",      /* 8 */
  "ljebdge"       /* 9 */
};

char *LetterDesc[] =
{
  "kdbemhf",      /* A */
  "kabegjlk",     /* B */
  "cbflm",        /* C */
  "kabejlk",      /* D */
  "cafgfkm",      /* E */
  "cafgfk",       /* F */
  "bdiljhg",      /* G */
  "kafhcm",       /* H */
  "bl",           /* I */
  "cjli",         /* J */
  "akcgm",        /* K */
  "akm",          /* L */
  "kagcm",        /* M */
  "kamc",         /* N */
  "bdiljeb",      /* O */
  "kabegf",       /* P */
  "mlidbejl",     /* Q */
  "kabegfgm",     /* R */
  "ebdjli",       /* S */
  "lbac",         /* T */
  "ailjc",        /* U */
  "alc",          /* V */
  "akgmc",        /* W */
  "amgkc",        /* X */
  "aglgc",        /* Y */
  "ackm"          /* Z */
};



/* PrintLetters - create letter objects from a string */

void PrintLetters( char *npszText, POINT Pos, POINT Vel,
		   BYTE byColor, int nSize )
{
  int             nLen = strlen( npszText );
  int             nCnt = nLen;
  int             nSpace = nSize + nSize / 2;
  int             nBase = (nLen - 1) * nSpace;
  int             nBaseStart = Pos.x + nBase / 2;

  while (nCnt--)
  {
    OBJ *npLtr = CreateLetter( npszText[nCnt], nSize / 2 );
    if (npLtr)
    {
      npLtr->Pos.x = nBaseStart;
      npLtr->Pos.y = Pos.y;
      npLtr->Vel = Vel;
      npLtr->byColor = byColor;
    }
    nBaseStart -= nSpace;
  }
}


/* SpinLetters - spin letter objects away from center for effect */

void SpinLetters( char *npszText, POINT Pos, POINT Vel,
		  BYTE byColor, int nSize )
{
  int             nLen = strlen( npszText );
  int             nCnt = nLen;
  int             nSpace = nSize + nSize / 2;
  int             nBase = (nLen - 1) * nSpace;
  int             nBaseStart = Pos.x + nBase / 2;

  while (nCnt--)
  {
    OBJ *npLtr = CreateLetter( npszText[nCnt], nSize / 2 );
    if (npLtr)
    {
      int nSpin = (nCnt - nLen / 2) * 2;
      npLtr->Pos.x = nBaseStart;
      npLtr->Pos.y = Pos.y;
      npLtr->Vel = Vel;
      npLtr->Vel.x += nSpin * 16;
      npLtr->nSpin = -nSpin;
      npLtr->byColor = byColor;
    }
    nBaseStart -= nSpace;
  }
}


/* Build the file names */
char *datafilename(char *prefix, char *name)
{
#ifdef HAVE_GETENV
  static char *env = NULL;
#endif
  if(prefix == NULL) {
#ifdef HAVE_GETENV
    if(env == NULL)
      env = getenv("SRDATADIR");
    if(env == NULL) return name;
    prefix = env;
#else
    return name;
#endif
  }
  if((strlen(prefix) + strlen(name)) > PATH_MAX) return name;
  strcpy(datafile, prefix);
  strcat(datafile, name);
  return datafile;
}
