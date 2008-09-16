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
 * rand.c - Custom random number generator, from Pike (http://pike.roxen.com/).
 */

#include "config.h"
RCSID("$Id: rand.c,v 1.2 2000/07/17 02:22:16 neotron Exp $");

static unsigned long RandSeed1 = 0x5c2582a4;
static unsigned long RandSeed2 = 0x64dff8ca;

static unsigned long slow_rand(void)
{
  RandSeed1 = ((RandSeed1 * 13 + 1) ^ (RandSeed1 >> 9)) + RandSeed2;
  RandSeed2 = (RandSeed2 * RandSeed1 + 13) ^ (RandSeed2 >> 13);
  return RandSeed1;
}

static void slow_srand(long seed)
{
  RandSeed1 = (seed - 1) ^ 0xA5B96384UL;
  RandSeed2 = (seed + 1) ^ 0x56F04021UL;
}

#define RNDBUF 250
#define RNDSTEP 7
#define RNDJUMP 103

static unsigned long rndbuf[ RNDBUF ];
static int rnd_index;

void my_srand(long seed)
{
  int e;
  unsigned long mask;

  slow_srand(seed);
  
  rnd_index = 0;
  for (e=0;e < RNDBUF; e++) rndbuf[e]=slow_rand();

  mask = (unsigned long) -1;

  for (e=0;e< (int)sizeof(long)*8 ;e++)
  {
    int d = RNDSTEP * e + 3;
    rndbuf[d % RNDBUF] &= mask;
    mask>>=1;
    rndbuf[d % RNDBUF] |= (mask+1);
  }
}

unsigned long my_rand(unsigned long range)
{
  if( ++rnd_index == RNDBUF) rnd_index=0;
  return (rndbuf[rnd_index] += rndbuf[rnd_index+RNDJUMP-(rnd_index<RNDBUF-RNDJUMP?0:RNDBUF)]) % range;
}

