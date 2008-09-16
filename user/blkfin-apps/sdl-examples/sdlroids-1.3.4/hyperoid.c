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
 * hyperoid.c - Main game backend.
 */

#include "config.h"
RCSID("$Id: hyperoid.c,v 1.15 2001/03/27 23:23:52 neotron Exp $");

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <math.h>
#include <time.h>
#include <limits.h>
#include <errno.h>
#include <sys/types.h>
#ifdef HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>

#include "SDL.h"
#include "rand.h"
#include "getargs.h"
#include "misc.h"
#include "roidsupp.h"
#include "sdlsound.h"
#include "graphics.h"

#include "hyperoid.h"

static int palrgb[16*3]=
{
  0,0,0,	128,128,128,
  192,192,192,	255,255,255,
  128,0,0,	255,0,0,
  0,128,0,	0,255,0,
  0,0,128,	0,0,255,
  128,128,0,	255,255,0,
  0,128,128,	0,255,255,
  128,0,128,	255,0,255
};

#define HIT_SHIP  0 
#define HIT_ROID  1
#define HIT_SHOT  2

/* globals */

static int nLevel;
static int nBadGuys; /* Number of badguys currently alive */
static int lHighScore; /* Highscore. Set but not saved or displayed */
int bRestart, bPaused=0;
PLAYER me;  /* The player struct */

LIST FreeList, RoidList, ShotList, FlameList, SpinnerList;
LIST HunterList, HunterShotList, SwarmerList, LetterList, BonusList;
int nCos[DEGREE_SIZE], nSin[DEGREE_SIZE]; /* Sinus and cosinus lookup tables */
OBJ Obj[MAX_OBJS]; 

static int restart_timer_count = 0, game_done = 0;

/* Directory of the binary */
char *bindir;


/* locals */

int dwSeed;
static RECT          rectShotClip;
static POINT         Player[] =
{ {0, 0}, {160, 150}, {0, 250}, {96, 150}, {0, 0} };
static POINT         Spinner[] =
{ {160, 150}, {224, 100}, {96, 100}, {32, 150}, {160, 150} };
static POINT         Swarmer[] =
{ {0, 100}, {64, 100}, {128, 100}, {192, 100}, {0, 100} };
static POINT         Hunter[] =
{
  {160, 150}, {0, 250}, {192, 30}, {64, 30},
  {0, 250}, {96, 150}, {128, 150}, {160, 150}
};
static POINT         Bonus[] =
{ {0, 150}, {102, 150}, {205, 150}, {51, 150}, {154, 150}, {0, 150} };


/* KillBadGuy - kill off a badguy (made into a macro) */

#define KillBadGuy() \
	((--nBadGuys <= 0)?(SetRestart( RESTART_NEXTLEVEL ),TRUE):FALSE)


/* my_rand - pseudorandom number from 0 to x-1 (thanks antman!) */

/* XXX replace? - it's probably v. poor */

/* AddHead - add an object to the head of a list */

void AddHead( LIST *npList, NODE *npNode )
{
  if (npList->npHead)
  {
    npNode->npNext = npList->npHead;
    npNode->npPrev = NULL;
    npList->npHead = (npList->npHead->npPrev = npNode);
  }
  else /* add to an empty list */
  {
    npList->npHead = npList->npTail = npNode;
    npNode->npNext = npNode->npPrev = NULL;
  }
}


/* RemHead - remove the first element in a list */

NODE *RemHead( LIST *npList )
{
  if (npList->npHead)
  {
    NODE *npNode = npList->npHead;
    if (npList->npTail != npNode)
    {
      npList->npHead = npNode->npNext;
      npNode->npNext->npPrev = NULL;
    }
    else npList->npHead = npList->npTail = NULL;
    return( npNode );
  }
  else return( NULL );
}


/* Remove - remove an arbitrary element from a list */

void Remove( LIST *npList, NODE *npNode )
{
  if (npNode->npPrev) npNode->npPrev->npNext = npNode->npNext;
  else npList->npHead = npNode->npNext;
  if (npNode->npNext) npNode->npNext->npPrev = npNode->npPrev;
  else npList->npTail = npNode->npPrev;
}


/* DrawObject - draw a single object */
int foo=0;
void DrawObject( OBJ *npObj )
{
  int nCnt;
  POINT           Pts[MAX_PTS];
  int nDir, x, y;
  if(bPaused) {
    nDir = npObj->nDir;
    x = npObj->Pos.x;
    y = npObj->Pos.y;
  } else {
    nDir = (npObj->nDir += npObj->nSpin);
    x = (npObj->Pos.x += (npObj->Vel.x));
    y = (npObj->Pos.y += (npObj->Vel.y));
  }

  if (x < -CLIP_COORD) npObj->Pos.x = x = CLIP_COORD;
  else if (x > CLIP_COORD) npObj->Pos.x = x = -CLIP_COORD;
  if (y < -CLIP_COORD) npObj->Pos.y = y = CLIP_COORD;
  else if (y > CLIP_COORD) npObj->Pos.y = y = -CLIP_COORD;

  for (nCnt = npObj->byPts - 1; nCnt >= 0; --nCnt)
  {
    int wDeg = DEG( npObj->Pts[nCnt].x + nDir );
    int nLen = npObj->Pts[nCnt].y;
    Pts[nCnt].x = x + MULDEG( nLen, nCos[wDeg] );
    Pts[nCnt].y = y + MULDEG( nLen, nSin[wDeg] );
  }
  ResetRefreshCoords();
  if (npObj->byPts > 1)
  {
    set_colour(BLACK);
    Polyline( npObj->Old, npObj->byPts );
    if (npObj->nCount > 0)
    {
      set_colour(npObj->byColor);
      Polyline( Pts, npObj->byPts );
      for (nCnt = npObj->byPts - 1; nCnt >= 0; --nCnt)
	npObj->Old[nCnt] = Pts[nCnt];
    }
  }
  else /* just a point */
  {
    SetPixel( npObj->Old[0].x, npObj->Old[0].y, BLACK );
    if (npObj->nCount > 0)
    {
      SetPixel( Pts[0].x, Pts[0].y, npObj->byColor );
      npObj->Old[0] = Pts[0];
    }
  }
  RedrawObject();
}


/* SetRestart - set the restart timer */

void SetRestart( RESTART_MODE Restart )
{
  POINT           Pt;
  char            szBuff[32];

  if (bRestart) return;
  restart_timer_count=RESTART_DELAY_FRAMES;
  bRestart = TRUE;

  Pt.x = Pt.y = 0;
  switch (Restart)
  {
  case RESTART_GAME:
    /*    PrintLetters( "STARTING NEW GAME", Pt, Pt, BLUE, 300 ); */
    break;
  case RESTART_DEATH:
    SpinLetters( "GAME OVER", Pt, Pt, RED, 400 );
    break;
  case RESTART_LEVEL:
    PrintLetters( "GET READY", Pt, Pt, BLUE, 300 );
    break;
  case RESTART_NEXTLEVEL:
    sprintf( szBuff, "LEVEL %d", nLevel + 1 );
    PrintLetters( szBuff, Pt, Pt, BLUE, 300 );
    break;
  }
}

/* DeleteBadguys - delete a list of badguys without explosions */

void DeleteBadguys( LIST *npList )
{
  OBJ *          npObj;

  while ((npObj = HeadObj( npList )))
  {
    nBadGuys--;
    npObj->nCount = 0;
    DrawObject( npObj );
    RemoveObj( npList, npObj );
    AddHeadObj( &FreeList, npObj );
  }
}
/* NewGame - start a new game */

void NewGame( RESTART_MODE restart )
{
  lock_graphics();
  game_done = 0;
  me.Shield.byColor = BLACK;
  Explode( me.Player );
  me.Player->nCount = 0;
  me.Player->byColor = WHITE;
  SetRestart( restart );
  DeleteBadguys( &RoidList );
  DeleteBadguys( &SpinnerList );
  DeleteBadguys( &SwarmerList );
  DeleteBadguys( &HunterList );
  nBadGuys=0;
  unlock_graphics();
}

/* PrintPlayerMessage - show the player a status message */

void PrintPlayerMessage( char * npszText )
{
  POINT Pos, Vel;

  Pos = me.Player->Pos;
  Pos.y -= 400;
  Vel.x = 0;
  Vel.y = -50;
  PrintLetters( npszText, Pos, Vel, GREEN, 150 );
}


/* AddExtraLife - give the player another life */

void AddExtraLife( void )
{
  PrintPlayerMessage( "EXTRA LIFE" );
  queuesam(EFFECT_CHANNEL,EXTRALIFE_SAMPLE);
  ++me.Player->nCount;
  me.Player->byColor = (BYTE)(BLACK + me.Player->nCount);
  if (me.Player->byColor > WHITE) me.Player->byColor = WHITE;
}


/* Hit - something hit an object, do fireworks */

void Hit( OBJ *npObj )
{
  int             nCnt;

  for (nCnt = 0; nCnt < 6; ++nCnt)
  {
    OBJ *npFlame = RemHeadObj( &FreeList );
    if (!npFlame) return;
    npFlame->Pos.x = npObj->Pos.x;
    npFlame->Pos.y = npObj->Pos.y;
    npFlame->Vel.x = npObj->Vel.x;
    npFlame->Vel.y = npObj->Vel.y;
    npFlame->nDir = npObj->nDir + (nCnt * DEGREE_SIZE) / 6;
    npFlame->nSpin = 0;
    npFlame->nCount = 10 + my_rand( 8 );
    npFlame->byColor = YELLOW;
    npFlame->byPts = 1;
    npFlame->Pts[0].x = npFlame->Pts[0].y = 0;
    ACCEL( npFlame, npFlame->nDir, 50 - npFlame->nCount );
    npFlame->nCount = (npFlame->nCount);
    AddHeadObj( &FlameList, npFlame );
  }
}


/* Explode - explode an object */

void Explode( OBJ *npObj )
{
  int             nCnt, nSize = npObj->byPts;

  DrawObject( npObj );
  for (nCnt = 0; nCnt < nSize; ++nCnt)
  {
    OBJ *npFlame;
    if (my_rand( 2 )) continue;
    if (!(npFlame = RemHeadObj( &FreeList ))) return;
    npFlame->Pos.x = npObj->Pos.x;
    npFlame->Pos.y = npObj->Pos.y;
    npFlame->Vel.x = npObj->Vel.x;
    npFlame->Vel.y = npObj->Vel.y;
    npFlame->nDir = npObj->nDir + nCnt * DEGREE_SIZE / nSize + my_rand( 32 );
    npFlame->nSpin = my_rand( 31 ) - 15;
    npFlame->nCount = 25 + my_rand( 16 );
    npFlame->byColor = npObj->byColor;
    npFlame->byPts = 2;
    npFlame->Pts[0] = npObj->Pts[nCnt];
    if (nCnt == nSize - 1) npFlame->Pts[1] = npObj->Pts[0];
    else npFlame->Pts[1] = npObj->Pts[nCnt + 1];
    ACCEL( npFlame, npFlame->nDir, 60 - npFlame->nCount);
    npFlame->nCount = (npFlame->nCount);
    AddHeadObj( &FlameList, npFlame );
  }
  Hit( npObj );
}


/* HitPlayer - blow up the player */

int HitPlayer( OBJ *npObj, int hittype )
{
  POINT           Vel;
  int             nMass, nSpin;

  if (me.Player->nCount <= 0) return( FALSE );

  /* rumble and shake both objects */
  nMass = me.Player->nMass + npObj->nMass;

  nSpin = me.Player->nSpin + npObj->nSpin;
  npObj->nSpin -= MulDiv( nSpin, me.Player->nMass, nMass );
  me.Player->nSpin -= MulDiv( nSpin, npObj->nMass, nMass );

  Vel.x = me.Player->Vel.x - npObj->Vel.x;
  Vel.y = me.Player->Vel.y - npObj->Vel.y;
  npObj->Vel.x += MulDiv( Vel.x, me.Player->nMass, nMass );
  npObj->Vel.y += MulDiv( Vel.y, me.Player->nMass, nMass );
  me.Player->Vel.x -= MulDiv( Vel.x, npObj->nMass, nMass );
  me.Player->Vel.y -= MulDiv( Vel.y, npObj->nMass, nMass );
  if(me.isSafe) {
    switch(hittype)
    {
    case HIT_SHOT:
    case HIT_SHIP:
      npObj->nCount = 1;
      Explode(npObj);
      queuesam(EFFECT_CHANNEL,PHIT_SAMPLE);
      break;
    case HIT_ROID:
      BreakRoid( npObj, NULL );
      break;
    }
    Hit( me.Player );
    return FALSE;
  } else {
    if (--me.Player->nCount)
    {
      me.Player->byColor = (BYTE)(BLACK + me.Player->nCount);
      if (me.Player->byColor > WHITE) me.Player->byColor = WHITE;
      Hit( me.Player );
      queuesam(EFFECT_CHANNEL,PHIT_SAMPLE);
      return TRUE;
    }
    
    /* final death */
    me.Player->byColor = WHITE;
    Explode( me.Player );
    queuesam(EFFECT_CHANNEL,EXPLODE2_SAMPLE);
    game_done = 1;
    return FALSE;
  }
}


/* CreateLetter - make a new letter object */

OBJ *CreateLetter( int cLetter, int nSize )
{
  OBJ *npLtr;
  int nCnt;
  char *npDesc;

  if (cLetter >= '0' && cLetter <= '9') npDesc = NumberDesc[cLetter - '0'];
  else if (cLetter >= 'A' && cLetter <= 'Z') npDesc = LetterDesc[cLetter - 'A'];
  else if (cLetter >= 'a' && cLetter <= 'z') npDesc = LetterDesc[cLetter - 'a'];
  else if (cLetter == '.') npDesc = "l";
  else if (cLetter == '-') npDesc = "fgf";
  else return( NULL );

  if ((npLtr = RemHeadObj( &FreeList )))
  {
    npLtr->nMass = 1;
    npLtr->nDir = 0;
    npLtr->nSpin = 0;
    npLtr->nCount = 40;
    npLtr->byColor = WHITE;
    npLtr->byPts = (BYTE)(nCnt = strlen( npDesc ));
    while (nCnt--)
    {
      npLtr->Pts[nCnt] = LetterPart[npDesc[nCnt] - 'a'];
      npLtr->Pts[nCnt].y = MulDiv( npLtr->Pts[nCnt].y, nSize, LETTER_MAX );
    }
    AddHeadObj( &LetterList, npLtr );
  }
  return( npLtr );
}


/* DrawLetters - draw letters and such */

void DrawLetters( void )
{
  OBJ *npLtr, *npNext;

  for (npLtr = HeadObj( &LetterList ); npLtr; npLtr = npNext)
  {
    npNext = NextObj( npLtr );
    switch (--npLtr->nCount)
    {
     case 3:
      --npLtr->byColor;
      break;
     case 0:
      RemoveObj( &LetterList, npLtr );
      AddHeadObj( &FreeList, npLtr );
      break;
    }
    DrawObject( npLtr );
  }
}


/* CreateBonus - make a new bonus object */

void CreateBonus( void )
{
  OBJ *          npBonus;
  int             nCnt;

  if ((npBonus = RemHeadObj( &FreeList )))
  {
    queuesam(EFFECT_CHANNEL,NEWBONUS_SAMPLE);
    npBonus->Pos.x = my_rand( CLIP_COORD * 2 ) - CLIP_COORD;
    npBonus->Pos.y = -CLIP_COORD;
    npBonus->Vel.x = npBonus->Vel.y = 0;
    npBonus->nDir = my_rand( DEGREE_SIZE );
    npBonus->nSpin = (my_rand( 2 ) ? 12 : -12);
    npBonus->nCount = (my_rand( 6 ) + 1);
    npBonus->nDelay = 64 + my_rand( 128 );
    npBonus->nMass = 1;
    npBonus->byColor = YELLOW; /*(BYTE)(WHITE + (npBonus->nCount * 2));*/
    npBonus->byPts = DIM(Bonus);
    for (nCnt = 0; nCnt < DIM(Bonus); ++nCnt)
      npBonus->Pts[nCnt] = Bonus[nCnt];
    ACCEL( npBonus, npBonus->nDir, 30 + nLevel * 2 );
    AddHeadObj( &BonusList, npBonus );
  }
}


/* DrawBonuses - process and draw the bonus list */

void DrawBonuses( void )
{
  OBJ *npBonus, *npNext;
  static int       nNextBonus = 1000;

  if (!bPaused && nBadGuys && (--nNextBonus < 0))
  {
    CreateBonus();
    nNextBonus = 1000;
  }

  for (npBonus = HeadObj( &BonusList ); npBonus; npBonus = npNext)
  {
    OBJ *          npShot;
    int             nDelta;
    RECT            rect;

    npNext = NextObj( npBonus );

    MKRECT( &rect, npBonus->Pos, 150 );

    if (PTINRECT( &rect, me.Player->Pos ))
    {
      if (me.Player->nCount > 0) switch (npBonus->nCount)
      {
      case 1:
	{
	  char szBuff[32];
	  int lBonus = 1000L * nLevel;
	  if (lBonus == 0) lBonus = 500;
	  me.Score += lBonus;
	  sprintf( szBuff, "%d", lBonus );
	  PrintPlayerMessage( szBuff );
	}
	break;
      case 2:
	me.Shields += 50;
	me.ExtraShields = 30;
	me.Shield.byColor = GREEN;
	PrintPlayerMessage( "EXTRA SHIELD" );
	break;
      case 3:
	++me.Bombs;
	PrintPlayerMessage( "EXTRA BOMB" );
	break;
      case 4:
	AddExtraLife();
	break;
      case 5:
	if(me.Guns < 3) {
	  PrintPlayerMessage( "EXTRA CANNON" );
	  me.Guns++;
	  break;
	}
	/* FALLTHROUGH */
      case 6:
	me.GunRange += 0.1 * (my_rand(3)+1);
	PrintPlayerMessage( "INCREASED GUN RANGE" );
	break;
      }
	npBonus->nCount = 0;
	Explode( npBonus );
	queuesam(BADDIE_CHANNEL,BONUSGOT_SAMPLE);
	RemoveObj( &BonusList, npBonus );
	AddHeadObj( &FreeList, npBonus );
      }
      else if (INTRECT(&rect, &rectShotClip))
      {
	for (npShot = HeadObj( &ShotList ); npShot; npShot = NextObj( npShot ))
	{
	  if (!PTINRECT( &rect, npShot->Pos )) continue;
	  npShot->nCount = 1;
	  npBonus->nCount = 0;
	  Explode( npBonus );
	  queuesam(BADDIE_CHANNEL,BONUSSHOT_SAMPLE);
	  RemoveObj( &BonusList, npBonus );
	  AddHeadObj( &FreeList, npBonus );
	}
      }
      if (npBonus->nCount && --npBonus->nDelay <= 0)
      {
	--npBonus->nCount;
	npBonus->nDelay = 64 + my_rand( 128 );
	/*      npBonus->byColor = (BYTE)(WHITE + (npBonus->nCount * 2)); */
	if (npBonus->nCount == 0)
	{
	  Explode( npBonus );
	  queuesam(BADDIE_CHANNEL,BONUSTIMEOUT_SAMPLE);
	  RemoveObj( &BonusList, npBonus );
	  AddHeadObj( &FreeList, npBonus );
	}
      }
      if(!bPaused) {
	nDelta = me.Player->Pos.x - npBonus->Pos.x;
	while (nDelta < -16 || nDelta > 16) nDelta /= 2;
	npBonus->Vel.x += nDelta - npBonus->Vel.x / 16;
	nDelta = me.Player->Pos.y - npBonus->Pos.y;
	while (nDelta < -16 || nDelta > 16) nDelta /= 2;
	npBonus->Vel.y += nDelta - npBonus->Vel.y / 16;
      }
      DrawObject( npBonus );
    }
}


/* DrawHunterShots - process and draw the hunter shot list */

void DrawHunterShots( void )
{
  OBJ *npShot, *npNext;

  for (npShot = HeadObj( &HunterShotList ); npShot; npShot = npNext)
  {
    RECT            rect;

    npNext = NextObj( npShot );

    if(!bPaused) {
      MKRECT( &rect, npShot->Pos, 200 );
    
      if (PTINRECT( &rect, me.Player->Pos ))
      {
	HitPlayer( npShot, HIT_SHOT );
	npShot->nCount = 1;
      }
      switch (--npShot->nCount)
      {
       case 7:
	npShot->byColor = DKGREEN;
	break;
       case 0:
	RemoveObj( &HunterShotList, npShot );
	AddHeadObj( &FreeList, npShot );
	break;
      }
    }
    DrawObject( npShot );
  }
}


/* FireHunterShot - fire a hunter bullet */

void FireHunterShot( OBJ *npHunt )
{
  OBJ *          npShot;

  if ((npShot = RemHeadObj( &FreeList )))
  {
    queuesam(BSHOT_CHANNEL,BSHOT_SAMPLE);
    npShot->Pos.x = npHunt->Pos.x;
    npShot->Pos.y = npHunt->Pos.y;
    npShot->Vel.x = npHunt->Vel.x;
    npShot->Vel.y = npHunt->Vel.y;
    npShot->nMass = 8;
    npShot->nDir = npHunt->nDir + my_rand( 5 ) - 2;
    npShot->nSpin = (my_rand( 2 ) ? 10 : -10);
    npShot->nCount = (16 + my_rand( 8 ));
    npShot->byColor = GREEN;
    npShot->byPts = 2;
    npShot->Pts[0].x = 128;
    npShot->Pts[0].y = 50;
    npShot->Pts[1].x = 0;
    npShot->Pts[1].y = 50;
    ACCEL( npShot, npShot->nDir, 200 + npShot->nCount );
    AddHeadObj( &HunterShotList, npShot );
  }
}


/* CreateHunter - make a new hunter */

void CreateHunter( void )
{
  OBJ *          npHunt;
  int             nCnt;

  if ((npHunt = RemHeadObj( &FreeList )))
  {
    queuesam(EFFECT_CHANNEL,NEWHUNT_SAMPLE);
    npHunt->Pos.x = my_rand( CLIP_COORD * 2 ) - CLIP_COORD;
    npHunt->Pos.y = -CLIP_COORD;
    npHunt->Vel.x = npHunt->Vel.y = 0;
    npHunt->nMass = 256;
    npHunt->nDir = my_rand( DEGREE_SIZE );
    npHunt->nSpin = 0;
    npHunt->nCount = 1 + my_rand( nLevel );
    npHunt->nDelay = 2 + my_rand( 10 );
    npHunt->byColor = CYAN;
    npHunt->byPts = DIM(Hunter);
    for (nCnt = 0; nCnt < DIM(Hunter); ++nCnt)
      npHunt->Pts[nCnt] = Hunter[nCnt];
    ACCEL( npHunt, npHunt->nDir, 30 + nLevel * 2 );
    AddHeadObj( &HunterList, npHunt );
    ++nBadGuys;
  }
}


/* DrawHunters - process and draw the hunter list */

void DrawHunters( void )
{
  OBJ *npHunt, *npNext;
  static int       nNextHunter = 200;

  if (!bPaused && nBadGuys && (--nNextHunter < 0))
  {
    CreateHunter();
    nNextHunter = (1000 + my_rand( 1000 ) - nLevel * 8);
  }

  for (npHunt = HeadObj( &HunterList ); npHunt; npHunt = npNext)
  {
    OBJ *          npShot;
    RECT            rect;

    npNext = NextObj( npHunt );
    if(!bPaused) {
      MKRECT( &rect, npHunt->Pos, 200 );

      if (PTINRECT( &rect, me.Player->Pos ))
      {
	HitPlayer( npHunt, HIT_SHIP );
	--npHunt->nCount;
	if (npHunt->nCount < 1)
	{
	  KillBadGuy();
	  npHunt->byColor = CYAN;
	  Explode( npHunt );
	  queuesam(BADDIE_CHANNEL,HUNTEXPLODE_SAMPLE);
	  RemoveObj( &HunterList, npHunt );
	  AddHeadObj( &FreeList, npHunt );
	}
	else if (npHunt->nCount == 1)
	{
	  npHunt->byColor = DKCYAN;
	  queuesam(BADDIE_CHANNEL,BADDIEWOUND_SAMPLE);
	}
      }
      else if (INTRECT(&rect, &rectShotClip))
      {
	for (npShot = HeadObj( &ShotList ); npShot; npShot = NextObj( npShot ))
	{
	  if (!PTINRECT( &rect, npShot->Pos )) continue;
	  npShot->nCount = 1;
	  me.Score += npHunt->nCount * 1000;
	  if (--npHunt->nCount < 1)
	  {
	    KillBadGuy();
	    npHunt->byColor = CYAN;
	    Explode( npHunt );
	    queuesam(BADDIE_CHANNEL,HUNTEXPLODE_SAMPLE);
	    RemoveObj( &HunterList, npHunt );
	    AddHeadObj( &FreeList, npHunt );
	  }
	  else
	  {
	    if (npHunt->nCount == 1) npHunt->byColor = DKCYAN;
	    Hit( npHunt );
	    queuesam(BADDIE_CHANNEL,BADDIEWOUND_SAMPLE);
	  }
	  break;
	}
      }
      ACCEL( npHunt, npHunt->nDir, 8 );
      npHunt->Vel.x -= npHunt->Vel.x / 16;
      npHunt->Vel.y -= npHunt->Vel.y / 16;
      if (--npHunt->nDelay <= 0)
      {
	npHunt->nDelay = (my_rand( 10 ));
	npHunt->nSpin = my_rand( 11 ) - 5;
	FireHunterShot( npHunt );
      }
    }
    DrawObject( npHunt );
  }
}


/* CreateSwarmer - make a new swarmer */

void CreateSwarmer( POINT Pos, int nDir, int nCount )
{
  OBJ *          npSwarm;
  int             nCnt;

  if ((npSwarm = RemHeadObj( &FreeList )))
  {
    queuesam(EFFECT_CHANNEL,NEWSWARM_SAMPLE);
    npSwarm->Pos = Pos;
    npSwarm->Vel.x = npSwarm->Vel.y = 0;
    npSwarm->nDir = nDir;
    npSwarm->nSpin = my_rand( 31 ) - 15;
    npSwarm->nCount = nCount;
    npSwarm->nDelay = 64 + my_rand( 64 );
    npSwarm->nMass = 32;
    npSwarm->byColor = DKGREEN;
    npSwarm->byPts = DIM(Swarmer);
    for (nCnt = 0; nCnt < DIM(Swarmer); ++nCnt)
    {
      npSwarm->Pts[nCnt] = Swarmer[nCnt];
      npSwarm->Pts[nCnt].y += nCount * 10;
    }
    ACCEL( npSwarm, npSwarm->nDir, 30 + nLevel * 2 );
    AddHeadObj( &SwarmerList, npSwarm );
    ++nBadGuys;
  }
}


/* DrawSwarmers - process and draw the swarmer list */

void DrawSwarmers( void )
{
  OBJ *npSwarm, *npNext;
  static int nNextSwarmer = 1000;

  if (!bPaused && nBadGuys && (--nNextSwarmer < 0))
  {
    POINT Pos;
    Pos.x = my_rand( CLIP_COORD * 2 ) - CLIP_COORD;
    Pos.y = -CLIP_COORD;
    CreateSwarmer( Pos, my_rand( DEGREE_SIZE ), 8 + nLevel * 2 );
    nNextSwarmer = 1000 + my_rand( 500 ) - nLevel * 4;
  }

  for (npSwarm = HeadObj( &SwarmerList ); npSwarm; npSwarm = npNext)
  {
    OBJ *          npShot;
    RECT            rect;

    npNext = NextObj( npSwarm );

    if(!bPaused) {
      MKRECT( &rect, npSwarm->Pos, 150 + npSwarm->nCount * 10 );

      if (PTINRECT( &rect, me.Player->Pos ))
      {
	HitPlayer( npSwarm, HIT_SHIP );
	npSwarm->nCount = 0;
      }
      else if (INTRECT(&rect, &rectShotClip))
      {
	for (npShot = HeadObj( &ShotList ); npShot; npShot = NextObj( npShot ))
	{
	  if (!PTINRECT( &rect, npShot->Pos )) continue;
	  npShot->nCount = 1;
	  me.Score += npSwarm->nCount * 25;
	  npSwarm->nCount = 0;
	  break;
	}
      }
      if (npSwarm->nCount <= 0)
      {
	npSwarm->byColor = GREEN;
	KillBadGuy();
	Explode( npSwarm );
	queuesam(BADDIE_CHANNEL,SWARMSPLIT_SAMPLE);
	RemoveObj( &SwarmerList, npSwarm );
	AddHeadObj( &FreeList, npSwarm );
      }
      else
      {
	if ((npSwarm->nCount > 1) && (--npSwarm->nDelay <= 0))
	{
	  int nDir = my_rand( DEGREE_SIZE );
	  int nCount = npSwarm->nCount / 2;
	  CreateSwarmer( npSwarm->Pos, nDir, nCount );
	  nCount = npSwarm->nCount - nCount;
	  CreateSwarmer( npSwarm->Pos, nDir + 128, nCount );
	  npSwarm->nCount = 0;
	}
	DrawObject( npSwarm );
      }
    } else
      DrawObject( npSwarm );
  }
}


/* CreateSpinner - make a new spinner */

void CreateSpinner( void )
{
  OBJ *          npSpin;
  int             nCnt;

  if ((npSpin = RemHeadObj( &FreeList )))
  {
    queuesam(EFFECT_CHANNEL,NEWSPIN_SAMPLE);
    npSpin->Pos.x = my_rand( CLIP_COORD * 2 ) - CLIP_COORD;
    npSpin->Pos.y = -CLIP_COORD;
    npSpin->Vel.x = npSpin->Vel.y = 0;
    npSpin->nDir = my_rand( DEGREE_SIZE );
    npSpin->nSpin = -12;
    npSpin->nCount = 1 + my_rand( nLevel );
    npSpin->nMass = 64 + npSpin->nCount * 32;
    npSpin->byColor = (BYTE)(MAGENTA - npSpin->nCount);
    npSpin->byPts = DIM(Spinner);
    for (nCnt = 0; nCnt < DIM(Spinner); ++nCnt)
      npSpin->Pts[nCnt] = Spinner[nCnt];
    ACCEL( npSpin, npSpin->nDir, 30 + nLevel * 2 );
    AddHeadObj( &SpinnerList, npSpin );
    ++nBadGuys;
  }
}


/* DrawSpinners - process and draw the spinner list */

void DrawSpinners( void )
{
  OBJ *npSpin, *npNext;
  static int       nNextSpinner = 1000;

  if (!bPaused && nBadGuys && (--nNextSpinner < 0))
  {
    CreateSpinner();
    nNextSpinner = 100 + my_rand( 900 ) - nLevel * 2;
  }

  for (npSpin = HeadObj( &SpinnerList ); npSpin; npSpin = npNext)
  {
    OBJ *          npShot;
    int             nDelta;
    RECT            rect;

    npNext = NextObj( npSpin );
    if(!bPaused) {
      MKRECT( &rect, npSpin->Pos, 150 );

      if (PTINRECT( &rect, me.Player->Pos ))
      {
	HitPlayer( npSpin, HIT_SHIP );
	--npSpin->nCount;
	npSpin->byColor = (BYTE)(MAGENTA - npSpin->nCount);
	if (npSpin->nCount < 1)
	{
	  KillBadGuy();
	  Explode( npSpin );
	  queuesam(BADDIE_CHANNEL,SPINEXPLODE_SAMPLE);
	  RemoveObj( &SpinnerList, npSpin );
	  AddHeadObj( &FreeList, npSpin );
	}
	else
	{
	  queuesam(BADDIE_CHANNEL,BADDIEWOUND_SAMPLE);
	}
      }
      else if (INTRECT(&rect, &rectShotClip))
      {
	for (npShot = HeadObj( &ShotList ); npShot; npShot = NextObj( npShot ))
	{
	  if (!PTINRECT( &rect, npShot->Pos )) continue;
	  npShot->nCount = 1;
	  me.Score += npSpin->nCount * 500;
	  npSpin->byColor = (BYTE)(MAGENTA - (--npSpin->nCount));
	  if (npSpin->nCount < 1)
	  {
	    KillBadGuy();
	    Explode( npSpin );
	    queuesam(BADDIE_CHANNEL,SPINEXPLODE_SAMPLE);
	    RemoveObj( &SpinnerList, npSpin );
	    AddHeadObj( &FreeList, npSpin );
	  }
	  else
	  {
	    Hit( npSpin );
	    queuesam(BADDIE_CHANNEL,BADDIEWOUND_SAMPLE);
	  }
	  break;
	}
      }
      nDelta = me.Player->Pos.x - npSpin->Pos.x;
      while (nDelta < -16 || nDelta > 16) nDelta /= 2;
      npSpin->Vel.x += nDelta - npSpin->Vel.x / 16;
      nDelta = me.Player->Pos.y - npSpin->Pos.y;
      while (nDelta < -16 || nDelta > 16) nDelta /= 2;
      npSpin->Vel.y += nDelta - npSpin->Vel.y / 16;
    }
    DrawObject( npSpin );
  }
}


/* CreateRoid - make a new asteroid */

void CreateRoid( POINT Pos, POINT Vel, int nSides, BYTE byColor,
		 int nDir, int nSpeed, int nSpin )
{
  OBJ *          npRoid;
  int             nCnt;
  if ((npRoid = RemHeadObj( &FreeList )))
  {
    npRoid->Pos = Pos;
    npRoid->Vel = Vel;
    npRoid->nMass = nSides * 128;
    npRoid->nDir = nDir;
    npRoid->nSpin = nSpin + my_rand( 11 ) - 5;
    npRoid->nCount = nSides * 100;
    npRoid->byColor = byColor;
    npRoid->byPts = (BYTE)(nSides + 1);
    for (nCnt = 0; nCnt < nSides; ++nCnt)
    {
      npRoid->Pts[nCnt].x = nCnt * DEGREE_SIZE / nSides + my_rand( 30 );
      npRoid->Pts[nCnt].y = (nSides - 1) * 100 + 20 + my_rand( 80 );
    }
    npRoid->Pts[nSides] = npRoid->Pts[0];
    ACCEL( npRoid, nDir, nSpeed );
    AddHeadObj( &RoidList, npRoid );
    ++nBadGuys;
  } 
}


/* BreakRoid - break up an asteroid */

void BreakRoid( OBJ *npRoid, OBJ *npShot )
{
  int             nCnt, nNew;

  me.Score += npRoid->nCount;
  if (npShot) npShot->nCount = 1;
  switch (npRoid->byPts)
  {
   case 8:
    nNew = 2 + my_rand( 3 );
    break;
   case 7:
    nNew = 1 + my_rand( 3 );
    break;
   case 6:
    nNew = 1 + my_rand( 2 );
    break;
   case 5:
    nNew = my_rand( 2 );
    break;
   default:
    nNew = 0;
    break;
  }
  if (nNew == 1)		/* don't explode outward */
  {
    POINT Pt = npRoid->Pos;
    Pt.x += my_rand( 301 ) - 150; Pt.y += my_rand( 301 ) - 150;
    CreateRoid( Pt, npRoid->Vel, npRoid->byPts - (nNew + 1),
		npRoid->byColor, npShot?(npShot->nDir):npRoid->nDir,
		8, npRoid->nSpin );
  }
  else if (nNew > 0)
  {
    int nSpeed = npRoid->nSpin * npRoid->nSpin * nNew + 16;
    for (nCnt = 0; nCnt < nNew; ++nCnt)
    {
      POINT Pt = npRoid->Pos;
      Pt.x += my_rand( 601 ) - 300; Pt.y += my_rand( 601 ) - 300;
      CreateRoid( Pt, npRoid->Vel, npRoid->byPts - (nNew + 1),
		  npRoid->byColor,
		  npRoid->nDir + nCnt * DEGREE_SIZE / nNew + my_rand( 32 ),
		  nSpeed + my_rand( nLevel * 4 ),
		  npRoid->nSpin / 2 );
    }
  }
  KillBadGuy();
  ++npRoid->byColor;
  npRoid->nCount = 0;
  if (nNew)
  {
    Hit( npRoid );
    DrawObject( npRoid );
    queuesam(ASTEROID_CHANNEL,ROIDSPLIT_SAMPLE);
  }
  else
  {
    Explode( npRoid );
    queuesam(ASTEROID_CHANNEL,ROIDNOSPLIT_SAMPLE);
  }
  RemoveObj( &RoidList, npRoid );
  AddHeadObj( &FreeList, npRoid );
}


/* DrawRoids - process and draw the asteroid list */

void DrawRoids( void )
{
  OBJ *npRoid, *npNext;

  for (npRoid = HeadObj( &RoidList ); npRoid; npRoid = npNext)
  {
    int             nSize = npRoid->nCount;
    OBJ *          npShot;
    RECT            rect;

    npNext = NextObj( npRoid );

    DrawObject( npRoid );
    if(bPaused)
      continue;
    MKRECT( &rect, npRoid->Pos, nSize );

    if (PTINRECT( &rect, me.Player->Pos ) && HitPlayer( npRoid, HIT_ROID ))
    {
      me.Player->nCount = -me.Player->nCount;
      me.Player->byColor = WHITE;
      Explode( me.Player );
      BreakRoid( npRoid, NULL );
      if (nBadGuys) SetRestart( RESTART_LEVEL );
      else SetRestart( RESTART_NEXTLEVEL );
    }
    else if (INTRECT(&rect, &rectShotClip))
    {
      for (npShot = HeadObj( &ShotList ); npShot; npShot = NextObj( npShot ))
      {
	if (!PTINRECT( &rect, npShot->Pos )) continue;
	BreakRoid( npRoid, npShot );
	break;
      }
    }
  }
}


/* DrawShots - process and draw the player shot list */

void DrawShots( void )
{
  OBJ *npShot, *npNext;

  if ((npShot = HeadObj( &ShotList )))
  {
    rectShotClip.left = rectShotClip.right = npShot->Pos.x;
    rectShotClip.top = rectShotClip.bottom = npShot->Pos.y;
    while (npShot)
    {
      npNext = NextObj( npShot );
      if(!bPaused) {
	switch (--npShot->nCount)
	{
	 case 10:
	  npShot->byColor = DKCYAN;
	  break;
	 case 5:
	  npShot->byColor = DKBLUE;
	  break;
	 case 0:
	  RemoveObj( &ShotList, npShot );
	  AddHeadObj( &FreeList, npShot );
	  break;
	}
      }
      DrawObject( npShot );
      if(!bPaused) {
	if (npShot->Pos.x < rectShotClip.left)
	  rectShotClip.left = npShot->Pos.x;
	else if (npShot->Pos.x > rectShotClip.right)
	  rectShotClip.right = npShot->Pos.x;
	if (npShot->Pos.y < rectShotClip.top)
	  rectShotClip.top = npShot->Pos.y;
	else if (npShot->Pos.y > rectShotClip.bottom)
	  rectShotClip.bottom = npShot->Pos.y;
      }
      npShot = npNext;
    }
  }
  else
    rectShotClip.left = rectShotClip.right =
      rectShotClip.top = rectShotClip.bottom = 32767;
}


/* DrawFlames - process and draw the flame list */

void DrawFlames( void )
{
  OBJ *npFlame, *npNext;

  for (npFlame = HeadObj( &FlameList ); npFlame; npFlame = npNext)
  {
    npNext = NextObj( npFlame );
    if(!bPaused) {
      switch (--npFlame->nCount)
      {
       case 7:
	npFlame->byColor = RED;
	break;
       case 3:
	npFlame->byColor = DKRED;
	break;
       case 0:
	RemoveObj( &FlameList, npFlame );
	AddHeadObj( &FreeList, npFlame );
	break;
      }
    }
    DrawObject( npFlame );
  }
}


/* FireShot - fire a bullet */

void LowFireShot(int nDir, int nCount)
{
  OBJ *          npShot;
  if ((npShot = RemHeadObj( &FreeList )))
  {
    npShot->Pos.x = me.Player->Pos.x;
    npShot->Pos.y = me.Player->Pos.y;
    npShot->Vel.x = me.Player->Vel.x;
    npShot->Vel.y = me.Player->Vel.y;
    npShot->nMass = 8;
    npShot->nDir = nDir;
    npShot->nSpin = 0;
    npShot->nCount = nCount;
    npShot->byColor = CYAN;
    npShot->byPts = 2;
    npShot->Pts[0].x = 128;
    npShot->Pts[0].y = 50;
    npShot->Pts[1].x = 0;
    npShot->Pts[1].y = 50;
    ACCEL( npShot, npShot->nDir, 200 + npShot->nCount );
    AddHeadObj( &ShotList, npShot );
  }
}  

void FireShot( void )
{
  int nDir, nCount;
  
  nDir = me.Player->nDir + my_rand( 5 ) - 2;
  nCount = (int)(me.GunRange * (16 + my_rand( 8 )));
  queuesam(PSHOT_CHANNEL, PSHOT_SAMPLE);
  switch(me.Guns) {
  case 1:
    LowFireShot(nDir, nCount);
    break;
  case 2:    
    LowFireShot(nDir-5, nCount);
    LowFireShot(nDir+5, nCount);
    break;
  case 3:
    LowFireShot(nDir, nCount);
    LowFireShot(nDir-15, nCount-5);
    LowFireShot(nDir+15, nCount-5);
  }
}


/* AccelPlayer - move the player forward */

void AccelPlayer( int nDir, int nAccel )
{
  OBJ *          npFlame;

  /*  queuesam(PTHRUST_CHANNEL,PTHRUST_SAMPLE);*/
  nDir += me.Player->nDir;
  if (nAccel) ACCEL( me.Player, nDir, nAccel );
  if ((npFlame = RemHeadObj( &FreeList )))
  {
    npFlame->Pos.x = me.Player->Pos.x;
    npFlame->Pos.y = me.Player->Pos.y;
    npFlame->Vel.x = me.Player->Vel.x;
    npFlame->Vel.y = me.Player->Vel.y;
    npFlame->nDir = nDir + 100 + my_rand( 57 );
    npFlame->nSpin = 0;
    npFlame->nCount = (nAccel + my_rand( 7 ));
    npFlame->byColor = YELLOW;
    npFlame->byPts = 1;
    npFlame->Pts[0].x = npFlame->Pts[0].y = 0;
    ACCEL( npFlame, npFlame->nDir, 50 + my_rand( 10 ) );
    AddHeadObj( &FlameList, npFlame );
  }
}


/* HitList - Hit() a list of things */

void HitList( LIST *npList )
{
  OBJ *          npObj;

  for (npObj = HeadObj( npList ); npObj; npObj = NextObj( npObj ))
    if (npObj->nCount) Hit( npObj );
}


/* ExplodeBadguys - explode a list of badguys */

void ExplodeBadguys( LIST *npList )
{
  OBJ *          npObj;

  while ((npObj = HeadObj( npList )))
  {
    KillBadGuy();
    npObj->nCount = 0;
    Explode( npObj );
    RemoveObj( npList, npObj );
    AddHeadObj( &FreeList, npObj );
  }
}


/* DrawShield - draw the shield around the player */
void DrawShield( void ) {
  ResetRefreshCoords();
  if(me.Shield.Old.x != -1)
    /* Must delete old shield */
  {
    set_colour(BLACK);
    Circle(me.Shield.Old.x, me.Shield.Old.y, me.Shield.Radius);
  }
  if(me.Shield.byColor == BLACK) {
    /* Shield gone..*/
    me.Shield.Old.x = -1;
  } else {
    set_colour(me.Shield.byColor);
    Circle(me.Shield.Pos.x, me.Shield.Pos.y, me.Shield.Radius);
    me.Shield.Old.x = me.Shield.Pos.x;
    me.Shield.Old.y = me.Shield.Pos.y;
  }
  RedrawObject();
}


/* DrawPlayer - process and draw the player */

void DrawPlayer( void )
{
  static int       nBombing = 0;
  static int       nShotDelay = 0;
  float keyval;
  if (me.Player->nCount <= 0) return;
  if(!bPaused) {
    if (me.ExtraShields) { 
      me.Shield.byColor = GREEN;
      me.ExtraShields--;
      me.isSafe = 1;
    } else if(IsKeyDown( KEY_TAB ) && me.Shields) {
      me.Shield.byColor = GREEN;
      me.Shields--;
      me.isSafe = 1;
    } else if(me.Shield.byColor != BLACK) {
      me.Shield.byColor = BLACK;
      me.isSafe = 0;
      DrawShield();
    }
    if (nBombing > 0)
    {
      if (--nBombing == 0)
      {
	ExplodeBadguys( &SpinnerList );
	ExplodeBadguys( &SwarmerList );
	ExplodeBadguys( &HunterList );
	queuesam(EFFECT_CHANNEL,EXPLODE2_SAMPLE);
      }
      else
      {
	HitList( &SpinnerList );
	HitList( &SwarmerList );
	HitList( &HunterList );
      }
    }
    else if (me.Bombs && IsKeyDown( KEY_S )) --me.Bombs, nBombing = (5);
    
    if ( (keyval = IsKeyDown( KEY_LEFT )) ) {
      me.Player->nSpin += (int)(keyval * 8);
    } else if ( (keyval = IsKeyDown( KEY_RIGHT )) ) {
      me.Player->nSpin -= (int)(keyval * 8);
    }
    if ( (keyval = IsKeyDown( KEY_UP )) ) {
      AccelPlayer( 0, (int)(keyval * 12) );
    }
    else if ( (keyval = IsKeyDown( KEY_DOWN )) ) {
      AccelPlayer( 128, (int)(keyval * 12));
    }
    if (!bPaused && nShotDelay) --nShotDelay;
    else if (IsKeyDown( KEY_SPACE )) FireShot(), nShotDelay = (2);
  }
  DrawObject( me.Player );
  if(me.Shield.byColor != BLACK) {
    me.Shield.Pos.y = me.Player->Pos.y;
    me.Shield.Pos.x = me.Player->Pos.x;
    DrawShield();
  }
  if(!bPaused)
    me.Player->nSpin /= 2;
}



/* DrawObjects - transform and redraw everything in the system */

void DrawObjects( void )
{
  /* move and draw things (I don't think the order is important...) */
  lock_graphics();
  DrawPlayer();
  DrawFlames();
  DrawShots();
  DrawRoids();
  DrawSpinners();
  DrawSwarmers();
  DrawHunters();
  DrawHunterShots();
  DrawBonuses();
  DrawLetters();
  unlock_graphics();
  /* (...but I'm not changing it!!! :-) */
}


/* CheckScore - show the score and such stuff */

void CheckScore( void )
{
  int nLives;

  if (me.Score - me.LastLife > EXTRA_LIFE)
  {
    AddExtraLife();
    me.LastLife = me.Score;
  }

  /* apparently, -ve player lives means we're starting a new
   * life soon (ouch). -rjm
   */
  nLives=((me.Player->nCount > 0) ? me.Player->nCount : -me.Player->nCount);

  /* actually do the score/lives/etc-drawing */
  score_graphics(nLevel,me.Score,nLives,me.Shields,me.Bombs);
}

/* RestartHyperoid - set up a game! */

void RestartHyperoid( void )
{
  if (me.Player->nCount == 0)
  { /* Player died, this is a new game */
    POINT Pos, Vel;
    Pos.x = 0;
    Pos.y = -CLIP_COORD / 2;
    Vel.x = 0;
    Vel.y = 150;
    PrintLetters( VERSION, Pos, Vel, YELLOW, 800 );
    Vel.y = -150;
    Pos.y = CLIP_COORD/2;
    PrintLetters( "SDLROIDS", Pos, Vel, YELLOW, 800 );
    queuesam(BADDIE_CHANNEL,TITLE_SAMPLE);
    queuesam(BSHOT_CHANNEL,TITLE_SAMPLE);
    me.Player->nCount = 3;
    if (lHighScore < me.Score) lHighScore = me.Score;
    me.LastLife = me.Score = 0;
    nLevel = 0;
    me.Shields = 150;
    me.Bombs = 3;
    me.Guns = 1; 
    me.GunRange = 1.0;
  }
  else if (me.Player->nCount < 0)
  {
    /* cheesy way of restarting after a major collision */
    me.Player->nCount = -me.Player->nCount;
  }
  me.Player->Pos.x = me.Player->Pos.y = 0;
  me.Player->Vel.x = me.Player->Vel.y = 0;
  me.Player->nDir = 64;
  me.Player->nSpin = 0;
  me.Player->byColor = WHITE;
  me.ExtraShields = 30;
  me.Shield.byColor = GREEN;
  if (ShotList.npHead)
  {
    OBJ *npShot;
    for (npShot = HeadObj( &ShotList ); npShot; npShot = NextObj( npShot ))
      npShot->nCount = 1;
  }

  /* reseed the asteroid field */
  if (nBadGuys == 0)
  {
    int nCnt;
    ++nLevel;
    for (nCnt = 5 + nLevel; nCnt; --nCnt)
    {
      POINT Pos, Vel;
      Pos.x = my_rand( MAX_COORD * 2 ) - MAX_COORD;
      Pos.y = my_rand( MAX_COORD * 2 ) - MAX_COORD;
      Vel.x = Vel.y = 0;
      CreateRoid( Pos, Vel, 6 + my_rand( 2 ),
		  (BYTE)(my_rand( 2 ) ? DKYELLOW : DKGREY),
		  my_rand( DEGREE_MAX ), 30 + my_rand( nLevel * 8 ), 0 );
    }
  }
}



/* InitHyperoid - initialize everything */

void InitHyperoid( void )
{
  double          dRad;
  int             nCnt;

  /* seed the randomizer */
  dwSeed = time(NULL);	/* XXX GetCurrentTime(); */

  /* create the lookup table */
  for (nCnt = 0; nCnt < DEGREE_SIZE; ++nCnt)
  {
    dRad = nCnt * 6.2831855 / DEGREE_SIZE;
    nCos[nCnt] = (int)(DEGREE_MAX * cos( dRad ));
    nSin[nCnt] = (int)(DEGREE_MAX * sin( dRad ));
  }

  /* allocate all objects as free */
  for (nCnt = 0; nCnt < MAX_OBJS; ++nCnt)
    AddHeadObj( &FreeList, &(Obj[nCnt]) );

  /* set up the player */
  me.Player = RemHeadObj( &FreeList );
  me.Player->byPts = DIM(Player);
  me.Player->nMass = 256;
  for (nCnt = 0; nCnt < DIM(Player); ++nCnt)
    me.Player->Pts[nCnt] = Player[nCnt];
  me.Shield.Radius = 200;
  me.Shield.Old.x = -1;
}

void do_sleep()
{
  static int lasttick = 0;
  int frametime;
  if(!lasttick) { 
    lasttick = SDL_GetTicks();
    return;
  }
  frametime = SDL_GetTicks() -lasttick;   
  if(frametime <50) SDL_Delay(50-frametime );
  lasttick = SDL_GetTicks();
}

int main(int argc,char *argv[])
{
  int quit=0, framecount=0, i;
  Uint32 start, timed;
  getargs(argc, argv);
  my_srand(time(NULL));
  /* find the last slash */
  for (i = strlen(argv[0]); i >= 0 && argv[0][i] != '/'; i--)
    ;
  if(i > 0) {
    bindir = malloc(i+2);
    strncpy(bindir, argv[0], i+1);
  }
  else bindir = NULL;
  
  init_graphics(palrgb);
  if(!ARG_NOSND) init_sound();

  InitHyperoid();
  RestartHyperoid();
  start = SDL_GetTicks();
  while(!quit)
  {    
    if(ARG_BENCH==0) {
      do_sleep();
    }
    
    else if((++framecount) >= ARG_BENCH)
      quit = 1;
    if(!bPaused) {
      DrawObjects();
      CheckScore();
    }
    update_graphics();
    if(bRestart)
    {
      restart_timer_count--;
      if(restart_timer_count==0)
      {
	bRestart = FALSE;
	bPaused = 0;
	RestartHyperoid();
      }
    }
    if(game_done) NewGame(RESTART_DEATH);
    else if(IsKeyDown(KEY_F1)) {
      NewGame(RESTART_GAME);
      update_graphics();
    }
    if(IsKeyDown(KEY_ESC)) quit=1;
  }
  timed = SDL_GetTicks() - start;
  if(ARG_BENCH) 
    printf("\r%10d frames in %5.2f seconds, %f fps.\n",
	   framecount, timed/1000.0, 
	   (float)framecount / (timed / 1000.0));
  
  exit_sound();
  exit_graphics();
  if(bindir != NULL) free(bindir);
  exit(0);
}
