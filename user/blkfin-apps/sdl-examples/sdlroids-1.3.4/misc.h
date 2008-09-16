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
 * misc.h - misc defines and prototypes.
 */

/* extra data types and defines */

typedef unsigned char BYTE;

typedef struct { int x,y; } POINT;
typedef struct { int left,right,top,bottom; } RECT;


/* typedefs and defines */
#ifndef TRUE
#define TRUE		1
#define FALSE		0
#endif

/* color stuff */
#define PALETTE_SIZE 16
typedef enum
{
  BLACK, DKGREY, GREY, WHITE,
  DKRED, RED, DKGREEN, GREEN, DKBLUE, BLUE,
  DKYELLOW, YELLOW, DKCYAN, CYAN, DKMAGENTA, MAGENTA
} COLORS;

enum
{
  KEY_F1, KEY_TAB, KEY_S,
  KEY_LEFT, KEY_RIGHT, KEY_DOWN, KEY_UP,
  KEY_SPACE, KEY_ESC
};

/* degrees scaled to integer math */
#define DEGREE_SIZE 256
#define DEGREE_MASK 255
#define DEGREE_MAX 0x4000

/* object limits */
#define MAX_PTS 8
#define MAX_OBJS 200
#define MAX_COORD 0x2000
#define CLIP_COORD (MAX_COORD+300)

/* timer stuff */
#define FPS 50
#define RESTART_DELAY_FRAMES 60

/* restart modes */
typedef enum { RESTART_GAME, RESTART_LEVEL, RESTART_NEXTLEVEL, RESTART_DEATH } RESTART_MODE;

/* letter scaling */
#define LETTER_MAX 256

/* extra life every */
#define EXTRA_LIFE 100000

/* list node */
typedef struct tagNODE
{
  struct tagNODE  *npNext, *npPrev;
} NODE;

/* list header */
typedef struct
{
  NODE *npHead, *npTail;
} LIST;

/* object descriptor */
typedef struct
{
  NODE    Link;               /* for object list */
  POINT   Pos;                /* position of center of object */
  POINT   Vel;                /* velocity in logical units/update */
  int     nMass;              /* mass of object */
  int     nDir;               /* direction in degrees */
  int     nSpin;              /* angular momentum degrees/update */
  int     nCount;             /* used by different objects */
  int     nDelay;             /* used by different objects */
  BYTE    byColor;            /* palette color */
  BYTE    byPts;              /* number of points in object */
  POINT   Pts[MAX_PTS];       /* points making up an object */
  POINT   Old[MAX_PTS];       /* last plotted location */
} OBJ;

/* ship shield struct */
typedef struct
{
  POINT   Pos;                /* position of center of object */
  POINT   Old;		      /* old position of the object */
  BYTE    byColor;            /* palette color */
  int     Radius;             /* circle radius */
} CIRCLE;

typedef struct {
  OBJ 	*Player;	/* The player object */
  CIRCLE Shield;	/* The shield circle object */
  int 	 isSafe;	/* 1 == shields are on, 0 = shields off */
  int 	 Bombs;         /* Number of bombs left */
  int    Guns;          /* Number of guns */
  float  GunRange;      /* Gun range modified */
  int    Score; 	/* Player Score */
  int    LastLife;     /* Last score based extra life */
  int    Shields;       /* Shield strength */
  int    ExtraShields;  /* Bonus shield strength */
} PLAYER;
  

/* inline macro functions */

/* function aliases */
#define AddHeadObj(l,o) AddHead((l),((NODE *)o))
#define RemHeadObj(l) ((OBJ *)RemHead(l))
#define RemoveObj(l,o) Remove((l),((NODE *)o))
#define HeadObj(l) ((OBJ *)((l)->npHead))
#define NextObj(o) ((OBJ *)((o)->Link.npNext))


/* size of an array */
#define DIM(x) (sizeof(x)/sizeof((x)[0]))

/* faster than MulDiv! */
#define MULDEG(x,y) ((int)(((long)(x)*(y))/DEGREE_MAX))

/* DEG - convert an integer into a degree lookup index */
#define DEG(x) ((int)(x)&DEGREE_MASK)

/* ACCEL - accelerate an object in a given direction */
#define ACCEL(o,d,s) \
	(((o)->Vel.x += MULDEG((s),nCos[DEG(d)])), \
	((o)->Vel.y += MULDEG((s),nSin[DEG(d)])))

/* PTINRECT - a faster PtInRect */
#define PTINRECT(r,p) \
	(((r)->left <= (p).x) && ((r)->right > (p).x) && \
	((r)->top <= (p).y) && ((r)->bottom > (p).y))

/* INTRECT - a faster IntersectRect that just returns the condition */
#define INTRECT(r1,r2) \
	(((r1)->right >= (r2)->left) && \
	((r1)->left < (r2)->right) && \
	((r1)->bottom >= (r2)->top) && \
	((r1)->top < (r2)->bottom))

/* MKRECT - make a rect around a point */
#define MKRECT(r,p,s) \
	(((r)->left = ((p).x-(s))), ((r)->right = ((p).x+(s))), \
	((r)->top = ((p).y-(s))), ((r)->bottom = ((p).y+(s))))

/* this seems to be what MulDiv does -rjm */
#define MulDiv(x,y,z) ((x)*(y)/(z))

extern void BreakRoid( OBJ *, OBJ * );
extern void ExplodeBadguys( LIST * );
extern void Explode( OBJ * );

extern char *bindir;
