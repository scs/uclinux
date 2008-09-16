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
 * graphics.h - graphic backend prototypes.
 */


extern float IsKeyDown(int);
extern void Circle(Sint16, Sint16, Sint32);
extern void Polyline(POINT *,int);
extern void SetPixel(Sint16, Sint16, Uint32);
extern void set_colour(int);
extern void score_graphics(int,int,int,int,int);
extern void init_graphics(int *);
extern void update_graphics(void);
extern void exit_graphics(void);
extern void ResetRefreshCoords(void);
extern void RedrawObject(void);
extern void lock_graphics(void);
extern void unlock_graphics(void);

