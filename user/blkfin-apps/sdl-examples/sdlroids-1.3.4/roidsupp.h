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
 * roidsupp.h - support function prototypes
 */


extern void PrintLetters( char *npszText, POINT Pos, POINT Vel,
			  BYTE byColor, int nSize );
extern void SpinLetters( char *npszText, POINT Pos, POINT Vel,
			 BYTE byColor, int nSize );

extern POINT LetterPart[];
extern char *NumberDesc[],*LetterDesc[];
extern char *datafilename(char *, char *);
