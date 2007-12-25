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
 * getargs.g - command line defines and prototypes.
 */

/* Number of integer (flag) options */
#define NUMARGS    10

/* Shortcut for accessing the values */
#define ARG_FSCRN   flagargs[0]
#define ARG_BENCH   flagargs[1]
#define ARG_NOSND   flagargs[2]
#define ARG_WIDTH   flagargs[3]
#define ARG_HEIGHT  flagargs[4]
#define ARG_JOYNUM  flagargs[5]
#define ARG_JFIRE   flagargs[6]
#define ARG_JSHIELD flagargs[7]
#define ARG_JBOMB   flagargs[8]
#define ARG_JLIST   flagargs[9]

/* getargs() prototype */
void getargs(int, char *[]);
int flagargs[NUMARGS];
