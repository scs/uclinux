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
 * sound.h - sound related defines and prototypes.
 */

/* virtual sound channels, used for mixing.
 * each can play at most one sample at a time.
 */

#define PSHOT_CHANNEL	0	/* player shot */
#define PTHRUST_CHANNEL 1
#define ASTEROID_CHANNEL 2	/* asteroid being hit */
#define BADDIE_CHANNEL	3	/* baddie being hit */
#define BSHOT_CHANNEL	4	/* baddie shot channel */
#define EFFECT_CHANNEL  5	/* effects like level end noises */

#define NUM_CHANNELS	6

/* sample offsets in sample[] */
#define PSHOT_SAMPLE		0
#define PTHRUST_SAMPLE		1
#define EXPLODE_SAMPLE		2
#define EXPLODE2_SAMPLE		3
#define BSHOT_SAMPLE		4
#define PHIT_SAMPLE		5
#define TITLE_SAMPLE		6
#define NEWBONUS_SAMPLE		7
#define NEWHUNT_SAMPLE		8
#define NEWSWARM_SAMPLE		NEWHUNT_SAMPLE
#define NEWSPIN_SAMPLE		NEWHUNT_SAMPLE
#define BONUSGOT_SAMPLE		9
#define BONUSSHOT_SAMPLE	EXPLODE_SAMPLE
#define BONUSTIMEOUT_SAMPLE	EXPLODE_SAMPLE
#define HUNTEXPLODE_SAMPLE	EXPLODE2_SAMPLE
#define SPINEXPLODE_SAMPLE	EXPLODE_SAMPLE
#define ROIDSPLIT_SAMPLE	EXPLODE_SAMPLE
#define ROIDNOSPLIT_SAMPLE	EXPLODE_SAMPLE
#define BADDIEWOUND_SAMPLE	10
#define SWARMSPLIT_SAMPLE	11
#define EXTRALIFE_SAMPLE	BONUSGOT_SAMPLE
#define NUM_SAMPLES		12


extern void queuesam(int chan,int sam);
extern void loopsam(int chan,int sam);
extern void init_sound(void);
extern void exit_sound(void);
