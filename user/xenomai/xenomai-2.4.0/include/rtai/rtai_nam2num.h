/**
 * @note Copyright &copy; 1999-2003 Paolo Mantegazza <mantegazza@aero.polimi.it>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef _RTAI_XENO_NAM2NUM_H
#define _RTAI_XENO_NAM2NUM_H

#include <rtai/rtai_types.h>

static inline unsigned long nam2num (const char *name)
{
        unsigned long retval = 0;
	int c, i;

	for (i = 0; i < 6; i++) {
		if (!(c = name[i]))
			break;
		if (c >= 'a' && c <= 'z') {
			c +=  (11 - 'a');
		} else if (c >= 'A' && c <= 'Z') {
			c += (11 - 'A');
		} else if (c >= '0' && c <= '9') {
			c -= ('0' - 1);
		} else {
			c = c == '_' ? 37 : 38;
		}
		retval = retval*39 + c;
	}
	if (i > 0)
		return retval;
	else
		return 0xFFFFFFFF;
}

static inline void num2nam (unsigned long num, char *name)
{
        int c, i, k, q; 
	if (num == 0xFFFFFFFF) {
		name[0] = 0;
		return;
	}
        i = 5; 
	while (num && i >= 0) {
		q = num/39;
		c = num - q*39;
		num = q;
		if ( c < 37) {
			name[i--] = c > 10 ? c + 'A' - 11 : c + '0' - 1;
		} else {
			name[i--] = c == 37 ? '_' : '$';
		}
	}
	for (k = 0; i < 5; k++) {
		name[k] = name[++i];
	}
	name[k] = 0;
}

#endif /* !_RTAI_XENO_NAM2NUM_H */
