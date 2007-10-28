/****************************************************************************
 ** hw_accent.h *************************************************************
 ****************************************************************************
 *
 * Author:	Niccolo Rigacci <niccolo@rigacci.org>
 *
 * Credits:	Christoph Bartelmus <lirc@bartelmus.de>
 * 		Bart Alewijnse <scarfboy@yahoo.com>
 * 		Leandro Dardini <ldardini@tiscali.it>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef _HW_ACCENT_H
#define _HW_ACCENT_H

#include "drivers/lirc.h"

int accent_decode (struct ir_remote *remote,
		   ir_code *prep,
		   ir_code *codep,
		   ir_code *postp,
		   int *repeat_flagp,
		   lirc_t *remaining_gapp);

int accent_open_serial_port(char *device);
int accent_init(void);
int accent_deinit(void);
char *accent_rec(struct ir_remote *remotes);

#endif
