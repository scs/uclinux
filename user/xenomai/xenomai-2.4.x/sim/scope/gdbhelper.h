/* -*- C++ -*-
 * This file is part of the XENOMAI project.
 *
 * Copyright (C) 1997-2000 Realiant Systems.  All rights reserved.
 * Copyright (C) 2001,2002 Philippe Gerum <rpm@xenomai.org>.
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
 *
 * The original code is CarbonKernel - Real-time Operating System Simulator,
 * released April 15, 2000. The initial developer of the original code is
 * Realiant Systems (http://www.realiant.com).
 *
 * Description: Miscellaneous definitions for the GDB support code.
 *
 * Author(s): rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifndef _gdbhelper_h
#define _gdbhelper_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#define GDBPROTO_UNSPEC 0	// <= Must be zero
#define GDBPROTO_KISRT  1
#define GDBPROTO_KDSRT  2
#define GDBPROTO_KROOT  3
#define GDBPROTO_KCOUT  4
#define GDBPROTO_KIDLE  5
#define GDBPROTO_KDOOR  6
#define GDBPROTO_KHOOK  7
#define GDBPROTO_KINIT  8
#define GDBPROTO_KPREA  9
#define GDBPROTO_KPRIV  10
#define GDBPROTO_KHIDE  11

void helperAttach(Tcl_Interp *tclInterp);

void helperDetach(Tcl_Interp *tclInterp);

#endif // !_gdbhelper_h
