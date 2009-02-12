/*
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
 * The original code is FROGS - A Free Object-oriented General-purpose
 * Simulator, released November 10, 1999. The initial developer of the
 * original code is Realiant Systems (http://www.realiant.com).
 *
 * Author(s): tb
 * Contributor(s): rpm
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifdef __GNUG__
#pragma implementation
#endif // __GNUG__
#include <xeno_config.h>
#include <stdlib.h>
#include "vmutils/tclist++.h"
#include "vmutils/interface.h"
#include "vmutils/object.h"

u_long MvmObject::objectStamps = 0;

// MvmObject - a class modelizing a stateful object. It implements a
// dual control interface, accessible :
// 1) from a standard state diagram plotter.
// 2) from a custom Tcl/Tk graphical counterpart.
// This object is a monitor access point allowing a graphical
// front-end to extract and display its internal state and possibly
// change such state.

MvmObject::MvmObject (const char *_name,
		      const char *_group,
		      int _pflags,
		      MvmConnector *_connector,
		      int _logSize) :
    MvmStateDiagram(_name,
		    _logSize,
		    _connector,
		    _pflags)
{
    group = _group;
    state = SRAW;
    oid = ++objectStamps;
}

int MvmObject::setState (int _state)

{
    int nfires = 0;

    if (state != _state || getNumVal() < 2)
	{
	state = _state;
	add((double)stateIndex(state));
	}

    return nfires;
}

int MvmObject::stateIndex (int _state) {
    return _state;
}

const char *MvmObject::getCurveName ()

{
    static TclList fullName;

    fullName.set(ifGetName());

    if (!group.isEmpty())
	fullName.append(group);

    return fullName;
}
