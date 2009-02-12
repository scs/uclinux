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
 * Author(s): rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifdef __GNUG__
#pragma implementation
#endif // __GNUG__
#include <xeno_config.h>
#include "vmutils/toolshop.h"
#include "vmutils/interface.h"
#include "vmutils/statobj.h"

unsigned MvmBackend::stamps = 0;

MvmInterfaceGList MvmConnector::allInterfaces;

// MvmInterface

MvmInterface::MvmInterface (const char *_name,
			    MvmConnector *_connector,
			    int _pflags)
{
    iStatus = 0;
    iName = NULL;
    ifSetName(_name);
    iType = -1;
    iHandle = 0;
    iConnector = _connector;

    if (!iConnector)
	iStatus |= MVM_IFACE_HIDDEN;
    
    iStatus |= _pflags;
    MvmConnector::allInterfaces.append(this);
}

MvmInterface::MvmInterface (const MvmInterfaceExportMsg *gpex,
			    MvmConnector *connector)
{
    iName = stringDup(gpex->name);
    iHandle = gpex->handle;
    iType = gpex->type;
    iStatus = 0;
    iConnector = connector;
    MvmConnector::allInterfaces.append(this);
}

MvmInterface::MvmInterface (MvmInterface& src)

{
    iName = src.iName ? stringDup(src.iName) : 0;
    iType = src.iType;
    iStatus = src.iStatus;
    iHandle = src.iHandle;
    iConnector = src.iConnector;
    // *Breakpoints are not copied*
    MvmConnector::allInterfaces.append(this);
}

MvmInterface::~MvmInterface ()

{
    if (iName)
	stringFree(iName);

    ifBP.destroy();

    if (iConnector)
	{
	if (iConnector->type == MvmMasterConnector)
	    {
	    if (ifIsExported())
		{
		MvmInterfaceDestroyMsg gpdm;
		ifSend(MVM_IFACE_UNEXPORT,&gpdm,sizeof(gpdm));
		}
	    }
	
	if (iConnector->handles.find(iHandle) == this)
	    iConnector->handles.remove(iHandle);
	}

    MvmConnector::allInterfaces.remove(this);
}

void MvmInterface::ifSetName (const char *_name)

{
    if (iName)
	stringFree(iName);

    iName = _name && *_name ? stringDup(_name) : 0;

    if (!iName)
	{
	if (!ifIsExported())
	    iStatus |= MVM_IFACE_HIDDEN;

	iStatus |= MVM_IFACE_ANON;
	}
    else if (iStatus & MVM_IFACE_ANON)
	// this object may still remain hidden
	iStatus &= ~MVM_IFACE_ANON;
}

void MvmInterface::ifSetConnector (MvmConnector *_iConnector)

{
    iConnector = _iConnector;

    if (iConnector)
	ifSetExportable();
}

void MvmInterface::ifInit () {} 

void MvmInterface::ifProcess (int, const MvmInterfaceMsg *, int) {}

void MvmInterface::ifSend (int mtype, MvmInterfaceMsg *gpm, int msize)

{
    if (iConnector)
	{
	MvmInterfaceMsg fakeMsg;

	if (!gpm) // If no mesg has been passed, provided a basic one
	    {	  // to carry the protocol handle.
	    gpm = &fakeMsg;
	    msize = sizeof(fakeMsg);
	    }

	gpm->handle = iHandle;
	gpm->seqNum = iConnector->seqNum++;
	iConnector->send(mtype,gpm,msize);
	}
}

void MvmInterface::ifExport (MvmInterfaceExportMsg *gpex, int msize)

{
    if (ifIsExportable() &&
	!ifIsExported() &&
	iConnector &&
	iConnector->type == MvmMasterConnector &&
	iConnector->handles.enter(gpex->handle,this) > 0)
	{
	iStatus |= MVM_IFACE_EXPORTED;
	iHandle = gpex->handle;
	iType = gpex->type;
	ifSend(MVM_IFACE_EXPORT,gpex,msize);
	}
}

void MvmInterface::ifDisplay ()

{
    ifSetDisplayed();
    MvmInterfaceDisplayMsg toggle(1);
    ifSend(MVM_IFACE_TOGGLE,&toggle,sizeof(toggle));
}

void MvmInterface::ifConceal ()

{
    ifSetConcealed();
    MvmInterfaceDisplayMsg toggle(0);
    ifSend(MVM_IFACE_TOGGLE,&toggle,sizeof(toggle));
}

void MvmInterface::ifInfo (int mtype, const char *data, int size)

{
    if (size < 0)
	size = strlen(data);
    
    MvmInterfaceInfoMsg *iblock = (MvmInterfaceInfoMsg *)
	new char[sizeof(*iblock) + size];

    // info block is a null terminated string
    strncpy(iblock->data,data,Max(1,size))[size] = '\0';
    ifSend(mtype,iblock,sizeof(*iblock) + size);

    delete[] iblock;
}

void MvmInterface::ifSetBreak (double threshold)

{
    for (MvmInterfaceBreakPoint *bp = (MvmInterfaceBreakPoint *)ifBP.first();
	 bp; bp = (MvmInterfaceBreakPoint *)bp->next())
	{
	if (bp->threshold == threshold)
	    return;
	}

    ifBP.append(new MvmInterfaceBreakPoint(threshold));

    if (iConnector && iConnector->type == MvmSlaveConnector)
	{
	MvmInterfaceBreakMsg toggle(threshold,1);
	ifSend(MVM_IFACE_BREAK_TOGGLE,&toggle,sizeof(toggle));
	}
}

void MvmInterface::ifClrBreak (double threshold)

{
    for (MvmInterfaceBreakPoint *bp = (MvmInterfaceBreakPoint *)ifBP.first();
	 bp; bp = (MvmInterfaceBreakPoint *)bp->next())
	{
	if (bp->threshold == threshold)
	    {
	    ifBP.remove(bp);
	    delete bp;

	    if (iConnector && iConnector->type == MvmSlaveConnector)
		{
		MvmInterfaceBreakMsg toggle(threshold,0);
		ifSend(MVM_IFACE_BREAK_TOGGLE,&toggle,sizeof(toggle));
		}

	    return;
	    }
	}
}

// NOTE: As a side-effect of remap(), a destroyed object may share its
// protocol handle with another one which has replaced it and thus is
// still active.  This is why the MvmInterface ctor() checks whether the
// destroyed object is the currently active one or not.

void MvmInterface::ifDestroy ()

{
    if (iConnector)
	{
	if (iConnector->type == MvmMasterConnector)
	    {
	    if (ifIsExported() &&
		iConnector->handles.find(iHandle) == this &&
		iConnector->handles.remove(iHandle))
		{
		MvmInterfaceDestroyMsg gpdm;
		ifSend(MVM_IFACE_UNEXPORT,&gpdm,sizeof(gpdm));
		iStatus &= ~MVM_IFACE_EXPORTED;
		}
	    }
	else // otherwise, frontend side
	    {
	    if (iConnector->handles.find(iHandle) == this &&
		iConnector->handles.remove(iHandle))
		{
		MvmInterfaceDestroyMsg gpdm;
		ifSend(MVM_IFACE_DESTROY,&gpdm,sizeof(gpdm));
		}
	    }
	}
}

void MvmInterface::ifSignal (MvmInterfaceSignal) {}

// MvmInterfaceExportMsg -- Null handle is guaranteed to remain unused
// (except if more than 4GB objects are created within a single
// session :-} )

MvmInterfaceExportMsg::MvmInterfaceExportMsg (MvmInterfaceObjectType _type,
					      const char *_name)
{
    type = _type;
    scopy(name,_name,sizeof(name)-1);
    handle = (MvmInterfaceHandle)++MvmBackend::stamps;
}

// MvmInterfaceDisplayMsg

MvmInterfaceDisplayMsg::MvmInterfaceDisplayMsg (int _okDisplay)

{ okDisplay = _okDisplay; }

// MvmInterfaceBreakMsg

MvmInterfaceBreakMsg::MvmInterfaceBreakMsg (double _threshold, int _okBreakOn)

{
    threshold = _threshold;
    okBreakOn = _okBreakOn;
}

// MvmConnector

MvmConnector::MvmConnector (MvmConnectorType _type) :
    type(_type), handles(1024)

{ seqNum = 0; }

void MvmConnector::remap (MvmInterface *object, MvmInterfaceHandle handle)

{
    object->iHandle = handle;
    handles.update(handle,object);
}

int MvmConnector::dispatch (int mtype, const void *mbuf, int msize)

{
    if (!mbuf || msize == 0)
	return 0;

    const MvmInterfaceMsg *gpm = (MvmInterfaceMsg *)mbuf;
    MvmInterface *object = (MvmInterface *)handles.find(gpm->handle);

    if (object)	// check that object still exists
	{
	if (mtype == MVM_IFACE_BREAK_TOGGLE)
	    {
	    const MvmInterfaceBreakMsg *toggle =
		(MvmInterfaceBreakMsg *)gpm;

	    if (toggle->okBreakOn)
		// redundant breakpoints are caught in ifSetBreak()
		object->ifSetBreak(toggle->threshold);
	    else
		object->ifClrBreak(toggle->threshold);
	    }
	else // delegate msg processing to object
	    object->ifProcess(mtype,gpm,msize);

	return 1;
	}

    return 0;
}

int MvmBackend::dispatch (int mtype, const void *mbuf, int msize)

{
    const MvmInterfaceMsg *gpm = (MvmInterfaceMsg *)mbuf;

    if (mtype == MVM_IFACE_DESTROY)
	{
	MvmInterface *object = (MvmInterface *)handles.find(gpm->handle);

	if (object)
	    {
	    handles.remove(object->iHandle);
	    destroyObject(object);
	    return 1;
	    }

	return 0;
	}

    // otherwise, try canonical processing
    return MvmConnector::dispatch(mtype,mbuf,msize);
}

void MvmBackend::destroyObject (MvmInterface *object)

{
    object->iConnector = NULL;	// disable UNEXPORT protocol
    delete object;
}

int MvmFrontend::dispatch (int mtype, const void *mbuf, int msize)

{
    const MvmInterfaceMsg *gpm = (MvmInterfaceMsg *)mbuf;

    if (mtype == MVM_IFACE_EXPORT)
	{
	// Trap this message here, as our peer asks us to
	// create the object's graphical counterpart.
	const MvmInterfaceExportMsg *gpex = (const MvmInterfaceExportMsg *)gpm;
	MvmInterface *object = createDisplay(gpex,msize);

	if (object)
	    {
	    if (!object->iHandle)
		{
		// Usually set by MvmInterface(MvmInterfaceExportMsg)
		// ctor() when creating the associated display.
		object->iHandle = gpm->handle;
		object->iType = gpex->type;
		}
	    
	    handles.enter(object->iHandle,object);
	    return 1;
	    }

	return 0;
	}
    else if (mtype == MVM_IFACE_UNEXPORT)
	{
	MvmInterface *object = (MvmInterface *)handles.find(gpm->handle);

	if (object)
	    {
	    handles.remove(object->iHandle);
	    object->ifSetZombie();
	    destroyDisplay(object);
	    return 1;
	    }

	return 0;
	}

    // Otherwise, try canonical processing.
    return MvmConnector::dispatch(mtype,mbuf,msize);
}
