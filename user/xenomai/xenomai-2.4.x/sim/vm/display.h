/*
 * This file is part of the XENOMAI project.
 *
 * Copyright (C) 2001,2002 Philippe Gerum.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 */

#ifndef _mvm_display_h
#define _mvm_display_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include "vmutils/interface.h"

struct mvm_displayctx;

class MvmDashboard : public MvmInterface {

protected:

    CString prefix,
	    privateInfo;

    struct mvm_displayctx *displayContext;

    void (*objCtlRoutine)(struct mvm_displayctx *ctx,
			  int op,
			  const char *arg);
public:

    MvmDashboard(const char *name,
		 const char *prefix,
		 const char *privateInfo =0,
		 struct mvm_displayctx *displayContext =0,
		 void (*objCtlRoutine)(struct mvm_displayctx *ctx,
				       int op,
				       const char *arg) =0);

    const char *getPrefix() const {
	return prefix;
    }

    virtual const char *getPrivateInfo() {
	return privateInfo;
    }

    virtual void ifProcess(int mtype,
			   const MvmInterfaceMsg *gpm,
			   int msize);

    virtual void ifInit();

    virtual void dynamicExpose() {
        if (objCtlRoutine)
	    objCtlRoutine(displayContext,MVM_OBJCTL_EXPOSE,NULL);
    }

    virtual void dynamicConfigure(MvmInterfaceInfoMsg *mbuf) {
        if (objCtlRoutine)
	    objCtlRoutine(displayContext,MVM_OBJCTL_CONFIGURE,mbuf->data);
    }

    virtual void dynamicTrigger(MvmInterfaceInfoMsg *mbuf) {
        if (objCtlRoutine)
	    objCtlRoutine(displayContext,MVM_OBJCTL_TRIGGER,mbuf->data);
    }
};

class MvmGraph : public MvmObject {

public:

    MvmGraph(const char *name,
	     const char *group,
	     const char *const *sarray);

    int kdoor(sendState)(int newState) {
	int oldState = getState();
	setState(newState);
	return oldState;
    }

    virtual void ifSignal(int signo);
};

#endif // !_mvm_display_h
