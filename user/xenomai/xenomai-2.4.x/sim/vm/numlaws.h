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
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifndef _mvm_numlaws_h
#define _mvm_numlaws_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include <limits.h>
#include <math.h>
#include <stdio.h>
#include "vmutils/statobj.h"

class MvmNumericLaw {

 protected:

    double x0;

 public:

    MvmNumericLaw(double x=0.0) {
    x0 = x;
    }

    virtual ~MvmNumericLaw() {
    }

    int iget() {
    return (int)get();
    }

    virtual double get();
};

class MvmTimeNumericLaw : public MvmNumericLaw {

 protected:

    ITime tLastGen;

 public:

    MvmTimeNumericLaw(double x=0.0);

    virtual double get();

    ITime getTime() {
    return tLastGen;
    }
};

class MvmSlope : public MvmTimeNumericLaw {

 protected:

    double slant;

    double xLim;

    ITime tMax;

 public:

    MvmSlope(double x0,
	     double slant,
	     double xLim);

    virtual double get();
};

class MvmSqWave : public MvmTimeNumericLaw {

 protected:

    ITime  dtPeriod;

    double dxMax;

    double xMid;

    double phase[4];

 public:

    MvmSqWave(ITime,
	      double,
	      double =0.0,
	      double =0.5,
	      double =0.0);

    virtual double get();
};

class MvmSinus : public MvmTimeNumericLaw {

 protected:

    ITime dtPeriod;

    double dxMax;

    double xMid;

 public:

    MvmSinus(ITime,
	     double =1.0,
	     double =0.0);

    virtual double get();
};

class MvmRandLaw;

class MvmModulation : public MvmTimeNumericLaw {

 protected:

    ITime dtBand;

    ITime dtSignal;

    double dxMax;

    double xMidSignal;

    double xLimSignal;

    double dxMaxSignal;
	
    ITime dtDraw;

    ITime tNextDraw;
	
    MvmRandLaw *rand;

 public:

    MvmModulation(ITime, ITime, double);

    virtual double get();
};

#define MULTIPLIER  1103515245
#define ADDENDVAL  12345
#define MAXDRAWINT 2147483648.0

#define ALEA -2
#define RAND -1

class MvmRandLaw : public MvmNumericLaw {

 protected:

    long x;

    public :

	MvmRandLaw(long s =RAND);

    int idraw() {
    return (x = ((x*MULTIPLIER + ADDENDVAL ) & LONG_MAX));
    }

    virtual double draw();

    virtual double get();
};


// uniform distribution in [inf,sup]
class MvmUniLaw : public MvmRandLaw {

 protected:

    double l;

    double h;

    public :
	
	MvmUniLaw(double a,
		  double b,
		  long s=RAND) :
	MvmRandLaw(s) {
    l = a;
    h = b;
    }

    virtual double draw();
};

// exponential distribution
class MvmExpLaw : public MvmRandLaw {

 protected:

    double tau;

    public :

	MvmExpLaw(double t,
		  long s =RAND) :
	MvmRandLaw(s) {
    tau = t;
    }

    virtual double draw();
};

class MvmHistLaw;

class MvmPDPoint {

    friend class MvmHistLaw;

 protected:

    double x;

    double y;

 public:

    MvmPDPoint(double, double);

    MvmPDPoint() {
    x = y = 0.0;
    }
};

class MvmHistLaw : public MvmRandLaw {

 protected:

    int nPDPs;

    MvmPDPoint *pDPs;

 public:

    MvmHistLaw(MvmPDPoint *, long =RAND);

    virtual double draw();
};
	
class MvmFileLaw : public MvmTimeNumericLaw {

 protected:

    CString fileName;

    FILE *fp;

    int ecount;

    ETimeUnits timeUnit;

    CString currArg;

    int timedInput;

    int rawMode;

    char buf[BUFSIZ];

    void initialize(FILE *fp,
		    int rawMode);

 public:

    MvmFileLaw(const char *fileName,
	       int rawMode =0);

    MvmFileLaw(FILE *fp,
	       int rawMode =0);

    virtual ~MvmFileLaw();

    const char *getArg() const {
    return currArg;
    }

    int rawModeP() const {
    return !!rawMode;
    }

    virtual double get();
};

#endif // !_mvm_numlaws_h
