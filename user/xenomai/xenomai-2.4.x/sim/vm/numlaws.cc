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

#ifdef __GNUG__
#pragma implementation
#endif // __GNUG__
#include <xeno_config.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>
#include "vmutils/string++.h"
#include "vmutils/statobj.h"
#include "vm/numlaws.h"

static const double _2PI = 6.2831853072;

double MvmNumericLaw::get()

{ return x0; }

MvmTimeNumericLaw::MvmTimeNumericLaw (double x) :
    MvmNumericLaw(x)

{ tLastGen = MvmClock; }

double MvmTimeNumericLaw::get()

{
    tLastGen = MvmClock;
    return x0;
}

MvmSlope::MvmSlope(double x, double a, double xm)
    : MvmTimeNumericLaw(x)
{	
    slant = a;
    xLim = xm;
    if ( a*(xLim - x0) < 0 ) {
    if (xLim != infinity())
	statWarning("MvmSlope::MvmSlope() - unreachable limit");
    tMax = MAXITIME;
    }
    tMax = MvmClock + ITime((xLim - x0) / slant);
}

double MvmSlope::get()

{
    if (MvmClock > tMax) return xLim;
    x0 += slant * (MvmClock - tLastGen);
    tLastGen = MvmClock;
    return x0;
}

MvmSqWave::MvmSqWave(ITime dt, double dx, double xm, double r, double s)
    : MvmTimeNumericLaw(xm)
{
    dtPeriod = dt;
    dxMax = dx;
    xMid = xm;
    if (s > r) s = r;
    if (s > (1.0 - r)) s = 1.0 - r;
    phase[0] = (s==0.0) ? -1.0 : s/2;
    phase[1] = r - s/2;
    phase[2] = (s==0.0) ? -1.0 : phase[1] + s;
    phase[3] = 1.0 - s/2;
}

double MvmSqWave::get()

{
    double rem = (MvmClock % dtPeriod) / dtPeriod;
    if (rem < 0.0) rem += 1.0;
    if (rem <= phase[0])
	x0 = xMid + rem * dxMax / phase[0];
    else if (rem <= phase[1])
	x0 = xMid + dxMax;
    else if (rem <= phase[2]) 
	x0 = xMid + dxMax - (rem - phase[1]) * dxMax / phase[0];
    else if (rem <= phase[3])
	x0 = xMid - dxMax;
    else	x0 = xMid - (1.0 - rem) * dxMax / phase[0];
    return x0;
}

MvmSinus::MvmSinus(ITime dt, double dx, double xm)
    : MvmTimeNumericLaw(xm)
{
    dtPeriod = dt;
    dxMax = dx;
    xMid = xm;
}

double MvmSinus::get()

{
    double rem = (MvmClock % dtPeriod) / dtPeriod;
    return x0 = xMid + sin(rem * _2PI) * dxMax;
}

MvmModulation::MvmModulation(ITime dt0, ITime dt1, double dx)
    : MvmTimeNumericLaw()
{
    dtBand = dt0;
    dtSignal = dt1;

    if (dtSignal <  dtBand * 2.0)
	dtSignal = dtBand * 2.0;

    dxMax = dx;
    xMidSignal = dxMax;
    xLimSignal = dxMax;
    dxMaxSignal = 0.0;
    rand = new  MvmRandLaw(RAND);
    dtDraw = dtSignal / 2.0;
    tNextDraw = dtDraw / 2.0;
}
		
double MvmModulation::get()

{
    double rem, dx;
    if (MvmClock >= tNextDraw) {
    while (tNextDraw <= MvmClock) tNextDraw += dtDraw;
    dx = rand->draw() * dxMax;
    xMidSignal = (dx + xLimSignal) / 2;
    xLimSignal = dx;
    dxMaxSignal = xLimSignal - xMidSignal;
    if (dxMaxSignal < 0) dxMaxSignal = - dxMaxSignal;
    }
    rem = (MvmClock % dtSignal) / dtSignal;
    dx = xMidSignal + cos(rem * _2PI) * dxMaxSignal;
    rem = (MvmClock % dtBand) / dtBand;
    return sin(rem * _2PI) * dx;
}

MvmRandLaw::MvmRandLaw(long s)

{
    if(s >= 0)
	x = s ;
    else
	{
	switch (s)
	    {
	    case ALEA:
		statWarning("MvmRandLaw::MvmRandLaw() - ALEA mode not yet implemented, using RAND");
	    case RAND:
		x = rand();
		break;
	    }
	}
}

double MvmRandLaw::draw()
{ 	return idraw()/ MAXDRAWINT; }

double MvmRandLaw::get()
{	return draw(); }

double MvmUniLaw::draw()
{ 	return(l+((h-l)*MvmRandLaw::draw())); }

double MvmExpLaw::draw()
{ 	return -tau * log( 1.0 - MvmRandLaw::draw()); }

MvmPDPoint::MvmPDPoint(double xi, double yi)

{
    if ( (yi < 0.0) || (yi > 1.0))
	statError("MvmPDPoint::MvmPDPoint() - invalid argument(s): %f, %f",xi,yi);
    x = xi;
    y = yi;
}

MvmHistLaw::MvmHistLaw(MvmPDPoint* pd, long s)
    : MvmRandLaw(s)
{
    pDPs = pd;
    nPDPs = 0;
    double yold = 0.0;

    if ( pd->y != 0.0 )
	statError("MvmHistLaw::MvmHistLaw() - invalid argument: %f",pd->y);

    pd++;
    nPDPs++;
    while ( pd->y < 1.0 )
	{
	if ( pd->y < yold )
	    statError("MvmHistLaw::MvmHistLaw() - invalid argument: %f",pd->y);
	nPDPs++;
	pd++;
	}
}

double MvmHistLaw::draw()
{
    double p = MvmRandLaw::draw();
    int i = 0;
    MvmPDPoint* pd = &pDPs[0];
    while ( p > pd->y )
	i++, pd++;
    if ( i == 0 )
	return pd->x;
    MvmPDPoint* pd0 = &pDPs[i-1];
    return pd0->x + (pd->x - pd0->x) * ((p - pd0->y) / (pd->y - pd0->y));
}

MvmFileLaw::MvmFileLaw (const char *_fileName,
			int _rawMode)
{
    fileName = _fileName;
    FILE *_fp = fopen(fileName.posixize(),"r");

    if (!_fp)
	statError("MvmFileLaw::MvmFileLaw() - invalid filename: %s",_fileName);

    initialize(_fp,_rawMode);
}

MvmFileLaw::MvmFileLaw (FILE *_fp,
			int _rawMode)

{ initialize(_fp,_rawMode); }

void MvmFileLaw::initialize (FILE *_fp,
			     int _rawMode)
{
    fp = _fp;

    timedInput = 0;

    // If the first line of input contains the "$@timelog" marker at
    // the beginning of a comment line, expect reading timed-stamped
    // strings such as "timeval unit:string". If not, read the file
    // contents as raw input.

    if (fgets(buf,BUFSIZ,fp))
	{
	CString strippedString(buf);
	strippedString.removeAllSpaces();
	if (!strncmp(strippedString,"#$@timelog",10))
	    timedInput = 1;
	else
	    rewind(fp);
	}

    rawMode = _rawMode;
    ecount = 0;
    timeUnit = defaultETimeUnit;
}

MvmFileLaw::~MvmFileLaw ()

{
    if (!fileName.isEmpty() && fp)
	fclose(fp);
}

// MvmFileLaw::get() is a bit tricky to allow reading a file including
// time information or not in raw mode.

double MvmFileLaw::get ()

{
    ITime t;
    
    currArg.clear();
    
    while (fgets(buf,BUFSIZ,fp))
	{
	if (timedInput && (*buf == '#' || !t.scan(buf)))
	    // comment or invalid time format
	    continue;

	ecount++;

	if (!rawMode && timedInput)
	    {
	    if (t < MvmClock)
		// discard preposterous dates
		continue;
	    }
	else
	    // raw mode means that characters should be immediately
	    // available
	    t = MvmClock;

	if (timedInput)
	    {
	    char *wp = strrchr(buf,'\n');
	    if (wp) *wp = '\0';
	    wp = strchr(buf,':');
	    if (wp) currArg.overwrite(wp + 1);
	    }
	else
	    currArg.overwrite(buf); // \n is passed back
	
	tLastGen = MvmClock;

	return t - MvmClock;
	}
    
    return MAXITIME;
}
