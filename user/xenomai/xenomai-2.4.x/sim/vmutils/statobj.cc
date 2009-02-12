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
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include "vmutils/list++.h"
#include "vmutils/statobj.h"

MvmStatObjGList allMvmStatObjs;

MvmStatObj::MvmStatObj (const char *_name,
			MvmConnector *_connector,
			int _pflags) :
    MvmInterface(_name,_connector,_pflags)
{
    lastV = 0.0;
    resetValues();
    allMvmStatObjs.append(this);
}

MvmStatObj::MvmStatObj (MvmInterfaceExportMsg *_gpex,
			MvmConnector *_connector) :
    MvmInterface(_gpex,_connector)
{
    lastV = 0.0;
    resetValues();
    allMvmStatObjs.append(this);
}

MvmStatObj::~MvmStatObj() {

    allMvmStatObjs.remove(this);
}

int MvmStatObj::compare (LinkedObject *buddy)

{
    MvmStatObj *so = (MvmStatObj *)buddy;

    if (!ifGetName() && so->ifGetName())
	return -1;
    else if (ifGetName() && !so->ifGetName())
	return 1;
    else if (!ifGetName() && !so->ifGetName())
	return 0;

    return strcmp(ifGetName(),so->ifGetName());
}

double MvmStatObj::getValue(StValueType vt)

{ 	
    switch (vt) {
    case VAL:
	return lastV;
    case NUM:
	return nVal;
    case MINVAL:
	return vMin;
    case MAXVAL:
	return vMax;
    default: ;
    }

    return 0.0;
}

void MvmStatObj::add(double x)

{
    lastV = x;
    nVal++;

    if (x < vMin)
	vMin = x;

    if (x > vMax)
	vMax = x;
}

void MvmStatObj::resetValues()

{
    nVal = 0;
    vMin = infinity();
    vMax = -infinity();
    nSampleDone = 0;
}

void MvmStatObj::sample () {
    nSampleDone++;
}

void MvmStatObj::result() {
}

MvmCounter::MvmCounter (const char *_name,
			MvmConnector *_connector,
			int _pflags) :
    MvmStatObj(_name,_connector,_pflags) {

    resetValues();
}

MvmCounter::MvmCounter (MvmInterfaceExportMsg *_gpex,
			MvmConnector *_connector) :
    MvmStatObj(_gpex,_connector) {

    resetValues();
}

void MvmCounter::add(double a)

{
    sv1 += a;
    lastV = a;
    nVal++;

    if (a < vMin)
	vMin = a;

    if (a > vMax)
	vMax = a;
}

void MvmCounter::resetValues()

{
    nVal = 0;
    sv1 = se1 = se2 = 0.0;
}

void MvmCounter::sample()

{
    nSampleDone++;
    se1 +=  sv1;
    se2 +=  sv1 * sv1;
    sv1 = 0.0;
}

void MvmCounter::result() {}

double MvmCounter::getValue(StValueType vt)

{
    switch (vt)
        {
        case VAL:

	    return lastV;

	case CMES:
	    
	    return sv1;

	case NUM:

	    return nVal;

        case SUM:

	    return se1 + sv1;

        case SUM2:

	    return se2 + sv1 * sv1;

	case MINVAL:
	    
	    return vMin;

	case MAXVAL:

	    return vMax;

	case MEAN:

	    return (nVal == 0) ? 0.0 : (se1+sv1)/nVal;

	case STDEV:

	    return (nVal == 0) ? 0.0 : sqrt((se2-se1*(se1-2*sv1))/nVal);

	default: ;
        }

    return 0.0;
}

MvmIntegrator::MvmIntegrator(const char *_name,
			     const ITime& _tStart,
			     const ITime& _tEnd,
			     const ITime& _dtSample,
			     MvmConnector *_connector,
			     int _pflags)
    : MvmStatObj(_name,_connector,_pflags)
{
    tStart = _tStart;
    tEnd = _tEnd;
    tLastSample = MvmClock;
    tLastUpdate = MvmClock;
    lastV  = 0.0;
    dtSample = _dtSample;
    resetValues();
}

MvmIntegrator::MvmIntegrator(MvmInterfaceExportMsg *_gpex,
			     MvmConnector *_connector,
			     const ITime& _tStart,
			     const ITime& _tEnd,
			     const ITime& _dtSample) :
    MvmStatObj(_gpex,_connector)
{
    tStart = _tStart;
    tEnd = _tEnd;
    tLastSample = MvmClock;
    tLastUpdate = MvmClock;
    lastV  = 0.0;
    dtSample = _dtSample;
    resetValues();
}

void MvmIntegrator::resetValues()

{
    s = se1 = se2 = 0.0;
    nVal = 0;
    vMin = infinity();
    vMax = -infinity();
}

void MvmIntegrator::sample()

{
    tLastSample = nSampleDone > 0 ? MvmClock - dtSample : tStart;
    nSampleDone++;

    add(lastV);
    double r = s / dtSample;
    se2 += r * r;
    se1 += r;
    s = 0.0;
}

void MvmIntegrator::result() {}

void MvmIntegrator::add(double y)

{
    ITime dt = MvmClock - tLastUpdate;
    tLastUpdate = MvmClock;
    s += lastV * dt;
    nVal++;

    if (y == lastV)
	return;

    nVal++;

    if (y < vMin)
	vMin = y;

    if (y > vMax)
	vMax = y;

    lastV = y;
}

double  MvmIntegrator::getValue(StValueType vt)

{
    switch (vt)
        {
	case VAL:

	    return lastV;

	case NUM:

	    return nVal;

	case MINVAL:

	    return vMin;

	case MAXVAL:

	    return vMax;

	case MEAN:
        case CMES:

	    return (MvmClock == tLastSample) ? 0.0 : s / ((double) (MvmClock - tLastSample));

        case SUM:

	    return s + se1;

	default: ;
        }

    return 0.0;
}

MvmHistogram::MvmHistogram (const char *_name,
			    int _nbin,
			    double _l,
			    double _r,
			    StHistAdjustMode _mode,
			    MvmConnector *_connector,
			    int _pflags) :
    MvmStatObj(_name,
	       _connector,
	       _pflags)
{
    l = _l;
    r = _r;
    mode = _mode;
    nbin = _nbin;
    displayMode = STHistoDENSITY;
    init();
}

MvmHistogram::MvmHistogram (const char *_name,
			    int _nbin,
			    int _l,
			    int _r,
			    StHistAdjustMode _mode,
			    MvmConnector *_connector,
			    int _pflags) :
    MvmStatObj(_name,
	       _connector,
	       _pflags)
{
    while ((_r - _l) % _nbin)
	_r++;

    l = (double)_l;
    r = (double)_r;
    mode = _mode;
    nbin = _nbin;
    displayMode = STHistoDENSITY;
    init();
}

MvmHistogram::MvmHistogram (MvmHistogramExportMsg *_exmsg,
			    MvmConnector *_connector) :
    MvmStatObj(_exmsg,_connector)
{
    l = r = 0.0;
    nbin = _exmsg->nbin;
    displayMode = STHistoDENSITY;
    init();
}

MvmHistogram::MvmHistogram (MvmHistogram& src) :
    MvmStatObj(src.ifGetName(),
	       src.iConnector)
{
    l = src.l;
    r = src.r;
    binsize = src.binsize;
    nbin = src.nbin;

    if (nbin > 0)
	{
	vLog = new int[nbin];

	for(int i = 0; i < nbin; i++)
	    vLog[i] = src.vLog[i];
	}
    else
	vLog = 0;

    nv = src.nv;
    vMin = src.vMin;
    vMax = src.vMax;
    sv1 = src.sv1;
    ssv1 = src.ssv1;
    sv2 = src.sv2;
    ssv2 = src.ssv2;
    sm2 = src.sm2;
    sd2 = src.sd2;
    mode = src.mode;
    sm1 = src.sm1;
    sd1 = src.sd1;
    garbage = src.garbage;
    displayMode = STHistoDENSITY;
}

MvmHistogram::~MvmHistogram()

{
    if (vLog)
	delete[] vLog;
}

void MvmHistogram::init()

{
    if (nbin % 2)
	{
	r = r + (r -l) * ((double)nbin + 1) / ((double)nbin);
	nbin++;
	}

    if (nbin > 0)
	{
	binsize = (r - l) / nbin;
	vLog = new int[nbin];
	}
    else
	{
	binsize = 0;
	vLog = 0;
	}

    resetValues();
}

void MvmHistogram::add(double x)

{
    int i;

    if ((x < l) || (x >= r))
	i = adjust(x,mode);
    else
	i = (int) ((x - l) / binsize);

    vLog[i]++;
    nv++;
    sv1 += x;
    sv2 += x * x;
    lastV = x;


    if (x < vMin)
	vMin = x;
    else if (x > vMax)
	vMax = x;
}

int MvmHistogram::adjust (double x, StHistAdjustMode am)

{
    int i, j;

    switch(am)
        {
        case MULTIPLY:

	    while (x < l)
		{
		if (vMax == l)
		    vMax -= r - l;

		l -= r - l;

		for (i=nbin-1, j=nbin-2; 0<=j; i--, j-=2)
		    vLog[i] = vLog[j] + vLog[j+1];

		while(i >= 0)
		    vLog[i--] = 0;
		}

	    while (r<=x)
		{
		if (vMin == r)
		    vMin += r - l;

		r += r - l;
		for (i=0, j=0; i<nbin/2; i++, j+=2)
		    vLog[i] = vLog[j] + vLog[j+1];

		while (i < nbin)
		    vLog[i++] = 0;
		}

	    binsize = (r - l) / nbin;

	    return (int)((x - l) / binsize);

        case GARBAGE:

	    if (x<l)
		{
		garbage |= 1;
		return 0;
		}
	    else
		{
		garbage |= 2;
		return nbin - 1;
		}
        }

    return 0;
}


void MvmHistogram::resetValues ()

{
    for (int i = 0; i < nbin; i++) 
	vLog[i] = 0;
        
    vMin = r;
    vMax = l;
    nv  = nVal = 0;
    sv1 = ssv1 = sv2 = ssv2 = 0.0;
    sm1 = sm2 = sd1 = sd2 = 0.0;
    garbage = 0;
}

void MvmHistogram::sample ()

{
    nSampleDone++;
    if (!nv)
	return;

    double x = sv1 / nv;         
    sm1 += x;
    sm2 += x * x;
    nVal += nv;

    x = variance(sv2, sv1, nv);
    sd1 += sqrt(x);
    sd2 += x;

    ssv1 += sv1;
    sv1 = 0;
    ssv2 += sv2;
    sv2 = 0;
    nv = 0;
}

void MvmHistogram::result() {}

double MvmHistogram::getValue(StValueType vt)

{
    switch (vt)
        {
	case VAL:

	    return lastV;

	case NUM:

	    return (double) (nv + nVal);

	case SUM:

	    return ssv1 + sv1;

	case SUM2:

	    return ssv2 + sv2;

	case MAXVAL:

	    return vMax;

	case MINVAL:

	    return vMin;

	case MEAN:

            return (nv+nVal == 0) ? 0.0 : (ssv1+sv1)/(nv+nVal);

	case STDEV:

	    return (nv+nVal == 0) ? 0.0 : sqrt(((ssv2+sv2)-(ssv1+sv1)/(nv+nVal)*(ssv1+sv1)/(nv+nVal))/(nv+nVal));

	default: ;
        }

    return 0.0;
}

void MvmHistogram::setDisplayMode(StHistDisplayMode mode)

{ displayMode = mode; }

void MvmHistogram::ifInit ()

{
    MvmHistogramExportMsg exmsg(this);
    ifExport(&exmsg,sizeof(exmsg));
}

void MvmHistogram::ifProcess (int mtype, const struct MvmInterfaceMsg *gpm, int)

{
    if (mtype == MVM_IFACE_TOGGLE) // may not be anything else as of now
	{
	const struct MvmInterfaceDisplayMsg *toggle =
	    (struct MvmInterfaceDisplayMsg *)gpm;

	if (toggle->okDisplay)
	    {
	    ifSetDisplayed();

	    MvmHistogramHeader hd;
    
	    hd.l = l;
	    hd.r = r;
	    hd.nval = nVal + nv;
	    hd.vmin = vMin;
	    hd.vmax = vMax;
	    hd.s1 = ssv1 + sv1;
	    hd.s2 = ssv2 + sv2;
	    hd.garb = garbage;
	    hd.time = MvmClock;
    
	    ifSend(MVM_IFACE_HISTOGRAM_HEAD,&hd,sizeof(hd));
	    MvmHistogramInit hi;
    
	    int nb = 0;
    
	    while (nb < nbin)
		{
		for(hi.nPtr = 0;
		    hi.nPtr < MVM_IFACE_HISTOGRAM_MAX_INIT && nb < nbin;
		    nb++, hi.nPtr++)
		    hi.hTab[hi.nPtr] = vLog[nb];
	    
		if (nb >= nbin)
		    hi.nPtr = -hi.nPtr;	// mark last packet :-|
	
		ifSend(MVM_IFACE_HISTOGRAM_INIT,&hi,sizeof(hi));
		}
	    }
	else
	    ifSetConcealed();
	}
}

// STSCALER

MvmScaler::MvmScaler (const char *_name,
		      MvmStatObj *_scaledObject,
		      StValueType _vt,
		      MvmConnector *_connector,
		      int _pflags) :
    MvmStatObj(_name,
	       _connector,
	       _pflags)
{
    soScaled = _scaledObject;
    tUpdate = MvmClock;
    vTypeScaled = _vt;
    lastS = 1.0;
}

MvmScaler::MvmScaler (MvmInterfaceExportMsg *_gpex,
		      MvmConnector *_connector,
		      MvmStatObj *_scaledObject,
		      StValueType _vt) :
    MvmStatObj(_gpex,_connector)
{
    soScaled = _scaledObject;
    tUpdate = MvmClock;
    vTypeScaled = _vt;
    lastS = 1.0;
}

double MvmScaler::getValue(StValueType vt)
{
    double x, y;
    switch (vt)
	{
	case NUM:
	    return nVal;
	case VAL:
	    nVal++;
	    switch (vTypeScaled)
		{
		case DSUM:
		case DNUM:
		    y = - lastS;
		    lastS = scale->compute();
		    y += lastS;
		    x = -lastV;
		    if (vTypeScaled == DSUM)
			lastV = soScaled->getValue(SUM);
		    else lastV = soScaled->getValue(NUM);
		    x += lastV;
		    break;
		default:
		    x = soScaled->getValue(vTypeScaled);
		    y = scale->compute();
		}

	    if (y == 0)
		return 0.0;

	    return x / y;
	default: ;
	}

    return 0.0;
}

// MvmTimeScaling

MvmTimeScaling::MvmTimeScaling (double _timeFactor)

{ timeFactor = _timeFactor; }

double MvmTimeScaling::compute()

{ return MvmClock * timeFactor; }

// MvmStatObjScaling

MvmStatObjScaling::MvmStatObjScaling (MvmStatObj *_scalingObject,
				      StValueType _vt)
{
    soScaling = _scalingObject;
    vTypeScaling = _vt;
}

double MvmStatObjScaling::compute()

{ return soScaling->getValue(vTypeScaling); }

MvmTimeScaler::MvmTimeScaler(const char *_name,
			     MvmStatObj *_scaledObject,
			     StValueType _vt,
			     double _timeFactor,
			     MvmConnector *_connector,
			     int _pflags) :
    MvmScaler(_name,
	      _scaledObject,
	      _vt,
	      _connector,
	      _pflags)

{ scale = new MvmTimeScaling(_timeFactor); }

MvmTimeScaler::MvmTimeScaler(MvmInterfaceExportMsg *_gpex,
			     MvmConnector *_connector,
			     MvmStatObj *_scaledObject,
			     StValueType _vt,
			     double _timeFactor) :
    MvmScaler(_gpex,
	      _connector,
	      _scaledObject,
	      _vt)

{ scale = new MvmTimeScaling(_timeFactor); }

MvmTimeScaler::~MvmTimeScaler ()

{ delete scale; }

MvmObjectScaler::MvmObjectScaler(const char *_name,
				 MvmStatObj *_scaledObject,
				 MvmStatObj *_scalingObject,
				 StValueType _vtScaled,
				 StValueType _vtScaling,
				 MvmConnector *_connector,
				 int _pflags) :
    MvmScaler(_name,
	      _scaledObject,
	      _vtScaled,
	      _connector,
	      _pflags)

{ scale = new MvmStatObjScaling(_scalingObject,_vtScaling); }

MvmObjectScaler::MvmObjectScaler(MvmInterfaceExportMsg *_gpex,
				 MvmConnector *_connector,
				 MvmStatObj *_scaledObject,
				 MvmStatObj *_scalingObject,
				 StValueType _vtScaled,
				 StValueType _vtScaling) :
    MvmScaler(_gpex,
	      _connector,
	      _scaledObject,
	      _vtScaled)

{ scale = new MvmStatObjScaling(_scalingObject,_vtScaling); }

MvmObjectScaler::~MvmObjectScaler()

{ delete scale; }

// STfilter

MvmFilter::MvmFilter(const char *_name,
		     MvmStatObj *_filteredObject,
		     ITime _dtUpdate,
		     StValueType _vType,
		     int _nvMax,
		     MvmConnector *_connector,
		     int _pflags) :
    MvmStatObj(_name,
	       _connector,
	       _pflags)
{
    soBase = _filteredObject;
    dtUpdate = _dtUpdate;
    tUpdate = -dtUpdate;
    vType = _vType;
    nvMax = _nvMax;
    vMax = -infinity();
    vMin = infinity();

    if (nvMax > 0)
	v = new double[nvMax];
    else
	v = NULL;

    for (int i = 0; i < nvMax; i++)
	v[i] = 0.0;
    
    iCurr = (int) (MvmClock/dtUpdate) - 1;
}

MvmFilter::MvmFilter(MvmInterfaceExportMsg *_gpex,
		     MvmConnector *_connector,
		     MvmStatObj *_filteredObject,
		     ITime _dtUpdate,
		     StValueType _vType,
		     int _nvMax) :
    MvmStatObj(_gpex,_connector)
{
    soBase = _filteredObject;
    dtUpdate = _dtUpdate;
    tUpdate = -dtUpdate;
    vType = _vType;
    nvMax = _nvMax;
    vMax = -infinity();
    vMin = infinity();

    if (nvMax > 0)
	v = new double[nvMax];
    else
	v = NULL;

    for (int i = 0; i < nvMax; i++)
	v[i] = 0.0;
    
    iCurr = (u_long) (MvmClock / dtUpdate) - 1;
}

MvmFilter::MvmFilter (MvmFilter& src) :
    MvmStatObj(src.ifGetName(),
	       src.iConnector)
{
    nvMax = src.nvMax;
    vMin = src.vMin;
    vMax = src.vMax;
    vType = src.vType;
    soBase = src.soBase;
    dtUpdate = src.dtUpdate;
    tUpdate = src.tUpdate;
    iCurr = src.iCurr;

    if (nvMax > 0)
	{
	v = new double[nvMax];
	
	for (int i = 0; i < nvMax; i++)
	    v[i] = src.v[i];
	}
    else
	v = NULL;
}

MvmFilter::~MvmFilter()

{
    if (v)
	delete[] v;
}

void MvmFilter::resetValues() {}

void MvmFilter::update()
{
    double x, y;

    switch(vType) {
    case DSUM:
	x = soBase->getValue(SUM);
	y = x - lastV;
	lastV = x;
	break;
    case DNUM:
	x = soBase->getValue(NUM);
	y = x - lastV;
	lastV = x;
	break;
    default:
	y = lastV = soBase->getValue(vType);
    }
    add(y);
}

void MvmFilter::add(double y)
{
    iCurr = int(MvmClock / dtUpdate);
    int i = iCurr % nvMax;
    tUpdate = MvmClock;
    v[i] = y;

    if (y > vMax)
	vMax = y;

    if (y < vMin)
	vMin = y;
}  

double MvmFilter::derive(ITime dt)
{
    if (dt < dtUpdate)
        {
	statWarning("MvmFilter::derive() - arg lower than update period");
        dt = dtUpdate;
        }

    int i = (int) ((dt / dtUpdate) + 0.5);

    if (i >= nvMax)
        {
	statWarning("MvmFilter::derive() - arg outside of log");
        i = nvMax - 1;
        }

    if (iCurr - i != 0)
    	return (v[iCurr%nvMax]-v[(iCurr - i)%nvMax])/(i * double(dtUpdate));
    
    if (iCurr != 0)
	return v[iCurr]/(iCurr * double(dtUpdate));

    return 0.0;
}

double MvmFilter::sift (ITime dt)

{
    double s = 0.0;
    int k;

    if (dt < dtUpdate)
        {
	statWarning("MvmFilter::sift() - arg lower than update period");
        dt = dtUpdate;
        }

    int i = (int) ((dt / dtUpdate) + 0.5);

    if (i >= nvMax)
        {
	statWarning("STfilter::sift() - arg outside of log");
        i = nvMax - 1;
        }
    
    if (i > iCurr)
	k = 0;
    else
	k = iCurr - i;

    for ( ; k <= iCurr ; k++)
        s += v[k%nvMax];

    return s / ((double) i);
}

double MvmFilter::getValue(StValueType vt)

{
    switch (vt) {
    case VAL:
	return v[iCurr];
    case NUM:
	return nVal;
    case DMES:
	return derive(dtUpdate*(double)(nvMax-1));
    default : ;
    }

    return 0.0;
}

// MvmTimeGraph

MvmTimeGraph::MvmTimeGraph(const char *_name,
			   MvmStatObj *_filteredObject,
			   ITime _dtUpdate,
			   StValueType _vType,
			   int _nvMax,
			   MvmConnector *_connector,
			   int _pflags) :
    MvmFilter(_name,
	      _filteredObject,
	      _dtUpdate,
	      _vType,
	      _nvMax,
	      _connector,
	      _pflags)
{
    yTgMin = vMin;
    yTgMax = vMax;
    yAdjust = 1;
    lastSval = -infinity();
}

MvmTimeGraph::MvmTimeGraph (MvmTimeGraphExportMsg *_exmsg,
			    MvmConnector *_connector) :
    MvmFilter(_exmsg,
	      _connector,
	      0,
	      _exmsg->dtUpdate,
	      VAL,
	      _exmsg->nvMax)
{
    vMax = _exmsg->vMax;
    vMin = _exmsg->vMin;
    yTgMax = _exmsg->yTgMax;
    yTgMin = _exmsg->yTgMin;
    yAdjust = _exmsg->yAdjust;
}

void MvmTimeGraph::resetValues() {}

void MvmTimeGraph::update ()

{
    MvmFilter::update();

    if (ifIsDisplayed())
	{
	double sval = getCurrentPoint();

	MvmTimeGraphPointMsg tgp(sval);
	ifSend(MVM_IFACE_TIMEGRAPH_POINT,&tgp,sizeof(tgp));

	for (MvmInterfaceBreakPoint *bp = (MvmInterfaceBreakPoint *)ifBP.first();
	     bp; bp = (MvmInterfaceBreakPoint *)bp->next())
	    {
	    if ((lastSval <= sval &&
		 bp->threshold >= lastSval &&
		 bp->threshold <= sval) ||
		(lastSval >= sval &&
		 bp->threshold <= lastSval &&
		 bp->threshold >= sval))
		{
		ifSignal(MVM_IFACE_SIGBREAK);
		break;
		}
	    }
	
	lastSval = sval;
	}
}

void MvmTimeGraph::setYLimits(double ymin , double ymax, int yadj)

{
    yTgMin = ymin;
    yTgMax = ymax;
    yAdjust = yadj;
}

void MvmTimeGraph::ifInit ()

{
    MvmTimeGraphExportMsg exmsg(this);
    ifExport(&exmsg,sizeof(exmsg));
}

void MvmTimeGraph::ifProcess (int mtype, const struct MvmInterfaceMsg *gpm, int)

{
    if (mtype == MVM_IFACE_TOGGLE)
	{
	const struct MvmInterfaceDisplayMsg *toggle =
	    (struct MvmInterfaceDisplayMsg *)gpm;
	
	if (toggle->okDisplay)
	    {
	    ifSetDisplayed();

	    if (iCurr >= 0)
		{
		int imin, imax = (int) (MvmClock/dtUpdate);
			
		if (imax > nvMax)
		    imin = imax - nvMax + 1;
		else
		    imin = 0;

		MvmTimeGraphInit ti;

		while (imin <= imax)
		    {
		    ti.time = dtUpdate * (double)imin;
		    
		    for (ti.pointNr = 0;
			 imin <= imax && ti.pointNr < MVM_IFACE_TIMEGRAPH_MAX_INIT;
			 ti.pointNr++, imin++)
			ti.pointTab[ti.pointNr] = v[imin % nvMax];

		    if (imin > imax)
			ti.pointNr = -ti.pointNr;

		    ifSend(MVM_IFACE_TIMEGRAPH_INIT,&ti,sizeof(ti));
		    }
		}
	    }
	else
	    ifSetConcealed();
        }
}

double variance (double s2, double s1, int n)

{
    double y;

    if (n > 1)
	{
    	y = (s2 - ((s1 * s1) / n)) / (n - 1.0);

	if (y < 0)
	    {
	    if ((s2 > 0.0) && (y / s2 > - EPSILON_3))
		y = 0.0;
	    else
		statError("variance() - Epsilon < 0");
	    }
	}
    else
	y = 0.0;

    return y;
}

char *rawAccuracy (char *buf, double s1, double s2, int nsample)

{
    if (nsample <= 1)
        return "";

    double ect = s2 - s1 * s1 / nsample;
    
    if (ect < 0)
	{
        if ((s2 > 0.0) && (ect / s2 > - EPSILON_3))
	    ect = 0;
        else
	    statError("rawAccuracy() - Epsilon < 0");
	}

    ect = sqrt(ect / (nsample * (nsample - 1)));
    sprintf(buf,"%.5g",ect);

    return buf;
}

char *strAccuracy (char *buf, double v, double s1, double s2, int nsample, double vmin)

{
    if (s2 <= 0.0 || nsample <= 1)
	{
	sprintf(buf,"% .6g",v);
        return buf;
	}

    double ect = s2 - s1 * s1 / nsample;
    
    if (ect < 0)
	{
        if (ect / s2 > - EPSILON_3)
	    ect = 0;
        else
	    statError("strAccuracy() - Epsilon < 0");
	}

    ect = sqrt(ect / (nsample * (nsample - 1)));

    if (vmin < 0.0 )
	sprintf(buf,"% .6g # %.5g",v,ect);
    else
	sprintf(buf,"% .6g #%4.1f%%",v,ect * 100 / v);

    return buf;
}

double decRounding(double x, int n)
{
    if (x == 0.0)
	return(x);

    int sign = x < 0.0 ? (-1) : 1;
    int exp = (int) log10(x * sign) - n + 1;
    double mul = pow(10.0,exp);
    double xr = floor (x/mul - sign * EPSILON_9) + sign;
    return (xr * mul);
}

double decRounding2(double x, int n)
{
    return decRounding(x, (int)floor(log10(x)) + 1 + n);
}

// STATE DIAGRAM

MvmStateDiagram::MvmStateDiagram (const char *_name,
				  int _nstates,
				  const char *const *_sarray,
				  int _logSize,
				  MvmConnector *_connector,
				  int _pflags) :
    MvmStatObj(_name,_connector,_pflags)
{
    logSize = _logSize;
    stateLog = new MvmStatePoint[logSize];
    defineStates(_nstates,_sarray);
}

MvmStateDiagram::MvmStateDiagram (const char *_name,
				  int _logSize,
				  MvmConnector *_connector,
				  int _pflags) :
    MvmStatObj(_name,_connector,_pflags)
{
    sarray = 0;
    nstates = 0;
    logSize = _logSize;
    stateLog = new MvmStatePoint[logSize];
}

MvmStateDiagram::MvmStateDiagram (MvmStateDiagramExportMsg *_exmsg,
				  int _logSize,
				  MvmConnector *_connector) :
    MvmStatObj(_exmsg,_connector)
{
    logSize = _logSize;
    stateLog = new MvmStatePoint[logSize];
    nstates = _exmsg->nstates;
    sarray = new char *[nstates];

    for (int n = 0; n < nstates; n++)
	sarray[n] = stringDup(_exmsg->sarray[n]);

    resetValues();
}

MvmStateDiagram::MvmStateDiagram (MvmStateDiagram& src) :
    MvmStatObj(src)
{
    defineStates(src.nstates,src.sarray);
    logSize = src.logSize;
    stateLog = new MvmStatePoint[logSize];
    memcpy(stateLog,src.stateLog,logSize * sizeof(MvmStatePoint));
}

MvmStateDiagram::~MvmStateDiagram ()

{
    delete[] stateLog;

    if (sarray)
	{
	for (int n = 0; n < nstates; n++)
	    stringFree(sarray[n]);

	delete[] sarray;
	}
}

void MvmStateDiagram::defineStates (int _nstates,
				    const char *const *_sarray)
{
    nstates = _nstates;

    if (nstates > 0)
	{
	sarray = new char *[nstates];

	for (int n = 0; n < nstates; n++)
	    sarray[n] = stringDup(_sarray[n]);
	}
    else
	sarray = NULL;

    resetValues();
}

void MvmStateDiagram::resetValues()

{
    nVal = 0;
    vMin = 0;
    vMax = nstates - 1;
    nSampleDone = 0;
    lastV = -1.0;
}

void MvmStateDiagram::ifInit ()

{
    if (nstates > 0)
	{
	MvmStateDiagramExportMsg exmsg(this);
	ifExport(&exmsg,sizeof(exmsg));
	}
}

void MvmStateDiagram::ifProcess (int mtype, const struct MvmInterfaceMsg *gpm, int)

{
    if (mtype == MVM_IFACE_TOGGLE)
	{
	const MvmInterfaceDisplayMsg *toggle = (struct MvmInterfaceDisplayMsg *)gpm;

	if (toggle->okDisplay)
	    {
	    ifSetDisplayed();

	    int logStart = nVal >= logSize ? nVal % logSize : 0;
	    int initSize = Min(logSize,nVal);

	    while (initSize > 0)
		{
		MvmStateDiagramInitMsg initMsg;
		int n;

		for (n = 0;
		     initSize > 0 && n < MVM_IFACE_SDIAGRAM_MAX_INIT;
		     n++, initSize--)
		    {
		    initMsg.tab[n] = stateLog[logStart];
		    
		    if (++logStart >= logSize)
			logStart = 0;
		    }

		initMsg.nPoints = initSize > 0 ? n : -n;
		ifSend(MVM_IFACE_SDIAGRAM_INIT,&initMsg,sizeof(initMsg));
		}
	    }
	else
	    ifSetConcealed();
        }
}

void MvmStateDiagram::add (double stateno)

{
    // Updates to the log *must* be done before any break state can
    // exist due to a threshold breakpoint.  Otherwise, states could
    // be recorded with a wrong time stamp if the underlying thread
    // goes sleeping as a result of its state change (i.e. another
    // thread gets the CPU after the state changes, and makes MvmClock
    // advance before the suspended thread have stored the transition
    // information).
    
    int cursor = nVal % logSize;
    stateLog[cursor].stateno = (int)stateno;
    stateLog[cursor].time = MvmClock;
    // nVal is incremented in MvmStatObj::add()
    MvmStatObj::add(stateno);

    if (ifIsDisplayed())
	{
	MvmStateDiagramPointMsg sdp(MvmClock,(int)stateno);
	ifSend(MVM_IFACE_SDIAGRAM_POINT,&sdp,sizeof(sdp));

	for (MvmInterfaceBreakPoint *bp = (MvmInterfaceBreakPoint *)ifBP.first();
	     bp; bp = (MvmInterfaceBreakPoint *)bp->next())
	    {
	    if (bp->threshold == stateno)
		{
		ifSignal(MVM_IFACE_SIGBREAK);
		break;
		}
	    }
	}
}

void statError (const char *format, ...)

{
    va_list ap;
    va_start(ap,format);
    vfprintf(stderr,format,ap);
    fprintf(stderr,"\n");
    va_end(ap);
    abort();
}

void statWarning (const char *format, ...)

{
    va_list ap;
    va_start(ap,format);
    vfprintf(stderr,format,ap);
    fprintf(stderr,"\n");
    va_end(ap);
}
