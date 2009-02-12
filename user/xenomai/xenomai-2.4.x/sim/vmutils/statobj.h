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

#ifndef _mvm_statobj_h
#define _mvm_statobj_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include <sys/types.h>
#include <string.h>
#include <memory.h>
#include <math.h>
#include <stdio.h>
#include "vmutils/interface.h"

#define NTGVALUEDEF	500
#define NSTVALUEDEF	100

#define EPSILON_3 0.001
#define EPSILON_5 0.00001
#define EPSILON_9 0.000000001

class MvmCounter;
class MvmIntegrator;
class MvmHistogram;
class MvmFilter;
class MvmScaler;
class MvmTimeGraph;
class MvmHistogramExportMsg;
class MvmTimeGraphExportMsg;
class MvmStateDiagramExportMsg;

extern double variance(double,
		       double,
		       int);

extern char *rawAccuracy(char *buf,
			 double,
			 double,
			 int);

extern char *strAccuracy(char *buf,
			 double,
			 double,
			 double,
			 int,
			 double = -1.0);

extern double decRounding(double,
			  int);

extern double decRounding2(double,
			   int);

// STATISTIC OBJECT

enum StValueType {
    VAL,
    CMES,
    NUM,
    SUM,
    SUM2,
    DMES,
    DNUM,
    DSUM,
    MINVAL,
    MAXVAL,
    MEAN,
    STDEV
};

class MvmStatObj : public MvmInterface {

 protected:

    double lastV;		// last summed value

    int nVal;			// count of summed values

    int nSampleDone;		// sample count

    double vMin;		// min. summed value

    double vMax;		// max. summed value

    virtual int compare(LinkedObject *buddy);

 public:

    MvmStatObj(const char *name =0,
	       MvmConnector *connector =0,
	       int pflags =0);

    MvmStatObj(MvmInterfaceExportMsg *gpex,
	       MvmConnector *connector);

    int getNumVal() const {
    return nVal;
    }

    virtual ~MvmStatObj();

    virtual void add(double v);

    virtual double getValue(StValueType vt =VAL);

    virtual void resetValues();

    virtual void sample();

    virtual void result();

    virtual const char *getCurveName() {
    return ifGetName();
    }

    void add(int v) {
    add((double)v);
    }
};

MakeGList(MvmStatObj);

// COUNTER

class MvmCounter : public MvmStatObj {

 protected:

    double sv1;

    double se1;

    double se2;

 public:

    MvmCounter (const char *name,
		MvmConnector *connector =0,
		int pflags =0);

    MvmCounter (MvmInterfaceExportMsg *gpex,
		MvmConnector *connector);

    virtual void add(double v);

    virtual double getValue(StValueType =VAL);

    virtual void resetValues();

    virtual void sample();

    virtual void result();

    void inc() {
    add(1.0);
    }
};

// TIME INTEGRATOR

class MvmIntegrator : public MvmStatObj {

 protected:

    ITime dtSample;

    ITime tStart;

    ITime tEnd;

    ITime tLastUpdate;

    ITime tLastSample;

    double s;

    double se1;

    double se2;

 public:

    MvmIntegrator(const char *name,
		  const ITime& tStart,
		  const ITime& tEnd,
		  const ITime& dtSample,
		  MvmConnector *connector =0,
		  int pflags =0);

    MvmIntegrator(MvmInterfaceExportMsg *gpex,
		  MvmConnector *connector,
		  const ITime& tStart,
		  const ITime& tEnd,
		  const ITime& dtSample);

    virtual void add(double v);

    virtual double getValue(StValueType vt =VAL) ;

    virtual void resetValues();

    virtual void sample();

    virtual void result();

    void inc() {
    add(lastV + 1.0);
    }

    void dec() {
    add(lastV - 1.0);
    }
};

// HISTOGRAM

enum StHistAdjustMode {

    MULTIPLY,
    GARBAGE
};

enum StHistDisplayMode {

    STHistoDENSITY,
    STHistoREPART
};

class MvmHistogram : public MvmStatObj {

    friend class MvmHistogramExportMsg;

 protected:

    double l,
	r,
	binsize;

    int nbin;

    int *vLog;

    int nv;

    double sv1,
	ssv1,
	sv2,
	ssv2,
	sm1,
	sd1,
	sm2,
	sd2;

    StHistAdjustMode mode;

    int garbage;

    int adjust(double, StHistAdjustMode);

    void init();

    StHistDisplayMode displayMode;

 public:

    MvmHistogram(const char *name,
		 int nbins,
		 double min,
		 double max,
		 StHistAdjustMode adj =MULTIPLY,
		 MvmConnector *connector =0,
		 int pflags =0);

    MvmHistogram(const char *name,
		 int nbins,
		 int ll,
		 int rr,
		 StHistAdjustMode mode =MULTIPLY,
		 MvmConnector *connector =0,
		 int pflags =0);

    MvmHistogram(MvmHistogramExportMsg *exmsg,
		 MvmConnector *connector =0);

    MvmHistogram(MvmHistogram& src);

    virtual ~MvmHistogram();

    void setDisplayMode(StHistDisplayMode);

    StHistDisplayMode getDisplayMode() {
    return displayMode;
    }

    virtual void ifInit();

    virtual void ifProcess(int mtype,
			   const MvmInterfaceMsg *gpm,
			   int msize);

    virtual void add(double);

    virtual double getValue(StValueType =VAL);

    virtual void resetValues();

    virtual void sample();

    virtual void result();
};

MakeGList(MvmHistogram);

// SCALER

class StScaling {

 public:

    virtual double compute() =0;
};

class MvmTimeScaling : public StScaling {

 protected:

    double timeFactor;

 public:

    MvmTimeScaling(double timeFactor =1.0);

    virtual double compute();
};

class MvmStatObjScaling : public StScaling {

 protected:

    MvmStatObj *soScaling;

    StValueType vTypeScaling;

 public:

    MvmStatObjScaling(MvmStatObj *scalingObject,
		      StValueType vt =VAL);

    virtual double compute();
};

class MvmScaler : public MvmStatObj {

 protected:

    MvmStatObj *soScaled;

    ITime tUpdate;

    StValueType vTypeScaled;

    StScaling *scale;

    double lastS;

    MvmScaler(const char *name,
	      MvmStatObj *scaledObject,
	      StValueType vt =VAL,
	      MvmConnector *connector =0,
	      int pflags =0);

    MvmScaler(MvmInterfaceExportMsg *gpex,
	      MvmConnector *connector,
	      MvmStatObj *scaledObject,
	      StValueType vt =VAL);
 public:

    virtual double getValue(StValueType =VAL);
};

class MvmTimeScaler : public MvmScaler {

 public:

    MvmTimeScaler(const char *name,
		  MvmStatObj *scaledObject,
		  StValueType vt =VAL,
		  double timeFactor =1.0,
		  MvmConnector *connector =0,
		  int pflags =0);

    MvmTimeScaler(MvmInterfaceExportMsg *gpex,
		  MvmConnector *connector,
		  MvmStatObj *scaledObject,
		  StValueType vt =VAL,
		  double timeFactor =1.0);

    virtual ~MvmTimeScaler();
};

class MvmObjectScaler : public MvmScaler {

 public:

    MvmObjectScaler(const char *name,
		    MvmStatObj *scaledObject,
		    MvmStatObj *scalingObject,
		    StValueType vtScaled =VAL,
		    StValueType vtScaling =VAL,
		    MvmConnector *connector =0,
		    int pflags =0);

    MvmObjectScaler(MvmInterfaceExportMsg *gpex,
		    MvmConnector *connector,
		    MvmStatObj *scaledObject,
		    MvmStatObj *scalingObject,
		    StValueType vtScaled =VAL,
		    StValueType vtScaling =VAL);

    virtual ~MvmObjectScaler();
};

// FILTER

class MvmFilter : public MvmStatObj {

 protected:

    MvmStatObj *soBase;

    StValueType vType;

    ITime dtUpdate;

    ITime tUpdate;

    double *v;

    int nvMax;

    int iCurr;

 public:

    MvmFilter(const char *name,
	      MvmStatObj *filteredObject,
	      ITime dtUpdate,
	      StValueType vt =VAL,
	      int logSize =2,
	      MvmConnector *connector =0,
	      int pflags =0);

    MvmFilter(MvmInterfaceExportMsg *gpex,
	      MvmConnector *connector,
	      MvmStatObj *so,
	      ITime dtUpdate,
	      StValueType type =VAL,
	      int logSize =2);
		 
    MvmFilter(MvmFilter& src);

    virtual ~MvmFilter();

    const ITime& getDtUpdate() {
    return dtUpdate;
    }

    double getCurrentPoint() {
    return v[iCurr % nvMax];
    }

    virtual void update();

    virtual void resetValues();

    virtual void add(double);

    virtual double getValue(StValueType);

    virtual double derive(ITime);

    virtual double sift(ITime);
};

// TIME GRAPH

class MvmTimeGraph : public MvmFilter {

    friend class MvmTimeGraphExportMsg;

 protected:

    double yTgMax;

    double yTgMin;

    double lastSval;

    int yAdjust;

 public:

    MvmTimeGraph(const char *name,
		 MvmStatObj *filteredObject,
		 ITime dtUpdate,
		 StValueType vt =VAL,
		 int logSize =NTGVALUEDEF,
		 MvmConnector *connector =0,
		 int pflags =0);

    MvmTimeGraph(MvmTimeGraphExportMsg *exmsg,
		 MvmConnector *connector =0);

    void setYLimits(double yMin,
		    double yMax,
		    int okYAdjust =1);

    int getMaxValues() {
    return nvMax;
    }

    virtual void ifInit();

    virtual void ifProcess(int mtype,
			   const MvmInterfaceMsg *gpm,
			   int msize);

    virtual void resetValues();

    virtual void update();
};

MakeGList(MvmTimeGraph);

// MvmTimeGraph MESSAGES

struct MvmTimeGraphPointMsg : public MvmInterfaceMsg {

    double y;

    MvmTimeGraphPointMsg(double _y) {
	y = _y;
    }
};

#define MVM_IFACE_TIMEGRAPH_MAX_INIT 64

struct MvmTimeGraphInit : public MvmInterfaceMsg {

    int pointNr;
    ITime time;
    double pointTab[MVM_IFACE_TIMEGRAPH_MAX_INIT];
};

struct MvmTimeGraphExportMsg : public MvmInterfaceExportMsg {

    double dtUpdate;
    double vMin;
    double vMax;
    double yTgMax;
    double yTgMin;
    int yAdjust;
    int nvMax;
    u_long iCurr;

    MvmTimeGraphExportMsg(MvmTimeGraph *_timegraph) :
	MvmInterfaceExportMsg(MVM_IFACE_TIMEGRAPH_ID,
			      _timegraph->getCurveName()) {
	dtUpdate = (double)_timegraph->dtUpdate;
	nvMax = _timegraph->nvMax;
	yTgMin = _timegraph->yTgMin;
	yTgMax = _timegraph->yTgMax;
	yAdjust = _timegraph->yAdjust;
	vMin = _timegraph->vMin;
	vMax = _timegraph->vMax;
	iCurr = _timegraph->iCurr;
    }
};

// STATE DIAGRAM OBJECT

struct MvmStatePoint {

    int stateno;
    double time;
};

class MvmStateDiagram : public MvmStatObj {

    friend class MvmStateDiagramExportMsg;

 protected:

    int nstates;

    char **sarray;

    MvmStatePoint *stateLog;

    int logSize;

 public:

    MvmStateDiagram(const char *name,
		    int nstates,
		    const char *const *sarray,
		    int logSize =NSTVALUEDEF,
		    MvmConnector *connector =0,
		    int pflags =0);

    MvmStateDiagram(const char *name,
		    int logSize =NSTVALUEDEF,
		    MvmConnector *connector =0,
		    int pflags =0);

    MvmStateDiagram(MvmStateDiagramExportMsg *exmsg,
		    int logSize =NSTVALUEDEF,
		    MvmConnector *connector =0);

    MvmStateDiagram(MvmStateDiagram& src);

    virtual ~MvmStateDiagram();

    void defineStates(int nstates,
		      const char *const *sarray);

    int getNStates() const {
    return nstates;
    }

    const char *getStateName(int nth) const {
    return sarray[nth];
    }

    virtual void ifInit();

    virtual void ifProcess(int mtype,
			   const MvmInterfaceMsg *gpm,
			   int msize);

    virtual void resetValues();

    virtual void add(double stateno);
};

MakeGList(MvmStateDiagram);

// StateDiagram MESSAGES

#define MVM_IFACE_SDIAG_STATE_NAMELEN  32
#define MVM_IFACE_SDIAG_MAX_STATES     36
#define MVM_IFACE_SDIAGRAM_MAX_INIT    64

struct MvmStateDiagramInitMsg : public MvmInterfaceMsg {

    int nPoints;
    MvmStatePoint tab[MVM_IFACE_SDIAGRAM_MAX_INIT];
};

struct MvmStateDiagramExportMsg : public MvmInterfaceExportMsg {

    int nstates;
    char sarray[MVM_IFACE_SDIAG_MAX_STATES][MVM_IFACE_SDIAG_STATE_NAMELEN];

    MvmStateDiagramExportMsg(MvmStateDiagram *_sdiagram) :
	MvmInterfaceExportMsg(MVM_IFACE_SDIAGRAM_ID,
			      _sdiagram->getCurveName()) {
	nstates = _sdiagram->nstates;
	for (int n = 0; n < nstates; n++)
	    scopy(sarray[n],
		  _sdiagram->sarray[n],
		  MVM_IFACE_SDIAG_STATE_NAMELEN - 1);
    }
};

struct MvmStateDiagramPointMsg : public MvmInterfaceMsg {

    int stateno;
    double time;

    MvmStateDiagramPointMsg(double _time,
			    int _stateno) {
	time = _time;
	stateno = _stateno;
    }
};

// MvmHistogram MESSAGES

struct MvmHistogramExportMsg : public MvmInterfaceExportMsg {

    int nbin;

    MvmHistogramExportMsg(MvmHistogram *_histogram) :
	MvmInterfaceExportMsg(MVM_IFACE_HISTOGRAM_ID,
			      _histogram->getCurveName()) {
	nbin = _histogram->nbin;
    }
};

struct MvmHistogramHeader : public MvmInterfaceMsg {

    double l;
    double r;
    int	nval;
    double vmin;
    double vmax;
    double s1;
    double s2;
    int	garb;
    ITime time;
};

#define MVM_IFACE_HISTOGRAM_MAX_INIT 64

struct MvmHistogramInit : public MvmInterfaceMsg {

    int nPtr;
    int hTab[MVM_IFACE_HISTOGRAM_MAX_INIT];
};

void statError(const char *format, ...);

void statWarning(const char *format, ...);

extern ITime MvmClock;

extern MvmStatObjGList allMvmStatObjs;

#endif // !_mvm_statobj_h
