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
 * The original code is FROGS - A Free Object-oriented General-purpose
 * Simulator, released November 10, 1999. The initial developer of the
 * original code is Realiant Systems (http://www.realiant.com).
 *
 * Author(s): rwestrel from an original by tb
 * Contributor(s): rpm
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifndef _plotter_h
#define _plotter_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include "drawable.h"

class TkPlotterFrame;

enum TkPlotterViewModes { Compressed, Uncompressed };

struct TkPlotterSettings {

    friend class TkPlotter;

protected:

    CString yUnitName,
	xUnitName;

    ETimeUnits timeUnit;

public:

    TkPlotterSettings(const char *_yUnitName =0,
		      const char *_xUnitName =0);
  
    void setUnitNames(const char *_yUnitName,
		      const char *_xUnitName) {
	yUnitName = _yUnitName;
	xUnitName = _xUnitName;
    }
  
    void setTimeUnit(ETimeUnits _timeUnit) {
	timeUnit = _timeUnit;
    }
};

class TkPlotter : public LinkedObject, public TkContext {

    friend class TkPlotterFrame;
    friend class STDisplayObject;

protected:

    TkPlotterSettings settings;

    int pixXMax,
	pixYMax;

    ETimeUnits timeUnit;
  
    CString title;
  
    TkPlotterFrame *pframe;
  
    TkPlotterViewModes viewMode;

    int xrule,
	yrule;

    STDisplayObjectGList allObjectGList;

public:

    TkPlotter(const char *title,
	      TkPlotterFrame *pframe, // parent plotter frame
	      const TkPlotterSettings& settings,
	      TkContext* _master); 

    ~TkPlotter();

    virtual void getProperties(TclList*);

    int getPixXMax() {
	return pixXMax;
    }

    int getPixYMax() {
	return pixYMax;
    }

    void setAllPixXMax(int pixXMax);

    void setAllPixYMax(int pixYMax);

    TkPlotterFrame *getFrame() {
	return pframe;
    }

    const char *getTitle() {
	return title;
    }

    TkPlotterViewModes getViewMode() {
	return viewMode;
    }

    ETimeUnits getTimeUnit() const {
	return timeUnit;
    }

    STDisplayObjectGList& getAllObjectList() {
	return allObjectGList;
    }

    virtual void setPixXMax(int pixXMax);

    virtual void setPixYMax(int pixYMax);

    virtual void updateStatistics(); // empty

    virtual void setBreakPoint(int y, int x); // empty

    virtual STDisplayObject *acceptObject(const MvmInterfaceExportMsg *gpex) =0;

    virtual void notify(TkEvent event,
			int argc,
			char *argv[],
			TkClientData clientData);

    virtual void compact() {}

    virtual void uncompact() {}
  
    const TkPlotterSettings& getSettings() {
	return settings;
    }

    virtual CString printObjects(TkPlotterViewModes format,
				 const char* fileName,
				 const char *footer); // empty
};

MakeGList(TkPlotter);

class TkCurvePlotter : public TkPlotter {

protected:

    int nMaxPointDisplayed;
  
public:

    TkCurvePlotter(const char *title,
		   TkPlotterFrame *pframe,
		   const TkPlotterSettings& settings,
		   TkContext* master,
		   int logSize =STDISPLAY_FRAME_LOGSZ);

    int getNMaxPointDisplayed() {
	return nMaxPointDisplayed;
    }

    virtual void setPixXMax(int pixXMax);

    virtual void setPixYMax(int pixYMax);

    virtual STDisplayObject *acceptObject(const MvmInterfaceExportMsg *gpex); // empty

    virtual void setBreakPoint(int y, int x);

    virtual void notify(TkEvent event,
			int argc,
			char *argv[],
			TkClientData clientData);

    virtual void compact() {}

    virtual void uncompact() {}

    virtual void getProperties(TclList*);
};

class TkTimeCurvePlotter : public TkCurvePlotter {

    friend class STDisplayTimeCurveObject;
    friend class MvmTimeGraphDisplay;
    friend class MvmStateDiagramDisplay;

protected:

    ITime dtUpdateMin;	//	Plus petit intervalle entre points
    ITime tOldest;
    ITime tMin;		//	Plus petit temps affiche
    ITime tMax;		//	plus grand temps affiche
    ITime tCur;		//	temps courant
    ITime tAll;		//	temps maximal ou duree de simulation
    ITime lastDt;		//	dernier largeur en temps avant compaction
  
    int okXAdjust;	//	ajustement automatique en X sur dtUpdateMin
    int okXTranslate;	//	translation automatique en X si tCur > tMax
    int okInfiniteTimeLimit; // True if survey is infinite
  
    double xScale;
    int okXScale;
  
    ITime deltaStartTime;
    double hScrollUnit;
  
    STDisplayTimeCurveObject* mergeFrom;
    STDisplayTimeCurveObject* mergeTo;

public:

    TkTimeCurvePlotter(const char *title,
		       TkPlotterFrame *pframe, // parent plotter frame
		       const TkPlotterSettings& settings,  
		       TkContext* master,
		       int logSize =STDISPLAY_FRAME_LOGSZ,
		       // tAll == ZEROTIME means that survey is infinite
		       ITime tAll =ZEROTIME);

    virtual CString printObjects(TkPlotterViewModes format,
				 const char* fileName,
				 const char *footer);
  
    void setXBounds(ITime, ITime);

    void getTimeBounds(double& tmin, double& tmax) {
	tmin = tMin.getUSec();
	tmax = tMax.getUSec();
    }

    void getTimeBounds(ITime& tmin, ITime& tmax) {
	tmin = tMin;
	tmax = tMax;
    }

    void setTimeBounds(double tmin, double tmax) {
	tMin = tmin;
	tMax = tmax;
    }

    ITime getCurrentTime() {
	return tCur;
    }

    void findDtUpdateMin();

    void findTOldest();

    void setXScale();

    void setXScale(double);

    void setXAdjust(int okAutoScale);

    void setXAdjustNoRescale(int okAutoScale) {
	okXScale = okAutoScale;
    }

    int autoXAdjust() {
	return okXAdjust;
    }

    double getXScale() {
	return xScale;
    }

    void timeUpdate(ITime time);

    virtual void setPixXMax(int);

    virtual void setPixYMax(int);

    virtual STDisplayObject *acceptObject(const MvmInterfaceExportMsg *gpex);

    virtual void notify(TkEvent event,
			int argc,
			char *argv[],
			TkClientData clientData);
    void compact();

    void uncompact();

    void doMergeFrom(STDisplayTimeCurveObject* gtcp) {
	mergeFrom = gtcp;
    }

    void doMergeTo(STDisplayTimeCurveObject* gtcp) {
	mergeTo = gtcp;
    }

    virtual void getProperties(TclList*);

    ETime getTimeValueWithUnit(int);

    ETime addUnitToTime(ITime);

    ITime getTimeValue(int);
};

class TkGraphPlotter : public TkTimeCurvePlotter {

public:

    TkGraphPlotter(const char *title,
		   TkPlotterFrame *pframe, // parent plotter frame
		   const TkPlotterSettings& settings, 
		   TkContext* master,
		   int logSize =STDISPLAY_FRAME_LOGSZ,
		   // tAll == ZEROTIME means that survey is infinite
		   ITime tAll =ZEROTIME);

    virtual STDisplayObject *acceptObject(const MvmInterfaceExportMsg *gpex);

    virtual void notify(TkEvent event,
			int argc,
			char *argv[],
			TkClientData clientData);

    virtual void getProperties(TclList*);
};

class TkStatePlotter : public TkTimeCurvePlotter {

public:

    TkStatePlotter(const char *title,
		   TkPlotterFrame *pframe, // parent plotter frame
		   const TkPlotterSettings& settings, 
		   TkContext* master,
		   int logSize =STDISPLAY_FRAME_LOGSZ,
		   // tAll == ZEROTIME means that survey is infinite
		   ITime tAll =ZEROTIME);

    virtual STDisplayObject *acceptObject(const MvmInterfaceExportMsg *gpex);

    virtual void notify(TkEvent event,
			int argc,
			char *argv[],
			TkClientData clientData);

    virtual void getProperties(TclList*);
};

class TkHistoPlotter : public TkCurvePlotter {

public:

    TkHistoPlotter(const char *title,
		   TkPlotterFrame *pframe, // parent plotter frame
		   const TkPlotterSettings& settings, 
		   TkContext* master,
		   int logSize =STDISPLAY_FRAME_LOGSZ);

    virtual CString printObjects(TkPlotterViewModes format,
				 const char* fileName,
				 const char *footer);

    virtual STDisplayObject *acceptObject(const MvmInterfaceExportMsg *gpex);

    virtual void updateStatistics();

    virtual void notify(TkEvent event,
			int argc,
			char *argv[],
			TkClientData clientData);

    void compact() {}

    void uncompact() {}

    virtual void getProperties(TclList*);
};

class TkPlotterFrame : public MvmFrontend, public TkContext {

protected:

    TkPlotterGList plotterGList;
    int autoSaveSession;

public:
  
    virtual ITime getCurrentTime() const {
	return 0;
    }

    void waitHack();

    void saveSession();

    void trySaveSession();

    TkPlotterFrame(const char *title =0,
		   const char *toolName =0);

    ~TkPlotterFrame();

    virtual MvmInterface *createDisplay(const MvmInterfaceExportMsg *gpex,
					int msize);

    virtual void destroyDisplay(MvmInterface *object);

    virtual void send(int mtype,
		      MvmInterfaceMsg *gpm =0,
		      int msize =0) =0;

    TkTimeCurvePlotter *addTimeCurvePlotter(const char *title,
					    const TkPlotterSettings& settings,
					    int logSize =STDISPLAY_FRAME_LOGSZ,
					    // i.e. infinite
					    ITime surveyTime =ZEROTIME);

    TkGraphPlotter *addGraphPlotter(const char *title,
				    const TkPlotterSettings& settings,
				    int logSize =STDISPLAY_FRAME_LOGSZ,
				    // i.e. infinite
				    ITime surveyTime =ZEROTIME);
  
    TkStatePlotter *addStateDiagramPlotter(const char *title,
					   const TkPlotterSettings& settings,
					   int logSize =STDISPLAY_FRAME_LOGSZ,
					   // i.e. infinite
					   ITime surveyTime =ZEROTIME);
  
    TkHistoPlotter *addHistogramPlotter(const char *title,
					const TkPlotterSettings& settings,
					int logSize =STDISPLAY_FRAME_LOGSZ);
    void popup();
  
    virtual void notify(TkEvent event,
			int argc,
			char *argv[],
			TkClientData clientData);

    virtual void holdNotified();

    virtual void releaseNotified();
};

#define AvailableForDisplay   0
#define GetProperties         1
#define GetPointsToDisplay    2
#define GetYAxisInfo          3
#define GetXAxisInfo          4
#define SetTimeBounds         5
#define GetXYValues           6
#define FromXYValuesToPix     7
#define SetYBounds            8
#define HistoPolling          9
#define ProtoSetDisplay      10
#define ProtoSetConceal      11
#define SetBreakpoint        12
#define GetBreakpointList    13
#define ClearBreakpoint      14
#define ProtoSetTempConceal  15
#define Compress             16
#define UnCompress           17
#define GetXAxisHisto        18
#define SetHistoDisplay      19
#define SetHistoView         20
#define GetXYValuesString    21
#define GetConf              22
#define SetConf              23
#define SetMergeFrom         24
#define SetMergeTo           25
#define DoMerge              26
#define SetCompoundTitle     27
#define RemoveFromCmpd       28
#define ForceSetDisplay      29
#define SetCurrentTime       30
#define getNextDate          31
#define getPrevDate          32
#define getYBounds           33
#define BuildCompound        34
#define AddToCmpd            35
#define FakeSetDisplay       36
#define SetPrintMe           37
#define PrintIt              38
#define ResetPrintMe         39
#define getRoundedDate       40
#define CheckMerge           41

#endif // !_plotter_h
