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
 * Author(s): rwestrel from an original by tb
 * Contributor(s): rpm
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifdef __GNUG__
#pragma implementation
#endif // __GNUG__
#include <xeno_config.h>
#include <stdlib.h>
#include "plotter.h"
#include "postscript.h"

// TkPlotterSettings
 
TkPlotterSettings::TkPlotterSettings (const char *_yUnitName,
				      const char *_xUnitName)
{
    yUnitName = _yUnitName;
    xUnitName = _xUnitName;
    timeUnit = defaultETimeUnit;
}

// TkPlotter
TkPlotter::TkPlotter (const char *_title,
		      TkPlotterFrame *_pframe,
		      const TkPlotterSettings& _settings, 
		      TkContext* _master)
    :   TkContext(_master)
{
    title = _title;
    pframe = _pframe;
    settings = _settings;
    timeUnit = _settings.timeUnit;
  
    pixXMax = 0; 
    xrule = -1;
    yrule = -1;

    handleEvent("GetProperties", GetProperties, this);
    handleEvent("SetConf", SetConf, this);
    handleEvent("GetConf", GetConf, this);
    handleEvent("PrintIt", PrintIt, this);
}

TkPlotter::~TkPlotter ()

{
    callTkProc("plotter:unSetHierarchy", "&C", (TkContext*)pframe);
    allObjectGList.destroy();
}

CString TkPlotter::printObjects (TkPlotterViewModes, const char*, const char *)

{ return CString(""); }

void TkPlotter::getProperties(TclList* list)
{
    TclList sublist;
    sublist.append(title);
    list->append(sublist);
}

void TkPlotter::notify(TkEvent event,
		       int argc,
		       char *argv[],
		       TkClientData clientData)
{
    switch(event)
	{
	case GetProperties:
	    {
	    TclList properties;
	    getProperties(&properties);
	    setTkResult("&L", &properties);
	    break;
	    }
	case PrintIt:
	    {
	    int mode = atoi(argv[1]);
	    CString errmsg;
	    errmsg = printObjects((!mode)?Compressed: Uncompressed,
				  argv[2],
				  argv[3]);
	    setTkResult("&S", (const char *)errmsg);
	    }
	}
}


void TkPlotter::setPixXMax (int pixxm)

{
    pixXMax = Max(pixxm,STDISPLAY_FRAME_PIXXMIN);

    STDisplayObjectIterator it(allObjectGList);
    STDisplayObject *displayObject;

    while ((displayObject = it.next()) != NULL)
	displayObject->setPixXMax(pixXMax);
}

void TkPlotter::setPixYMax (int pixym)

{ pixYMax = Max(pixym,STDISPLAY_FRAME_PIXYMIN); }

void TkPlotter::setAllPixXMax (int pixx)

{
    STDisplayObjectIterator it(allObjectGList);
    STDisplayObject *displayObject;

    while ((displayObject = it.next()) != NULL)
	displayObject->setPixXMax(pixx);
}

void TkPlotter::setAllPixYMax (int pixy)

{
    STDisplayObjectIterator it(allObjectGList);
    STDisplayObject *displayObject;

    while ((displayObject = it.next()) != NULL)
	displayObject->setPixYMax(pixy);
}

// TkPlotterFrame

TkPlotterFrame::TkPlotterFrame (const char *_title,
				const char *_toolName)
    : MvmFrontend(), TkContext()
{
    autoSaveSession = 0;
    linkTkVar("plotter:autoSaveSession", &autoSaveSession);

    handleEvent("AvailableForDisplay", AvailableForDisplay, this);
    handleEvent("GetProperties", GetProperties, this);
    callTkProc("plotter:initialize","&S &S",_title,_toolName);
    callTkProc("plotter:setHierarchy","&S", "");
}

TkPlotterFrame::~TkPlotterFrame ()

{
    callTkProc("plotter:destroy");
    plotterGList.destroy();
}

TkTimeCurvePlotter *TkPlotterFrame::addTimeCurvePlotter (const char *_title,
							 const TkPlotterSettings& _settings,
							 int _logSize,
							 ITime _surveyTime)
{
    TkTimeCurvePlotter *plotter = new TkTimeCurvePlotter(_title,
							 this,
							 _settings, this,
							 _logSize,
							 _surveyTime);
    plotterGList.append(plotter);
    return plotter;
}

TkGraphPlotter *TkPlotterFrame::addGraphPlotter (const char *_title,
						 const TkPlotterSettings& _settings,
						 int _logSize,
						 ITime _surveyTime)
{
    TkGraphPlotter *plotter = new TkGraphPlotter(_title,
						 this,
						 _settings, this,
						 _logSize,
						 _surveyTime);
    plotterGList.append(plotter);
    return plotter;
}

TkStatePlotter *TkPlotterFrame::addStateDiagramPlotter (const char *_title,
							const TkPlotterSettings& _settings,
							int _logSize,
							ITime _surveyTime)
{ 
    TkStatePlotter *plotter = new TkStatePlotter(_title,
						 this,
						 _settings, this,
						 _logSize,
						 _surveyTime);
    plotterGList.append(plotter);
    return plotter;
}

TkHistoPlotter *TkPlotterFrame::addHistogramPlotter (const char *_title,
						     const TkPlotterSettings& _settings,
						     int _logSize)
{
    TkHistoPlotter *plotter = new TkHistoPlotter(_title,
						 this,
						 _settings, this,
						 _logSize);
    plotterGList.append(plotter);
    return plotter;
}

MvmInterface *TkPlotterFrame::createDisplay (const MvmInterfaceExportMsg *gpex, int)

{
    TkPlotterIterator it(plotterGList);
    TkPlotter *plotter;

    // Try to find an active plotter which may accept
    // the exported object

    while ((plotter = it.next()) != NULL)
	{
	STDisplayObject *displayObject = plotter->acceptObject(gpex);

	if (displayObject)
	    return displayObject->getProto();
	}

    return NULL;
}

void TkPlotterFrame::destroyDisplay (MvmInterface *)

{
    // Object has been marked as zombie by the proto level code.
    // Do not actually delete this object to allow frozen display,
    // even if the peer stat object cannot send data anymore.
}

void TkPlotterFrame::saveSession () 

{ callTkProc("plotter:saveSession"); }

void TkPlotterFrame::trySaveSession () 

{
    if (autoSaveSession)
	saveSession();
}

void TkPlotterFrame::notify(TkEvent event,
			    int argc,
			    char *argv[],
			    TkClientData clientData)
{
    switch(event)
	{
	case AvailableForDisplay:
	    {
	    TclList display;
	    TclList sublist1;
	    TclList sublist2;
	    TclList empty;

	    display.append(empty);
	    display.append(empty);
	    display.append(empty);

	    TkPlotterIterator it(plotterGList);
	    STDisplayObject *displayObject;
	    TkPlotter *plotter;

	    while ((plotter = it.next()) != NULL)
		{
		sublist2.append(plotter -> getTitle());
		sublist2.append(empty);

		STDisplayObjectIterator it(plotter->getAllObjectList());

		while ((displayObject = it.next()) != NULL)
		    sublist1.append(displayObject->getProto()->ifGetName());

		sublist2.append(sublist1);
		sublist1.clear();
		}
	    
	    display.append(sublist2);
	    setTkResult("&L", &display);
	    break;
	    }
	case GetProperties:
	    {
	    TclList empty;
	    setTkResult("&L", &empty);
	    break;
	    }
	}
}

void TkPlotterFrame::popup ()

{
    callTkProc("plotter:popup");
}

void TkPlotterFrame::waitHack()

{
    callTkProc("plotter:choiceMade");
}

void TkPlotterFrame::holdNotified () 

{
    callTkProc("plotter:simStopped");
}

void TkPlotterFrame::releaseNotified () 

{
    callTkProc("plotter:simRunning");
}

void TkPlotter::updateStatistics () {}

void TkPlotter::setBreakPoint (int, int) {}

// Graphcurveplotter

TkCurvePlotter::TkCurvePlotter (const char *_title,
				TkPlotterFrame *_pframe,
				const TkPlotterSettings& _settings,
				TkContext* _master,
				int _np)
    : TkPlotter(_title,_pframe,_settings, _master)
{ 
  
    nMaxPointDisplayed = _np; 
    handleEvent("GetXAxisInfo", GetXAxisInfo, this);
}

void TkCurvePlotter::getProperties(TclList* list)
{
    TkPlotter::getProperties(list);
}

void TkCurvePlotter::notify(TkEvent event,
			    int argc,
			    char *argv[],
			    TkClientData clientData)
{
    switch(event)
	{
	case GetXAxisInfo:
	    {
	    setPixXMax(atoi(argv[1]));
	    setPixYMax(atoi(argv[2]));
	    break;
	    }
	default:
	    TkPlotter::notify(event, argc, argv, clientData);
	    break;
	}

}

void TkCurvePlotter::setPixXMax (int pixx)

{ TkPlotter::setPixXMax(pixx); }

void TkCurvePlotter::setPixYMax (int pixy)

{ TkPlotter::setPixYMax(pixy); }

STDisplayObject *TkCurvePlotter::acceptObject (const MvmInterfaceExportMsg *)

{ return 0; }

void TkCurvePlotter::setBreakPoint (int y, int x)

{}

// TkTimeCurvePlotter
TkTimeCurvePlotter::TkTimeCurvePlotter (const char *_title,
					TkPlotterFrame *_pframe,
					const TkPlotterSettings& _settings,
					TkContext* _master,
					int _logSize,
					ITime _tAll) :
    TkCurvePlotter(_title,
		   _pframe,
		   _settings,
		   _master,
		   _logSize)
{
    lastDt = 0;
    okXAdjust = 0;
    okXTranslate = 1;
    tMin = tCur = ZEROTIME;
  
    if (_tAll == ZEROTIME)
	{
	okInfiniteTimeLimit = 1;
	if (timeUnit == TCalendar)
	    _tAll = ETime(365,TDay);
	else
	    _tAll = ETime(200,MSec);
	}
    else
	okInfiniteTimeLimit = 0;
  
    tMax = _tAll;
    tAll = _tAll;
    dtUpdateMin = tAll / (double)nMaxPointDisplayed;

    okXScale = 0;
    setPixXMax(0);
    setXScale();
  
    if (timeUnit == TCalendar)
	hScrollUnit = 60.0;
    else
	hScrollUnit = 1.0;
  
    deltaStartTime = ZEROTIME;
    handleEvent("SetTimeBounds", SetTimeBounds, this);
    handleEvent("Compress", Compress, this);
    handleEvent("UnCompress", UnCompress, this);
    handleEvent("DoMerge", DoMerge, this);
    handleEvent("CheckMerge", CheckMerge, this);
    handleEvent("BuildCompound", BuildCompound, this);
    handleEvent("SetCurrentTime", SetCurrentTime, this);  
    handleEvent("getRoundedDate", getRoundedDate, this);  
    CString tMinVar, tMaxVar;
    tMinVar.format("plotter:tMin(%s)",getTkName());
    tMaxVar.format("plotter:tMax(%s)",getTkName());
    linkTkVar(tMinVar, tMin.getValAddr());
    linkTkVar(tMaxVar, tMax.getValAddr());
}

CString TkTimeCurvePlotter::printObjects (TkPlotterViewModes format,
					  const char* fileName,
					  const char *footer)
{
    CString errmsg;
    PSTimeCurveFrame *psframe = new PSTimeCurveFrame("no_title",
						     footer,
						     fileName,
						     this,
						     errmsg,
						     format);
    delete psframe;
    return errmsg;
}

void TkTimeCurvePlotter::timeUpdate (ITime t)

{
    STDisplayObjectIterator it(allObjectGList);
    STDisplayTimeCurveObject *dtco;
    ITime newt, dtcot;

    while((dtco = (STDisplayTimeCurveObject *)it.next()) != NULL)
	{
	dtcot = dtco->whatIsYourTime(t, 1);

	if (dtcot > newt)
	    newt = dtcot;
	}

    if (newt > tCur)
	{
	tCur = newt;


	double ftCur;

	if (tCur > tMax && okXTranslate)
	    {
	    if (okXAdjust) 
		{
		compact();
		} else {
		ITime dt = (tMax - tMin) / 2.0;
		double n = ((tCur - tMax) / dt) + 1;
		setXBounds(tMin + n * dt, tMax + (double)n * dt);
		}
	    
	    setPixXMax(pixXMax);
	    ftCur = (double)tCur;

	    TclList allPoints;
	    TclList points;

	    it.reset();

	    while ((dtco = (STDisplayTimeCurveObject *)it.next()) != NULL)
		{
		points.clear();
		dtco -> getPointsToDisplay(&points);
		if(points.length())
		    {
		    allPoints.append(dtco->getTkName());
		    allPoints.append(points);
		    }
		}

	    callTkProc("plotter:updateTime", "&G &L", &ftCur, &allPoints);
	    }
	else if (tCur > tMin && tCur < tMax)
	    {
	    ftCur = (double)tCur;
	    callTkProc("plotter:updateTime", "&G", &ftCur);
	    
	    int x = (int)((double)(tCur -tMin) * xScale + 0.5);

	    it.reset();

	    while ((dtco = (STDisplayTimeCurveObject *)it.next()) != NULL)
		{
		if (dtco->getNPointDisplayed() > 0)
		    dtco->displayUpdate(x);
		}
	    }
	}
}

ITime TkTimeCurvePlotter::getTimeValue(int deltaX)
{
    double tdrag = double(tMin) + 
	deltaX * (double(tMax - tMin) / double(pixXMax));

    ITime td(tdrag);
    return td;
}

ETime TkTimeCurvePlotter::getTimeValueWithUnit(int deltaX)
{
    ITime td = getTimeValue(deltaX);
  
    return addUnitToTime(td);;
}

ETime TkTimeCurvePlotter::addUnitToTime(ITime td)
{
    return ETime(decRounding2((double)ETime(td, timeUnit), 1), timeUnit);  
}

void TkTimeCurvePlotter::getProperties(TclList* list)
{
    /* property list for a TkTimeCurvePlotter:
       0- the title
       1- time graph container flag
       2- empty slot!
       3- tCur
       4- the smallest significant time
       5- a list of the names of the units
       6- the index of the default unit
    */

    TkCurvePlotter::getProperties(list);
    list->append("time");
    list->append("empty");
    list->append((double) tCur);

    list->append(ITime(ETime(1, timeUnit)));
	
    TclList units;
    if(timeUnit != TCalendar)
	{
	units.append(TimeString[USec]);
	units.append(TimeString[MSec]);
	units.append(TimeString[Sec]);
	}
    list->append(units);
    if(timeUnit != TCalendar)
	{
	list->append((int)timeUnit - (int)USec);
	} else {
	list->append(0);
	}
}


void TkTimeCurvePlotter::notify(TkEvent event, int argc, char *argv[], TkClientData clientData)
{
    switch(event)
	{
	case getRoundedDate:
	    {
	    ETime t = addUnitToTime(ITime(atof(argv[1])));
	    setTkResult("&S", t.format(""));
	    break;
	    }
	case SetCurrentTime:
	    { 
	    tCur = pframe->getCurrentTime();
	    ITime dt = (tMax - tMin) / 2.0;
	    double n = ((tCur - tMax) / dt) + 1;
	    setXBounds(tMin + n * dt, tMax + (double)n * dt);
	    setTkResult("&G", &tCur);
	    break;
	    }
	case CheckMerge:
	    {
	    if (!mergeFrom || !mergeTo)
		{
		setTkResult("&D", 0);
		return;
		}
	    if (mergeFrom->getMyType() != CompoundObj && mergeTo->getMyType() != CompoundObj)
		{
		if (mergeFrom->getMyType() != mergeTo->getMyType())
		    {
		    setTkResult("&D", 0);
		    return;
		    }
		if(!mergeTo->checkYBounds(mergeFrom))
		    {
		    setTkResult("&D", 0);
		    return;
		    }
		}
	    if (mergeFrom->getMyType() != CompoundObj && mergeTo->getMyType() != CompoundObj)
		{
		setTkResult("&D", 1);
		} 
	    else if (mergeFrom->getMyType() == CompoundObj)
		{
		DisplayObjectType type;
		if (mergeTo->getMyType() == CompoundObj) 
		    type = ((STimeCompoundObject*)mergeTo)->getDataType();
		else 
		    type = mergeTo->getMyType();
		if (type != ((STimeCompoundObject*)mergeFrom)->getDataType())
		    {
		    setTkResult("&D", 0);
		    return;
		    }
		if(!mergeFrom->checkYBounds(mergeTo))
		    {
		    setTkResult("&D", 0);
		    return;
		    }
		setTkResult("&D", -1);
		}
	    else if (mergeTo->getMyType() == CompoundObj)
		{
		if ( mergeFrom->getMyType() != ((STimeCompoundObject*)mergeTo)->getDataType())
		    {
		    setTkResult("&D", 0);
		    return;
		    }
		if(!mergeTo->checkYBounds(mergeFrom))
		    {
		    setTkResult("&D", 0);
		    return;
		    }
		setTkResult("&D", -1);
		}
	    break;
	    }
	case DoMerge:
	    {
	    if (mergeFrom->getMyType() != CompoundObj && mergeTo->getMyType() != CompoundObj)
		{
		STimeCompoundObject* cmpd = new STimeCompoundObject(this);
		cmpd -> addObject(mergeFrom);
		cmpd -> addObject(mergeTo);
		setTkResult("&C", cmpd);
		} 
	    else if (mergeTo->getMyType() == CompoundObj)
		{
		((STimeCompoundObject*)mergeTo) -> addObject(mergeFrom);
		setTkResult("&C", mergeTo);
		}
	    else if (mergeFrom->getMyType() == CompoundObj)
		{
		((STimeCompoundObject*)mergeFrom) -> addObject(mergeTo);
		setTkResult("&C", mergeFrom);
		}
	    break;
	    }
	case BuildCompound:
	    {
	    STimeCompoundObject* cmpd = new STimeCompoundObject(this);
	    setTkResult("&C", cmpd);
	    break;
	    }
	case GetConf:
	    {
	    TclList conf;
	    conf.append(okXAdjust);
	    setTkResult("&L", &conf);
	    break;
	    }
	case SetConf:
	    {
	    setXAdjust(atoi(argv[1]));
	    break;
	    }
	case Compress:
	    {
	    compact();
	    break;
	    }
	case UnCompress:
	    {
	    uncompact();
	    break;
	    }
	case GetXAxisInfo:
	    {
	    TclList axis;
	    CString tbound = ETime(tMin,timeUnit).format("");
	    axis.append(tbound);
	    tbound = ETime(tMax,timeUnit).format(""); // Display the max time on the bar
	    axis.append(tbound);
	    setTkResult("&L", &axis);
	    break;
	    }
	case SetTimeBounds:
	    {
	    if (argc != 3) {
	    return;
	    }
	    TclList realTimes;
	    ITime newtMin = (ITime) atof(argv[1]),
		newtMax = (ITime) atof(argv[2]);
	    // FIXME: rounding must be done here
	    newtMin = floor((double) newtMin);
	    newtMax = floor((double) newtMax);
	    if (newtMin < newtMax)
		setXBounds(newtMin, newtMax);

	    ITime dt = (tMax - tMin) / 2.0;
	    double n;
	    if(tCur >= tMax)
		n = ((tCur - tMax) / dt) + 1;
	    else 
		n = 0;
	    realTimes.append(tMax + (double)n * dt);

	    setTkResult("&L", &realTimes);
	    break;
	    } 
	default:
	    TkCurvePlotter::notify(event, argc, argv, clientData);
	    break;
	}
}
 
void TkTimeCurvePlotter::setXBounds (ITime tl, ITime tr)

{
    if (tl >= tr)
	statError("TkTimeCurvePlotter::setXBounds() - inconsistent time bounds");

    ITime dt = tr - tl;

    if (!okInfiniteTimeLimit && dt > tAll)
	{
	tr = dt = tAll;
	tl = ZEROTIME;
	}
    else if (tl > tCur)
	{
	tr = tCur + dt;
	tl = tCur;
	}

    if (!okInfiniteTimeLimit && tr > tAll)
	{
	tr = tAll;
	tl = tr  - dt;
	}
    else if (tl < ZEROTIME)
	{
	tl = ZEROTIME;
	tr = tl + dt;
	}

    tMin = tl;
    tMax = tr;

    setXScale();

    STDisplayObjectIterator it(allObjectGList);
    STDisplayObject *displayObject;

    while ((displayObject = it.next()) != NULL)
	((STDisplayCurveObject *)displayObject)->setXBounds(tMin,tMax);
}

void TkTimeCurvePlotter::setPixXMax (int pixxm)

{
    ITime tmaxupd;

    if (pixxm >= pixXMax)
	{	// window enlarged...
	pixXMax = pixxm;

	if (okXScale)
	    {
	    tMax = tMin + ITime(double(pixXMax) / xScale); // a xScale constant

	    if (!okInfiniteTimeLimit && tMax > tAll)
		tMax = tAll;
	    }

	int ndtmin = pixXMax / STDISPLAY_FRAME_PIXXBYDT;

	if (ndtmin > nMaxPointDisplayed)
	    ndtmin = nMaxPointDisplayed;

	if (okXScale)
	    {
	    tmaxupd = tMin + dtUpdateMin * (double)ndtmin;

	    if ((tmaxupd < tMax) && okXAdjust )
		tMax = tmaxupd;
	    }
	}
    else
	{			// window shrinked...
	pixXMax = Max(pixxm,STDISPLAY_FRAME_PIXXMIN);

	if (okXScale)
	    {
	    tmaxupd = ITime(double(pixXMax)/xScale);
	    tMax = tMin + tmaxupd;
	    }
	}

    setAllPixXMax(pixXMax);
    setXBounds(tMin,tMax);
}

void TkTimeCurvePlotter::setXScale ()

{ xScale = double(pixXMax) / (double(tMax - tMin)); }

void TkTimeCurvePlotter::setXScale (double xscale)

{
    xScale = xscale;
    okXScale = 1;
}

void TkTimeCurvePlotter::setPixYMax (int pixym)

{ pixYMax = Max(pixym,STDISPLAY_FRAME_PIXYMIN); }

void TkTimeCurvePlotter::findDtUpdateMin ()

{
    if (okInfiniteTimeLimit)
	dtUpdateMin = tCur / (double)nMaxPointDisplayed;
    else
	dtUpdateMin = tAll / (double)nMaxPointDisplayed;

    STDisplayObjectIterator it(allObjectGList);
    STDisplayTimeCurveObject *tco;

    while ((tco = (STDisplayTimeCurveObject *)it.next()) != NULL)
	{
	if (dtUpdateMin > tco->getDtUpdate())
	    dtUpdateMin = tco->getDtUpdate();
	}
}

void TkTimeCurvePlotter::compact()
{
    lastDt = tMax - tMin;

    if (okInfiniteTimeLimit)
	{
	findTOldest();
	tMin = tOldest;
	tMax = tCur + (tCur - tOldest) * 0.2;
	}
    else
	{
	if (lastDt > tAll)
	    lastDt = tAll;

	tMin = ZEROTIME;
	tMax  = tAll;
	}

    setXScale();
}

void TkTimeCurvePlotter::uncompact ()
{
    tMin = tCur - (lastDt/2.0);
    tMax = tCur + (lastDt/2.0);

    if (tMin < ZEROTIME)
	{
	tMin = ZEROTIME;
	tMax = lastDt;
	}
    else if (!okInfiniteTimeLimit && tMax > tAll)
	{
	tMax = tAll;
	tMin = tMax - lastDt;
	}

    setXScale();
}


void TkTimeCurvePlotter::findTOldest ()

{
    STDisplayObjectIterator it(allObjectGList);
    STDisplayTimeCurveObject *tco;
    ITime tinf;

    tOldest = tCur;

    while ((tco = (STDisplayTimeCurveObject *)it.next()) != NULL)
	{
	tinf = tco->getTOldest();

	if (tOldest > tinf)
	    tOldest = tinf;
	}
}

void TkTimeCurvePlotter::setXAdjust (int ok)

{
    if (okXAdjust || !ok)
	{
	okXAdjust = ok;
	return;
	}

    okXAdjust = ok;
    findDtUpdateMin();
    setPixXMax(pixXMax);
}


STDisplayObject *TkTimeCurvePlotter::acceptObject (const MvmInterfaceExportMsg *gpex)

{
    if (gpex->type == MVM_IFACE_TIMEGRAPH_ID)
	{
	MvmTimeGraphDisplay *timeGraphDisplay =
	    new MvmTimeGraphDisplay((MvmTimeGraphExportMsg *)gpex,
				    this,
				    pframe);
	return timeGraphDisplay;
	}
    else if (gpex->type == MVM_IFACE_SDIAGRAM_ID)
	{
	MvmStateDiagramDisplay *stateDiagramDisplay =
	    new MvmStateDiagramDisplay((MvmStateDiagramExportMsg *)gpex,
				       this,
				       STDISPLAY_SDIAGRAM_LOGSZ,
				       pframe);
	return stateDiagramDisplay;
	}

    return 0;
}


// TkGraphPlotter

TkGraphPlotter::TkGraphPlotter (const char *_title,
				TkPlotterFrame *_pframe,
				const TkPlotterSettings& _settings,
				TkContext* _master,
				int _logSize,
				ITime _tAll)
    : TkTimeCurvePlotter(_title,
			 _pframe,
			 _settings,
			 _master,
			 _logSize,
			 _tAll)
{}

void TkGraphPlotter::getProperties(TclList* list)
{
    TkTimeCurvePlotter::getProperties(list);
}

void TkGraphPlotter::notify(TkEvent event,
			    int argc,
			    char *argv[],
			    TkClientData clientData)
{
    TkTimeCurvePlotter::notify(event, argc, argv, clientData);
}

STDisplayObject *TkGraphPlotter::acceptObject (const MvmInterfaceExportMsg *gpex)

{
    if (gpex->type == MVM_IFACE_TIMEGRAPH_ID) // constraint object acceptance to TGraphs only
	return TkTimeCurvePlotter::acceptObject(gpex);

    return 0;
}

// TkStatePlotter

TkStatePlotter::TkStatePlotter (const char *_title,
				TkPlotterFrame *_pframe,
				const TkPlotterSettings& _settings,
				TkContext* _master,
				int _logSize,
				ITime _tAll)
    : TkTimeCurvePlotter(_title,
			 _pframe,
			 _settings,_master,
			 _logSize,
			 _tAll)
{}

void TkStatePlotter::notify(TkEvent event, int argc, char *argv[], TkClientData clientData)
{
    TkTimeCurvePlotter::notify(event, argc, argv, clientData);
}

void TkStatePlotter::getProperties(TclList* list)
{
    TkTimeCurvePlotter::getProperties(list);
}


STDisplayObject *TkStatePlotter::acceptObject (const MvmInterfaceExportMsg *gpex)

{
    if (gpex->type == MVM_IFACE_SDIAGRAM_ID) // constraint object acceptance to StateDiagrams only
	return TkTimeCurvePlotter::acceptObject(gpex);

    return 0;
}

// TkHistoPlotter

TkHistoPlotter::TkHistoPlotter (const char *_title,
				TkPlotterFrame *_pframe,
				const TkPlotterSettings& _settings,
				TkContext* _master,
				int _logSize)
    : TkCurvePlotter(_title,
		     _pframe,
		     _settings,
		     _master,
		     _logSize)
{
}

CString TkHistoPlotter::printObjects (TkPlotterViewModes format,
				      const char* fileName,
				      const char *footer)
{
    CString errmsg;
    PSCurveFrame *psframe = new PSCurveFrame("no_title",
					     footer,
					     fileName,
					     this,
					     errmsg,
					     format);
    delete psframe;
    return errmsg;
}

void TkHistoPlotter::getProperties(TclList* list)
{
    TkCurvePlotter::getProperties(list);
    list->append("histo");
}

void TkHistoPlotter::notify(TkEvent event,
			    int argc,
			    char *argv[],
			    TkClientData clientData)
{
    TkCurvePlotter::notify(event, argc, argv, clientData);
}

STDisplayObject *TkHistoPlotter::acceptObject (const MvmInterfaceExportMsg *gpex)

{
    if (gpex->type == MVM_IFACE_HISTOGRAM_ID)
	{
	MvmHistogramDisplay *histogramDisplay =
	    new MvmHistogramDisplay((MvmHistogramExportMsg *)gpex,this,pframe);
	return histogramDisplay;
	}

    return 0;
}

void TkHistoPlotter::updateStatistics ()

{
}
