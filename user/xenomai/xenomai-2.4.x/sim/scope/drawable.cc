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
 * Contributor(s): chris, gt, rpm
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifdef __GNUG__
#pragma implementation
#endif // __GNUG__
#include <xeno_config.h>
#include <stdlib.h>
#include "drawable.h"
#include "plotter.h"
#include "postscript.h"

static double XIntersect(int y, STDisplayPixelPoint p0, STDisplayPixelPoint p1)

{
    double x;

    if (p1.y != p0.y)
	{
	x = (p1.x-p0.x)*y + (p1.y*p0.x - p1.x*p0.y);
	x /= (p1.y - p0.y);
	}
    else
	x = p1.x;

    return x;
}

static int YIntersect(int x, STDisplayPixelPoint p0, STDisplayPixelPoint p1)

{
    double y;

    if (p1.x != p0.x)
	{
	y = (p1.y-p0.y)*x + (p1.x*p0.y - p1.y*p0.x);
	y /= (p1.x - p0.x);
	}
    else
	y = p1.y;

    return (int)y;
}

// Basic display objects

STDisplayObject::STDisplayObject (TkPlotter *_plotter)
    :TkContext(_plotter)
{
    plotter = _plotter;
    plotter->allObjectGList.append(this);
    handleEvent("GetProperties", GetProperties, this);
    handleEvent("GetConf", GetConf, this);
    handleEvent("SetConf", SetConf, this);
    handleEvent("SetPrintMe", SetPrintMe, this);
    handleEvent("ResetPrintMe", SetPrintMe, this);
    roundedXMax = 0;
    CString rxmaxVar;
    rxmaxVar.format("plotter:roundedXMax(%s)",getTkName());
    linkTkVar(rxmaxVar, &roundedXMax);
    printMe = 0;
    xtop = ytop = 0;
}

void STDisplayObject::pointDisplayForPrint(PSCurve*) {}

void STDisplayObject::yaxisPrint(PSCurve*) {}

void STDisplayObject::psPrint (FILE *) {}

STDisplayObject* STDisplayObject::psCopy (TkPlotter *)

{ return NULL; }

void STDisplayObject::psYStrings (CStringList *) {}


STDisplayObject::~STDisplayObject ()

{ 
    callTkProc("plotter:unSetHierarchy", "&C", (TkContext*)plotter);
    plotter->allObjectGList.remove(this); 
}

void STDisplayObject::getProperties(TclList* list)
{
    /* property list for a STDisplayObject
       0- a list containing the title and the group
    */
    list->append(proto->ifGetName());
}


void STDisplayObject::notify(TkEvent event,
			     int argc,
			     char *argv[],
			     TkClientData clientData)
{
    switch(event)
	{
	case GetConf: 
	    {
	    TclList conf;
	    getConf(&conf);
	    setTkResult("&L", &conf);	
	    break;
	    }
	case SetConf:
	    {
	    setConf(argc, argv);
	    break;
	    }
	case GetProperties:
	    {
	    TclList properties;
	    getProperties(&properties);
	    setTkResult("&L", &properties);	
	    break;
	    }
	case SetPrintMe:
	    {
	    printMe = 1;
	    break;
	    }
	case ResetPrintMe:
	    {
	    printMe = 0;
	    break;
	    }
	}
}

void STDisplayObject::display (TclList*) {}

void STDisplayObject::setPixXMax (int pixxm)

{ 
    pixXMax = pixxm; 
    roundedXMax = pixXMax;
}

void STDisplayObject::setPixYMax (int pixym)

{ pixYMax = pixym; }

void STDisplayObject::scale () {}

CString STDisplayObject::makeYStr (double, int, double) { return CString("?"); }

double STDisplayObject::getY (int) { return 0.0; }

// STDisplayCurveObject

STDisplayCurveObject::STDisplayCurveObject (TkCurvePlotter *_plotter)
    : STDisplayObject(_plotter)
{
    nMaxPointDisplayed = _plotter->getNMaxPointDisplayed();
    okYAdjust = 1;
    points = new STDisplayPixelPoint[nMaxPointDisplayed + 1];
    nPointDisplayed = 0;
    yMin = infinity();
    yMax = -infinity();
    xMin = xMax = 0.0;
    yScale = 0.0;
    isMapped = 0;
    isDisplayed = 0;

    setPixXMax(0);
    setPixYMax(0);
    setXScale();

    handleEvent("GetPointsToDisplay", GetPointsToDisplay, this);
    handleEvent("GetYAxisInfo", GetYAxisInfo, this);
    handleEvent("GetXYValues", GetXYValues, this);
    handleEvent("GetXYValuesString", GetXYValuesString, this);
    handleEvent("FromXYValuesToPix", FromXYValuesToPix, this);
    handleEvent("ProtoSetDisplay", ProtoSetDisplay, this);
    handleEvent("ForceSetDisplay", ForceSetDisplay, this);
    handleEvent("FakeSetDisplay", FakeSetDisplay, this);
    handleEvent("ProtoSetConceal", ProtoSetConceal, this);
    handleEvent("ProtoSetTempConceal", ProtoSetTempConceal, this);
    handleEvent("getYBounds", getYBounds, this);
  
    char *ismapped;
    int size = strlen("plotter:isMapped()") + strlen(getTkName()) + 1;
    ismapped = (char*) malloc(size);

    sprintf(ismapped, "plotter:isMapped(%s)", getTkName());
    linkTkVar(ismapped, &isMapped);
    free(ismapped);
}

//used for postScript display
STDisplayCurveObject::STDisplayCurveObject(STDisplayCurveObject* dco,
					   TkCurvePlotter *_plotter)
    : STDisplayObject(_plotter)
{
    yMin = dco->yMin ;
    yMax = dco->yMax ;
    xMin = dco->xMin ;
    xMax = dco->xMax ;

    setPixXMax (dco->getPixXMax()) ;
    setPixYMax (dco->getPixYMax()) ;
    nMaxPointDisplayed = dco->nMaxPointDisplayed;
    nPointDisplayed = dco->nPointDisplayed ;  okYAdjust = 1;
    if (nMaxPointDisplayed)
	points = new STDisplayPixelPoint[nMaxPointDisplayed + 1];
    else
	points = 0;
    yScale = 0.0;
    pixYMin = STDISPLAY_CURVE_PIXYMIN;
    printMe = dco->printMe;
}

void STDisplayCurveObject::getProperties(TclList *list)
{
    STDisplayObject::getProperties(list);
}

void STDisplayCurveObject::notify(TkEvent event,
				  int argc,
				  char *argv[],
				  TkClientData clientData)
{
    switch(event)
	{    
	case GetPointsToDisplay:
	    {
	    if (argc == 5)
		{
		plotter->setPixXMax(atoi(argv[1]));
		setPixYMax(atoi(argv[2]));
		setDisplayBounds(atoi(argv[4]), atoi(argv[3]));	                          

		TclList pointsToDisplay;
		getPointsToDisplay(&pointsToDisplay);
		setTkResult("&L", &pointsToDisplay);
		}
	    break;
	    }
	case ProtoSetDisplay:
	    isDisplayed = 1;
	case FakeSetDisplay:
	    {
	    proto -> ifDisplay();
	    break;
	    }
	case ProtoSetConceal:
	case ProtoSetTempConceal:
	    {
	    isDisplayed = 0;
	    proto -> ifConceal();
	    break;
	    }
	case getYBounds:
	    {
	    TclList res;
	    res.append(yMin);
	    res.append(yMax);
	    setTkResult("&L", &res);
	    break;
	    }
	default:
	    STDisplayObject::notify(event, argc, argv, clientData);
	    break;

	}

  
}

STDisplayCurveObject::~STDisplayCurveObject()

{ 
    if (points)
	delete[] points; 
}

void STDisplayCurveObject::setPixXMax(int pixxm)

{
    pixXMax = Max(STDISPLAY_CURVE_PIXXMIN,pixxm);
    setXScale();
    roundedXMax = pixXMax;
}

void STDisplayCurveObject::setXBounds (double xl, double xr)

{
    if (xl >= xr)
	statError("STDisplayCurveObject::setXBounds() - invalid argument(s): %d / %d",xl,xr);

    xMin = xl;
    xMax = xr;
    setXScale();
}

#define ROUND(a) ((a - floor(a) <= 0.5)?floor(a):ceil(a))

double STDisplayCurveObject::_pixX(double x)
{
    return (x - xMin) * xScale;
}

double STDisplayCurveObject::pixX(double x)
{
    double p = _pixX(x);
    if (p < 0) p = 0;
    else if (p > pixXMax) p = pixXMax;
    return p;
}

double STDisplayCurveObject::_pixX(double x, double oldx, double oldpix)
{
    double delta = (x - xMin) * xScale - (oldx - xMin) * xScale;
    return oldpix + floor(delta);
}

double STDisplayCurveObject::pixX(double x, double oldx, double oldpix)
{
    double p = _pixX(x, oldx, oldpix);
    if (p < 0) p = 0;
    else if (p > pixXMax) p = pixXMax;
    return p;
}

void STDisplayCurveObject::setPixYMax (int pixym)

{
    pixYMax = Max(pixym,STDISPLAY_CURVE_PIXYMIN);
    setYScale();
}

void STDisplayCurveObject::setYBounds (double ymin, double ymax,int setYBoundsDone)

{
    if (yMax != yMin && ymax == ymin)
	return;

    if ( ymin >= ymax)
	{
	yMin = yMax = ymax;
	yScale = infinity();
	}
    else
	{
	yMax = decRounding(ymax, 2);
	yMin = decRounding(ymin, 2);
	if (yMin > ymin)
	    yMin = decRounding(ymin - 1e-1, 2);
	setYScale();
	}
}

int STDisplayCurveObject::_pixY(double y)
{
    return ((int) ((y - yMin) * yScale + 0.5));
}

int STDisplayCurveObject::pixY(double y)
{
    int p = _pixY(y);
    if (p > pixYMax ) p = pixYMax;
    else if (p < 0) p = 0;
    return p;
}

int STDisplayCurveObject::getYAdjust()
{
    return okYAdjust;
}

void STDisplayCurveObject::setYAdjust(int ok)

{
    if (okYAdjust)
	{
	okYAdjust = ok;
	return;
	}

    if (!ok)
	return;

    okYAdjust = 1;
    setYBounds(yMin, yMax);
}

double STDisplayCurveObject::getXValue(int pixx)
{
    double x = xMin + (double) pixx * (xMax - xMin) / (double) pixXMax;
    return x;
}

double STDisplayCurveObject::getYValue(int pixy)
{
    double y = yMin + (double) pixy * (yMax - yMin) / (double) pixYMax;
    return y;
}

void STDisplayCurveObject::setXScale()
{ xScale = pixXMax / (xMax - xMin); }

void STDisplayCurveObject::setYScale()
{	yScale = pixYMax / (yMax - yMin); }

void STDisplayCurveObject::reDrawPlotWithPts(TclList *list)
{
    if(isMapped)
	callTkProc("plotter:reDrawPlotWithPts", "&L", list);
}

void STDisplayCurveObject::drawData (int okDrawYZero, TclList* list)

{
    for (int n = 0; n < nPointDisplayed; n++)
	pointDisplay(n, list);
}


// STDisplayTimeCurveObject

STDisplayTimeCurveObject::STDisplayTimeCurveObject(TkTimeCurvePlotter *_tplotter)
    : STDisplayCurveObject(_tplotter)
{
    dtUpdateMean = MAXITIME;
    timePlotter = _tplotter;
    xMin = timePlotter->tMin;
    xMax = timePlotter->tMax;

    contextForDrawing = this;

    isFirstProtoInitMsg = 1;
    handleEvent("SetYBounds", SetYBounds, this);
    handleEvent("GetBreakpointList", GetBreakpointList, this);
    handleEvent("SetBreakpoint", SetBreakpoint, this);
    handleEvent("ClearBreakpoint", ClearBreakpoint, this);
    handleEvent("SetMergeFrom", SetMergeFrom, this);
    handleEvent("SetMergeTo", SetMergeTo, this);
    handleEvent("getNextDate", getNextDate, this);
    handleEvent("getPrevDate", getPrevDate, this);
}

//used for postScript display
STDisplayTimeCurveObject::STDisplayTimeCurveObject(STDisplayTimeCurveObject* dtco,
						   TkTimeCurvePlotter *tplotter_p)
    : STDisplayCurveObject(dtco,tplotter_p)
{
    timePlotter = tplotter_p ;
}

void STDisplayTimeCurveObject::addToPlot(TclList *list, STDisplayTimeCurveObject* context)
{
    if(isMapped)
	callTkProc("plotter:addToPlot", "&L &C", list, (TkContext*) context);
}

void STDisplayTimeCurveObject::getProperties(TclList* list)
{
    STDisplayCurveObject::getProperties(list);
}


void STDisplayTimeCurveObject::getPointsToDisplay(TclList* pointsToDisplay, int check)
{
    if (isDisplayed || !check) {
    TclList sublist;
    scale();
    display(&sublist);
    pointsToDisplay->append(sublist);
    }
}

void STDisplayTimeCurveObject::notify(TkEvent event,
				      int argc,
				      char *argv[],
				      TkClientData clientData)
{
    switch(event)
	{
	case getNextDate:
	    {
	    int found;
	    ITime t = searchInLog(timePlotter->tMax, 1, &found);
	    double tval;
	    if (found)
		tval = (double) t;
	    else
		tval = -1;
	    setTkResult("&G", &tval);
	    break;
	    }
	case getPrevDate:
	    {
	    int found;
	    ITime t = searchInLog(timePlotter->tMin, -1, &found);
	    double tval;
	    if (found)
		tval = (double) t;
	    else
		tval = -1;
	    setTkResult("&G", &tval);
	    break;
	    }
	case SetMergeFrom:
	    {
	    timePlotter->doMergeFrom(this);
	    break;
	    }
	case SetMergeTo:
	    {
	    timePlotter->doMergeTo(this);
	    break;
	    }
	case SetYBounds:
	    {
	    double newyMin = atof(argv[1]),
		newyMax = atof(argv[2]);
	    TclList realY;
	    setYBounds(newyMin, newyMax);
	    // Rounding is done in setYBounds
	    realY.append(yMin);
	    realY.append(yMax);
	    setTkResult("&L", &realY);
	    break;
	    }
	case GetBreakpointList:
	    {
	    TclList bpts;
	
	    MvmInterfaceBreakPointList breakpts = getProto()->ifGetBPList();
	    for (MvmInterfaceBreakPoint *bp = (MvmInterfaceBreakPoint *)breakpts.first();
		 bp; bp = (MvmInterfaceBreakPoint *)bp->next())
		{
		bpts.append(bp->threshold);
		}
	    setTkResult("&L", &bpts);
	    break;
	    }
	case SetBreakpoint:
	    {
	    TclList bpts;
	    double threshold = atof(argv[1]);

	    getProto()->ifSetBreak(threshold);

	    MvmInterfaceBreakPointList breakpts = getProto()->ifGetBPList();
	    for (MvmInterfaceBreakPoint *bp = (MvmInterfaceBreakPoint *)breakpts.first();
		 bp; bp = (MvmInterfaceBreakPoint *)bp->next())
		{
		bpts.append(bp->threshold);
		}
	    setTkResult("&L", &bpts);
	    break;
	    }
	case ClearBreakpoint:
	    {
	    TclList bpts;
	    double threshold = atof(argv[1]);

	    getProto()->ifClrBreak(threshold);

	    MvmInterfaceBreakPointList breakpts = getProto()->ifGetBPList();
	    for (MvmInterfaceBreakPoint *bp = (MvmInterfaceBreakPoint *)breakpts.first();
		 bp; bp = (MvmInterfaceBreakPoint *)bp->next())
		{
		bpts.append(bp->threshold);
		}
	    setTkResult("&L", &bpts);
	    break;
	    }
	case ProtoSetDisplay:
	case FakeSetDisplay:
	    setContextForDrawing(this);
	default:
	    STDisplayCurveObject::notify(event, argc, argv, clientData);
	    break;

	}

  
}

ITime STDisplayTimeCurveObject::getDtUpdate()
{	return dtUpdateMean; }

ITime STDisplayTimeCurveObject::getTOldest()

{	return MAXITIME; }

ITime STDisplayTimeCurveObject::getCurrentTime ()

{ return timePlotter->getCurrentTime(); }
	
// MvmTimeGraphDisplay

MvmTimeGraphDisplay::MvmTimeGraphDisplay (MvmTimeGraphExportMsg *_exmsg,
					  TkTimeCurvePlotter *_tplotter,
					  MvmFrontend *_connector)
    : MvmTimeGraph(_exmsg,_connector),
      STDisplayTimeCurveObject(_tplotter)
{
    dtDisplay = dtUpdateMean = dtUpdate;
    iLag = 1;
    sLag = 0.0;
    lastY = -1.0;

    okYAdjust = yAdjust;
    yMin = ( yTgMin < vMin ) ? yTgMin : vMin;
    yMax = ( yTgMax > vMax ) ? yTgMax : vMax;
    
    iNextPoint = (double) iCurr - 0.5;
    iMaxPoint = (timePlotter->okInfiniteTimeLimit) ?
	infinity() : timePlotter->tAll / dtUpdate;
    nVbyP = 1.0;
    
    iOld = iCurr - iLag + 1;
    int k = iOld < 0 ? 0 : iOld;

    while (k < iCurr)
	sLag += v[k++ % nvMax];

    if (dtUpdate < timePlotter->dtUpdateMin)
	{
	timePlotter->dtUpdateMin = dtUpdate;
	timePlotter->setPixXMax(timePlotter->pixXMax);
	}
  
    myType = TGraphObject;
    setProto(this);
 
    plotter->callTkProc("plotter:setHierarchy","&C", plotter->getTkMaster());
    callTkProc("plotter:setHierarchy", "&C", (TkContext*)plotter);
}

// used for postScript display
MvmTimeGraphDisplay::MvmTimeGraphDisplay (MvmTimeGraphDisplay* src,
					  TkTimeCurvePlotter *tplotter)
    : MvmTimeGraph(*src),STDisplayTimeCurveObject(src,tplotter)
{
    dtUpdateMean = src->dtUpdateMean;
    dtDisplay = src->dtDisplay;
    iLag = src->iLag;
    sLag = src->sLag;
    lastY = -1.0;

    iNextPoint = (double) iCurr - 0.5;
    iMaxPoint = (timePlotter->okInfiniteTimeLimit) ? infinity() : timePlotter->tAll / dtUpdate;

    nVbyP = 1.0;
    iOld = iCurr - iLag + 1;
    myType = TGraphObject;
}


void MvmTimeGraphDisplay::pointDisplayForPrint(PSCurve* curve)
{
    if (nPointDisplayed > 0)
	curve->directStart((int)points[0].x,(int)points[0].y);

    for(int i=1; i < nPointDisplayed; i++) 
	{
	int x0 = (int)points[i - 1].x;
	int y0 = (int)points[i - 1].y;
	int x1 = (int)points[i].x;
	int y1 = (int)points[i].y;

	if (y0 <= pixYMax && y1 > pixYMax)
	    {
	    x1 = (int)XIntersect(pixYMax,points[i - 1],points[i]);
	    y1 = pixYMax;
	    }
	
	if (y1 <= pixYMax && y0 > pixYMax)
	    {
	    x0 = (int)XIntersect(pixYMax,points[i - 1],points[i]);
	    y0 = pixYMax;
	    curve->directStart(x0,y0);
	    }
	
	if (y0 >= 0 && y1 < 0)
	    {
	    x1 = (int)XIntersect(0,points[i - 1],points[i]);
	    y1 = 0;
	    }
	
	if (y1>= 0 && y0 < 0)
	    {
	    x0 = (int)XIntersect(0,points[i - 1],points[i]);
	    y0 = 0;
	    curve->directStart(x0,y0);
	    }
	
	if (y0 >= 0 && y1 >= 0 && y0 <= pixYMax && y1 <= pixYMax)
	    curve->directPrint(x1,y1);
	}

}
void MvmTimeGraphDisplay::yaxisPrint(PSCurve* curve)
{
    curve->addYAxisDouble(yMin,"%0.4g");
    if (vMin < 0) curve->addYAxisDouble(0.0,"%0.4g");
    curve->addYAxisDouble(yMax,"%0.4g");
}

void MvmTimeGraphDisplay::psPrint(FILE *fp)

{
    PSCurve curve(fp);
    int smoothing = 0;
    double tcur, tmin, tmax;

    timePlotter->getTimeBounds(tmin,tmax);
    tcur = timePlotter->getCurrentTime();
    curve.setCaract(getPixXMax(),getPixYMax(),tmin,tmax,yMin,yMax);

    curve.addXAxisString(tmin,ETime(tmin,USec).format());

    if (tcur < tmax)
	curve.addXAxisString(tcur,ETime(tcur,USec).format());

    curve.addXAxisString(tmax,ETime(tmax,USec).format());
    
    yaxisPrint(&curve);
    curve.beginPrint(ifGetName(),smoothing);
    scale();
    pointDisplayForPrint(&curve);
    curve.endPrint();
}

STDisplayObject* MvmTimeGraphDisplay::psCopy(TkPlotter *df_p)

{ return (STDisplayObject*)new MvmTimeGraphDisplay(this,(TkTimeCurvePlotter*)df_p); }

void MvmTimeGraphDisplay::psYStrings(CStringList *l)

{
    new LString(l,CString(vMin,"%0.4g"));

    if (vMin < 0)
	new LString(l,CString(0.0,"%0.4g"));

    new LString(l,CString(vMax,"%0.4g"));
}


#define MIN(a,b) a<b?a:b
#define MAX(a,b) a<b?b:a

void MvmTimeGraphDisplay::setYBounds (double ymin, double ymax, int setYBoundsDone)
{
    STDisplayCurveObject::setYBounds(ymin, ymax);

    if (contextForDrawing != this)
	{
	if(!setYBoundsDone)
	    contextForDrawing->setYBounds(contextForDrawing->getMinYBounds(), 
					  contextForDrawing->getMaxYBounds());
	}
}


ITime MvmTimeGraphDisplay::searchInLog(ITime t, int dir, int* found)
{
    if (iCurr == -1)
	{
	*found = 0;
	return t;
	}
    int imax = (iCurr > nvMax - 1)?iCurr-nvMax + 1:0;

    int ipoint;
    if (dir == 1) {
    if (t > tUpdate) {
    *found = 0;
    return t;
    }
    if (t < ZEROTIME) 
	ipoint = 0;
    else
	ipoint = (int) floor(t/dtUpdate) + 1;
  
    // check if this point is still in the log
    if (ipoint < imax)
	ipoint = imax;
    } else {
    if (t < ZEROTIME) {
    *found = 0;
    return t;
    }
    if (t > tUpdate) {
    *found = 1;
    return tUpdate;
    }
    
    ipoint = (int) floor(t/dtUpdate) - 1;
    if (ipoint < imax) {
    *found = 0;
    return t;
    }
    }
    *found = 1;
    return ITime(ipoint*dtUpdate);
}

void MvmTimeGraphDisplay::getConf(TclList* list)
{
    list->append(okYAdjust);
    list->append((double)ETime(getDtDisplay(),timePlotter->timeUnit)); 
}

void MvmTimeGraphDisplay::getProperties(TclList* list)
{
    /* property list for a MvmTimeGraphDisplay
       0- the properties of a STDisplayTimeCurveObject
       1- the fact that it used floating point values on the Y axis
       2- the fact it is a time graph
    */
  
    STDisplayTimeCurveObject::getProperties(list);
    list->append("float");
    list->append("time");
}

void MvmTimeGraphDisplay::setConf(int argc, char *argv[])
{
    okYAdjust = atoi(argv[1]);
    double t = atof(argv[2]);
    ETimeUnits xunit;
    ITime it;
    if(timePlotter->timeUnit != TCalendar)
	{
	if (argc > 3) 
	    xunit = (ETimeUnits)(atoi(argv[3]) + (int)USec);
	else
	    xunit = defaultETimeUnit;
	ETime et(t, xunit);
	it = ITime(et);
	} else
	    it = (double) t;
  
    ITime oldDtDisplay = dtDisplay; 
    setDtDisplay(it);
  
    if (dtDisplay != oldDtDisplay) 
	{
	TclList pointsToDisplay;
	getPointsToDisplay(&pointsToDisplay);
	contextForDrawing->reDrawPlotWithPts(&pointsToDisplay);
	}
}

ITime MvmTimeGraphDisplay::whatIsYourTime (ITime, int check)

{ return (isDisplayed||!check)?tUpdate:ZEROTIME; }

void MvmTimeGraphDisplay::notify(TkEvent event,
				 int argc,
				 char *argv[],
				 TkClientData clientData)
{
    switch(event)
	{
	case GetYAxisInfo:
	    {
	    TclList axis;
	    if (yMin < yMax) // don't draw yMin/yMax during the first display
		{
		CString symax, symin;
		symax = yMax;
		axis.append(symax);
		axis.append(ytop);
		symin = yMin;
		axis.append(symin);
		axis.append(ytop+ pixYMax - 1);
		}
	    setTkResult("&L", &axis);
	    break;
	    }
	case GetXYValuesString:
	    {
	    int deltaX = atoi(argv[1]);
	    int deltaY = atoi(argv[2]);

	    ETime td = timePlotter->getTimeValueWithUnit(deltaX);
	
	    double yVal = getY(deltaY - 1);
	    TclList xyValues;
	    xyValues.append(td.format(""));
	    xyValues.append(yVal);
	    setTkResult("&L", &xyValues);
	    break;
	    }
	case GetXYValues:
	    {
	    int deltaX = atoi(argv[1]);
	    int deltaY = atoi(argv[2]);

	    ETime td =  timePlotter->getTimeValueWithUnit(deltaX);
	
	    double yVal = getY(deltaY - 1);
	    TclList xyValues;
	    xyValues.append((double)td);
	    xyValues.append(yVal);
	    setTkResult("&L", &xyValues);
	    break;
	    }
	case FromXYValuesToPix:
	    {
	    double t = atof(argv[1]);
	    double yval = atof(argv[2]);
	    int xbounded = atoi(argv[3]), 
		ybounded = atoi(argv[4]);;
		
	    ETimeUnits xunit;
	    ITime it;

	    if(timePlotter->timeUnit != TCalendar)
		{
		if(argc > 5) // use the default unit if none is given
		    xunit = (ETimeUnits)(atoi(argv[5]) + (int)USec);
		else 
		    xunit = timePlotter->timeUnit;
		ETime et(t, xunit);
		it = ITime(et);
		} else
		    it = (double) t;

	    TclList pix;
	    int x, y;
	    if(xbounded)
		{
		if(it < ZEROTIME)
		    it = 0;
		if (it > timePlotter -> tCur)
		    it = timePlotter -> tCur;
		}
	  
	    if (it < timePlotter-> tMin)
		x = 0;
	    else if (it > timePlotter -> tMax)
		x = pixXMax;
	    else 
		x = (int)ceil(((double(it) - double(timePlotter -> tMin)) * double(pixXMax)) / 
			      double(timePlotter -> tMax - timePlotter -> tMin)); //FIXME: ceil, floor?
	
	    pix.append(x);

	    if(ybounded) 
		{
		if (yval > vMax) 
		    yval = vMax;
		if (yval < vMin) 
		    yval = vMin;
		}

	    if (yval < yMin)
		y = 0;
	    else if (yval > yMax)
		y = pixYMax;
	    else
		y = (int)floor((yval - yMin) / (yMax - yMin) * pixYMax);
	    
	    pix.append(y);

	    ETime et(it, timePlotter->timeUnit);
	    pix.append((double)et);
	    pix.append(yval);
	    setTkResult("&L", &pix);
	    break;
	    }
	default:
	    STDisplayTimeCurveObject::notify(event, argc, argv, clientData);
	    break;
	}
}

void MvmTimeGraphDisplay::ifProcess (int mtype, const struct MvmInterfaceMsg *gpm, int msize)

{
    if (mtype == MVM_IFACE_TIMEGRAPH_INIT)
	{
	if (isFirstProtoInitMsg)
	    {
	    iCurr = -1;
	    isFirstProtoInitMsg = 0;
	    }
	MvmTimeGraphInit *imsg = (MvmTimeGraphInit *)gpm;
	int npoints = imsg->pointNr < 0 ? -imsg->pointNr : imsg->pointNr;
	initPoint(imsg->pointTab,npoints,imsg->time,imsg->pointNr < 0);
	}
    else if (mtype == MVM_IFACE_TIMEGRAPH_POINT)
	{
	MvmTimeGraphPointMsg *pmsg = (MvmTimeGraphPointMsg *)gpm;

	addPoint(pmsg,msize / sizeof(MvmTimeGraphPointMsg));
	}
}

void MvmTimeGraphDisplay::add (double y)

{
    tUpdate += dtUpdate;

    int i = ++iCurr % nvMax;
    v[i] = y;

    okHasChanged = 0;

    if (y > vMax)
	{
	vMax = y;
	okHasChanged = 1;
	}

    if (y < vMin)
	{
	vMin = y;
	okHasChanged = 1;
	}
}

void MvmTimeGraphDisplay::initPoint (double *tab, int nr, ITime t0, int done)

{

    tUpdate = t0 - dtUpdate;
    iCurr = (int) (t0 / dtUpdate) - 1;

    for (int i = 0; i < nr; i++)
	add(tab[i]);

    if (done) {
    if (tUpdate > timePlotter->tCur)
	timePlotter->timeUpdate(tUpdate);
      
    setYBounds(vMin, vMax);
    TclList pointsToDisplay;
    getPointsToDisplay(&pointsToDisplay,0);
    contextForDrawing->reDrawPlotWithPts(&pointsToDisplay);
    isFirstProtoInitMsg = 1;
    }
}

void MvmTimeGraphDisplay::addPoint(MvmTimeGraphPointMsg  *mtab, int mcount)
{
    if ((mtab+mcount-1)->y != lastY)
	lastY = (mtab+mcount-1)->y;

    TclList pointsToDisplay;

    pointsToDisplay.clear();
    double yy;
    if (dtUpdate*(double)(iCurr + mcount) < timePlotter -> tMax 
	&& nPointDisplayed + 2*mcount <= nMaxPointDisplayed)
	{
	okHasChanged = 0;
	for (int i = 0; i < mcount; i++)
	    {
	    yy = (mtab+i)->y;
	    tUpdate += dtUpdate;
	    v[++iCurr % nvMax] = yy;

	    sLag += yy;
	    if (iOld >= 0)
		sLag -= v[iOld%nvMax];
	    iOld++;
	  
	    if (yy > vMax)
		{
		vMax = yy;
		okHasChanged = 1;
		}
	    if (yy < vMin)
		{
		vMin = yy;
		okHasChanged = 1;
		}

	    if ((!okHasChanged || !okYAdjust) && iCurr > iNextPoint)
		{
		double px = _pixX(dtUpdate*(double)iCurr);
		points[nPointDisplayed].x = px;
	      
		points[nPointDisplayed].y = _pixY(sLag/iLag);
	      
		if (nPointDisplayed > 0 && points[nPointDisplayed-1].x < 0)
		    {
		    int y = YIntersect(0,points[nPointDisplayed-1],points[nPointDisplayed]);
		    points[nPointDisplayed-1].y = y;
		    points[nPointDisplayed-1].x = 0;
		    }
		if (nPointDisplayed > 0 && points[nPointDisplayed].x > pixXMax && points[nPointDisplayed-1].x <= pixXMax)
		    {
		    int y = YIntersect(pixXMax,points[nPointDisplayed-1],points[nPointDisplayed]);
		    points[nPointDisplayed].y = y;
		    points[nPointDisplayed].x = pixXMax;
		    }
		iNextPoint += nVbyP;
	      
		if (points[nPointDisplayed].x >= 0 && points[nPointDisplayed].x <= pixXMax)
		    {
		    pointDisplay(nPointDisplayed, &pointsToDisplay);
		    }
	      
		nPointDisplayed++;
		}
	    }
	if (okHasChanged && okYAdjust)
	    {
	    setYBounds(vMin,vMax);	
	    TclList pointsToDisplay;
	    getPointsToDisplay(&pointsToDisplay);
	    contextForDrawing->reDrawPlotWithPts(&pointsToDisplay);
	    } else {
	    contextForDrawing->addToPlot(&pointsToDisplay, this);
	    }
	}  else {
	for (int i = 0; i < mcount; i++)
	    {
	    yy = (mtab+i)->y;
	    tUpdate += dtUpdate;
	    v[++iCurr % nvMax] = yy;
	    sLag += yy;
	    if (iOld >= 0)
		sLag -= v[iOld%nvMax];
	    iOld++;

	    if (yy > vMax)
		{
		vMax = yy;
		okHasChanged = 1;
		}
	    if (yy < vMin)
		{
		vMin = yy;
		okHasChanged = 1;
		}
	    }

	if (okHasChanged && okYAdjust)
	    setYBounds(vMin,vMax);	

	if (nPointDisplayed + 2*mcount > nMaxPointDisplayed &&
	    dtUpdate*(double)iCurr < timePlotter -> tMax)
	    {
	    getPointsToDisplay(&pointsToDisplay);
	    contextForDrawing->reDrawPlotWithPts(&pointsToDisplay);
	    pointsToDisplay.clear();
	    }

	}
}

void MvmTimeGraphDisplay::addPoint(double yy)
{
    add(yy);

    sLag += yy;
    if (iOld >= 0)
	sLag -= v[iOld%nvMax];
    iOld++;

    TclList pointsToDisplay;
    if (nPointDisplayed > nMaxPointDisplayed - 1)
	{
	scale();
	display(&pointsToDisplay);
	}
    else if ( iCurr > iNextPoint)
	{
	double px = _pixX(dtUpdate*(double)iCurr);
	points[nPointDisplayed].x = px;

	points[nPointDisplayed].y = _pixY(sLag/iLag);

	if (nPointDisplayed > 0 && points[nPointDisplayed-1].x < 0)
	    {
	    int y = YIntersect(0,points[nPointDisplayed-1],points[nPointDisplayed]);
	    points[nPointDisplayed-1].y = y;
	    points[nPointDisplayed-1].x = 0;
	    }
	if (nPointDisplayed > 0 && points[nPointDisplayed].x > pixXMax && points[nPointDisplayed-1].x <= pixXMax)
	    {
	    int y = YIntersect(pixXMax,points[nPointDisplayed-1],points[nPointDisplayed]);
	    points[nPointDisplayed].y = y;
	    points[nPointDisplayed].x = pixXMax;
	    }
	iNextPoint += nVbyP;

	if (points[nPointDisplayed].x >= 0 && points[nPointDisplayed].x <= pixXMax)
	    {
	    pointsToDisplay.clear();
	    pointDisplay(nPointDisplayed, &pointsToDisplay);
	    contextForDrawing->addToPlot(&pointsToDisplay, this);
	    }

	nPointDisplayed++;
	}

    if (okHasChanged) // vMin or vMax have changed
	{
	if (okYAdjust)
	    {
	    setYBounds(vMin,vMax);
	    TclList pointsToDisplay;
	    getPointsToDisplay(&pointsToDisplay);
	    contextForDrawing->reDrawPlotWithPts(&pointsToDisplay);
	    }
	}
}

	
void MvmTimeGraphDisplay::setDtDisplay (ITime dt)

{
    if (dt < dtUpdate)
	iLag = 1;
    else
	{
	int i = (int) ((dt / dtUpdate) + 0.5);

	if (i > (nvMax / 2))
	    iLag = nvMax / 2;
	else
	    iLag = i;
	}

    dtDisplay = dtUpdate * (double)iLag;

    TclList pointsToDisplay;
    getPointsToDisplay(&pointsToDisplay);
    contextForDrawing->reDrawPlotWithPts(&pointsToDisplay);
}


void MvmTimeGraphDisplay::scale()
{
    if (iCurr < 0) return;

    nPointDisplayed = 0;

    // calcul indice global du 1er point affiche

    int icur = (int)(timePlotter->tMin / dtUpdate);
    // si icur < iCurr-nvMax+iLag, alors il manque des points pour arriver a tMin
    // compte tenu des iLag points de lissage necessaires

    if (icur < iCurr - nvMax + iLag) icur = iCurr - nvMax + iLag;

    // tcur indique le temps courant pour le point calcule

    ITime tcur = dtUpdate * (double)icur;
    if ( tcur > timePlotter->tCur)
	return;

    nVbyP = (timePlotter->tMax - tcur) / (dtUpdate * (double)nMaxPointDisplayed);

    if (nVbyP < 1.0) nVbyP = 1.0; //	il n'y a pas de compaction

    iNextPoint = tcur / dtUpdate;
    iMaxPoint = (timePlotter->tCur > timePlotter->tMax) 
	? timePlotter->tMax / dtUpdate + 1
	: (double)iCurr;
    if (iMaxPoint > (double)iCurr) iMaxPoint = (double)iCurr;

    if (iMaxPoint < 0.0) iMaxPoint = 0.0;

    double iVal = iNextPoint;

    // on calcule la somme mobile de filtrage

    sLag = 0.0;
    iOld = icur - iLag;
    int k = iOld < 0 ? 0 : iOld;

    while (k<icur)
	sLag += v[k%nvMax], k++;

    while (iNextPoint <= iMaxPoint)
	{
	while (iVal <= iNextPoint)
	    {
	    sLag += v[icur%nvMax];
	    icur++;
	    if (iOld >= 0)
		sLag -= v[iOld%nvMax];
	    iOld++;
	    tcur += dtUpdate;
	    iVal += 1.0;
	    }
	points[nPointDisplayed].x = _pixX(tcur - dtUpdate);
	points[nPointDisplayed].y = _pixY(sLag/iLag);
	if (nPointDisplayed > 0 && points[nPointDisplayed-1].x < 0)
	    {
	    int y = YIntersect(0,points[nPointDisplayed-1],points[nPointDisplayed]);
	    points[nPointDisplayed-1].y = y;
	    points[nPointDisplayed-1].x = 0;
	    }
	if (nPointDisplayed > 0 && points[nPointDisplayed].x > pixXMax)
	    {
	    int y = YIntersect(pixXMax,points[nPointDisplayed-1],points[nPointDisplayed]);
	    points[nPointDisplayed].y = y;
	    points[nPointDisplayed].x = pixXMax;
	    }
	nPointDisplayed++;
	iNextPoint +=  nVbyP;
	}

    while (iVal <= iMaxPoint)
	{
	sLag += v[icur%nvMax];
	icur++;
	if (iOld >= 0)
	    sLag -= v[iOld%nvMax];
	iOld++;
	iVal += 1.0;
	}
}

ITime MvmTimeGraphDisplay::getDtUpdate()

{ return dtUpdate; }

ITime MvmTimeGraphDisplay::getTOldest ()

{
    ITime tinf = dtUpdate * (double)(iCurr - nvMax);
    return ( tinf < ZEROTIME ) ? ZEROTIME : tinf;
}

void MvmTimeGraphDisplay::display (TclList* list)

{
    drawData(1, list);
}

void MvmTimeGraphDisplay::pointDisplay (int pointNo, TclList* pointsToDisplay)

{
    if (contextForDrawing->getIsMapped() && pointNo > 0)
	{
	double y1 = points[pointNo].y;
	double x1 = points[pointNo].x;
	
	double y0 = points[pointNo - 1].y;
	double x0 = points[pointNo - 1].x;

	if (y1 <= getPixYMax() && y0 > getPixYMax())
	    {
	    x0 = XIntersect(getPixYMax(),points[pointNo - 1],points[pointNo]);
	    y0 = getPixYMax();
	    }
	
	if (y0 <= getPixYMax() && y1 > getPixYMax())
	    {
	    x1 = XIntersect(getPixYMax(),points[pointNo - 1],points[pointNo]);
	    y1 = getPixYMax();
	    }
	
	if (y1>= 0 && y0 < 0)
	    {
	    x0 = XIntersect(0,points[pointNo - 1],points[pointNo]);
	    y0 = 0;
	    }
	
	if (y0 >= 0 && y1 < 0)
	    {
	    x1 = XIntersect(0,points[pointNo - 1],points[pointNo]);
	    y1 = 0;
	    }

	if (y0 >= 0 && y1 >= 0 && y0 <= getPixYMax() && y1 <= getPixYMax())
	    {
	    // Change coordinates
	    x0 += xtop;
	    x1 += xtop;
	    y0 = ytop + getPixYMax() - y0 - 1;
	    y1 = ytop + getPixYMax() - y1 - 1;


	    pointsToDisplay->append(x0);
	    pointsToDisplay->append(y0);
	    pointsToDisplay->append(x1);
	    pointsToDisplay->append(y1);
	
	    }
	}
}

CString MvmTimeGraphDisplay::makeYStr (double tdrag, int pixy, double val)

{
    CString yStr;
    ITime td(tdrag);
    double yVal = getY(pixy);
    
    yStr = "(T=";
    yStr += ETime(td,plotter->getTimeUnit()).format("");
    yStr += ", Y=";
    yStr += CString(yVal,"%g");

    if (val != 0.0)
	{
	yStr += ", Val=";
	yStr += CString(val,"%g");
	}

    yStr += ")";
    
    return yStr;
}

double MvmTimeGraphDisplay::getY (int pixy)

{ return decRounding(getYValue(pixy),3); }

// MvmHistogramDisplay

MvmHistogramDisplay::MvmHistogramDisplay(MvmHistogramExportMsg *_exmsg,
					 TkCurvePlotter *_dcf,
					 MvmFrontend *_connector)
    : MvmHistogram(_exmsg,_connector),
      STDisplayCurveObject(_dcf)
{
    viewMode = GraphHistoREL;
    okXAdjust = 1;
    isStretched = 0;
    yMin = 0.0;
    binWidthDef = 20;
    handleEvent("HistoPolling", HistoPolling, this);
    handleEvent("GetXAxisHisto", GetXAxisHisto, this);
    handleEvent("SetHistoDisplay", SetHistoDisplay, this);
    handleEvent("SetHistoView", SetHistoView, this);
    handleEvent("GetBreakpointList", TKCONTEXT_NULL_EVENT, NULL);

    realPixXMax = pixXMax;
    setProto(this);

    plotter->callTkProc("plotter:setHierarchy","&C", plotter->getTkMaster());
    callTkProc("plotter:setHierarchy", "&C", (TkContext*)plotter);
}

//used for postScript display
MvmHistogramDisplay::MvmHistogramDisplay(MvmHistogramDisplay* src, TkCurvePlotter *dcf) :
    MvmHistogram(*src), STDisplayCurveObject(src,dcf)
{
    displayMode  = src->displayMode;
    viewMode = src->viewMode;
    okXAdjust = src->okXAdjust;
    binWidthDef = 80;
  
    nbInit = 0;
    nVal = src->nVal;
    tCur = src->tCur;
    isStretched = src->isStretched;
}

STDisplayObject* MvmHistogramDisplay::psCopy(TkPlotter *df_p)
{
    return (STDisplayObject*)new MvmHistogramDisplay(this,(TkCurvePlotter*)df_p) ;
}

void MvmHistogramDisplay::psYStrings (CStringList *l)

{
    new LString(l,CString(yMin,"%0.4g"));

    if (yMin < 0 && yMax > 0)
	new LString(l,CString(0.0,"%0.4g"));

    new LString(l,CString(yMax,"%0.4g"));
}

void MvmHistogramDisplay::pointDisplayForPrint(PSCurve* curve)
{
    if (nPointDisplayed > 0)
	curve->directStart((int)points[0].x,(int)points[0].y);
  
    for(int i=1; i < nPointDisplayed; i++) 
	curve->directPrint((int)points[i].x,(int)points[i].y);
}
void MvmHistogramDisplay::yaxisPrint (PSCurve* curve)
{
    curve->addYAxisDouble(yMin,"%0.4g");
    if (yMin < 0) curve->addYAxisDouble(0.0,"%0.4g");
    curve->addYAxisDouble(yMax,"%0.4g");
}

void MvmHistogramDisplay::psPrint (FILE *fp)

{
    int lissage = 0;

    PSCurve curve(fp);
    curve.setCaract(getPixXMax(),getPixYMax(),xMin,xMax,yMin,yMax);

    curve.addXAxisDouble(xMin,"%0.2f");
    curve.addXAxisDouble(xMax,"%0.2f");

    yaxisPrint(&curve);
    
    curve.beginPrint(ifGetName(),lissage);
    scale();
    pointDisplayForPrint(&curve);

    curve.endPrint();
}

void MvmHistogramDisplay::getProperties(TclList* list)
{
    /* property list for a MvmHistogramDisplay
       0- the properties of a STDisplayCurveObject
       1- the fact that it used floating point values on the Y axis
       2- the fact it is a histogram
       3- the display mode (density or repartition)
       4- the view mode (relative or absolute)	   
    */
  
    STDisplayCurveObject::getProperties(list);
    list->append("float");
    list->append("histo");
    list->append((displayMode == STHistoDENSITY)?"density":"rep"); 
    list->append((viewMode == GraphHistoREL)?"rel":"abs");
}

void MvmHistogramDisplay::getPointsToDisplay(TclList* pointsToDisplay, int)
{
    scale();
    display(pointsToDisplay);
}


void MvmHistogramDisplay::getConf(TclList* list)
{
    list->append(isStretched);
    list->append(getXMin());
    list->append(getXMax());
}

void MvmHistogramDisplay::setConf(int argc, char *argv[])
{
    int redraw = 0;
    int oldIsStretched = isStretched;
    int boundsModified ;

    if (argc >= 5)
	boundsModified = atoi(argv[4]);
    else
	boundsModified = 1;

    if ((isStretched = atoi(argv[1])) != oldIsStretched)
	redraw = 1;
  
    double xmin = atof(argv[2]),
	xmax = atof(argv[3]);
    double oldxmin = getXMin(),
	oldxmax = getXMax();
    if (boundsModified && (oldxmin != xmin || oldxmax != xmax))
	{
	setXBounds(xmin, xmax);
	xmin = getXMin();
	xmax = getXMax();
	if (oldxmin != xmin || oldxmax != xmax)
	    redraw = 1;
	}
  
    if (redraw)
	{
	TclList pointsToDisplay;
	getPointsToDisplay(&pointsToDisplay);
	reDrawPlotWithPts(&pointsToDisplay);
	}
}

void MvmHistogramDisplay::setPixXMax(int pixxm)
{
    pixXMax = Max(STDISPLAY_CURVE_PIXXMIN,pixxm);
    realPixXMax = pixXMax;
    roundedXMax = pixXMax;
    setXScale();
}


void MvmHistogramDisplay::notify(TkEvent event,
				 int argc,
				 char *argv[],
				 TkClientData clientData)
{
    switch(event)
	{
	case GetXAxisHisto:
	    {
	    CString sxmax = xMax,
		sxmin = xMin;
	    TclList x;
	    x.append(sxmin);
	    x.append(sxmax);
	    setTkResult("&L", &x);
	    break;
	    }
	case GetYAxisInfo:
	    {
	    TclList axis;
	    CString symax, symin;
	    if (yMin < yMax)
		{
		symax = yMax;
		axis.append(symax);
		axis.append(ytop);
		symin = yMin;
		axis.append(symin);
		axis.append(ytop + pixYMax - 1);
		}
	    setTkResult("&L", &axis);
	    break;
	    }
	case GetXYValuesString:
	    {
	    if (xMin == xMax || yMax < yMin)
		{
		TclList empty;
		setTkResult("&L", &empty);	
		break;	  
		}  
	    }
	case GetXYValues:
	    {
	    int deltaX = atoi(argv[1]);
	    int deltaY = atoi(argv[2]);
	    double yVal = getY(deltaY - 1),
		xVal = decRounding(getXValue(int(deltaX)),3);

	    TclList xyValues;
	    xyValues.append(xVal);
	    xyValues.append(yVal);
	    setTkResult("&L", &xyValues);
	    break;
	    }
	case HistoPolling:
	    {
	    proto->ifDisplay();
	    break;
	    }
	case SetHistoDisplay:
	    {
	    if (!strcmp(argv[1], "density")) 
		displayMode = STHistoDENSITY;
	    else
		displayMode = STHistoREPART;
	    break;
	    }
	case SetHistoView:
	    {
	    if (!strcmp(argv[1], "rel")) 
		viewMode = GraphHistoREL;
	    else
		viewMode = GraphHistoABS;
	    break;
	    }
	default:
	    STDisplayCurveObject::notify(event, argc, argv, clientData);
	    break;
	}
}

void MvmHistogramDisplay::ifProcess (int mtype, const struct MvmInterfaceMsg *gpm, int)

{
    if (mtype == MVM_IFACE_HISTOGRAM_HEAD)
	{
	MvmHistogramHeader *hmsg = (MvmHistogramHeader *)gpm;
	initHistogram(hmsg);
	}
    else if (mtype == MVM_IFACE_HISTOGRAM_INIT)
	{
	MvmHistogramInit *imsg = (MvmHistogramInit *)gpm;
	int npoints = imsg->nPtr < 0 ? -imsg->nPtr : imsg->nPtr;
	initPoint(imsg->hTab,npoints,imsg->nPtr < 0);
	}
}

void MvmHistogramDisplay::initHistogram (MvmHistogramHeader* hd)

{
    nbInit = 0;
    nVal = hd->nval;

    if (nVal == 0)
	return;

    l = hd->l;
    r = hd->r;
    binsize = (r - l) / (double)nbin;
    vMin = hd->vmin;
    vMax = hd->vmax;
    ssv1 = hd->s1;
    ssv2 = hd->s2;
    garbage = hd->garb;
    tCur = hd->time;
}

void MvmHistogramDisplay::initPoint (int* tab, int nr, int done)

{
    for (int i=0;  i < nr; i++, nbInit++)
	vLog[nbInit] = tab[i];

    if (done)
	{
	TclList pointsToDisplay;
	getPointsToDisplay(&pointsToDisplay);
	reDrawPlotWithPts(&pointsToDisplay);
	}
}

void MvmHistogramDisplay::scale()

{
    int		i, i1;			//	indices de travail
    int		ileft=0,		//	indice premiere tranche affichable
	iright=nbin - 1;		//	indice derniere tranche affichable
    int		hmax=0;			//	maximum des vLog[i]

    int		lmargin = 0,
	rmargin = 0;

    double	dmax,			//	densite maximale dans une tranche
	dmin,			//	densite minimale representable
	dleft=0.0,		//	densite cumulee tranche gauche
	dright=0.0,		//	densite cumulee tranche droite
	d,
	pixBin;

    double	ratio = 1.0;

    if (nVal == 0) return;
	        


    if (displayMode == STHistoDENSITY) {
    for (i = 0; i < nbin; i++)
	hmax = (vLog[i] > hmax)? vLog[i] : hmax;
    dmax = ((double)hmax) / ((double)nVal);
    } else dmax = 1.0;

    dmin = dmax / (2.0 * pixYMax);

    if (garbage & 1) {
    ileft = 1;
    dleft = double(vLog[0])/double(nVal);
    }

    if (garbage & 2) {
    iright = nbin - 2;
    dright = double(vLog[nbin - 1])/double(nVal);
    }


    if (okXAdjust)
	{
	xMin = l;
	xMax = r;
	}

    if (displayMode == STHistoDENSITY)
	{
	while (	((d = double(vLog[ileft]) / double(nVal)) < dmin)
		&& (ileft < nbin - 1))
	    {
	    dleft += d;
	    ileft++;
	    }

	while (	((d = double(vLog[iright])/double(nVal)) < dmin)
		&& (iright >= ileft+1))
	    {
	    dright += d;
	    iright--;
	    }
        
	if (dleft + dright >= 0.5)
	    return;
	}
    else
	{
	while ((dleft < dmin) && (ileft < nbin - 1))
	    {
	    if ((d = double(vLog[ileft]) / double(nVal)) > dmin/2)
		break;
	    dleft += d;
	    ileft++;
	    }

	while ((dright < dmin) && (iright >= ileft+1))
	    {
	    if ((d = double(vLog[iright])/double(nVal)) > dmin/2)
		break;
	    dright += d;
	    iright--;
	    }
	}
    if (ileft > 0 && dleft > 0) lmargin = 1;
    if (dleft > dmax) dmax = dleft;

    if ( iright != nbin - 1 && dright > 0) rmargin = 1;
    if (dright > dmax) dmax = dright;


    if (okXAdjust)
	{
	pixXMax = realPixXMax;
	xMax = l + (iright + rmargin + 1) * binsize;
	pixBin = pixXMax / (double)(iright + rmargin + 1);

	if (pixBin < STDISPLAY_HISTOGRAM_BINWIDTHMIN) {
	pixBin = pixXMax / (double)(iright - ileft + lmargin + rmargin + 1);
	if (pixBin < STDISPLAY_HISTOGRAM_BINWIDTHMIN)
	    xMin = l + (ileft + lmargin) * binsize;
	else {
	pixBin = (double)STDISPLAY_HISTOGRAM_BINWIDTHMIN;
	xMin = xMax - (pixXMax / pixBin) * binsize;
	}
	} else if (pixBin > binWidthDef && !isStretched) {
	pixBin = (double) binWidthDef;
	pixXMax = (int) ((iright + rmargin + 1) * pixBin);
	}
	} else {
	pixXMax = realPixXMax;
	if (!isStretched)
	    {
	    pixBin = pixXMax / (double)(xMax - xMin) * binsize;
	    if (pixBin > binWidthDef)
		{
		pixBin = (double)binWidthDef;
		pixXMax = (int)((xMax - xMin) * pixBin / binsize);
		}
	    }
	}
  

  
    if ((iright - ileft) * 2 + 16 > nMaxPointDisplayed) {
    iright = ileft + nMaxPointDisplayed / 2 - 8;
    }

    if ( displayMode == STHistoREPART || viewMode == GraphHistoREL) {
    yMax = decRounding(dmax,3);
    ratio = 1.0 / (double) nVal;
    } else 
	yMax = decRounding(hmax,4);

    setYScale();

    setXScale();

    i1 = 1;
    points[0].x = 0;
    points[0].y = 0;

    double x = l + ileft * binsize;
    double sy = 0.0;
    if(lmargin) {
    sy = dleft * nVal;
    points[2].y = pixY(dleft*ratio*nVal);
    if (x - binsize < xMin) {
    points[1].x = 0;
    points[1].y = points[2].y;
    points[2].x = pixX(x);
    i1 += 2;
    } else {
    points[1].x = pixX(x - binsize);
    points[1].y = 0;
    points[2].x = points[1].x;
    points[3].y = points[2].y;
    points[3].x = pixX(x);
    i1 += 3;
    }
    points[i1].x = points[i1 - 1].x;
    points[i1++].y = 0;
    } else {
    points[i1].x = pixX(x);
    points[i1++].y = 0;
    }

    for (i=ileft; i<=iright; i++) {
    points[i1].x = points[i1 - 1].x;
    if (displayMode == STHistoDENSITY)
	points[i1].y = points[i1+1].y = pixY(ratio*vLog[i]);
    else {
    sy += vLog[i];
    points[i1].y = points[i1+1].y = pixY(ratio*sy);
    }

    x += binsize;
    points[i1+1].x = pixX(x);
    i1 += 2;
    }
    points[i1].x = points[i1 - 1].x;
    points[i1++].y = 0;

    if (rmargin) {
    if (displayMode == STHistoDENSITY)
	sy = dright * nVal;
    else sy = nVal; 
    points[i1].x = points[i1 - 1].x;
    points[i1].y = points[i1+1].y = pixY(sy*ratio);
    x += binsize;
    if (x > xMax) x = xMax;
    points[i1+1].x = pixX(x);
    i1 += 2;
    points[i1].x = points[i1 - 1].x;
    points[i1++].y = 0;
    }
    nPointDisplayed = i1;
}

void MvmHistogramDisplay::setXBounds(double xl, double xr)
{
    if (xl > r - binsize) xl = r - binsize;
    else if (xl > l) xl = l + (int)((xl - l)/binsize) * binsize;
    if (xr < l + binsize) xr = l + binsize;
    else if (xr < r) xr = l + (int)((xr - l)/binsize) * binsize;
    if (xr - xl < binsize) xr = xl + binsize;
    okXAdjust = 0;
    STDisplayCurveObject::setXBounds(xl,xr);
}

void MvmHistogramDisplay::setXAdjust(int ok)
{
    okXAdjust = ok;
    scale();
}

void MvmHistogramDisplay::setViewMode(MvmHistogramViewModes mode)
{
    viewMode = mode;
    scale();
}

CString MvmHistogramDisplay::makeYStr (double pixx, int pixy, double)

{
    CString yStr;
    double yVal = getY(pixy),
	xVal = decRounding(getXValue(int(pixx)),3);

    yStr = "(X=";
    yStr += CString(xVal,"%g");
    yStr += ", Y=";
    yStr += CString(yVal,"%g");
    yStr += ")";

    return yStr;
}

void MvmHistogramDisplay::display (TclList* pointsToDisplay)

{
    // uncomment for centered plots
    //  int xoffset = (realPixXMax - pixXMax)/2;
    int xoffset = 0;

    pointsToDisplay->append(xoffset);
    pointsToDisplay->append(realPixXMax - pixXMax - xoffset);  

    drawData(1, pointsToDisplay);
}

void MvmHistogramDisplay::pointDisplay (int pointNo, TclList* pointsToDisplay)

{
    if (isMapped) {
    double y0, y1;
    double x0, x1;
    
    // uncomment for centered plots
    //    int xoffset = (realPixXMax - pixXMax)/2;
    int xoffset = 0;
    
    y1 = points[pointNo].y;
    x1 = points[pointNo].x;
    
    if (pointNo > 0)
	{
	y0 = points[pointNo - 1].y;
	x0 = points[pointNo - 1].x;
	}
    else
	{
	y0 = y1;
	x0 = x1;
	}
    
    // Ensure selection is not visible when drawing histogram point
    double xx0 = xtop + x0 + xoffset;
    double xx1 = xtop + x1 + xoffset;
    double yy0 = ytop + pixYMax - y0 - 1;
    double yy1 = ytop + pixYMax - y1 - 1;
    
    pointsToDisplay->append(xx0);
    pointsToDisplay->append(yy0);
    pointsToDisplay->append(xx1);
    pointsToDisplay->append(yy1);
    }
}

double MvmHistogramDisplay::getY (int pixy)

{ return decRounding(getYValue(pixy),3); }

// MvmStateDiagramDisplay


MvmStateDiagramDisplay::MvmStateDiagramDisplay(MvmStateDiagramExportMsg *_exmsg,
					       TkTimeCurvePlotter *_tplotter,
					       int _logSize,
					       MvmFrontend *_connector)
    : MvmStateDiagram(_exmsg,_logSize,_connector),
      STDisplayTimeCurveObject(_tplotter)
{
    iCur = -1;
    xDisp = 0.0;
    yMin = 0.0;
    yMax = (double)(getNStates() - 1);
    oldX = oldY = 9999999;
    lastState = -1;

    myType = StateDiag;
    setProto(this);
  
    plotter->callTkProc("plotter:setHierarchy","&C", plotter->getTkMaster());
    callTkProc("plotter:setHierarchy", "&C", (TkContext*)plotter);
}

//used for postScript display
MvmStateDiagramDisplay::MvmStateDiagramDisplay (MvmStateDiagramDisplay* _src,
						TkTimeCurvePlotter *_tplotter)
    : MvmStateDiagram(*_src), STDisplayTimeCurveObject(_src,_tplotter) 
{
    xDisp = _src->xDisp;
  
    memcpy(stateLog,_src->stateLog,logSize * sizeof(MvmStatePoint));
    iCur = _src->iCur;
    oldX = oldY = 9999999;
    lastState = -1;
  
    pixYMin = STDISPLAY_SDIAGRAM_PIXYMIN;
    myType = StateDiag;
}

STDisplayObject* MvmStateDiagramDisplay::psCopy(TkPlotter *df_p)
{ return (STDisplayObject*)new MvmStateDiagramDisplay(this,(TkTimeCurvePlotter*)df_p); }


void MvmStateDiagramDisplay::psYStrings(CStringList *l)

{
    for(int i=(int)yMax; i>=(int)yMin; i--)
	new LString(l,sarray[i]);
}


void MvmStateDiagramDisplay::pointDisplayForPrint (PSCurve* curve)
{
    if (nPointDisplayed > 0)
	curve->directStart((int)points[0].x,(int)points[0].y);
  
    for(int i=1; i < nPointDisplayed; i++) 
	{
      
	int y1 = (int)points[i].y;
	int x1 = (int)points[i].x;
      
	int y0 = (int)points[i - 1].y;
	int x0 = (int)points[i - 1].x;
      
	if (y1 <= pixYMax && y0 > pixYMax)
	    {
	    y0 = pixYMax;
	    curve->directStart(x0,y0);
	    }
      
	if (y0 <= pixYMax && y1 > pixYMax)
	    y1 = pixYMax;
      
	if (y1>= 0 && y0 < 0)
	    {
	    y0 = 0;
	    curve->directStart(x0,y0);
	    }
      
	if (y0 >= 0 && y1 < 0)
	    y1 = 0;
      
	if (y0 >= 0 && y1 >= 0 && y0 <= pixYMax && y1 <= pixYMax)
	    curve->directPrint(x1,y1);
	}
}
void MvmStateDiagramDisplay::yaxisPrint (PSCurve* curve)
{
    for(int i=(int)yMin; i<=(int)yMax; i++)
	curve->addYAxisString(pixY((double)i),sarray[i]);
}

void MvmStateDiagramDisplay::psPrint (FILE *fp)

{
    int lissage = 0;

    ITime tmin,tmax ;
    timePlotter->getTimeBounds(tmin,tmax);

    ITime tcur = timePlotter->getCurrentTime();

    PSCurve curve(fp);
    curve.setCaract(getPixXMax(),getPixYMax(),tmin,tmax,pixY(yMin),pixY(yMax));

    curve.addXAxisString(tmin,ETime(tmin,USec).format());
    if (tcur < tmax) curve.addXAxisString(tcur,ETime(tcur,USec).format());
    curve.addXAxisString(tmax,ETime(tmax,USec).format());
    
    yaxisPrint(&curve);
    scale();
    curve.beginPrint(ifGetName(),lissage);

    pointDisplayForPrint(&curve);
    
    curve.endPrint();
}

ITime MvmStateDiagramDisplay::searchInLog(ITime t, int dir, int* found)
{
    if (iCur <= 0)
	{
	*found = 0;
	return t;
	}

    int imax = iCur,
	imin = (iCur > logSize - 1)?(iCur - logSize + 1):0;
    double tmax = stateLog[imax % logSize].time,
	tmin = stateLog[imin % logSize].time;

    int ipoint;
    if (dir == 1) {
    if ((double)t > tmax) {
    *found = 0;
    return t;
    }
    if ((double)t < tmin) { 
    *found = 1;
    return tmin;
    }
    ipoint = search(t, imin, imax) + 1; 
    } else {
    if ((double)t <= tmin) {
    *found = 0;
    return t;
    }
    if ((double)t > tmax) {
    *found = 1;
    return tmax;
    }
    ipoint = search(t, imin, imax); 
    }
    *found = 1;
    return stateLog[ipoint % logSize].time;
}

int MvmStateDiagramDisplay::search(ITime t, int imin, int imax)
{
    int half = (imin + imax)/2;
  
    if (stateLog[half % logSize].time < t)
	{
	if (imax - half == 1)
	    return half;
	else
	    return search(t, half, imax);
	}
    else
	{
	if (half - imin == 1)
	    return imin;
	else
	    return search(t, imin, half);
	}
}

int MvmStateDiagramDisplay::checkYBounds(STDisplayTimeCurveObject *dtco)
{
    if(getNStates() != ((MvmStateDiagramDisplay*)dtco)->getNStates())
	return 0;
  
    for (int i = (int)yMin; i <= (int)yMax; i++)
	if(strcmp(sarray[i], ((MvmStateDiagramDisplay*)dtco)->sarray[i]))
	    return 0;

    return 1;
}

ITime MvmStateDiagramDisplay::whatIsYourTime(ITime t, int check)
{ 
    return ITime((isDisplayed||!check)?(double)t:0); 
}

void MvmStateDiagramDisplay::getConf(TclList* list)
{
}

void MvmStateDiagramDisplay::setConf(int argc, char *argv[])
{
}

void MvmStateDiagramDisplay::getProperties(TclList* list)
{
    /* property list for a MvmStateDiagramDisplay
       0- the properties of a STDisplayTimeCurveObject
       1- the fact that it uses state names on the Y axis
       2- the fact it is a time graph
       3- a list of the names of the states
    */
  
    STDisplayTimeCurveObject::getProperties(list);
    list->append("state");
    list->append("time");
    TclList states;
    for (int n = 0; n < nstates; n++)
	states.append(sarray[n]);
    list->append(states);
}

void MvmStateDiagramDisplay::notify(TkEvent event,
				    int argc,
				    char *argv[],
				    TkClientData clientData)
{
    switch(event)
	{
	case GetYAxisInfo:
	    {
	    TclList axis;
	    if (getNStates() > 0)
		{
		double spix = pixYMax / Max(int(yMax - yMin),1); // special case if nstates == 1
	    
		for (int i = (int)yMin; i <= (int)yMax; i++)
		    {
		    double sy = ytop + pixYMax - 1 - (i - (int)yMin) * spix;
		    CString st(sarray[i]);
		    axis.append(st);
		    axis.append(sy);
		    }
		}
	    setTkResult("&L", &axis);
	    break;
	    }
	case GetXYValuesString:
	    {
	    int deltaX = atoi(argv[1]);
	    int deltaY = atoi(argv[2]);

	    ETime td =  timePlotter->getTimeValueWithUnit(deltaX);
	
	    TclList xyValues;
	    xyValues.append(td.format("")); //FIXME
	    xyValues.append(sarray[(int)getY(deltaY - 1)]);
	    setTkResult("&L", &xyValues);
	    break;
	    }
	case GetXYValues:
	    {
	    int deltaX = atoi(argv[1]);
	    int deltaY = atoi(argv[2]);

	    ETime td = timePlotter-> getTimeValueWithUnit(deltaX);

	    TclList xyValues;
	    xyValues.append((double)td);
	    xyValues.append((int)getY(deltaY - 1));
	    setTkResult("&L", &xyValues);
	    break;
	    }
	case FromXYValuesToPix:
	    {
	    double t = (ITime) atof(argv[1]);
	    int yval = atoi(argv[2]);
	    int xbounded = atoi(argv[3]), 
		ybounded = atoi(argv[4]);;
	    int xtrunc = 1,
		ytrunc = 1;
		
	    ETimeUnits xunit;
	    ITime it;
	    if(timePlotter->timeUnit != TCalendar)
		{
		if(argc > 5) // use the default unit if none is given
		    xunit = (ETimeUnits)(atoi(argv[5]) + (int)USec);
		else 
		    xunit = timePlotter->timeUnit;
		ETime et(t, xunit);
		it = ITime(et);
		} else
		    it = (double) t;

	    TclList pix;
	    int x, y;
	
	    if(xbounded)
		{
		if(it < ZEROTIME)
		    it = 0;
		if (it > timePlotter -> tCur)
		    it = timePlotter -> tCur;
		}

	
	    if (it < timePlotter-> tMin)
		x = 0;
	    else if (it > timePlotter -> tMax)
		x = pixXMax;
	    else 
		{
		xtrunc = 0;
		x = (int)ceil(((double(it) - double(timePlotter -> tMin)) * double(pixXMax)) / 
			      double(timePlotter -> tMax - timePlotter -> tMin)); //FIXME: ceil, floor?
		}
	
	    pix.append(x);

	    if (ybounded)
		{
		if (yval > vMax) 
		    yval = int(vMax);
		if (yval < vMin) 
		    yval = int(vMin);
		}

	    if (yval >= yMax) 
		y = pixYMax;
	    else if (yval <= yMin)
		y = 0;
	    else
		{
		ytrunc = 0;
		y = int(double(yval - yMin) / double(yMax - yMin) * pixYMax);
		}
	
	    pix.append(y);
	
	    ETime et(it, timePlotter->timeUnit);
	    pix.append((double)et);
	    pix.append(yval);
	    pix.append(xtrunc);
	    pix.append(ytrunc);
	
	    setTkResult("&L", &pix);
	    break;
	    }
	case getYBounds:
	    {
	    TclList res;
	    res.append((int)yMin);
	    res.append((int)yMax);
	    setTkResult("&L", &res);
	    break;
	    }
	default:
	    STDisplayTimeCurveObject::notify(event, argc, argv, clientData);
	    break;
	}
  
}

void MvmStateDiagramDisplay::ifProcess (int mtype, const struct MvmInterfaceMsg *gpm, int msize)

{
    if (mtype == MVM_IFACE_SDIAGRAM_INIT)
	{
	if (isFirstProtoInitMsg)
	    {
	    iCur = -1;
	    isFirstProtoInitMsg = 0;
	    }
	MvmStateDiagramInitMsg *imsg = (MvmStateDiagramInitMsg *)gpm;
	int npoints = imsg->nPoints < 0 ? -imsg->nPoints : imsg->nPoints;
	initPoint(imsg->tab, npoints, imsg->nPoints < 0);
	}
    else if (mtype == MVM_IFACE_SDIAGRAM_POINT)
	{
	MvmStateDiagramPointMsg *pmsg = (MvmStateDiagramPointMsg *)gpm;
	addPoint(pmsg,msize / sizeof(MvmStateDiagramPointMsg));
	}
}

void MvmStateDiagramDisplay::add (double t, int s)
{
    if (s >= getNStates())
	statError("GraphDisplay::MvmStateDiagramDisplay - state number out of bounds: %d",s);
  
    int i = ++iCur % logSize;
    stateLog[i].stateno = s;
    stateLog[i].time = t;
}

void MvmStateDiagramDisplay::initPoint (MvmStatePoint *tab, int nr, int done)
{
    for (int i = 0; i < nr; i++)
	add((tab+i)->time, (tab+i)->stateno);

    if (done) {
    lastState = stateLog[iCur % logSize].stateno;

    if (stateLog[iCur % logSize].time > timePlotter->tCur)
	timePlotter->timeUpdate(stateLog[iCur % logSize].time);
      
    TclList pointsToDisplay;
    getPointsToDisplay(&pointsToDisplay,0);
    contextForDrawing->reDrawPlotWithPts(&pointsToDisplay);
    isFirstProtoInitMsg = 1;
    }
}


void MvmStateDiagramDisplay::addPoint (MvmStateDiagramPointMsg *mtab, int mcount)
{
    if ((mtab+mcount-1) -> stateno != lastState)
	lastState = (mtab+mcount-1)->stateno;
  
    int stateno;
    double t;

    TclList pointsToDisplay;

    if (nPointDisplayed + 2*mcount > nMaxPointDisplayed-1)
	{
	while (nPointDisplayed + 2*mcount > nMaxPointDisplayed - 1) {
	xDisp += (xMax - xMin) * 0.2;
	scale();
	}
	TclList sublist;
	display(&sublist);
	pointsToDisplay.append(sublist);
	contextForDrawing->reDrawPlotWithPts(&pointsToDisplay);
	pointsToDisplay.clear();
	}
  
    if((mtab+mcount-1) -> time > timePlotter -> tMax)
	{ 
	/* we'll have to redraw all the graph */
	for(int j=0; j < mcount; j++) 
	    {
	    stateno = (mtab+j) -> stateno;
	    t = (mtab+j) -> time;
	
	    add(t, stateno);
	    }

	} else {
	for(int j=0; j < mcount; j++) 
	    {
	    stateno = (mtab+j) -> stateno;
	    t = (mtab+j) -> time;

	    add(t, stateno);
	    
	    if (!nPointDisplayed)
		{
		points[nPointDisplayed].x = pixX(t);
		points[nPointDisplayed].y = _pixY((double)stateLog[iCur%logSize].stateno);
		nPointDisplayed++;
		} else {
		//	      tprev = (double)stateLog[(i-1)%logSize].time;
		points[nPointDisplayed].x = pixX(t);
		points[nPointDisplayed].y = points[nPointDisplayed - 1].y;
		if (_pixX(t) <= pixXMax)
		    pointDisplay(nPointDisplayed, &pointsToDisplay);
		nPointDisplayed++;
		points[nPointDisplayed].x = points[nPointDisplayed - 1].x;
		points[nPointDisplayed].y = _pixY((double)stateLog[iCur%logSize].stateno);
		if (_pixX(t) <= pixXMax)
		    pointDisplay(nPointDisplayed, &pointsToDisplay);
		nPointDisplayed++;
		}
	    }

	contextForDrawing->addToPlot(&pointsToDisplay, this);
	}
}

void MvmStateDiagramDisplay::addPoint (int stateno, double t)

{
    if (stateno >= getNStates())
	statError("GraphDisplay::MvmStateDiagramDisplay - state number out of bounds: %d",stateno);

    int i = ++iCur % logSize;
    stateLog[i].stateno = stateno;
    stateLog[i].time = t;

    if (t >= (double)timePlotter->tCur)
	timePlotter->timeUpdate(t);

    if (!nPointDisplayed)
	{
	points[nPointDisplayed].x = pixX(t);
	points[nPointDisplayed].y = _pixY((double)stateLog[iCur%logSize].stateno);
	nPointDisplayed++;
	return;
	}

    TclList pointsToDisplay;
    if (nPointDisplayed > nMaxPointDisplayed - 1)
	{
	xDisp += (xMax - xMin) * 0.2;
	getPointsToDisplay(&pointsToDisplay);
	contextForDrawing->reDrawPlotWithPts(&pointsToDisplay);
	return;
	}
    pointsToDisplay.clear();

    points[nPointDisplayed].x = pixX(t);
    points[nPointDisplayed].y = points[nPointDisplayed - 1].y;
    if (_pixX(t) <= pixXMax)
	{
	TclList pointsToDisplay;
	pointDisplay(nPointDisplayed, &pointsToDisplay);
	contextForDrawing->addToPlot(&pointsToDisplay, this);
	}
    nPointDisplayed++;
    points[nPointDisplayed].x = points[nPointDisplayed - 1].x;
    points[nPointDisplayed].y = _pixY((double)stateLog[iCur%logSize].stateno);
    if (_pixX(t) <= pixXMax)
	{
	TclList pointsToDisplay;
	pointDisplay(nPointDisplayed, &pointsToDisplay);
	contextForDrawing->addToPlot(&pointsToDisplay, this);
	}
    nPointDisplayed++;
}


void MvmStateDiagramDisplay::setXBounds(double xl, double xr)

{
    xDisp = xl;
    STDisplayCurveObject::setXBounds(xl,xr);
}

void MvmStateDiagramDisplay::scale()
{
    if (iCur < 0) return;
    int i0 = iCur - logSize + 1;
    int i1 = iCur;
    if (i0 < 0) i0 = 0;

    nPointDisplayed = 0;

    if (stateLog[i0%logSize].time > xMax) return;

    double xmin = (xDisp > xMin) ? xDisp : xMin;

    while((stateLog[i0%logSize].time < xmin) && (i0 < iCur)) i0++;
    while((stateLog[i1%logSize].time > xMax) && (i1 >= i0)) i1--;

    if ( 2*(i1 - i0 + 1) + 2 > nMaxPointDisplayed)
	{
	i0 = i1 + 2 - nMaxPointDisplayed/2;
	xmin = xDisp = stateLog[i0%logSize].time;
	}

    if (!i0)
	{
	points[0].x = pixX((double)stateLog[0].time);
	points[0].y = _pixY((double)stateLog[0].stateno);
	}
    else if (xMin == xmin)
	{
	points[0].x = 0;
	if (stateLog[i0%logSize].time == xMin)
	    points[0].y = _pixY((double)stateLog[i0%logSize].stateno);
	else if (stateLog[(i0 - 1)%logSize].time < xMin)
	    points[0].y = _pixY((double)stateLog[(i0 - 1)%logSize].stateno);
	else
	    {
	    points[0].x = pixX((double)stateLog[i0%logSize].time);
	    points[0].y = _pixY((double)stateLog[i0%logSize].stateno);
	    }
	}
    else
	{
	points[0].x = pixX((double)stateLog[i0%logSize].time);
	if (stateLog[(i0 - 1)%logSize].time < xmin)
	    points[0].y = _pixY((double)stateLog[(i0 - 1)%logSize].stateno);
	else
	    points[0].y = _pixY((double)stateLog[(i0)%logSize].stateno);
	}

    nPointDisplayed = 1;

    while(i0 <= i1)
	{
	points[nPointDisplayed].x = pixX((double)stateLog[i0%logSize].time);
	points[nPointDisplayed].y = points[nPointDisplayed - 1].y;
	nPointDisplayed++;
	points[nPointDisplayed].x = points[nPointDisplayed - 1].x;
	points[nPointDisplayed].y = _pixY((double)stateLog[i0%logSize].stateno);
	nPointDisplayed++;
	i0++;
	}

    double x = timePlotter->getCurrentTime();
  
    if (x > xMax) x = xMax;

    if (x > (double)stateLog[(i0-1)%logSize].time) 
	{
	points[nPointDisplayed].x = pixX(x);
	points[nPointDisplayed].y = points[nPointDisplayed  - 1].y;
	nPointDisplayed++;
	}
}

ITime MvmStateDiagramDisplay::getDtUpdate()
{
    if (iCur <= 0) return MAXITIME;
    int i0 = iCur - logSize + 1;
    ITime dt = timePlotter->tCur;
    if (i0 < 0)
	return dt / (double)iCur;
    else
	return ( dt - (ITime)stateLog[i0%logSize].time ) / (double)logSize;
}

ITime MvmStateDiagramDisplay::getTOldest()
{
    if (iCur <= 0) return ZEROTIME;
    int i0 = iCur - logSize + 1;
    if (i0 < 0)
	return ZEROTIME;
    else
	return (ITime)stateLog[i0%logSize].time;
}

void MvmStateDiagramDisplay::display (TclList* list ) {
    drawData(0,list);
}

void MvmStateDiagramDisplay::pointDisplay (int pointNo, TclList* pointsToDisplay)

{
    double y0, y1;
    double x0, x1;
    if (contextForDrawing->getIsMapped() && pointNo > 0)
	{
	y1 = points[pointNo].y;
	x1 = points[pointNo].x;
	
	y0 = points[pointNo - 1].y;
	x0 = points[pointNo - 1].x;

	oldY = y1;
	oldX = x1;

	if (y1 <= getPixYMax() && y0 > getPixYMax())
	    y0 = getPixYMax();
	
	if (y0 <= getPixYMax() && y1 > getPixYMax())
	    y1 = getPixYMax();
	
	if (y1>= 0 && y0 < 0)
	    y0 = 0;
	
	if (y0 >= 0 && y1 < 0)
	    y1 = 0;

	if (y0 >= 0 && y1 >= 0 && y0 <= getPixYMax() && y1 <= getPixYMax())
	    {
	    // Change coordinates
	    x0 += xtop;
	    x1 += xtop;
	    y0 = ytop + pixYMax - y0 - 1;
	    y1 = ytop + pixYMax - y1 - 1;

	    pointsToDisplay->append(x0);
	    pointsToDisplay->append(y0);
	    pointsToDisplay->append(x1);
	    pointsToDisplay->append(y1);
	    }
	}
}

CString MvmStateDiagramDisplay::makeYStr (double tdrag, int pixy, double)

{
    CString yStr;
    ITime td(tdrag);

    yStr = "(T=";
    yStr += ETime(td,plotter->getTimeUnit()).format("");
    yStr += ", State=";
    yStr += sarray[(int)getY(pixy)];
    yStr += ")";

    return yStr;
}

double MvmStateDiagramDisplay::getY (int pixy)
{ return (int)(getYValue(pixy) + 0.5); }

void MvmStateDiagramDisplay::displayUpdate (int x)
{
    double y = getPixYCur();
    if (contextForDrawing->getIsMapped() && iCur >= 0) // do not update display before 1st point has been received...
	{
	double y0, y1;
	double x0, x1;
	
	if (points[nPointDisplayed -1].x >= oldX) 
	    {
	    oldX = points[nPointDisplayed -1].x;
	    oldY = points[nPointDisplayed -1].y;
	    }
      
	if (x == oldX)
	    return;

	if (x < oldX)
	    {
	    y0 = nPointDisplayed > 0 ? points[nPointDisplayed - 1].y : y;
	    x0 = nPointDisplayed > 0 ? points[nPointDisplayed - 1].x : x;
	    y1 = y;
	    x1 = x;
	    }
	else
	    {
	    y0 = oldY;
	    x0 = oldX;
	    y1 = y;
	    x1 = x;
	    }
	
	if (y0 >= 0 && y1 >= 0 && y0 <= pixYMax && y1 <= pixYMax && y1 == y0)
	    {
	    // Draw new diagram position, ensuring selection is not visible
	    double yy1 = ytop + pixYMax - y0 - 1;
	    double xx1 = xtop + x0;
	    double yy2 = ytop + pixYMax - y1 - 1;
	    double xx2 = xtop + x1;

	    TclList points;
	    points.append(xx1);
	    points.append(yy1);
	    points.append(xx2);
	    points.append(yy2);
	    contextForDrawing->addToPlot(&points, this);	    
	    }

	oldX = x;
	oldY = y;
	}
}

STimeCompoundObject::STimeCompoundObject(TkTimeCurvePlotter *_tplotter)
    : STDisplayTimeCurveObject(_tplotter)
{ 
    nbObject = 0;
    myType = CompoundObj;
    isDisplayed = 1;
    nMaxPointDisplayed = 0;

    handleEvent("SetCompoundTitle", SetCompoundTitle, this);
    handleEvent("RemoveFromCmpd", RemoveFromCmpd, this);
    handleEvent("AddToCmpd", AddToCmpd, this);
    handleEvent("GetBreakpointList", GetBreakpointList, this);
    handleEvent("SetBreakpoint", SetBreakpoint, this);
    handleEvent("ClearBreakpoint", ClearBreakpoint, this);
    plotter->callTkProc("plotter:setHierarchy","&C", plotter->getTkMaster());
    callTkProc("plotter:setHierarchy", "&C", (TkContext*)plotter);
}

STimeCompoundObject::STimeCompoundObject(STimeCompoundObject* _src,
					 TkTimeCurvePlotter *_tplotter)
    : STDisplayTimeCurveObject(_src,_tplotter)
{ 
    nbObject = 0;
    myType = CompoundObj;
    isDisplayed = 1;

    STDisplayTimeCurveObjectIterator it(_src->timeObjectList);
    STDisplayTimeCurveObject *displayObject;
    STDisplayTimeCurveObject *newdtco;

    while((displayObject = it.next()) != NULL)
	{
	newdtco = (STDisplayTimeCurveObject*)displayObject->psCopy(_tplotter); 
	addObject(newdtco);
	}
    title = _src->title;
}

STimeCompoundObject::~STimeCompoundObject()
{
}

ITime STimeCompoundObject::searchInLog(ITime t, int dir, int* found)
{
    *found = 1;
    int itsFound;
    ITime gt = 0, lt;

    STDisplayTimeCurveObjectIterator it(timeObjectList);
    STDisplayTimeCurveObject *displayObject;

    while((displayObject = it.next()) != NULL)
	{
	lt = displayObject->searchInLog(t, dir, &itsFound);
	*found &= itsFound;
	if (itsFound)
	    {
	    if(dir == 1)
		{
		if (gt == ZEROTIME)
		    gt = lt;
		else if (lt < gt)
		    gt = lt;
		} else {
		if (gt == ZEROTIME)
		    gt = lt;
		else if (lt > gt)
		    gt = lt;
		}
	    }
	}
    if (!*found)
	return t;
    return lt;
}

void STimeCompoundObject::getProperties(TclList* list)
{
    /* property list for a STimeCompoundObject
       0- the title and the group
       1- the fact that it uses state names on the Y axis
       or 
       1- the fact that it uses floating point values on the Y axis 
       2- the fact it is a time graph
       3- a list of the names of the states if it is built with state diagrams or an empty list
       4- a list of the context of the plot
    */
  
    TclList sublist;
    sublist.append(title);
    sublist.append("COMPOUND");
    list->append(sublist);
    if (nbObject) 
	{
	if (plotType == StateDiag)
	    list->append("state");
	else 
	    list->append("float");
	}

    list->append("time");

    MvmStateDiagramDisplay *stObject = (MvmStateDiagramDisplay*)timeObjectList.first();
    TclList states;
    if (nbObject && (plotType == StateDiag))
	{
	for (int n = 0; n < stObject->getNStates(); n++)
	    states.append(stObject->getStateName(n));
	}
    list->append(states);

    STDisplayTimeCurveObjectIterator it(timeObjectList);
    STDisplayTimeCurveObject *displayObject;
    TclList context;

    while((displayObject = it.next()) != NULL)
	context.append(displayObject->getTkName());

    list->append(context);
}

void STimeCompoundObject::getConf(TclList* list)

{
    timeObjectList.first()->getConf(list);
}


void STimeCompoundObject::setConf(int argc, char *argv[])
{
    STDisplayTimeCurveObjectIterator it(timeObjectList);
    STDisplayTimeCurveObject *displayObject;

    while((displayObject = it.next()) != NULL)
	displayObject->setConf(argc, argv);
}

void STimeCompoundObject::notify(TkEvent event,
				 int argc,
				 char *argv[],
				 TkClientData clientData)
{
    switch(event)
	{
	case SetCompoundTitle:
	    {
	    title = argv[1];
	    break;
	    }

	case AddToCmpd:
	    {
	    STDisplayTimeCurveObject *first = timeObjectList.first(),
		*toAdd = (STDisplayTimeCurveObject*)findContext(argv[1]);
	    if (first)
		{
		toAdd->setPixYMax(first->getPixYMax());
		toAdd->setDisplayBounds(first->getYTop(), first->getXTop()); 
		}
	    addObject(toAdd);
	    break;
	    }
	case RemoveFromCmpd:
	    {
	    rmObject((STDisplayTimeCurveObject*)findContext(argv[1]), 1);
	    break;
	    }

	case ForceSetDisplay:
	case ProtoSetDisplay:
	    {
	    isDisplayed = 1;
	    STDisplayTimeCurveObjectIterator it(timeObjectList);
	    STDisplayTimeCurveObject *displayObject;

	    while((displayObject = it.next()) != NULL)
		displayObject-> getProto() -> ifDisplay();

	    break;
	    }
	case ProtoSetConceal:
	case ProtoSetTempConceal:
	    {
	    isDisplayed = 0;

	    STDisplayTimeCurveObjectIterator it(timeObjectList);
	    STDisplayTimeCurveObject *displayObject;

	    while((displayObject = it.next()) != NULL)
		rmObject(displayObject, 0);

	    if (event == ProtoSetConceal)
		delete this;
	    break;
	    }
	case GetBreakpointList:
	    {
	    TclList bpts;
	    STDisplayTimeCurveObjectIterator it(timeObjectList);
	    STDisplayTimeCurveObject *displayObject;

	    while((displayObject = it.next()) != NULL)
		{
		MvmInterfaceBreakPointList breakpts = displayObject->getProto()->ifGetBPList();
		for (MvmInterfaceBreakPoint *bp = (MvmInterfaceBreakPoint *)breakpts.first();
		     bp; bp = (MvmInterfaceBreakPoint *)bp->next())
		    bpts.append(bp->threshold);
		}
	    
	    setTkResult("&L", &bpts);
	    break;
	    }
	case SetBreakpoint:
	    {
	    TclList bpts;
	    double threshold = atof(argv[1]);
	    STDisplayTimeCurveObjectIterator it(timeObjectList);
	    STDisplayTimeCurveObject *displayObject;

	    while((displayObject = it.next()) != NULL)
		{
		displayObject->getProto()->ifSetBreak(threshold);
	    
		MvmInterfaceBreakPointList breakpts = displayObject->getProto()->ifGetBPList();
		for (MvmInterfaceBreakPoint *bp = (MvmInterfaceBreakPoint *)breakpts.first();
		     bp; bp = (MvmInterfaceBreakPoint *)bp->next())
		    bpts.append(bp->threshold);
		}

	    setTkResult("&L", &bpts);
	    break;
	    }
	case ClearBreakpoint:
	    {
	    TclList bpts;
	    double threshold = atof(argv[1]);
	    STDisplayTimeCurveObjectIterator it(timeObjectList);
	    STDisplayTimeCurveObject *displayObject;

	    while((displayObject = it.next()) != NULL)
		{
		displayObject->getProto()->ifClrBreak(threshold);

		MvmInterfaceBreakPointList breakpts = displayObject->getProto()->ifGetBPList();
		for (MvmInterfaceBreakPoint *bp = (MvmInterfaceBreakPoint *)breakpts.first();
		     bp; bp = (MvmInterfaceBreakPoint *)bp->next())
		    bpts.append(bp->threshold);
		}

	    setTkResult("&L", &bpts);
	    break;
	    }
	case GetYAxisInfo:
	    {
	    STDisplayTimeCurveObject *displayObject = timeObjectList.first();
	    displayObject->notify(event, argc, argv, clientData);
	    break;
	    }
	case GetPointsToDisplay:
	    {
	    timePlotter->setPixXMax(atoi(argv[1]));
	
	    TclList pointsToDisplay;
	    TclList sublist;
	    STDisplayTimeCurveObjectIterator it(timeObjectList);
	    STDisplayTimeCurveObject *displayObject;

	    while((displayObject = it.next()) != NULL)
		{
		sublist.clear();
		displayObject->setPixYMax(atoi(argv[2]));
		displayObject->setDisplayBounds(atoi(argv[4]), atoi(argv[3]));	                          
		displayObject->scale();
		displayObject->display(&sublist);
		pointsToDisplay.append(sublist);
		}
	    setTkResult("&L", &pointsToDisplay);
	    break;
	    }
	case GetXYValues:
	case GetXYValuesString:
	case FromXYValuesToPix:
	    {
	    STDisplayTimeCurveObject *displayObject = timeObjectList.first();
	    displayObject->notify(event, argc, argv, clientData);
	    break;
	    }
	case SetYBounds:
	    {
	    STDisplayTimeCurveObjectIterator it(timeObjectList);
	    STDisplayTimeCurveObject *displayObject;

	    while((displayObject = it.next()) != NULL)
		displayObject->notify(event, argc, argv, clientData);

	    break;
	    }
	default:
	    STDisplayTimeCurveObject::notify(event, argc, argv, clientData);
	    break;
	}
}

int STimeCompoundObject::addObject(STDisplayTimeCurveObject *dtco)
{
    plotType = dtco->getMyType();
  
    if (plotType == CompoundObj)
	{
	STDisplayTimeCurveObjectIterator it(((STimeCompoundObject*)dtco)->timeObjectList);
	STDisplayTimeCurveObject *displayObject;
	int newNbObject = 0;

	while((displayObject = it.next()) != NULL)
	    newNbObject = addObject(displayObject);

	return newNbObject;
	} 

    dtco -> setContextForDrawing(this);
    timeObjectList.append(dtco);
    nbObject++;

    if (plotType == TGraphObject)
	{
	double ymin = getMinYBounds(),
	    ymax = getMaxYBounds();

	setYBounds(ymin, ymax);
	if (nbObject > 1)
	    {
	    STDisplayTimeCurveObject *first = timeObjectList.first();
	    dtco->setYAdjust(first->getYAdjust());
	    ((MvmTimeGraphDisplay*)dtco)->setDtDisplay(((MvmTimeGraphDisplay*)first)->getDtDisplay()); //FIXME: cast
	    }
	}

    return nbObject;
}

int STimeCompoundObject::rmObject(STDisplayTimeCurveObject *dtco, int rem)
{
    if (rem)
	timeObjectList.remove(dtco);
    //  dtco -> setContextForDrawing(dtco);
    dtco-> getProto() -> ifConceal();
    nbObject--;
    return nbObject;
}

int STimeCompoundObject::checkYBounds(STDisplayTimeCurveObject *dtco)
{
    STDisplayTimeCurveObject *displayObject = timeObjectList.first();

    if (dtco->getMyType() == CompoundObj)
	return displayObject->checkYBounds(((STimeCompoundObject*)dtco)->timeObjectList.first());

    return displayObject->checkYBounds(dtco);
}

ITime STimeCompoundObject::whatIsYourTime(ITime t, int)
{ 
    STDisplayTimeCurveObjectIterator it(timeObjectList);
    STDisplayTimeCurveObject *displayObject;
    ITime itsTime, gTime;

    while((displayObject = it.next()) != NULL)
	{
	itsTime = displayObject->whatIsYourTime(t, 0);
	if (itsTime > gTime)
	    gTime = itsTime;
      	}

    return gTime;
}

void STimeCompoundObject::display(TclList*)
{ }
void STimeCompoundObject::pointDisplay(int, TclList*)
{ }

void STimeCompoundObject::displayUpdate(int x)
{
    STDisplayTimeCurveObjectIterator it(timeObjectList);
    STDisplayTimeCurveObject *displayObject;

    while((displayObject = it.next()) != NULL)
	displayObject->displayUpdate(x);
}

ITime STimeCompoundObject::getDtUpdate()
{ return ZEROTIME;  }

void STimeCompoundObject::scale()
{ 
    STDisplayTimeCurveObjectIterator it(timeObjectList);
    STDisplayTimeCurveObject *displayObject;

    while((displayObject = it.next()) != NULL)
	displayObject->scale();
}

ITime STimeCompoundObject::getTOldest()
{ return ZEROTIME; }

void STimeCompoundObject::getPointsToDisplay(TclList* pointsToDisplay, int check)
{
    if (isDisplayed || !check)
	{
	STDisplayTimeCurveObjectIterator it(timeObjectList);
	STDisplayTimeCurveObject *displayObject;

	while((displayObject = it.next()) != NULL)
	    {
	    TclList sublist;
	    displayObject->scale();
	    displayObject->display(&sublist);
	    pointsToDisplay->append(sublist);
	    }
	}
}

double STimeCompoundObject::getMinYBounds()
{
    STDisplayTimeCurveObjectIterator it(timeObjectList);
    STDisplayTimeCurveObject *displayObject = it.next();
    double min = displayObject->getMinYBounds();

    while ((displayObject = it.next()) != NULL)
	{
	double y = displayObject->getMinYBounds();

	if (y < min) 
	    min = y;
	}

    return min;
}

double STimeCompoundObject::getMaxYBounds()
{
    STDisplayTimeCurveObjectIterator it(timeObjectList);
    STDisplayTimeCurveObject *displayObject = it.next();
    double max = displayObject->getMaxYBounds();

    while((displayObject = it.next()) != NULL)
	{
	double y = displayObject->getMaxYBounds();

	if (y > max) 
	    max = y;
	}

    return max;
}

void STimeCompoundObject::setYBounds(double ymin, double ymax, int setYBoundsDone)
{
    STDisplayTimeCurveObjectIterator it(timeObjectList);
    STDisplayTimeCurveObject *displayObject;

    while((displayObject = it.next()) != NULL)
	displayObject->setYBounds(ymin, ymax, 1);
}

double STimeCompoundObject::getYMin()
{
    STDisplayTimeCurveObjectIterator it(timeObjectList);
    STDisplayTimeCurveObject *displayObject = it.next();
    double min = displayObject->getYMin();

    while((displayObject = it.next()) != NULL)
	{
	double y = displayObject->getYMin();

	if (y > min) 
	    min = y;
	}

    return min;
}

double STimeCompoundObject::getYMax()
{
    STDisplayTimeCurveObjectIterator it(timeObjectList);
    STDisplayTimeCurveObject *displayObject = it.next();
    double max = displayObject->getYMax();

    while((displayObject = it.next()) != NULL)
	{
	double y = displayObject->getYMax();

	if (y < max) 
	    max = y;
	}

    return max;
}

STDisplayObject* STimeCompoundObject::psCopy (TkPlotter *df_p) 
{ 
    return (STDisplayObject*)new STimeCompoundObject(this,(TkTimeCurvePlotter*)df_p); 
}


void STimeCompoundObject::psYStrings (CStringList *l)
{
    STDisplayTimeCurveObject *displayObject = timeObjectList.first();
    displayObject->psYStrings(l);
}

void STimeCompoundObject::pointDisplayForPrint(PSCurve* curve)
{
    STDisplayTimeCurveObjectIterator it(timeObjectList);
    STDisplayTimeCurveObject *displayObject;

    while((displayObject = it.next()) != NULL)
	displayObject->pointDisplayForPrint(curve);
}

void STimeCompoundObject::yaxisPrint (PSCurve* curve)
{
    STDisplayTimeCurveObject *displayObject = timeObjectList.first();
    displayObject->yaxisPrint(curve);
}

void STimeCompoundObject::psPrint (FILE *fp)
{
    int smoothing = 0;
    STDisplayTimeCurveObject *displayObject = timeObjectList.first();
  
    ITime tmin,tmax ;
    timePlotter->getTimeBounds(tmin,tmax);
  
    ITime tcur = timePlotter->getCurrentTime();
  
    PSCurve curve(fp);
    curve.setCaract(getPixXMax(),getPixYMax(),tmin,tmax,
		    pixY(displayObject->getYMin()),
		    pixY(displayObject->getYMax()));
  
    curve.addXAxisString(tmin,ETime(tmin,USec).format());
    if (tcur < tmax) curve.addXAxisString(tcur,ETime(tcur,USec).format());
    curve.addXAxisString(tmax,ETime(tmax,USec).format());

    yaxisPrint(&curve);
  
    scale();
  
    curve.beginPrint(title,smoothing);

    pointDisplayForPrint(&curve);
  
    curve.endPrint();
}

int STimeCompoundObject::getPixXMax() 
{ 
    return timeObjectList.first()->getPixXMax();
}

int STimeCompoundObject::getPixYMax() 
{ 
    return timeObjectList.first()->getPixYMax();
}

void STimeCompoundObject::setPixXMax(int pxmax)
{
    STDisplayTimeCurveObjectIterator it(timeObjectList);
    STDisplayTimeCurveObject *displayObject;

    while((displayObject = it.next()) != NULL)
	displayObject->setPixXMax(pxmax);

    roundedXMax = getPixXMax();
}

void STimeCompoundObject::setPixYMax(int pymax)
{

    STDisplayTimeCurveObjectIterator it(timeObjectList);
    STDisplayTimeCurveObject *displayObject;

    while((displayObject = it.next()) != NULL)
	displayObject->setPixYMax(pymax);
}

int STimeCompoundObject::getMinPixYMax()
{
    return timeObjectList.first()->getMinPixYMax();
}

int STimeCompoundObject::pixY(double y)
{
    return timeObjectList.first()->pixY(y);
}

