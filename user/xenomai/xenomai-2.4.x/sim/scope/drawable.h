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
 * Contributor(s): chris, gt, rpm
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifndef _drawable_h
#define _drawable_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include "vmutils/statobj.h"
#include "bridge.h"

#define STDISPLAY_FRAME_LOGSZ 		2000
#define STDISPLAY_CURVE_PIXXMIN	        100
#define STDISPLAY_CURVE_PIXYMIN	        20
#define STDISPLAY_FRAME_PIXXMIN		200
#define	STDISPLAY_FRAME_PIXYMIN		50
#define STDISPLAY_FRAME_PIXXBYDT	2
#define STDISPLAY_HISTOGRAM_BINWIDTHMIN	4

class TkPlotter;
class TkCurvePlotter;
class TkTimeCurvePlotter;

class PSCurve;

// Basic display objects

struct STDisplayPixelPoint {

    double x;
    double y;
};

class STDisplayObject :  public TkContext , public LinkedObject {
    friend class TkPlotter;

protected:

    int roundedXMax;

    int isDisplayed;
    int isMapped;
    int pixXMax;		// object width (pixels)
    int pixYMax;		// max. object height (pixels)
    int pixYMin;		// min. object height (pixels)
    int lastPixYMax;	// pixXMax before compression
    TkPlotter *plotter;	// host plotter

    // These are miscellaneous object's positions since last
    // redraw().
    int ytop,	// y-top of object
	xtop;	// x-start of object
  
    MvmInterface *proto; // protocol side of the encapsulating object
    // (sorry, but virtual base completely wrecks
    // GList scheme)
    int printMe;
  
public:
  
    int getPrintMe() {return printMe;}
    void setPrintMe(int pme) { printMe = pme;}

    int getIsMapped() { return isMapped; }
    STDisplayObject(TkPlotter *plotter);
    virtual ~STDisplayObject();
  
    virtual int getPixXMax() { return pixXMax; }
    virtual int getPixYMax() { return pixYMax; }
    int getPixYMin() { return pixYMin; }
    TkPlotter *getPlotter() { return plotter; }
    void setProto(MvmInterface *_proto) { proto = _proto; }
    MvmInterface *getProto() { return proto; }
    void setDisplayBounds(int _ytop,
			  int _xtop)
    { ytop = _ytop;
    xtop = _xtop;}
    int getYTop() { return ytop; }
    int getXTop() { return xtop; }

    virtual void setPixXMax(int);
    virtual void setPixYMax(int);
    virtual int  getMinPixYMax() { return pixYMin;};
    virtual void display(TclList*);	// empty (for use with GList::apply())
  
    virtual void scale();	// empty

    virtual CString makeYStr(double tdrag, int y, double val =0.0);
    virtual double getY(int pixy);
    virtual void notify(TkEvent event, int argc, char *argv[], TkClientData clientData);

    virtual void getConf(TclList*) = 0;
    virtual void getProperties(TclList*);
    virtual void setConf(int argc, char *argv[]) = 0;

    virtual void pointDisplayForPrint(PSCurve*);
    virtual void yaxisPrint(PSCurve*);
    virtual void psPrint(FILE *);
    virtual STDisplayObject* psCopy(TkPlotter *);
    virtual void psYStrings(CStringList *l);
};

MakeGList(STDisplayObject);

class STDisplayCurveObject : public STDisplayObject {

    friend class TkCurvePlotter;

protected:

    double xMax;		//	valeur max affichee en X
    double xMin;		//	valeur min affichee en X
    double xScale;		//	echelle en x pour calcul des pix
    double yMax;		// 	valeur max affichee en Y
    double yMin;		//	valeur min affichee en Y
    double yScale;		//	echelle en x pour calcul des pix
    STDisplayPixelPoint *points; //	tableau des pixels x a afficher
    int nPointDisplayed;	     //	nb de points effectivement affiches
    int nMaxPointDisplayed;
    int okYAdjust;	//	ajustement automatique a yMin et yMax

public:
  
    STDisplayCurveObject(TkCurvePlotter *plotter);
    STDisplayCurveObject(STDisplayCurveObject*,TkCurvePlotter *); // used for PostScript printing


    virtual ~STDisplayCurveObject();
  
    virtual void getPointsToDisplay(TclList*, int check=1) = 0; 
    void reDrawPlotWithPts(TclList*);
  
    virtual double getYMin() { return yMin; }
    virtual double getYMax() { return yMax; }
    double getXMin() { return xMin; }
    double getXMax() { return xMax; }
    int autoYAdjust() { return okYAdjust; }
  
    void setXScale();
    double _pixX(double);
    double pixX(double);
    double _pixX(double, double, double);
    double pixX(double, double, double);
    void setYScale();
    int _pixY(double);
    int pixY(double);
    int getNPointDisplayed() { return nPointDisplayed; }
    void drawData(int okDrawYZero, TclList*);
  
    virtual void setPixXMax(int);
    virtual void setPixYMax(int);
    virtual double getXValue(int);
    virtual void setYBounds(double, double, int setYBoundsDone=0);
    virtual double getYValue(int);
    virtual void setYAdjust(int);
    virtual int getYAdjust();
    virtual void setXBounds(double,double);
  
    virtual void pointDisplay(int pointNo, TclList*) =0;
    virtual void display(TclList*) =0;
    virtual void notify(TkEvent event, int argc, char *argv[], TkClientData clientData);

    virtual void getConf(TclList*) = 0;
    virtual void setConf(int argc, char *argv[]) = 0;
    virtual void getProperties(TclList*);

    virtual void pointDisplayForPrint(PSCurve*)=0;
    virtual void yaxisPrint(PSCurve*)=0;
    virtual void psPrint(FILE *fp) =0;
    virtual STDisplayObject* psCopy(TkPlotter *plotter) =0;
    virtual void psYStrings(CStringList *l) =0;

};

enum DisplayObjectType { TGraphObject, StateDiag, CompoundObj };

class STDisplayTimeCurveObject : public STDisplayCurveObject {
protected:

    DisplayObjectType myType;
    ITime dtUpdateMean;
    TkTimeCurvePlotter *timePlotter;
    STDisplayTimeCurveObject* contextForDrawing;
  
    int isFirstProtoInitMsg;

public:
  
    virtual ITime searchInLog(ITime t, int dir, int*) = 0;

    void addToPlot(TclList*, STDisplayTimeCurveObject*);
    void setContextForDrawing(STDisplayTimeCurveObject* _contextForDrawing) { contextForDrawing = _contextForDrawing; }
 
    virtual void getPointsToDisplay(TclList*, int check=1); 

    //  TclList* getPointList();
    DisplayObjectType getMyType() { return myType; }
    virtual ITime whatIsYourTime(ITime, int) = 0;
    virtual int checkYBounds(STDisplayTimeCurveObject*) = 0;

    STDisplayTimeCurveObject(TkTimeCurvePlotter *plotter);
    STDisplayTimeCurveObject(STDisplayTimeCurveObject*,
			     TkTimeCurvePlotter *plotter); // used for PostScript printing
  
    virtual ~STDisplayTimeCurveObject() {}
  
    virtual ITime getDtUpdate();
    virtual ITime getTOldest();
  
    ITime getCurrentTime();
    double getPixYCur() { return points[nPointDisplayed - 1].y; }
  
    virtual void display(TclList*) =0;
    virtual void pointDisplay(int pointNo, TclList*) =0;
    virtual void notify(TkEvent event, int argc, char *argv[], TkClientData clientData);

    virtual void displayUpdate(int x) =0;
  
    virtual double getMinYBounds() { return 0.0; }
    virtual double getMaxYBounds() { return 0.0; }
    virtual void getConf(TclList*) = 0;
    virtual void setConf(int argc, char *argv[]) = 0;
    virtual void getProperties(TclList*);
};

// MvmTimeGraphDisplay

class MvmTimeGraphDisplay : public MvmTimeGraph, public STDisplayTimeCurveObject {

protected:

    ITime dtDisplay;	// constante de temps affichage
    int iLag;		// dtDisplay/dtUpdate
    int iOld;
  
    double	iNextPoint,
	iMaxPoint,
	nVbyP,
	sLag;
  
    int okHasChanged;
  
    double lastY;
  
public:
  
    MvmTimeGraphDisplay(MvmTimeGraphExportMsg *exmsg,
			TkTimeCurvePlotter *tcplot,
			MvmFrontend *connector);
    MvmTimeGraphDisplay(MvmTimeGraphDisplay* src,
			TkTimeCurvePlotter *tcplot); // used for PostScript printing

  
    virtual ITime searchInLog(ITime t, int dir, int*);

    virtual void setYBounds(double, double, int setYBoundsDone=0);
    virtual ITime whatIsYourTime(ITime, int check);

    virtual int checkYBounds(STDisplayTimeCurveObject*) { return 1; }
    void add(double);
    void initPoint(double *, int, ITime, int);
    void addPoint(double);
    void addPoint(MvmTimeGraphPointMsg*, int);
    void setDtDisplay(ITime);
    void scale();
    ITime& getDtDisplay() { return dtDisplay; }
  
    ITime getDtUpdate();
    ITime getTOldest();
  
    virtual void ifProcess(int mtype, const struct MvmInterfaceMsg *gpm, int msize);
    virtual void display(TclList*);
    virtual void pointDisplay(int pointNo, TclList*);
    virtual CString makeYStr(double tdrag, int y, double val =0.0);
    virtual double getY(int pixy);
    virtual void notify(TkEvent event, int argc, char *argv[], TkClientData clientData);

    virtual void displayUpdate(int x) {}

    virtual double getMinYBounds() { return vMin; }
    virtual double getMaxYBounds() { return vMax; }
    virtual void getConf(TclList*);
    virtual void setConf(int argc, char *argv[]);
    virtual void getProperties(TclList*);

    virtual void pointDisplayForPrint(PSCurve*);
    virtual void yaxisPrint(PSCurve*);
    virtual void psPrint(FILE *fp);
    virtual STDisplayObject* psCopy(TkPlotter *);
    virtual void psYStrings(CStringList *l);
};

// MvmStateDiagramDisplay

#define STDISPLAY_SDIAGRAM_LOGSZ   1000
#define STDISPLAY_SDIAGRAM_PIXYMIN 5


class MvmStateDiagramDisplay : public MvmStateDiagram, public STDisplayTimeCurveObject {

protected:

    int iCur;
    double xDisp;

    double oldX;
    double oldY;
    int lastState;

public:

    MvmStateDiagramDisplay(MvmStateDiagramExportMsg *exmsg,
			   TkTimeCurvePlotter *tcplot,
			   int logSize,
			   MvmFrontend *connector);
    MvmStateDiagramDisplay(MvmStateDiagramDisplay* src,
			   TkTimeCurvePlotter *tcplot); // used for PostScript printing

    virtual ITime searchInLog(ITime t, int dir, int*);
    int search(ITime t, int imin, int imax);

    virtual int checkYBounds(STDisplayTimeCurveObject*);
    virtual ITime whatIsYourTime(ITime t, int check);

    int  getMinPixYMax() { return (getNStates() - 1) * pixYMin;}
    void addPoint(int, double);
    void addPoint(MvmStateDiagramPointMsg*, int);
    void setXBounds(double, double);
    void scale();

    ITime getDtUpdate();
    ITime getTOldest();

    virtual void ifProcess(int mtype, const struct MvmInterfaceMsg *gpm, int msize);
    virtual void display(TclList*);
    virtual void pointDisplay(int pointNo, TclList*);
    virtual CString makeYStr(double tdrag, int y, double val =0.0);
    virtual double getY(int pixy);
    virtual void notify(TkEvent event, int argc, char *argv[], TkClientData clientData);

    virtual void displayUpdate(int x);

    virtual void getConf(TclList*);
    virtual void setConf(int argc, char *argv[]);
    virtual void getProperties(TclList*);
    void initPoint (MvmStatePoint*, int, int);
    void add (double, int);

    virtual void pointDisplayForPrint(PSCurve*);
    virtual void yaxisPrint(PSCurve*);
    virtual void psPrint(FILE *fp);
    virtual STDisplayObject* psCopy(TkPlotter *);
    virtual void psYStrings(CStringList *l);
  

};

// MvmHistogramDisplay

enum MvmHistogramViewModes { GraphHistoREL, GraphHistoABS };

class MvmHistogramDisplay : public MvmHistogram, public STDisplayCurveObject {

protected:

    MvmHistogramViewModes viewMode;
    int nbInit;
    ITime tCur;
    int binWidthDef;
    int okXAdjust;
    int isStretched;


    int realPixXMax;

public:

    MvmHistogramDisplay(MvmHistogramExportMsg *exmsg,
			TkCurvePlotter *dcf,
			MvmFrontend *connector);
    MvmHistogramDisplay(MvmHistogramDisplay* src,
			TkCurvePlotter *dcf); // used for postscript display


    virtual void getPointsToDisplay(TclList*, int check=1); 

    void setPixXMax(int);

    void	initHistogram(struct MvmHistogramHeader *);
    void	initPoint(int*, int, int);
    void	setXBounds(double, double);
    void	setXAdjust(int);
    void	setViewMode(MvmHistogramViewModes);
    MvmHistogramViewModes getViewMode() { return viewMode; }
    void	scale();

    virtual void ifProcess(int mtype, const struct MvmInterfaceMsg *gpm, int msize);
    virtual void display(TclList*);
    virtual void pointDisplay(int pointNo, TclList*);
    virtual CString makeYStr(double tdrag, int y, double val =0.0);
    virtual double getY(int pixy);

    virtual void notify(TkEvent event, int argc, char *argv[], TkClientData clientData);

    virtual void getConf(TclList*);
    virtual void setConf(int argc, char *argv[]);
    virtual void getProperties(TclList*);

    virtual void pointDisplayForPrint(PSCurve*);
    virtual void yaxisPrint(PSCurve*);
    virtual void psPrint(FILE *fp);
    virtual STDisplayObject* psCopy(TkPlotter *);
    virtual void psYStrings(CStringList *l);


};


MakeGList(STDisplayTimeCurveObject);

class STimeCompoundObject : public STDisplayTimeCurveObject {
  
private:
    STDisplayTimeCurveObjectGList timeObjectList; 
    int nbObject;
    CString title;
    DisplayObjectType plotType ;

public:
    STimeCompoundObject(TkTimeCurvePlotter *tcplot);
    STimeCompoundObject(STimeCompoundObject* _src,
			TkTimeCurvePlotter *_tplotter);
    virtual ~STimeCompoundObject();

    virtual ITime searchInLog(ITime t, int dir, int*);
  
    int addObject(STDisplayTimeCurveObject*);
    int rmObject(STDisplayTimeCurveObject*, int);

    virtual int checkYBounds(STDisplayTimeCurveObject*);

    int getNbObject() { return nbObject; }
  
    virtual ITime whatIsYourTime(ITime, int);
  
    virtual ITime getDtUpdate();
    virtual ITime getTOldest();
  
    ITime getCurrentTime();
    double getPixYCur() { return points[nPointDisplayed - 1].y; }
  
    virtual void display(TclList*);
    virtual void pointDisplay(int pointNo, TclList*);
    virtual void notify(TkEvent event, int argc, char *argv[], TkClientData clientData);
  
    virtual void displayUpdate(int x);

    void scale();
  
    virtual void getPointsToDisplay(TclList*, int check=1);

    DisplayObjectType getDataType() { return plotType; }
  

    virtual double getMinYBounds();
    virtual double getMaxYBounds();
    virtual void setYBounds(double ymin, double ymax, int setYBoundsDone=0);

    virtual double getYMin();
    virtual double getYMax();
  
    virtual void getConf(TclList*);
    virtual void setConf(int argc, char *argv[]);
    virtual void getProperties(TclList*);

    virtual void pointDisplayForPrint(PSCurve*);
    virtual void yaxisPrint(PSCurve*);
    virtual void psPrint(FILE *);
    virtual STDisplayObject* psCopy(TkPlotter *);
    virtual void psYStrings(CStringList *l);

    virtual int getPixXMax();
    virtual int getPixYMax();
    virtual void setPixXMax(int);
    virtual void setPixYMax(int);
    virtual int getMinPixYMax();
    virtual int pixY(double y);
};

#endif // _drawable_h
