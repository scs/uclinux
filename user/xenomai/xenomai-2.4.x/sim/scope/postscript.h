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
 * Author(s): tm
 * Contributor(s): chris
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifndef _postscript_h
#define _postscript_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include "plotter.h"

class PSPlotter;
class YAxisStrings;
class YAxisStringsList;
class PSCurve;
class PSAxisPointList;

class PSAxisPoint : public Link {

    friend class PSCurve;

private:

    int incr;
    double val;
    CString valPrint;

    PSAxisPoint(double v, const CString& vp, PSAxisPointList *axis, int _incr = 1);

public:

    virtual int compare(Link *buddy);
};

MakeList(PSAxisPoint);

class PSCurve {

    FILE *fp;

    int pixXMax,
        pixYMax;

    double   xmin,
	xmax,
	ymin,
	ymax;

    PSAxisPointList xAxis,
	yAxis;

    void sortAxis();
    void printYAxis();
    void printXAxis();

public:

    PSCurve(FILE *fp);
    virtual ~PSCurve();

    void setPixMax(int pxM, int pyM) { pixXMax = pxM; pixYMax = pyM; }
    void setXBounds(double xm, double xM) { xmin = xm; xmax = xM; }
    void setYBounds(double ym, double yM) { ymin = ym; ymax = yM; }

    void setCaract(int pxM, int pyM, double xm, double xM, double ym, double yM)
    { setPixMax(pxM,pyM); setXBounds(xm,xM); setYBounds(ym,yM); }

    void addXAxisDouble(double v, const char *form = (char *)0)
    { addXAxisDouble(v,v,form); }
    void addXAxisDouble(double v, double vp, const char *form = (char *)0);
    void addXAxisString(double v, const char *vp);

    void addYAxisDouble(double v, const char *form = (char *)0)
    { addYAxisDouble(v,v,form); }
    void addYAxisDouble(double v, double vp, const char *form = (char *)0);
    void addYAxisString(double v, const char *vp);

    void beginPrint(const char *title, int smoothing =0);
    void printStartPoint(double x, double y);
    void printPoint(double x, double y);
    void directStart(int x, int y);
    void directPrint(int x, int y);
    void setSolid() { setDash(0); }
    void setDash(int dash);
    void endPrint();
};

class YAxisStrings : public Link {

    friend class PSPlotter;

private:

    int pixXMax,
        pixYMax;

    CStringList yStringsList;

    YAxisStrings(int pxmax, int pymax, YAxisStringsList *q);
    ~YAxisStrings();

public:

    void addString(const char *ys);
    void addDouble(double vp, const char *form = (char *)0);

    CStringList *getStringsQ() { return &yStringsList; }
};

MakeList(YAxisStrings);

class PSPlotter {

private:

    CString headerPath;
    CString fileName;
    FILE *fp;
    YAxisStringsList xAdjust;

    void printXAdjust();

public:

    PSPlotter(const char *argv0);
    ~PSPlotter();

    FILE *getfp() { return fp; }
    YAxisStrings *addYAxisStrings(int pixXMax,int pixYMax)
    { return new YAxisStrings(pixXMax,pixYMax,&xAdjust); }

    const char *printProlog(const char *title,
			    const char *footer,
			    double fontSize = 10.0,
			    double inBetweenCurve = 1.0,
			    double extraLine = 1.0,
			    int dpi = 300);
    void printEpilog();
    void send2printer(const char *lpName);
};

class PSPrint {

protected:

    double ExtraLine,
	InBetweenCurves,
	fontHeight,
	reduction;

    int calcReduction(STDisplayObjectGList& olist);

    const char *toPS(STDisplayObjectGList& olist,
		     const char *argv0,
		     const char *title,
		     const char *footer,
		     TkPlotterViewModes format);
};

class PSTimeCurveFrame : public TkTimeCurvePlotter, public PSPrint {

public:

    PSTimeCurveFrame(const char *title,
		     const char *footer,
		     const char* fileName,
		     TkTimeCurvePlotter *tplotter,
		     CString& error,
		     TkPlotterViewModes format =Uncompressed);
    ~PSTimeCurveFrame();
};

class PSCurveFrame : public TkCurvePlotter, public PSPrint {

public:

    PSCurveFrame(const char *title,
		 const char *footer,
		 const char* fileName,
		 TkCurvePlotter *plotter,
		 CString& error,
		 TkPlotterViewModes format =Uncompressed);
		 
    ~PSCurveFrame();
};

struct AxisSort {

    double val;
    CString vp;
};

#endif // !_postscript_h
