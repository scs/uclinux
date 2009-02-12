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
 * Author(s): tm
 * Contributor(s): chris
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifdef __GNUG__
#pragma implementation
#endif // __GNUG__
#include <xeno_config.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <math.h>
#include "postscript.h"

static int pScale (double x, double xmin, double xmax, int pmax)

{
    return xmax - xmin > 0.0 ?
	(int)(((double)(pmax) / (xmax - xmin) ) * (x - xmin)) : 0;
}

PSAxisPoint::PSAxisPoint(double v, const CString& vp, PSAxisPointList *axis, int _incr)
    : incr(_incr), val(v), valPrint(vp)
{ axis->append(this); }

int PSAxisPoint::compare (Link *buddy)

{
    PSAxisPoint *pspoint = (PSAxisPoint *)buddy;
    if (incr) {
    return val < pspoint->val ? -1 : val == pspoint->val ? 0 : 1;
    } else {
    return val > pspoint->val ? -1 : val == pspoint->val ? 0 : 1;
    }
}

YAxisStrings::YAxisStrings (int pxmax, int pymax, YAxisStringsList *q)
    : pixXMax(pxmax), pixYMax(pymax)

{ q->append(this); }

YAxisStrings::~YAxisStrings ()

{ yStringsList.destroy(); }

void YAxisStrings::addString (const char *ys)

{ new LString(&yStringsList,ys); }

void YAxisStrings::addDouble (double vp, const char *format)

{
    CString s(vp,format);
    new LString(&yStringsList,s);
}

PSPlotter::PSPlotter (const char *file)

{
    fileName = file;
    fileName.expand();
    fp = fopen(fileName,"w");
    headerPath = TkContext::installRootDir;
    headerPath += "/share/plotter.ps";
    headerPath.expand();
}

PSPlotter::~PSPlotter ()

{
    xAdjust.destroy();
    fclose(fp);
}

const char *PSPlotter::printProlog (const char *title,
				    const char *footer,
				    double fontSize,
				    double inBetweenCurve,
				    double extraLine,
				    int dpi)
{
    if (!fp)
	return "Failed to open temporary file.";

    FILE *hfp = fopen(headerPath,"r");

    if (!hfp)
	return "Failed to open PostScript header plotter.ps.";

    int c;
    while (EOF != (c = getc(hfp)))
	putc(c,fp);
    fclose(hfp);

    fprintf(fp,"\nTKPLOT begin\n");

    if (footer)
	fprintf(fp,"/FooterStr (%s) def\n",footer);

    fprintf(fp,"/DisplayScaleFont %f def\n",fontSize);
    fprintf(fp,"/InBetweenCurve %f def\n",inBetweenCurve);
    fprintf(fp,"/ExtraLine %f def\n",extraLine);
    fprintf(fp,"end\n\n");
    fprintf(fp,"[%d] Dpi\n\n",dpi);

    time_t t;
    time(&t);

    if (title)
	fprintf(fp,"[(%s) (%s)]\n\n\n",title,ctime(&t));

    printXAdjust();

    return 0;
}

void PSPlotter::printEpilog ()

{
    fprintf(fp,"\n\nEndAllDrawings\n");
    fflush(fp);
}

void PSPlotter::printXAdjust ()

{
    if (!xAdjust.first())
	return;

    fprintf(fp,"[\n");

    for (YAxisStrings *cur = (YAxisStrings *)xAdjust.first(); cur; cur = (YAxisStrings *)cur->next())
	{
	fprintf(fp,"\t[\n");
	fprintf(fp,"\t\t%d\n",cur->pixXMax);
	fprintf(fp,"\t\t%d\n",cur->pixYMax);
	fprintf(fp,"\t\t[\n");

	for (LString *sl = (LString *)cur->yStringsList.first(); sl; sl = (LString *)sl->next())
	    {
	    fprintf(fp,"\t\t\t(");
	    fprintf(fp,"%s",sl->gets());
	    fprintf(fp,")\n");
	    }

	fprintf(fp,"\t\t]\n");
	fprintf(fp,"\t]\n");
	}

    fprintf(fp,"]\n");
    fprintf(fp,"CalcDisplayAdjust\n\n\n");
}

void PSPlotter::send2printer (const char *lpName)

{
    CString cmd;
    cmd.format("lpr -h -P'%s' %s",(const char *)lpName,(const char *)fileName);

    FILE *cmdfp = popen(cmd,"r");
    char buf[BUFSIZ];
    while (fgets(buf,sizeof(buf),cmdfp)) // discard command output
	;
    pclose(cmdfp);
}

void PSCurve::addXAxisDouble (double v, double vp, const char *form)

{
    CString s(vp,form);
    new PSAxisPoint(v,s,&xAxis);
}

void PSCurve::addXAxisString(double v, const char *vp)

{ new PSAxisPoint(v,vp,&xAxis); }

void PSCurve::addYAxisDouble (double v, double vp, const char *form)

{
    CString s(vp,form);
    new PSAxisPoint(v,s,&yAxis,0);
}

void PSCurve::addYAxisString (double v, const char *vp)

{ new PSAxisPoint(v,vp,&yAxis,0); }

void PSCurve::printYAxis ()

{
    fprintf(fp,"\t\t[\n");
    fprintf(fp,"\t\t\t%d\n",pixYMax);
    fprintf(fp,"\t\t\t[\n");

    for (PSAxisPoint *cur = (PSAxisPoint *)yAxis.first(); cur; cur = (PSAxisPoint *)cur->next())
	{
	if ( finite(cur->val) )
	    fprintf(fp,"\t\t\t\t[ %d %0.2f (%s)]\n",pScale(cur->val,ymin,ymax,pixYMax),cur->val,(const char *)cur->valPrint);
	else if (cur->val < 0.0)
	    fprintf(fp,"\t\t\t\t[ %d %d (%s)]\n",0,0,(const char *)cur->valPrint);
	else
	    fprintf(fp,"\t\t\t\t[ %d %d (%s)]\n",pixYMax,pixYMax,(const char *)cur->valPrint);
	}

    fprintf(fp,"\t\t\t]\n");
    fprintf(fp,"\t\t]\n");
}

void PSCurve::printXAxis ()

{
    fprintf(fp,"\t\t[\n");
    fprintf(fp,"\t\t\t%d\n",pixXMax);
    fprintf(fp,"\t\t\t[\n");
    
    for (PSAxisPoint *cur = (PSAxisPoint *)xAxis.first(); cur; cur = (PSAxisPoint *)cur->next())
	{
	if (finite(cur->val))
	    fprintf(fp,"\t\t\t\t[ %d %0.2f (%s)]\n",pScale(cur->val,xmin,xmax,pixXMax),cur->val,(const char *)cur->valPrint);
	else if (cur->val < 0.0)
	    fprintf(fp,"\t\t\t\t[ %d %d (%s)]\n",0,0,(const char *)cur->valPrint);
	else
	    fprintf(fp,"\t\t\t\t[ %d %d (%s)]\n",pixXMax,pixXMax,(const char *)cur->valPrint);
	}

    fprintf(fp,"\t\t\t]\n");
    fprintf(fp,"\t\t]\n");
}

void PSCurve::beginPrint (const char *title, int smoothing)

{
    xAxis.sort();
    yAxis.sort();
    fprintf(fp,"[\n");
    fprintf(fp,"\t[ %d (%s) ] \n",smoothing,title);
    fprintf(fp,"\t[\n");
    printYAxis();
    printXAxis();
    fprintf(fp,"\t]\n");
    fprintf(fp,"]\n");
    fprintf(fp,"InitCurve\n\n");
    printStartPoint(xmin,ymin);
}

void PSCurve::endPrint ()

{ fprintf(fp,"EndCurve\n\n\n"); }

void PSCurve::printStartPoint (double x, double y)

{
    fprintf(fp,"%d %d ip\n",
	    pScale(x,xmin,xmax,pixXMax),
	    pScale(y,ymin,ymax,pixYMax));
}

void PSCurve::printPoint (double x, double y)

{
    fprintf(fp,"%d %d dp\n",
	    pScale(x,xmin,xmax,pixXMax),
	    pScale(y,ymin,ymax,pixYMax));
}

void PSCurve::directStart (int x, int y)

{  fprintf(fp,"%d %d ip\n",x,y); }

void PSCurve::directPrint (int x, int y)

{ fprintf(fp,"%d %d dp\n",x,y); }

void PSCurve::setDash (int dash)

{
    if (dash)
	fprintf(fp,"%d DashedPattern\n",dash);
    else
	fprintf(fp,"SolidPattern\n");
}

int PSPrint::calcReduction (STDisplayObjectGList& objectsList)

{
    int ok = 1;
    const double USABLE_HEIGHT = 745;	// page height
    
    ExtraLine = 1.0;	// given in FontHeight units
    InBetweenCurves = 1.2;

    double sumPixYMax = 0, sumFont = 0;

    STDisplayObjectIterator it(objectsList);
    STDisplayObject *displayObject;

    while ((displayObject = it.next()) != NULL)
	{
	if (displayObject->getPrintMe())
	    {
	    sumPixYMax += (double)displayObject->getPixYMax();  // get total of PixYMax
	    STDisplayCurveObject *displayCurveObject = (STDisplayCurveObject *)displayObject;
	    sumFont += (displayCurveObject->getYValue(0) < 0 ? 2 * ExtraLine : ExtraLine) + InBetweenCurves;
	    }
	}

    reduction = (sumPixYMax + (sumFont * fontHeight * fontHeight)) / USABLE_HEIGHT;
    
    if (reduction < 1.0)
	reduction = 1.0;
    else
	{
	it.reset();

	while ((displayObject = it.next()) != NULL)
	    {
	    if (displayObject->getPrintMe())
		if ((double(displayObject->getPixYMax()) / reduction) < displayObject->getMinPixYMax())
		    {
		    reduction = double(displayObject->getPixYMax()) / double(displayObject->getMinPixYMax());
		    ok = 0;
		    }
	    }
	}

    return ok;
}

const char *PSPrint::toPS (STDisplayObjectGList& objectsList,
			   const char *fileName,
			   const char *title,
			   const char *footer,
			   TkPlotterViewModes format)
{
    PSPlotter psplot(fileName);

    int dpi = 300;

    const double MIN_FONT_HEIGHT = 6;
    const double MAX_FONT_HEIGHT = 10;

    ExtraLine = 1.0;// given in FontHeight units
    InBetweenCurves = 1.5;
    
    switch(format)
	{
	case Uncompressed :

	    fontHeight = MAX_FONT_HEIGHT;
	    reduction = 1.0;
	    break;
	
	case Compressed :

	    fontHeight = MAX_FONT_HEIGHT;

	    while (fontHeight > MIN_FONT_HEIGHT && !calcReduction(objectsList))
		{ fontHeight -= 2.0; }

	    break;
	}

    // apply reduction factor

    STDisplayObjectIterator it(objectsList);
    STDisplayObject *displayObject;

    while ((displayObject = it.next()) != NULL)
	{
	if (displayObject->getPrintMe()) /* make sure this a graph we want to print (because of compounds) */
	    {
	    displayObject->setPixXMax(displayObject->getPixXMax() * dpi / 72);
	    displayObject->setPixYMax((int)((displayObject->getPixYMax() * dpi / 72) / reduction));
	    }
	}

    it.reset();

    while ((displayObject = it.next()) != NULL)
	{
	if (displayObject->getPrintMe())
	    {
	    YAxisStrings *yas = psplot.addYAxisStrings(displayObject->getPixXMax(),displayObject->getPixYMax());
	    displayObject->psYStrings(yas->getStringsQ());
	    }
	}
    
    const char *emsg = psplot.printProlog(title,
					  footer,
					  fontHeight,
					  InBetweenCurves,
					  ExtraLine);
    if (emsg)
	return emsg;

    it.reset();

    while ((displayObject = it.next()) != NULL)
	{
	if (displayObject->getPrintMe())
	    displayObject->psPrint(psplot.getfp());
	}

    psplot.printEpilog();
    //    psplot.send2printer(lpName);

    return (const char *)0;
}

PSTimeCurveFrame::PSTimeCurveFrame (const char *title,
				    const char *footer,
				    const char* fileName,
				    TkTimeCurvePlotter *tplotter,
				    CString& error,
				    TkPlotterViewModes format) :
    TkTimeCurvePlotter(title,
		       tplotter->getFrame(),
		       tplotter->getSettings(),
		       (TkContext*)tplotter->getFrame(),
		       ZEROTIME)
{
    ITime tmin,tmax;
    tplotter->getTimeBounds(tmin,tmax);

    tMin = tmin;
    tMax = tmax;
    tAll = tMax;
    tCur = tplotter->getCurrentTime();

    STDisplayObjectIterator it(tplotter->getAllObjectList());
    STDisplayObject *displayObject;

    while ((displayObject = it.next()) != NULL)
	{
	if (displayObject->getPrintMe())
	    displayObject->psCopy(this);
	}

    const char *emsg;
    if ((emsg = toPS(allObjectGList,
		     fileName,
		     title,
		     footer,
		     format)) != NULL)
	error = emsg;
    else 
	error = "";
    
}

PSTimeCurveFrame::~PSTimeCurveFrame ()

{ allObjectGList.destroy(); }

PSCurveFrame::PSCurveFrame (const char *title,
			    const char *footer,
			    const char* fileName,
			    TkCurvePlotter *plotter,
			    CString& error,
			    TkPlotterViewModes format) :
    TkCurvePlotter(title,
		   plotter->getFrame(),
		   plotter->getSettings(),
		   (TkContext*)plotter->getFrame(),
		   100)
{
    setPixXMax(getPixXMax() * 300 / 72);

    STDisplayObjectIterator it(plotter->getAllObjectList());
    STDisplayObject *displayObject;

    while ((displayObject = it.next()) != NULL)
	{
	if (displayObject->getPrintMe())
	    displayObject->psCopy(this);
	}

    const char *emsg = toPS(allObjectGList,
			    fileName,
			    title,
			    footer,
			    format);
    if (emsg)
	error = emsg;
    else 
	error = "";
}

PSCurveFrame::~PSCurveFrame ()

{ allObjectGList.destroy(); }

PSCurve::PSCurve (FILE *_fp)
    : fp(_fp),
      pixXMax(1750), pixYMax(1000),
      xmin(0.0), xmax(0.0),
      ymin(0.0), ymax(0.0)
{}

PSCurve::~PSCurve()

{
    xAxis.destroy();
    yAxis.destroy();
}
