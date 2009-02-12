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
 * Contributor(s): rpm
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifdef __GNUG__
#pragma implementation
#endif // __GNUG__
#include <xeno_config.h>
#include <math.h>
#include <string.h>
#include <ctype.h>
#include "vmutils/clock.h"

ITime MvmClock;

const double TimeValue[] = { 1.0, 1.e3, 1.e6, 1.e6, 6.e7, 36.e8, 864.e8 };

double USecByTick = 1.0;

const int MaxTimeValues = sizeof(TimeValue) / sizeof(TimeValue[0]);

ITime TickValue(ETime(USecByTick,USec));

const char *TimeString[] = { "usc","msc","sec", "cal", "min", "hr", "day", 0 };

const char *DisplayTimeString[] = { "u","ms","s", "s", "mn", "h", "d" };

const ETime ZEROETIME(0,USec);

const ETime MAXETIME(infinity(),USec);

const ITime NOW(ZEROETIME),
    ZEROTIME(ZEROETIME),
    MAXITIME(MAXETIME),
    NEGTIME(ETime(-1.0,USec));

ETimeUnits defaultETimeUnit = USec;

int DefaultETimeIsPos = 0;

ITime DisplayTick = TickValue;

int DisplayTickIsPos = 0;

CString DisplayTimeBuf;

void setDefaultETimeUnit(ETimeUnits unit)

{
    if (!DefaultETimeIsPos)
	defaultETimeUnit = unit;
}

void setDefaultETimeUnit (const char *dus)

{
    CString unit(dus);

    if (unit.isVoid() || unit.isEmpty())
	return;

    unit.downCase();

    DefaultETimeIsPos = 1;	// be optimistic...

    for (int i = 0; TimeString[i]; i++)
	{
	if (strncmp(unit,TimeString[i],strlen(TimeString[i])) == 0)
	    {
	    defaultETimeUnit = (ETimeUnits)i;
	    return;
	    }
	}

    // try another way
    switch (unit[0])
	{
	case 'D':
	    defaultETimeUnit = TDay;
	    break;

	case 'H':
	    defaultETimeUnit = THour;
	    break;

	case 'M':
	    defaultETimeUnit = TMinute;
	    break;

	case 'C':			// calendar unit is identical to second
	case 's':			// except that it is expressed since Jan
	    defaultETimeUnit = Sec;	// 1st 1970 (Unix time).
	    break;

	case 'm':
	    defaultETimeUnit = MSec;
	    break;

	case 'u':
	    defaultETimeUnit = USec;
	    break;

	default: 
	    DefaultETimeIsPos = 0;	// missed, sorry
	    break;
	}
}

void setDtTick(ETime dt)

{
    USecByTick = dt.usc();
    TickValue = dt;
}

ITime getDtTick()

{ return TickValue; }

int decodeTimeRange (const char *paramString,
		     ITime& stime,
		     ITime& etime)
{
    CStringTok s(paramString);
    const char *timeString;

    timeString = s.getNextTok('-');

    if (*timeString)
	{
	if (stime.scan(timeString) > 0)
	    {
	    timeString = s.getNextTok('\0');

	    if (timeString)
		etime.scan(timeString);

	    return 1;
	    }
	}
    else if (*paramString == '-')
	{
	// If the timepec starts with a dash, collect the closing
	// bound, leaving the starting bound untouched.
	etime.scan(paramString + 1);
	return 1;
	}

    return 0;
}

int decodeTimeBounds (const char *paramString,
		      ITime& stime,
		      ITime& etime,
		      ITime& lbound,
		      ITime& rbound)
{
    CStringTok s(paramString);
    const char *bounds = s.getNextTok(",/:");

    if (!*bounds)
	return 0;
    
    stime = ZEROTIME;
    etime = MAXITIME;
    lbound = ZEROTIME;
    rbound = MAXITIME;

    if (strlen(bounds) < s.len())
	{
	if (decodeTimeRange(bounds,stime,etime) == 0)
	    return 0;

	bounds = s.getNextTok('\0');
	}

    if (*bounds && decodeTimeRange(bounds,lbound,rbound) == 0)
	return 0;

    return stime <= etime && lbound <= rbound;
}

ETime::ETime ()
    
{
    val = 0.0;
    unit = defaultETimeUnit;
}

ETime::ETime(double t, ETimeUnits u)

{
    val = t * TimeValue[u];
    unit = u;
}

ETime::ETime(double t, const char *su)

{
    ETimeUnits u = TInvalid;
    
    for (int i = 0; TimeString[i]; i++)
	{
	if (strcasecmp(TimeString[i],su) == 0)
	    {
	    u = (ETimeUnits)i;
	    break;
	    }
	}

    if (u == TInvalid)
	u = USec; // default when invalid
    
    val = t * TimeValue[u];
    unit = u;
}

ETime::ETime(double t, ETimeUnits u, int)

{
    val = t;
    unit = u;
}

ETime::ETime(const ITime& t)

{
    val = t.val;
    unit = defaultETimeUnit;
}

ETime::ETime(const ITime& t, ETimeUnits _unit)

{
    val = t.val;
    unit = _unit;
}

ETime &ETime::operator = (const ITime &it)

{
    val = it.getUSec();
    unit = defaultETimeUnit;

    return *this;
}

double ETime::getVal () const

{ return val/TimeValue[unit]; }

ETime& ETime::usc() { unit = USec; return *this; }

ETime& ETime::msc() { unit = MSec; return *this; }

ETime& ETime::sec() { unit = Sec; return *this; }

ETime& ETime::minute() { unit = TMinute; return *this; }

ETime& ETime::hour() { unit = THour; return *this; }

ETime& ETime::day() { unit = TDay; return *this; }

ETime& ETime::std() { unit = defaultETimeUnit; return *this; }

ETime& ETime::setUnit(ETimeUnits u) { unit = u; return *this; }

ETime ETime::operator-() const { return ETime(-val,unit,0); }

ETime ETime::operator+(const ETime& t) const	{ return ETime(val + t.val,unit,0); }

ETime ETime::operator-(const ETime& t) const	{ return ETime(val - t.val,unit,0); }

ETime ETime::operator+(const ITime& t) const { return ETime(val + t.val,unit,0); }

ETime ETime::operator-(const ITime& t) const { return ETime(val - t.val,unit,0); }

double ETime::operator/(const ITime& it) const	{ return val / it.val; }

ETime& ETime::operator+=(const ITime& t)	{ val += t.val; return *this; }

ETime& ETime::operator-=(const ITime& t)	{ val -= t.val; return *this; }

ETime::operator int () const

{ return (int)(val/TimeValue[unit]); }

ETime::operator double () const

{ return val/TimeValue[unit]; }

ETime::operator time_t() const
{
    double temp = val/TimeValue[Sec];
    time_t t = (time_t)temp;
    return t;
}

const char *ETime::format (const char *suffix) const

{
    if (getUnit() == TCalendar)
	{			// format an absolute calendar date
	time_t unixTime = (time_t)*this;
  	struct tm *tm = localtime(&unixTime);

	DisplayTimeBuf.format("%.2d-%.2d-%.4d %.2d:%.2d:%.2d%s",
			      tm->tm_mon + 1,
			      tm->tm_mday,
			      tm->tm_year + 1900,
			      tm->tm_hour,
			      tm->tm_min,
			      tm->tm_sec,
			      suffix ? suffix : "");

 	return DisplayTimeBuf;
	}

    return ITime(getUSec()).format(suffix,getUnit());
}

ETime ITime::usc() const { return ETime(val, USec); }

ETime ITime::msc() const { return ETime(val, MSec); }

ETime ITime::sec() const { return ETime(val, Sec); }

ETime ITime::minute() const { return ETime(val, TMinute); }

ETime ITime::hour() const { return ETime(val, THour); }

ETime ITime::day() const { return ETime(val, TDay); }

ETime ITime::std() const { return ETime(*this); }

double ITime::getTicks() const { return val / USecByTick; }

ITime ITime::operator-() const			{ return ITime(-val); }

ITime ITime::operator+(const ITime& t) const	{ return ITime(val + t.val); }

ITime ITime::operator-(const ITime& t) const	{ return ITime(val - t.val); }

ITime ITime::operator+(const ETime& t) const	{ return ITime(val + t.val); }

ITime ITime::operator-(const ETime& t) const	{ return ITime(val - t.val); }

ITime ITime::operator*(double k) const		{ return ITime(val * k); }

ITime ITime::operator/(double k) const		{ return ITime(val / k); }

ITime ITime::operator%(const ITime& t) const	{ return ITime(remainder(val,t.val)); }

ITime& ITime::operator =(const ITime& t) { val = t.val; return *this; }

ITime getDisplayTick()

{ return DisplayTick; }

void setDisplayTick (ETime dt)

{
    if (!DisplayTickIsPos && dt > ZEROETIME)
	DisplayTick = dt.usc();
}

void setDisplayTick (double dt, ETimeUnits du)

{
    if (dt > 0.0)
	{
	DisplayTick = ETime(dt,du);
	DisplayTickIsPos = 1;
	}
}

void setDisplayTick (const ITime& dtick)

{
    if (dtick > ZEROTIME)
	{
	DisplayTick = dtick;
	DisplayTickIsPos = 1;
	}
}

const char *ITime::format (const char *suffix,
			   ETimeUnits timeUnit) const
{
    ETimeUnits formatUnit = timeUnit;

    if (formatUnit == TCalendar)
	{
	// format a duration using the most appropriate unit.
 
	formatUnit = USec;

	for (int unit = MaxTimeValues - 1; unit >= 0; unit--)
	    {
	    if (val >= TimeValue[(ETimeUnits)unit])
		{
		formatUnit = (ETimeUnits)unit;
		break;
		}
	    }
	}

    double tick  = ETime(1.0,formatUnit).usc();
    double dtick = getDisplayTick();
    double left = floor(getUSec()/tick);
    double rem  = getUSec() - left * tick;
    double pInt;
    int count;

    DisplayTimeBuf = emptyString;

    if (left == 0.0)
	{
	if (tick == USecByTick && rem > 0.0)
	    {
	    DisplayTimeBuf.format("%.3f",getUSec());
	    rem = 0.0;
	    }
	else
	    DisplayTimeBuf = "0";
	}
    else if (left != infinity())
	{
	count = 0;
	while (left > 0.0)
	    {
	    pInt = floor(left/10.0);
	    DisplayTimeBuf += left - pInt*10.0;
	    left = pInt;
	    if (++count == 3 && left > 0.0)
		{ count = 0; DisplayTimeBuf += " "; }
	    }
	DisplayTimeBuf.reverse();
	}
    else
	{
	DisplayTimeBuf = "inf";
	goto done;
	}

    if (tick == USecByTick && rem > 0.0)
	DisplayTimeBuf.cformat(".%03.0f",rem * 1000);
    else
	{
	if (tick > dtick)
	    DisplayTimeBuf += ".";

	count = 0;
	while (tick > dtick)
	    {
	    tick /= 10.0;
	    pInt = floor(rem/tick);
	    DisplayTimeBuf += int(pInt);
	    rem -= pInt*tick;
	    if (++count == 3 && tick > dtick)
		{ count = 0; DisplayTimeBuf += " "; }
	    }
	}

    DisplayTimeBuf += " ";
    DisplayTimeBuf += DisplayTimeString[formatUnit];

 done:

    if (suffix)
	DisplayTimeBuf += suffix;

    return DisplayTimeBuf;
}

const char *ITime::format (const char *suffix) const
    
{ return format(suffix,defaultETimeUnit); }

const char *ITime::formatHMS (const char *suffix) const

{
    double s = floor(val / 1000000.0);
    double ms = floor((val - (s * 1000000.0)) / 100000.0);
    
    double h = floor(s / 3600.0);
    double m = floor(s / 60.0 - h * 60.0);
    s -= (m * 60.0 - h * 3600.0);

    if (h > 0.0)
	DisplayTimeBuf.format("%dh %d' %d''",int(h),int(m),int(s));
    else if (m > 0.0)
	DisplayTimeBuf.format("%d' %d'' %d",int(m),int(s),int(ms));
    else if (ms > 0)
	DisplayTimeBuf.format("%d'' %d",int(s),int(ms));
    else
	DisplayTimeBuf.format("%d''",int(s));

    DisplayTimeBuf += suffix;

    return DisplayTimeBuf;
}

int ITime::scan (const char *s)

{
    CString cs(s);
    double _val;
    unsigned n;

    cs.removeSurroundingSpaces();
    n = cs.readDouble(_val);

    if (n > 0)
	{
	ETimeUnits unit;
	
	if (n == cs.len())
	    unit = defaultETimeUnit;
	else
	    {
	    while (isspace(cs[n]))
		n++;
	    
	    switch (tolower(cs[n]))
		{
		case 's' : unit = Sec; break;
		case 'm' : unit = MSec; break;
		case 'u' : unit = USec; break;
		default: return 0;
		}
	    }

	*this = (ITime)ETime(_val,unit);
	return 1;
	}

    return 0;
}
