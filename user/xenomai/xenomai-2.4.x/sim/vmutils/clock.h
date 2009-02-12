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

#ifndef _mvmutils_clock_h
#define _mvmutils_clock_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include <time.h>
#include "vmutils/string++.h"

class ITime;
class ETime;

enum ETimeUnits {
    USec, MSec, Sec,
    TCalendar, TMinute, THour, TDay,
    TInvalid
};

extern ETimeUnits defaultETimeUnit;

extern const double TimeValue[];

class ETime {

    friend class ITime;

 protected:

    double val;

    ETimeUnits unit;

    ETime(double, ETimeUnits, int);

 public:

    ETime();

    ETime(double, ETimeUnits);

    ETime(double, const char *unit);

    ETime(const ITime&);

    ETime(const ITime&, ETimeUnits);

    ETime &operator = (const ITime &);

    ETime& 	usc();

    ETime& 	msc();

    ETime& 	sec();

    ETime& 	minute();

    ETime& 	hour();

    ETime& 	day();

    ETime& 	std();

    ETime&	setUnit(ETimeUnits);

    ETimeUnits getUnit() const {
    return unit;
    }

    double getVal(void) const;

    double getUSec(void) const {
    return val;
    }

    ETime operator-() const;

    ETime operator+(const ETime&) const;

    ETime operator-(const ETime&) const;

    ETime operator+(const ITime&) const;

    ETime operator-(const ITime&) const;

    ETime operator*(double k) const {
    return ETime(val*k,unit,0);
    }

    friend ETime operator*(double k, const ETime& et) {
    return et*k;
    }

    ETime operator/(double k) const {
    return ETime(val/k,unit,0);
    }

    double operator/(const ETime& et) const {
    return val / et.val;
    }

    double operator/(const ITime&) const;

    ETime& operator+=(const ETime& t) {
    val += t.val; return *this;
    }

    ETime& operator-=(const ETime& t) {
    val -= t.val;
    return *this;
    }

    ETime& operator+=(const ITime& t);

    ETime& operator-=(const ITime& t);

    ETime& operator*=(double d)	{
    val *= d;
    return *this;
    }

    ETime& operator/=(double d)	{
    val /= d;
    return *this;
    }

    operator int() const;

    operator time_t() const;

    operator double() const;

    int operator<(const ETime& et) const {
    return val < et.val;
    }

    int operator>(const ETime& et) const {
    return val > et.val;
    }

    int operator<=(const ETime& et) const {
    return val <= et.val;
    }

    int operator>=(const ETime& et) const {
    return val >= et.val;
    }

    int operator==(const ETime& et) const {
    return val == et.val;
    }

    int operator!=(const ETime& et) const {
    return val != et.val;
    }

    const char *format(const char *suffix =0) const;
};

extern void setDtTick(ETime);

extern ITime getDtTick();

class ITime {

    friend class ETime;

 protected:

    double val;

 public:

    ITime() {
    val = 0.0;
    }

    ITime(const ETime& et) {
    val = et.val;
    }

    // BE AWARE that the time value you pass must be expressed
    // in USec. Generally speaking, avoid using constants such as
    // `1000000.0', use ETime(1,Sec).usc() instead.

    ITime(double t) {
    val = t;
    }

    operator double() const {
    return val;
    }

    double *getValAddr() {
    return &val;
    }

    // Do *not* define operator=(const ETime&) as it breaks many C++ cfronts
    ITime& operator=(const ITime& t);

    ETime usc() const;

    ETime msc() const;

    ETime sec() const;

    ETime minute() const;

    ETime hour() const;

    ETime day() const;

    ETime std() const;

    double  getTicks() const;

    double  getUSec() const {
    return val;
    }

    ITime& operator+=(const ITime& t) {
    val += t.val;
    return *this;
    }

    ITime& operator-=(const ITime& t) {
    val -= t.val;
    return *this;
    }

    ITime& operator+=(const ETime& t) {
    val += t.val;
    return *this;
    }

    ITime& operator-=(const ETime& t) {
    val -= t.val;
    return *this;
    }

    ITime& operator*=(double t)	{
    val *= t;
    return *this;
    }

    ITime& operator/=(double t) {
    val /= t;
    return *this;
    }

    ITime operator-() const;

    ITime operator+(const ITime& t) const;

    ITime operator-(const ITime& t) const;

    ITime operator+(const ETime& t) const;

    ITime operator-(const ETime& t) const;

    ITime operator*(double k) const;

    friend ITime operator*(double k, const ITime& t) {
    return t*k;
    }

    friend ITime operator*(int n, const ITime& t) {
	return t*(double)n;
    }

    ITime operator/(double k) const;

    ITime operator%(const ITime&) const; // remainder

    double operator/(const ITime& t) const {
    return val / t.val;
    }

    int operator>(const ITime& t) const {
    return (val>t.val);
    }

    int operator>=(const ITime& t) const {
    return (val>=t.val);
    }

    int operator<(const ITime& t) const {
    return (val<t.val);
    }

    int operator<=(const ITime& t) const {
    return (val<=t.val);
    }

    int operator==(const ITime& t) const {
    return (val==t.val);
    }

    int operator!=(const ITime& t) const {
    return (val!=t.val);
    }

    const char *format(const char *suffix,
		       ETimeUnits unit) const;

    const char *format(const char *suffix =0) const;

    const char *formatHMS(const char *suffix =0) const;

    int scan(const char *s);
};

extern double USecByTick;

extern const ETime ZEROETIME;

extern const ETime MAXETIME;

extern const ITime MAXITIME;

extern const ITime ZEROTIME;

extern const ITime NEGTIME;

extern const ITime NOW;

extern ITime TickValue;

extern const int MaxTimeValues;

extern const char *TimeString[8];

extern const char *DisplayTimeString[7];

extern int DefaultETimeIsPos;

extern ITime DisplayTick;

extern int DisplayTickIsPos;

extern CString DisplayTimeBuf;

extern void setDisplayTick(ETime dtick);

extern void setDisplayTick (const ITime& dtick);

extern void setDisplayTick(double dt, ETimeUnits du);

extern ITime getDisplayTick();

extern void setDefaultETimeUnit(ETimeUnits unit);

extern void setDefaultETimeUnit(const char *dus);

int decodeTimeRange(const char *paramString,
		    ITime& stime,
		    ITime& etime);

int decodeTimeBounds(const char *paramString,
		     ITime& stime,
		     ITime& etime,
		     ITime& lbound,
		     ITime& rbound);

#endif // !_mvmutils_clock_h
