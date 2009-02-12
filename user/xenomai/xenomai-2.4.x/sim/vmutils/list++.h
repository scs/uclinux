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
 * Author(s): tb
 * Contributor(s): rpm
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifndef _mvmutils_listplusplus_h
#define _mvmutils_listplusplus_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include <string.h>
#include <memory.h>
#include "vmutils/hash++.h"

#ifndef Max
#define Max(a,b)            ((a) < (b) ? (b) : (a))
#endif

#ifndef Min
#define Min(a,b)            ((a) > (b) ? (b) : (a))
#endif

#ifndef scopy
#define scopy(s1,s2,n)      strncpy(s1,s2,n)[n] = 0
#endif

#ifndef name2
#define name2(a,b) a ## b
#endif // !name2

class LinkedObject {

public:

    LinkedObject() {}

    virtual ~LinkedObject();

    virtual int compare(LinkedObject *buddy); // used in GList sorting,
    // should return -1 (this < buddy), 0 (this == buddy) or 1 (this > buddy)
};

class Link {

    friend class List;
    friend class PList;

protected:

    Link *_next;

    Link *_prev;

public:

    Link() {
	_next = _prev =  0;
    }

    virtual ~Link();

    Link *next() const {
	return _next;
    }

    Link *prev() const {
	return _prev;
    }

    Link *isLinked() const {
	return _next ? _next : _prev;
    }

    void setNext(Link *l) {
	_next = l;
    }

    void setPrev(Link *l) {
	_prev = l;
    }

    virtual int compare(Link *buddy); // used in List sorting
};

class List {

private:

    static int qsortCompareList(const void *e1,
				const void *e2);
protected:

    Link *_first;

    Link *_last;

    unsigned destroying : 1,
	count : 31;

public:

    List() {
	_first = _last = 0;
	count = 0;
	destroying = 0;
    }

    List(List&);

    virtual ~List();

    Link *last() const {
	return _last;
    }

    Link *first() const {
	return _first;
    }

    unsigned getCount() const {
	return count;
    }

    int isDestroying() const {
	return !!destroying;
    }

    Link *isLinked(Link*) const;

    Link *nth(int) const;

    Link *get();

    int  position(Link*) const;

    void append(Link *);

    void prepend(Link *);

    void remove(Link *);

    void insert(Link *, Link *);

    int moveTo(List& dst);

    virtual void sort();

    virtual void flush();

    virtual void destroy();
};

// NOTE: class TYPE must extend class Link

#define MakeList(TYPE) \
class name2(TYPE,List):public List { \
  public : \
  name2(TYPE,List) () : List() { }  \
  name2(TYPE,List) (name2(TYPE,List)& l) : List((List&)l) { } ; \
  TYPE *last() const { return (TYPE *) _last ;} \
  TYPE *first() const { return (TYPE *) _first ;} \
  TYPE *isLinked(TYPE* tl) const { return (TYPE*) List::isLinked(tl); } \
  TYPE *nth(int i) const { return (TYPE *) List::nth(i); } \
  TYPE *get() { return (TYPE*) List::get(); } \
  void apply(void (TYPE::*mf)()) \
  { TYPE *_xcurr; \
	for (_xcurr = (TYPE *)_first; _xcurr; _xcurr = (TYPE *)_xcurr->next()) \
	    ((_xcurr)->*mf)(); } \
}

enum InsertMode {
    FIFO,
    LIFO,
    PRUP,
    PRUPFF =PRUP,
    PRUPLF,
    PRDN,
    PRDNFF =PRDN,
    PRDNLF
};

class PLink : public Link {

    friend class PList;

protected:

    int _prio;

public:

    PLink(int p =0) {
	_prio = p;
    }

    virtual ~PLink();

    int prio() const {
	return _prio;
    }

    int getPrio() const {
	return _prio;
    }

    void setPrio(int p =0) {
	_prio = p;
    }

    PLink *next() const {
	return (PLink *)_next;
    }

    PLink *prev() const {
	return (PLink *)_prev;
    }
};

class PList : public List {

protected:

    InsertMode _mode;

public:

    PList(InsertMode m =FIFO) {
	_mode = m;
    }

    PList(PList& pl) : List((List&)pl) {
	_mode = pl._mode;
    }

    virtual ~PList();
	
    PLink *get()  {
	return (PLink *)List::get();
    }

    void put(PLink *);

    void insert(PLink *pl) {
	put(pl);
    }

    InsertMode getMode(void) const {
	return _mode;
    }

    void setMode(InsertMode m) {
	_mode = m;
    }

    PLink *first() const {
	return (PLink *)_first;
    }

    PLink *last() const {
	return (PLink *)_last;
    }

    PLink *nth(int i) const {
	return (PLink *)List::nth(i);
    }

    PLink *isLinked(PLink *pl) {
	return (PLink *)List::isLinked(pl);
    }

    int moveTo(PList& dst) {
	dst._mode = _mode;
	return List::moveTo(dst);
    }
};

#define MakePList(TYPE) \
class name2(TYPE,PList):public PList { \
  public : \
  name2(TYPE,PList) (InsertMode p=FIFO) : PList(p) { }  \
  name2(TYPE,PList) (name2(TYPE,PList)& l) : PList((PList&)l) { } ; \
  TYPE *last() const { return (TYPE *) _last ;} \
  TYPE *first() const { return (TYPE *) _first ;} \
  TYPE *isLinked(TYPE* tl) { return (TYPE*) List::isLinked(tl); } \
  TYPE *get()	{ return (TYPE*) List::get(); } \
  TYPE *nth(int i) const { return (TYPE*) List::nth(i); } \
}

class GLink : public PLink {

    friend class GList;

protected:

    static GLink * glTank;

public:

    LinkedObject *_item;

    GLink(LinkedObject *t, int p=0);

    virtual ~GLink();

    void *operator new(size_t);

    void operator delete(void *);

    GLink *next() const {
	return (GLink *)_next;
    }

    GLink *prev() const {
	return (GLink *)_prev;
    }
};

class HashTable;

class GList : public PList {

private:

    static int qsortCompareGList(const void *e1,
				 const void *e2);
protected:

    // NOTICE: hashing will not work with objects linked more
    // than once to the list
    HashTable *ltable;

    GLink *_curr;

    GLink *glnext(GLink* gl) {
	return (GLink*)gl->_next;
    }

    GLink *glprev(GLink* gl) {
	return (GLink*)gl->_prev;
    }

    LinkedObject *item(GLink *gl) {
	return gl->_item;
    }

public:

    GList(InsertMode im, unsigned long nitems =0);

    GList(unsigned long nitems);

    GList();

    GList(GList&l);

    virtual ~GList();

    LinkedObject *last() const;

    LinkedObject *first() const;

    void append(LinkedObject *);

    void prepend(LinkedObject *);

    void remove(LinkedObject *);

    void insert(LinkedObject *,LinkedObject *);

    void insert(LinkedObject *o,int p) {
	PList::put(new GLink(o,p));
    }

    void insert(LinkedObject *o) {
	put(o);
    }

    void put(LinkedObject *o,int p)	{
	PList::put(new GLink(o,p));
    }

    void put(LinkedObject *);

    int moveTo(GList& dst) {
	dst._curr = _curr; _curr = 0;
	return PList::moveTo(dst);
    }

    GList& operator =(GList& src);

    LinkedObject *isLinked(LinkedObject *);

    LinkedObject *nth(int) const;

    LinkedObject *get();

    int position(LinkedObject *);

    virtual void sort();

    virtual void flush();

    virtual void destroy();
};

// Somebody should replace MakeList() and MakeGList() macros
// with templates...some day...

#define MakeGList(TYPE) \
class name2(TYPE,GList) : public GList { \
  friend class name2(TYPE,Iterator); \
  public : \
  name2(TYPE,GList)() : GList() {} \
  name2(TYPE,GList)(unsigned long nitems) : GList(nitems) {} \
  name2(TYPE,GList)(InsertMode m, unsigned long nitems =0) : GList(m,nitems) {}; \
  TYPE *last() const { return (TYPE *) GList::last() ;} \
  TYPE *first() const { return (TYPE *) GList::first() ;} \
  TYPE *isLinked(TYPE* t) { return (TYPE*) GList::isLinked((LinkedObject *)t); } \
  TYPE *nth(int i) const { return (TYPE*) GList::nth(i); } \
  TYPE *get() { return (TYPE*) GList::get(); } \
  void apply(void (TYPE::*mf)()) \
  { GLink *_xcurr; \
    for(_xcurr=(GLink*)_first; \
	_xcurr;_xcurr=glnext(_xcurr)) \
	(((TYPE *)_xcurr->_item)->*mf)(); } \
}; \
class name2(TYPE,Iterator) { \
  protected: \
  name2(TYPE,GList) *_l; \
  GLink *_xcurr; \
  public: \
  name2(TYPE,Iterator)(name2(TYPE,GList) *l) { \
      _l = l; reset(); \
  } \
  name2(TYPE,Iterator)(name2(TYPE,GList)& l) { \
      _l = &l; reset(); \
  } \
  name2(TYPE,Iterator)(GList *l) { \
      _l = (name2(TYPE,GList) *)l; reset(); \
  } \
  name2(TYPE,Iterator)(GList& l) { \
      _l = (name2(TYPE,GList) *)&l; reset(); \
  } \
  void reset() { \
      _xcurr = 0; \
  } \
  TYPE *prev() { \
      if (_xcurr) _xcurr = _l->glprev(_xcurr); \
      else _xcurr = (GLink *)_l->_last; \
      return _xcurr ? (TYPE *)_xcurr->_item : 0; \
  } \
  TYPE *next() { \
      if (_xcurr) _xcurr = _l->glnext(_xcurr); \
      else _xcurr = (GLink *)_l->_first; \
      return _xcurr ? (TYPE *)_xcurr->_item : 0; \
  } \
  void unlink() { \
      if (_xcurr) { \
	    GLink *_pcurr = _l->glprev(_xcurr); \
	    if (_l->ltable) \
		_l->ltable->remove((unsigned long)_xcurr->_item) ; \
	    _l->PList::remove(_xcurr); \
	    delete _xcurr; \
	    _xcurr = _pcurr; \
	    } \
  } \
  TYPE *pop () { \
      unlink(); \
      return next(); \
  } \
  TYPE *current () { \
      return _xcurr ? (TYPE *)_xcurr->_item : 0; \
  } \
}

#endif // _mvmutils_listplusplus_h
