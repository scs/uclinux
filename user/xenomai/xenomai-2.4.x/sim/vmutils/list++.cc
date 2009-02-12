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
#include <stdlib.h>
#include "vmutils/list++.h"

GLink *GLink::glTank = NULL;

LinkedObject::~LinkedObject () {}

int LinkedObject::compare (LinkedObject *)

{ return 0; }

List::~List () {}

int Link::compare (Link *)

{ return 0; }

Link::~Link()
{
    if(_next) _next->_prev = _prev ;
    if(_prev) _prev->_next = _next ;
}

List::List(List& l)
{
    _first = l._first;
    _last = l._last;
    count = l.count;
    destroying = l.destroying;
}

void List::append(Link *l)
{
    if(!l) return;
    count++ ;
    if(_last) {
    _last->_next = l ;
    l->_prev = _last ;
    } else {
    _first = l ;
    l->_prev = 0;
    }
    _last = l ;
    l->_next = 0;
}

void List::prepend (Link *l) 
{
    if(!l) return;
    count++ ;
    if(_first) _first->_prev = l ;
    else _last = l ;
    l->_next = _first;
    _first = l ;
    l->_prev = 0;
}

void List::remove(Link *l)
{
    if (!l)
	return;

    count-- ;

    if(l==_first)
	_first = (Link *)_first->_next ;

    if(l==_last)
	_last = (Link *)_last->_prev ;

    if(l->_next)
	l->_next->_prev = l->_prev ;

    if(l->_prev)
	l->_prev->_next = l->_next ;

    l->_next = 0;
    l->_prev = 0;
}

void List::insert(Link *l1,Link *l2) // insert l2 before l1
{
    if(!l2) return;
    if(!l1) append(l2) ; // append to list if l2 == nil
    else {
    count++ ;
    if(l1->_prev) l1->_prev->_next = l2 ;
    l2->_prev = l1->_prev ;
    l1->_prev = l2 ;
    l2->_next = l1 ;

    if(l1 == _first) _first = l2 ;
    }
}

Link* List::isLinked(Link* l) const
{
    Link* l0 = _first;
    while(l0 && (l != l0)) l0 = l0->_next;
    return l0;
}

Link* List::nth(int i) const
{
    Link* l = _first;
    while (l && i--) l = l->_next;
    return l;
}

Link* List::get()
{
    if (_first) {
    Link* p = _first;
    _first = _first->_next;
    if (_first) _first->_prev = 0;
    else _last = 0;
    p->_next = 0;
    count--;
    return p;
    } else return 0;
}

int List::position(Link* l) const
{
    Link* l0 = _first;
    int pos = 0;
    while(l0 && (l != l0)) {
    l0 = l0->_next;
    pos++;
    }
    if (l0) return pos;
    else return -1;
}

int List::moveTo (List& dst)

{
    int n = count;
    Link *l;

    while ((l = get()) != NULL)
	dst.append(l);

    return n;
}

void List::destroy ()

{
    Link *l;

    destroying = 1;

    while ((l = get()) != NULL)
	delete l;

    destroying = 0;
}

void List::flush ()

{
    while (get())
	;
}

int List::qsortCompareList (const void *e1, const void *e2)

{
    Link *ln1 = *((Link **)e1), *ln2 = *((Link **)e2);
    return ln1->compare(ln2);
}

void List::sort ()

{
    int nbElems = getCount();

    if (nbElems < 2)
	return;

    Link **linkArray = (Link **)new Link *[nbElems], *ln;
    int n;

    for (ln = (Link *)_first, n = 0; ln; ln = ln->next(), n++)
	linkArray[n] = ln;
    
    qsort(linkArray,nbElems,sizeof(Link *),&List::qsortCompareList);

    _first = linkArray[0];
    _first->setPrev((Link *)0);
    _first->setNext(linkArray[1]);

    _last = linkArray[nbElems - 1];
    _last->setPrev(linkArray[nbElems - 2]);
    _last->setNext((Link *)0);

    for (n = 1; n < nbElems - 1; n++)
	{
	linkArray[n]->setPrev(linkArray[n - 1]);
	linkArray[n]->setNext(linkArray[n + 1]);
	}

    delete[] linkArray;
}

PLink::~PLink () {}

PList::~PList () {}

void PList::put(PLink *p)

{
    PLink *p0;
    int prio;

    if (!p) return;
    if (!_first) {
    _first = _last = p;
    p->_prev = p->_next = 0;
    count++;
    return;
    }

    switch (_mode)
	{
	case FIFO:
	    _last->_next = p;
	    p->_prev = _last;
	    _last = p;
	    p->_next = 0;
	    count++;
	    break;
	case LIFO:
	    _first->_prev = p;
	    p->_next = _first;
	    _first = p;
	    p->_prev = 0;
	    count++;
	    break;
	default:
	    p0 = (PLink*)_first;
	    prio = p->_prio;
	    switch (_mode)
		{
		case PRUPFF :
		    while(p0 && (p0->_prio <= prio)) p0 = (PLink*)p0->_next;
		    break;
		case PRUPLF :
		    while(p0 && (p0->_prio < prio)) p0 = (PLink*)p0->_next;
		    break;
		case PRDNFF:
		    while(p0 && (p0->_prio >= prio)) p0 = (PLink*)p0->_next;
		    break;
		case PRDNLF:
		    while(p0 && (p0->_prio > prio)) p0 = (PLink*)p0->_next;
		    break;
		default : return;
		}
	    List::insert(p0, p);
	}
}

GLink::GLink (LinkedObject *t, int p) : PLink(p)

{ _item = t; }

GLink::~GLink()
{
    if(_next) ((GLink*)_next)->_prev = _prev ;
    if(_prev) ((GLink*)_prev)->_next = _next ;
    _next = 0 ;
    _prev = 0 ;
}

void *GLink::operator new (size_t sz)

{
    GLink *c;

    if (glTank && sz <= sizeof(GLink))
	{
	c = glTank;
	glTank = (GLink *) c->_next;
	}
    else
	c = (GLink *)new char[sz];

    return c;
}

void GLink::operator delete (void *c)

{
    ((GLink *)c)->_next = glTank;
    glTank = (GLink *)c;
}

void GList::put(LinkedObject *o)
{
    if(o)
	switch ((int)_mode) {
	case PRDNFF:
	case PRUPFF :
	case FIFO:
	    append(o);
	    break;

	case PRDNLF:
	case PRUPLF :
	case LIFO:
	    prepend(o);
	    break;
	default: 
	    {
	    int p = (PList::first()) ? PList::first()->getPrio() : 0;
	    GLink *gl = new GLink(o, p);
	    PList::put((PLink *)gl);

	    if (ltable)
		ltable->enter((unsigned long)o,gl);
	    }
	}

    return;
}

LinkedObject* GList::last() const
{
    return (!_last ? 0 : ((GLink*)_last)->_item) ;
}

LinkedObject* GList::first() const
{
    return (!_first ? 0 : ((GLink*)_first)->_item) ;
}

void GList::append(LinkedObject *o)

{
    if(o)
	{
	GLink *gl = new GLink(o);
	List::append((Link*)gl);

	if (ltable)
	    ltable->enter((unsigned long)o,gl);

	if (gl->prev())
	    gl->setPrio(gl->prev()->getPrio());
	}
}

void GList::prepend (LinkedObject *o) 

{
    if(o)
	{
	GLink *gl = new GLink(o);
	List::prepend((Link*)gl);

	if (ltable)
	    ltable->enter((unsigned long)o,gl);

	if (gl->next())
	    gl->setPrio(gl->next()->getPrio());
	}
}

void GList::remove(LinkedObject *o)

{
    if (!o)
	return;

    Link *l;

    if (ltable)
	l = (Link *)ltable->remove((unsigned long)o);
    else
	{
	GLink *theCurr = (GLink *)_first;
	while (theCurr && theCurr->_item && (theCurr->_item != o))
	    theCurr = (GLink *)theCurr->_next;
	l = (Link*)theCurr ;
	}

    if (l)
	{
	PList::remove(l);
	delete l ;
	}
}

void GList::insert(LinkedObject *o1,LinkedObject *o2) // insert o2 before o1
{
    if(o2)
	{
	if(!o1)
	    append(o2);
	else
	    {
	    GLink *theCurr = (GLink *)_first;
	    while (theCurr && theCurr->_item && (theCurr->_item != o1)) theCurr = (GLink *)theCurr->_next;
	    GLink *gl1 = theCurr ;
	    if (!gl1) return;
	    GLink *gl2 = new GLink(o2) ;

	    if (ltable)
		ltable->enter((unsigned long)o2,gl2);

	    gl2->setPrio(gl1->getPrio());
	    count++ ;

	    if(gl1->_prev) gl1->prev()->setNext(gl2) ;
	    gl2->_prev = gl1->_prev ;
	    gl1->_prev = gl2 ;
	    gl2->_next = gl1 ;
	    if(gl1==_first) _first = gl2 ;
	    }
	}
}

LinkedObject *GList::isLinked(LinkedObject* o)

{
    if (ltable)
	return ltable->find((unsigned long)o) ? o : 0;

    LinkedObject* oo = NULL;
    GLink *theCurr = (GLink *)_first;
    while (theCurr && (oo = theCurr->_item) && (oo != o)) theCurr = (GLink *)theCurr->_next;
    return (theCurr) ? oo : (LinkedObject *)NULL;
}

LinkedObject *GList::nth(int i) const
{
    GLink* gl = (GLink*)_first;
    while (gl && i--) gl=gl->next();
    return (gl ? gl->_item : 0 );
}

LinkedObject* GList::get()

{
    GLink* gl = (GLink*)List::get();

    if (gl)
	{
	LinkedObject* o = gl->_item;

	if (ltable)
	    ltable->remove((unsigned long)o);

	delete gl;
	return o;
	}

    return 0;
}

int GList::position(LinkedObject* o)
{
    LinkedObject* oo;
    int p = 0;
    GLink *theCurr = (GLink *)_first;
    while (theCurr && (oo = theCurr->_item) && (oo != o)) theCurr = (GLink *)theCurr->_next, p++;
    return ( (theCurr) ? p : -1 );
}

int GList::qsortCompareGList (const void *e1, const void *e2)

{
    GLink *gl1 = *((GLink **)e1), *gl2 = *((GLink **)e2);
    return gl1->_item->compare(gl2->_item);
}

void GList::sort ()

{
    int nbElems = getCount();

    if (nbElems < 2)
	return;

    GLink **linkArray = (GLink **)new GLink *[nbElems], *gl;
    int n;

    for (gl = (GLink *)_first, n = 0; gl; gl = gl->next(), n++)
	linkArray[n] = gl;
    
    qsort(linkArray,nbElems,sizeof(GLink *),&GList::qsortCompareGList);

    _first = linkArray[0];
    _first->setPrev((Link *)0);
    _first->setNext(linkArray[1]);

    _last = linkArray[nbElems - 1];
    _last->setPrev(linkArray[nbElems - 2]);
    _last->setNext((Link *)0);

    for (n = 1; n < nbElems - 1; n++)
	{
	linkArray[n]->setPrev(linkArray[n - 1]);
	linkArray[n]->setNext(linkArray[n + 1]);
	}

    delete[] linkArray;
}

void GList::destroy ()

{
    LinkedObject *lo;
    HashTable *otable = ltable;
    ltable = 0;			// speeds up link removal
    destroying = 1;

    while ((lo = get()) != NULL)
	delete lo;

    ltable = otable;

    if (ltable)
	ltable->clear();	// fast cleanup of h-table

    destroying = 0;
}

void GList::flush ()

{
    HashTable *otable = ltable;
    ltable = 0;			// speeds up link removal

    while (get())
	;

    ltable = otable;

    if (ltable)
	ltable->clear();	// fast cleanup of h-table
}

GList::GList (InsertMode im, unsigned long nitems) : PList(im)

{
    _curr = (GLink *)_first;

    if (nitems > 0)		// If an advisory limit can be given, use
	ltable = new HashTable(nitems);	// hash coding to retrieve items
    else
	ltable = 0;
}

GList::GList (unsigned long nitems) : PList()

{
    _curr = (GLink *)_first;

    if (nitems > 0)		// If an advisory limit can be given, use
	ltable = new HashTable(nitems);	// hash coding to retrieve items
    else
	ltable = 0;
}

GList::GList () : PList()

{
    _curr = (GLink *)_first;
    ltable = 0;
}

GList::GList (GList& l) : PList(l._mode)

{
    _curr = (GLink *)_first;
    ltable = 0;
    *this = l;
}

GList& GList::operator =(GList& l)

{
    flush();

    if (l.ltable)
	ltable = new HashTable(l.ltable->getEntries());
    else
	ltable = 0;

    _first = 0;
    _last = 0;
    count = 0;

    for (GLink *gl = (GLink *)l._first; gl; gl = (GLink *)gl->_next)
	append(gl->_item);

    _curr = (GLink *)_first;

    return *this;
}

GList::~GList ()

{
    flush();

    if (ltable)
	delete ltable;
}
