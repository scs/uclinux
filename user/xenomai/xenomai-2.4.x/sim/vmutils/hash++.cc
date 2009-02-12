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
 * Author(s): rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifdef __GNUG__
#pragma implementation
#endif // __GNUG__
#include <xeno_config.h>
#include <string.h>
#include <malloc.h>
#include <ctype.h>
#include "vmutils/hash++.h"

HashSlot *HashSlotTank = 0,
    *HashSlotFree = 0;

static inline int compare (const char *s0, const char *s1)

{
    int n = -1;
    
    while (*s0 && *s1 && (n = (*s0++ - *s1++)) == 0)
	;
    return (*s0 || *s1 || n) ? 0 : 1;
}

HashSlot *HashTable::allocSlot (const char *key, const void *datum)

{
    if (!HashSlotFree)
	{
	HashSlot *extent = new HashSlot[256];
	HashSlotFree = extent;

	if (!HashSlotTank)
	    HashSlotTank = extent;

	for (int n = 0; n < 255; n++)
	    {
	    extent->hforward = extent + 1;
	    extent++;
	    }

	extent->hforward = 0;
	}

    HashSlot *hfree = HashSlotFree;
    HashSlotFree = hfree->hforward;

    hfree->key = strdup(key);
    hfree->datum = datum;
    hfree->hforward = NULL;
    hfree->ibackward = NULL;
    hfree->iforward = NULL;

    return hfree;
}

void HashTable::freeSlot (HashSlot *hfree)

{
    free(hfree->key);
    hfree->hforward = HashSlotFree;
    HashSlotFree = hfree;
}

const char *HashTable::toString (unsigned long nkey)

{
    static char key[11];
    char *s = &key[10];
    
    *s-- = '\0';

    do
	*s-- = (int)(nkey % 10 + '0');
    while (s >= &key[0] && (nkey /= 10) != 0);

    return ++s;
}

HashTable::HashTable (unsigned long _nentries)

{ alloc(_nentries); }

HashTable::HashTable ()

{
    table = NULL;
    kcount = 0;
    nentries = 0;
    size = 0;
    ifirst = ilast = NULL;
}

HashTable::~HashTable ()

{
    if (table)
	{
	clear();
	delete[] table;
	}
}

void HashTable::alloc (unsigned long _nentries)

{
    static const unsigned primes[] = {
    11, 23, 41, 83, 211, 509, 1021, 2039, 4093,
	8191, 16381, 32749, 65521, 131071, 262139,
	524287, 1048573, 0
	};

    unsigned long k = _nentries / 3;
    int n;
    
    for (n = 0; primes[n] < k; n++)
	{
	if (!primes[n])
	    { n--; break; }
	}

    nentries = _nentries;
    size = primes[n];
    table = (HashSlot **)new HashSlot *[size];

    for (unsigned i = 0; i < size; i++)
	table[i] = NULL;

    kcount = 0;
    ifirst = ilast = NULL;
}

void HashTable::clear ()

{
    HashSlot *inh, *newh;
    
    for (unsigned i = 0 ; i < size; i++)
	{
	for (inh = table[i]; inh; inh = newh)
	    {
	    newh = inh->hforward;
	    freeSlot(inh);
	    }

	table[i] = NULL;
	}

    ifirst = ilast = NULL;
    kcount = 0;
}

unsigned HashTable::crunch (const char *key) const
    
{
#define CHAR_BIT 8
#define UINT_BIT   (sizeof (unsigned) * CHAR_BIT)
#define ROL(v, n)  ((v) << (n) | (v) >> (UINT_BIT - (n)))
#define HASH(h, c) ((c) + ROL(h,7))

    unsigned h = 0;
    int c;

    while ((c = *key++) != 0)
	h = HASH(h,isupper (c) ? tolower (c) : c);

    return h % size;
}

void *HashTable::remove (const char *key)

{
    HashSlot *inh, *prev = NULL;
    unsigned slot = crunch(key);
    const void *wash = NULL;
    int found = 0;

    if ((inh = table[slot]) == (HashSlot *)0)
	return NULL;

    do
	{
	if (!(found = compare(key,inh->key)))
	    prev = inh;
	}
    while (!found && (inh = inh->hforward) != NULL);
    
    if (found)
	{
	wash = inh->datum;

	if (!prev)
	    table[slot] = inh->hforward;
	else
	    prev->hforward = inh->hforward;

	if (inh == ifirst)
	    {
	    ifirst = inh->iforward;

	    if (ifirst)
		ifirst->ibackward = NULL;
	    }
	else
	    {
	    HashSlot *iprev = inh->ibackward;
	    HashSlot *inext = inh->iforward;

	    iprev->iforward = inext;

	    if (inext)
		inext->ibackward = iprev;
	    }

	if (inh == ilast)
	    ilast = inh->ibackward;

	freeSlot(inh);
	kcount--;
	}
    
    return (void *)wash;
}

void *HashTable::find (const char *key) const

{
    HashSlot *inh = table[crunch(key)];
    
    if (inh)
	{
	do
	    {
	    if (compare(key,inh->key) == 1)
		return (void *)inh->datum;
	    }
	while ((inh = inh->hforward) != NULL);
	}
    
    return NULL;
}

int HashTable::find (const char *key,
		     void **valuep) const

{
    HashSlot *inh = table[crunch(key)];
    
    if (inh)
	{
	do
	    {
	    if (compare(key,inh->key) == 1)
		{
		*valuep = (void *)inh->datum;
		return 1;
		}
	    }
	while ((inh = inh->hforward) != NULL);
	}
    
    return 0;
}

int HashTable::enter (const char *key, const void *datum)
    
{
    if (!*key)			// disallow empty keys
	return -1;

    unsigned slot = crunch(key);
    HashSlot *inh = table[slot], *newh, *prev;

    if (inh)
	{
	while (inh)
	    {
	    if (compare(key,inh->key)) /* duplicate key match not allowed */
		return -1;

	    prev = inh;
	    inh = inh->hforward;
	    }

	prev->hforward = newh = allocSlot(key,datum);
	}
    else
	table[slot] = newh = allocSlot(key,datum);
    
    if (!ifirst)
	ifirst = newh;

    newh->iforward = NULL;
    newh->ibackward = ilast;

    if (ilast)
	ilast->iforward = newh;

    ilast = newh;
    
    return ++kcount;
}

void *HashTable::update (const char *key, const void *datum)

{
    HashSlot *inh = table[crunch(key)];
    const void *wash;
    
    if (inh)
	{
	while (inh && compare(key,inh->key) == 0) 
	    inh = inh->hforward;

	if (inh)
	    {
	    wash = inh->datum;
	    inh->datum = datum;
	    return (void *)wash;
	    }
	}

    return NULL;
}

int HashTable::probe (const char *key) const

{
    HashSlot *inh = table[crunch(key)];
    
    if (inh)
	{
	do
	    {
	    if (compare(key,inh->key) == 1)
		return 1;
	    }
	while ((inh = inh->hforward) != NULL);
	}
    
    return 0;
}

char *HashTable::getKeyPtr (const char *key)

{
    HashSlot *inh = table[crunch(key)];
    
    if (inh)
	{
	do
	    {
	    if (compare(key,inh->key) == 1)
		return inh->key;
	    }
	while ((inh = inh->hforward) != NULL);
	}
    
    return NULL;
}

void HashScanner::reset ()

{ cslot = nslot = NULL; }

const char *HashScanner::forward (void **datump)

{
    if (!nslot && !cslot)
	nslot = table->ifirst;
    
    if (nslot)
	{
	cslot = nslot;
	nslot = cslot->iforward;
	
	if (datump)
	    *datump = (void *)cslot->datum;
	
	return cslot->key;
	}
    else
	cslot = NULL;

    return NULL;
}

const char *HashScanner::current (void **datump)

{
    if (!cslot)
	return NULL;

    if (datump)
	*datump = (void *)cslot->datum;

    return cslot->key;
}
