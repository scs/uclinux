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
 * Author(s): rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifndef _mvmutils_hashplusplus_h
#define _mvmutils_hashplusplus_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

struct HashSlot {

    char *key;
    const void *datum;

    HashSlot *hforward,	// hash forward link
	*ibackward,	// insertion backward link
	*iforward;	// insertion forward link
};

class HashTable;

class HashScanner {

private:

    const HashTable *table;

    const HashSlot *cslot,
	*nslot;

public:

    HashScanner(const HashTable *_table) {
	table = _table;
	reset();
    }

    HashScanner(const HashTable& _table) {
	table = &_table;
	reset();
    }

    void reset();

    const char *forward(void ** =0);

    const char *current(void ** =0);
};

class HashTable {

    friend class HashScanner;

private:

    unsigned size,
	kcount;

    unsigned long nentries;

    HashSlot **table,
	*ifirst,
	*ilast;

protected:

    static const char *toString(unsigned long nkey);

    HashSlot *allocSlot(const char *key, const void *datum);

    void freeSlot(HashSlot *hfree);

    unsigned crunch(const char *key) const;

public:

    HashTable(unsigned long nentries);

    HashTable();

    virtual ~HashTable();

    void alloc(unsigned long nentries);

    void clear();

    void *find(const char *key) const;

    int find(const char *key, void **valuep) const;

    void *find(unsigned long nkey) const {
	return find(toString(nkey));
    }

    int find(unsigned long nkey, void **valuep) const {
	return find(toString(nkey),valuep);
    }

    int probe(const char *key) const;

    int probe(unsigned long nkey) const {
	return probe(toString(nkey));
    }

    int enter(const char *key, const void *datum =0);

    int enter(unsigned long nkey, const void *datum =0) {
	return enter(toString(nkey),datum);
    }

    void *update(const char *key, const void *datum);

    void *update(unsigned long nkey, const void *datum) {
	return update(toString(nkey),datum);
    }

    void *remove(const char *key);

    void *remove(unsigned long nkey) {
	return remove(toString(nkey));
    }

    unsigned count() const {
	return kcount;
    }

    unsigned long getEntries() {
	return nentries;
    }

    char *getKeyPtr(const char *key);
};

#endif // !_mvmutils_hashplusplus_h
