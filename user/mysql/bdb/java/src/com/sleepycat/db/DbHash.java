/*-
 * See the file LICENSE for redistribution information.
 *
 * Copyright (c) 2000
 *	Sleepycat Software.  All rights reserved.
 *
 *	$Id$
 */

package com.sleepycat.db;

/*
 * This interface is used by DbEnv.set_bt_compare()
 * 
 */
public interface DbHash
{
    public abstract int hash(Db db, byte[] data, int len);
}

// end of DbHash.java
