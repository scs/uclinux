/*-
 * See the file LICENSE for redistribution information.
 *
 * Copyright (c) 1997, 1998, 1999, 2000
 *	Sleepycat Software.  All rights reserved.
 *
 *	$Id$
 */

package com.sleepycat.db;

/**
 *
 * @author Donald D. Anderson
 */
public interface DbFeedback
{
    // methods
    //
    public abstract void feedback(Db db, int opcode, int pct);
}

// end of DbFeedback.java
