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
public class DbRunRecoveryException extends DbException
{
    // methods
    //

    public DbRunRecoveryException(String s)
    {
        super(s);
    }

    public DbRunRecoveryException(String s, int errno)
    {
        super(s, errno);
    }
}

// end of DbRunRecoveryException.java
