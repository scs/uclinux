/*
 * Stuff specific to the Borland C compiler.
 *
 * $Id$
 *
 */

/* _stklen defines how big the runtime stack is.  It must be set at
 * compile time as an assignment.
 */

extern unsigned _stklen = 65400U;
