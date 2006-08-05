/*
 * $Id$
 * ---------------------------------------------------------------------------
 * Debug-related procedures are located here. In case of "clean" compile, this
 * file may be omitted.
 *
 */

#include <time.h>

#include "arj.h"

DEBUGHDR(__FILE__)                      /* Debug information block */

/* Debug information report */

#ifdef DEBUG

int debug_report(char *module, unsigned int line, char sign)
{
 printf("\n*** [%c] %s:%u ***\n", sign, module, line);
 return(0);
}

#endif
