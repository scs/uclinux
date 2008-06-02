#ifndef PORT_H
#define PORT_H

#if defined (WIN32) || defined (OS2)
#ifdef WIN32
#include "port-nt.h"
#else
#include "port-os2.h"
#endif

#else

#include "port-unix.h"

#endif

#endif
