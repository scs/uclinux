/************************************************************************
 *
 * cdefBF53x.h
 *
 * This file is subject to the terms and conditions of the GNU Public 
 * License. See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Non-GPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 *
 * (c) Copyright 2001-2004 Analog Devices, Inc. All rights reserved
 *
 * Revision 1.3 - Wed Sep 17 10:44:01 2003 UTC 
 * This file under source code control, please send bugs or changes to:
 * dsptools.support@analog.com
 *
 ************************************************************************/

#ifndef _CDEFBF53x_H
#define _CDEFBF53x_H

# if defined(__ADSPBF531__)
#  include <cdefBF531.h>
# elif defined(__ADSPBF532__)
#  include <cdefBF532.h>
# elif defined(__ADSPBF533__)
#  include <cdefBF533.h>
# elif defined(__ADSPBF561__)
#  include <cdefBF561.h>
# elif defined(__ADSPBF535__)
#  include <cdefBF535.h>
# elif defined(__AD6532__)
#  include <cdefAD6532.h>
# else
#  if defined(__ADSPLPBLACKFIN__)
#   include <cdefBF532.h>
#  else
#   include <cdefBF535.h>
   #endif
# endif

#endif /* _CDEFBF53x_H */
