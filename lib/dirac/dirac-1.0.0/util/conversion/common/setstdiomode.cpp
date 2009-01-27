/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: setstdiomode.cpp,v 1.3 2004/06/30 16:44:52 asuraparaju Exp $ $Name: Dirac_1_0_0 $
*
* Version: MPL 1.1/GPL 2.0/LGPL 2.1
*
* The contents of this file are subject to the Mozilla Public License
* Version 1.1 (the "License"); you may not use this file except in compliance
* with the License. You may obtain a copy of the License at
* http://www.mozilla.org/MPL/
*
* Software distributed under the License is distributed on an "AS IS" basis,
* WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License for
* the specific language governing rights and limitations under the License.
*
* The Original Code is BBC Research and Development code.
*
* The Initial Developer of the Original Code is the British Broadcasting
* Corporation.
* Portions created by the Initial Developer are Copyright (C) 2004.
* All Rights Reserved.
*
* Contributor(s):
* Tim Borer (Original author)
*
* Alternatively, the contents of this file may be used under the terms of
* the GNU General Public License Version 2 (the "GPL"), or the GNU Lesser
* Public License Version 2.1 (the "LGPL"), in which case the provisions of
* the GPL or the LGPL are applicable instead of those above. If you wish to
* allow use of your version of this file only under the terms of the either
* the GPL or LGPL and not to allow others to use your version of this file
* under the MPL, indicate your decision by deleting the provisions above
* and replace them with the notice and other provisions required by the GPL
* or LGPL. If you do not delete the provisions above, a recipient may use
* your version of this file under the terms of any one of the MPL, the GPL
* or the LGPL.
* ***** END LICENSE BLOCK ***** */

#include "setstdiomode.h"

namespace dirac_vu { //dirac video utilities namespace

#ifdef _WIN32

#include <stdio.h>  //Defines _fileno (needed to set standard i/o to binary mode)
#include <io.h>     //Defines _setmode (needed to set standard input to binary mode)
#include <fcntl.h>  //Contains definition of _O_BINARY

int setstdinmode(std::ios_base::openmode mode) {
    int winMode;
    if ((mode&std::ios_base::binary)==std::ios_base::binary) winMode=_O_BINARY;
    else winMode=_O_TEXT;
    //Set standard input and standard output to binary mode.
    return _setmode(_fileno( stdin ), winMode );
}

int setstdoutmode(std::ios_base::openmode mode) {
    int winMode;
    if ((mode&std::ios_base::binary)==std::ios_base::binary) winMode=_O_BINARY;
    else winMode=_O_TEXT;
    //Set standard input and standard output to binary mode.
    return _setmode(_fileno( stdout ), winMode );
}

#else

int setstdinmode(std::ios_base::openmode) {
    return 0;
}

int setstdoutmode(std::ios_base::openmode) {
    return 0;
}

#endif

}  // end namespace dirac_vu

