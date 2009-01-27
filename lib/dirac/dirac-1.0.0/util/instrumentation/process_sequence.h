/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: process_sequence.h,v 1.5 2008/01/31 11:25:20 tjdwave Exp $ $Name: Dirac_1_0_0 $
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
* Contributor(s): Chris Bowley (Original Author)
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

#ifndef __PROCESS_SEQUENCE_H__
#define __PROCESS_SEQUENCE_H__

#include <iostream>
#include <fstream>
#include <libdirac_common/common.h>
using dirac::PictureParams;
using dirac::OLBParams;
using dirac::SourceParams;
using dirac::OneDArray;

#include <libdirac_common/motion.h>
using dirac::MEData;

#include <libdirac_common/pic_io.h>
using dirac::FileStreamInput;
using dirac::FileStreamOutput;

#include <util/instrumentation/libdirac_instrument/overlay.h>
using dirac_instr::OverlayParams;
using dirac_instr::Overlay;

//! Structure to hold motion data in array
struct me_data_entry
{
    MEData * me_data;
    OLBParams block_params;
    PictureParams picture_params;
};

//! Class to carry out instrumentation on sequence
class ProcessSequence
{
public :

    //! Constructor
    ProcessSequence(OverlayParams &, FileStreamInput &, FileStreamOutput &, std::ifstream &, bool, int, SourceParams &);

    //! Destructor
    ~ProcessSequence() {}

    //! DoSequence
    /*
        Public interface to the instrumentation process
    */
    void DoSequence(int, int);
    
private :

    //! DoPicture
    /*
        Queries data array for picture entry
        Returns true if picture entry is available
    */
    bool DoPicture();

    //! AddPictureEntry
    /*
        Adds data for picture to data array
    */
    void AddPictureEntry();

    //! Command-line overlay options
    OverlayParams & m_oparams;

    //! Input picture
    FileStreamInput & m_inputpic;

    //! Output picture
    FileStreamOutput & m_outputpic;

    //! True for user output during process
    bool m_verbose;

    //! Overlay data input stream
    std::ifstream & m_data_in;
    
    //! Data array
    OneDArray<me_data_entry> m_data_array;

    //! Picture numbers of process and overlay data
    int m_data_fnum, m_process_fnum;

    //! Read input picture data signal
    bool used_picture_data;

    //! Output source parameters
    SourceParams & m_srcparams;

};

#endif
