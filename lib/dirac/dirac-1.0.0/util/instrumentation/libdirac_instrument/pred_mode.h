/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: pred_mode.h,v 1.3 2008/01/31 11:25:20 tjdwave Exp $ $Name: Dirac_1_0_0 $
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

#ifndef _PRED_MODE_H_
#define _PRED_MODE_H_

#include <util/instrumentation/libdirac_instrument/draw_overlay.h>
using dirac::TwoDArray;
using dirac::PredMode;

namespace dirac_instr
{
    //! Class to carry out overlay of prediction mode
    /*
        Sub-clas of DrawOverlay.
        Displays which reference picture is used as prediction for block
    */
    class DrawPredMode : public DrawOverlay
    {
    public :

        //! Constructor
        /*
            Calls DrawOverlay constructor
        */
        DrawPredMode(Picture &, DrawPictureMotionParams &, 
                    const TwoDArray<PredMode> &);

        //! Destructor
        ~DrawPredMode();

        //! Colours a motion vector block according to prediction
        void DrawBlock(int, int);

        //! Displays legend
        void DrawLegend();
        
    private :

        // mode decision array
        const TwoDArray<PredMode> & m_mode;
    };

} // namespace dirac_instr

#endif
