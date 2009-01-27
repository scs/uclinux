/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: overlay_symbols.h,v 1.2 2004/11/22 13:42:33 asuraparaju Exp $ $Name: Dirac_1_0_0 $
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

#ifndef _OVERLAY_SYMBOLS_H_
#define _OVERLAY_SYMBOLS_H_

#include "libdirac_common/common.h"
using dirac::PicArray;

namespace dirac_instr
{
    class OverlaySymbols
    {
    public :
        OverlaySymbols();
        ~OverlaySymbols();

        // access functions
        const PicArray & Arrow0() const {return m_arrow_0;}
        const PicArray & Arrow7_5() const {return m_arrow_7_5;}
        const PicArray & Arrow15() const {return m_arrow_15;}
        const PicArray & Arrow22_5() const {return m_arrow_22_5;}
        const PicArray & Arrow30() const {return m_arrow_30;}
        const PicArray & Arrow37_5() const {return m_arrow_37_5;}
        const PicArray & Arrow45() const {return m_arrow_45;}
        const PicArray & Arrow52_5() const {return m_arrow_52_5;}
        const PicArray & Arrow60() const {return m_arrow_60;}
        const PicArray & Arrow67_5() const {return m_arrow_67_5;}
        const PicArray & Arrow75() const {return m_arrow_75;}
        const PicArray & Arrow82_5() const {return m_arrow_82_5;}
        const PicArray & Arrow90() const {return m_arrow_90;}
        const PicArray & ArrowNull() const {return m_arrow_null;}

        const PicArray & Number0() const {return m_number_0;}
        const PicArray & Number1() const {return m_number_1;}
        const PicArray & Number2() const {return m_number_2;}
        const PicArray & Number3() const {return m_number_3;}
        const PicArray & Number4() const {return m_number_4;}
        const PicArray & Number5() const {return m_number_5;}
        const PicArray & Number6() const {return m_number_6;}
        const PicArray & Number7() const {return m_number_7;}
        const PicArray & Number8() const {return m_number_8;}
        const PicArray & Number9() const {return m_number_9;}

        const PicArray & SymbolPlus() const {return m_symbol_plus;}
        const PicArray & SymbolMinus() const {return m_symbol_minus;}
        const PicArray & SymbolGreater() const {return m_symbol_greater;}
        const PicArray & SymbolColon() const {return m_symbol_colon;}
        const PicArray & SymbolNull() const {return m_symbol_null;}

        const PicArray & LetterF() const {return m_letter_f;}
        const PicArray & LetterI() const {return m_letter_i;}
        const PicArray & LetterR() const {return m_letter_r;}

        const PicArray & Arrow() const {return m_arrow;}
        void Arrow(const PicArray & arrow) {m_arrow=arrow;}

        const PicArray & Character() const {return m_character;}
        void Character(const PicArray & character) {m_character=character;}
        
    private :
        //! Arrow arrays
        PicArray m_arrow_0, m_arrow_7_5, m_arrow_15, m_arrow_22_5, m_arrow_30, m_arrow_37_5, m_arrow_45;
        PicArray m_arrow_52_5, m_arrow_60, m_arrow_67_5, m_arrow_75, m_arrow_82_5, m_arrow_90, m_arrow_null;
        PicArray & m_arrow;
        
        //! Number arrays
        PicArray m_number_0, m_number_1, m_number_2, m_number_3, m_number_4, m_number_5, m_number_6, m_number_7, m_number_8, m_number_9;
        PicArray m_symbol_null, m_symbol_plus, m_symbol_minus, m_symbol_greater, m_symbol_colon;

        //! Letter arrays
        PicArray m_letter_f, m_letter_i, m_letter_r;

        PicArray & m_character;
    };

} // namespace dirac_instr

#endif
