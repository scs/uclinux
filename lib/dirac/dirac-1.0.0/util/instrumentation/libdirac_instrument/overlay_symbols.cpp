/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: overlay_symbols.cpp,v 1.3 2008/05/27 01:29:56 asuraparaju Exp $ $Name: Dirac_1_0_0 $
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

#include "overlay_symbols.h"
using namespace dirac_instr;

OverlaySymbols::OverlaySymbols() :
    // initialise arrows
    m_arrow_0(16, 16), m_arrow_7_5(16, 16),  m_arrow_15(16, 16), 
    m_arrow_22_5(16, 16), m_arrow_30(16, 16), m_arrow_37_5(16, 16),
    m_arrow_45(16, 16), m_arrow_52_5(16, 16), m_arrow_60(16, 16),
    m_arrow_67_5(16, 16), m_arrow_75(16, 16), m_arrow_82_5(16, 16),
    m_arrow_90(16, 16),   m_arrow_null(16, 16), m_arrow(m_arrow_null),
    
    // initialise numbers
    m_number_0(16, 8), m_number_1(16, 8), m_number_2(16, 8), m_number_3(16, 8),
    m_number_4(16, 8), m_number_5(16, 8), m_number_6(16, 8), m_number_7(16, 8),
    m_number_8(16, 8), m_number_9(16, 8),

    // initialise sybomls
    m_symbol_null(16, 8), m_symbol_plus(16, 8), m_symbol_minus(16, 8),
    m_symbol_greater(16, 8), m_symbol_colon(16, 8),
    
    // initialise letters
    m_letter_f(16, 8), m_letter_i(16, 8), m_letter_r(16, 8),
    m_character(m_symbol_null)
{
    // initialise numbers
    for (int j=0; j<16; ++j)
    {
        for (int i=0; i<8; ++i)
        {
            m_number_0[j][i]=0;
            m_number_1[j][i]=0;
            m_number_2[j][i]=0;
            m_number_3[j][i]=0;
            m_number_4[j][i]=0;
            m_number_5[j][i]=0;
            m_number_6[j][i]=0;
            m_number_7[j][i]=0;
            m_number_8[j][i]=0;
            m_number_9[j][i]=0;

            m_symbol_plus[j][i]=0;
            m_symbol_minus[j][i]=0;
            m_symbol_greater[j][i]=0;
            m_symbol_null[j][i]=0;
            m_symbol_colon[j][i]=0;

            m_letter_f[j][i]=0;
            m_letter_i[j][i]=0;
            m_letter_r[j][i]=0;
        }
    }

    // m_number_0
    for (int j=3; j<13; ++j) {
        m_number_0[j][1]=1;
        m_number_0[j][5]=1;
    }

    m_number_0[2][2]=1;  m_number_0[2][3]=1;  m_number_0[2][4]=1;
    m_number_0[3][2]=1;  m_number_0[3][3]=1;  m_number_0[3][4]=1;
    m_number_0[12][2]=1; m_number_0[12][3]=1; m_number_0[12][4]=1;
    m_number_0[13][2]=1; m_number_0[13][3]=1; m_number_0[13][4]=1;

    // m_number_1
    for (int j=2; j<14; ++j) {
        m_number_1[j][4]=1;
    }

    m_number_1[2][3]=1;
    m_number_1[3][2]=1;  m_number_1[3][3]=1;
    m_number_1[12][3]=1; m_number_1[12][5]=1;
    m_number_1[13][2]=1; m_number_1[13][3]=1; m_number_1[13][5]=1; m_number_1[13][6]=1;

    // m_number_2
    for (int j=3; j<8; ++j) {
        m_number_2[j][5]=1;
    }
    for (int j=8; j<13; ++j) {
        m_number_2[j][1]=1;
    }

    m_number_2[2][2]=1;  m_number_2[2][3]=1; m_number_2[2][4]=1;
    m_number_2[3][1]=1;  m_number_2[3][2]=1; m_number_2[3][3]=1;   m_number_2[3][4]=1;
    m_number_2[7][2]=1;  m_number_2[7][3]=1;  m_number_2[7][4]=1;
    m_number_2[8][2]=1;  m_number_2[8][3]=1;  m_number_2[8][4]=1;
    m_number_2[12][2]=1; m_number_2[12][3]=1; m_number_2[12][4]=1; m_number_2[12][5]=1;
    m_number_2[13][2]=1; m_number_2[13][3]=1; m_number_2[13][4]=1;

    // m_number_3
    for (int j=3; j<13; ++j) {
        m_number_3[j][5]=1;
    }

    m_number_3[2][2]=1;  m_number_3[2][3]=1;  m_number_3[2][4]=1;
    m_number_3[3][1]=1;  m_number_3[3][2]=1;  m_number_3[3][3]=1;  m_number_3[3][4]=1;
    m_number_3[7][2]=1;  m_number_3[7][3]=1;  m_number_3[7][4]=1;
    m_number_3[8][2]=1;  m_number_3[8][3]=1;  m_number_3[8][4]=1;
    m_number_3[12][2]=1; m_number_3[12][3]=1; m_number_3[12][4]=1; m_number_3[12][5]=1;
    m_number_3[13][2]=1; m_number_3[13][3]=1; m_number_3[13][4]=1;

    // m_number_4
    for (int j=2; j<9; ++j) {
        m_number_4[j][1]=1;
    }
    for (int j=7; j<14; ++j) {
        m_number_4[j][3]=1;
    }

    m_number_4[7][2]=1; m_number_4[7][4]=1; m_number_4[7][5]=1;
    m_number_4[8][2]=1; m_number_4[8][3]=1; m_number_4[8][5]=1;

    // m_number_5
    for (int j=3; j<8; ++j) {
        m_number_5[j][1]=1;
    }
    for (int j=8; j<13; ++j) {
        m_number_5[j][5]=1;
    }

    m_number_5[2][2]=1;  m_number_5[2][3]=1;  m_number_5[2][4]=1;
    m_number_5[3][2]=1;  m_number_5[3][3]=1;  m_number_5[3][4]=1;  m_number_5[3][5]=1;
    m_number_5[7][2]=1;  m_number_5[7][3]=1;  m_number_5[7][4]=1;
    m_number_5[8][2]=1;  m_number_5[8][3]=1;  m_number_5[8][4]=1;
    m_number_5[12][1]=1; m_number_5[12][2]=1; m_number_5[12][3]=1; m_number_5[12][4]=1;
    m_number_5[13][2]=1; m_number_5[13][3]=1; m_number_5[13][4]=1;

    // m_number_6
    for (int j=3; j<13; ++j) {
        m_number_6[j][1]=1;
    }
    for (int j=8; j<13; ++j) {
        m_number_6[j][5]=1;
    }

    m_number_6[2][2]=1;  m_number_6[2][3]=1;  m_number_6[2][4]=1;
    m_number_6[3][2]=1;  m_number_6[3][3]=1;  m_number_6[3][4]=1; m_number_6[3][5]=1;
    m_number_6[7][2]=1;  m_number_6[7][3]=1;  m_number_6[7][4]=1;
    m_number_6[8][2]=1;  m_number_6[8][3]=1;  m_number_6[8][4]=1;
    m_number_6[12][2]=1; m_number_6[12][3]=1; m_number_6[12][4]=1;
    m_number_6[13][2]=1; m_number_6[13][3]=1; m_number_6[13][4]=1;

    // m_number_7
    m_number_7[2][2]=1; m_number_7[2][3]=1; m_number_7[2][4]=1;
    m_number_7[3][1]=1; m_number_7[3][2]=1; m_number_7[3][3]=1; m_number_7[3][4]=1; m_number_7[3][5]=1;
    m_number_7[4][5]=1;
    m_number_7[5][5]=1;
    m_number_7[6][5]=1;
    m_number_7[7][4]=1;
    m_number_7[8][4]=1;
    m_number_7[9][3]=1;
    m_number_7[10][3]=1;
    m_number_7[11][2]=1;
    m_number_7[12][2]=1;
    m_number_7[13][2]=1;

    // m_number_8
    for (int j=3; j<7; ++j) {
        m_number_8[j][1]=1;
        m_number_8[j][5]=1;
    }
    for (int j=9; j<13; ++j) {
        m_number_8[j][1]=1;
        m_number_8[j][5]=1;
    }

    m_number_8[2][2]=1;  m_number_8[2][3]=1;  m_number_8[2][4]=1;
    m_number_8[3][2]=1;  m_number_8[3][3]=1;  m_number_8[3][4]=1;
    m_number_8[7][2]=1;  m_number_8[7][3]=1;  m_number_8[7][4]=1;
    m_number_8[8][2]=1;  m_number_8[8][3]=1;  m_number_8[8][4]=1;
    m_number_8[12][2]=1; m_number_8[12][3]=1; m_number_8[12][4]=1;
    m_number_8[13][2]=1; m_number_8[13][3]=1; m_number_8[13][4]=1;

    // m_number_9
    for (int j=3; j<8; ++j) {
        m_number_9[j][1]=1;
    }
    for (int j=3; j<14; ++j) {
        m_number_9[j][5]=1;
    }

    m_number_9[2][2]=1; m_number_9[2][3]=1; m_number_9[2][4]=1;
    m_number_9[3][2]=1; m_number_9[3][3]=1; m_number_9[3][4]=1; m_number_9[3][5]=1;
    m_number_9[7][2]=1; m_number_9[7][3]=1; m_number_9[7][4]=1;
    m_number_9[8][2]=1; m_number_9[8][3]=1; m_number_9[8][4]=1;

    // m_symbol_Plus
    for (int j=6; j<11; ++j) {
        m_symbol_plus[j][4]=1;
    }
    for (int i=2; i<6; ++i) {
        m_symbol_plus[8][i]=1;
    }

    // m_symbol_Minus
    for (int i=2; i<6; ++i) {
        m_symbol_minus[8][i]=1;
    }

    // m_symbol_greater
    m_symbol_greater[4][1]=1;
    m_symbol_greater[5][2]=1; m_symbol_greater[5][3]=1;
    m_symbol_greater[6][4]=1; m_symbol_greater[6][5]=1;
    m_symbol_greater[7][6]=1;
    m_symbol_greater[8][4]=1; m_symbol_greater[8][5]=1;
    m_symbol_greater[9][2]=1; m_symbol_greater[9][3]=1;
    m_symbol_greater[10][1]=1;

    // m_symbol_colon
    m_symbol_colon[6][2]=1;  m_symbol_colon[6][3]=1;
    m_symbol_colon[7][2]=1;  m_symbol_colon[7][3]=1;    
    m_symbol_colon[12][2]=1; m_symbol_colon[12][3]=1;
    m_symbol_colon[13][2]=1; m_symbol_colon[13][3]=1;
    
    // m_letter_I
    for (int j=2; j<14; ++j) {
        m_letter_i[j][3]=1;
    }

    m_letter_i[2][1]=1; m_letter_i[2][2]=1; m_letter_i[2][4]=1; m_letter_i[2][5]=1;
    m_letter_i[13][1]=1; m_letter_i[13][2]=1; m_letter_i[13][4]=1; m_letter_i[13][5]=1;

    // m_letter_r
    for (int j=2; j<14; ++j) {
        m_letter_r[j][1]=1;
    }
    for (int j=3; j<7; ++j) {
        m_letter_r[j][5]=1;
    }
    for (int i=2; i<5; ++i) {
        m_letter_r[2][i]=1;
        m_letter_r[7][i]=1;
    }
    m_letter_r[8][4]=1;  m_letter_r[9][4]=1;
    m_letter_r[10][5]=1; m_letter_r[11][5]=1;
    m_letter_r[12][6]=1; m_letter_r[13][6]=1;

    // m_letter_f
    for (int j=2; j<14; ++j) {
        m_letter_f[j][1]=1;
    }
    for (int i=2; i<5; ++i) {
        m_letter_f[2][i]=1;
        m_letter_f[7][i]=1;
    }
    m_letter_f[2][5]=1;

    // ***** Luminance arrows *****
    for (int j=0; j<16; ++j) {
        for (int i=0; i<16; ++i) {
            m_arrow_0[j][i]=0;
            m_arrow_7_5[j][i]=0;
            m_arrow_15[j][i]=0;
            m_arrow_22_5[j][i]=0;
            m_arrow_30[j][i]=0;
            m_arrow_37_5[j][i]=0;
            m_arrow_45[j][i]=0;

            m_arrow_52_5[j][i]=0;
            m_arrow_60[j][i]=0;
            m_arrow_67_5[j][i]=0;
            m_arrow_75[j][i]=0;
            m_arrow_82_5[j][i]=0;
            m_arrow_90[j][i]=0;

            m_arrow_null[j][i]=0;
        }
    }

    // m_arrow_0
    for (int j=2; j<14; ++j) {
        m_arrow_0[j][7]=1;
        m_arrow_0[j][8]=1;
    }
    for (int j=4; j<8; ++j) {
        m_arrow_0[j][6]=1;
        m_arrow_0[j][9]=1;
    }
    for (int j=6; j<8; ++j) {
        m_arrow_0[j][5]=1;
        m_arrow_0[j][10]=1;
    }

    // m_arrow_7_5
    for (int j=2; j<7; ++j) {
        m_arrow_7_5[j][8]=1;
        m_arrow_7_5[j][9]=1;
    }
    for (int j=4; j<14; ++j) {
        m_arrow_7_5[j][7]=1;
    }
    m_arrow_7_5[5][6]=1;
    m_arrow_7_5[5][10]=1;
    m_arrow_7_5[6][6]=1;
    m_arrow_7_5[6][10]=1;
    m_arrow_7_5[7][8]=1;
    m_arrow_7_5[8][8]=1;
    m_arrow_7_5[9][8]=1;
    m_arrow_7_5[10][6]=1;
    m_arrow_7_5[11][6]=1;
    m_arrow_7_5[12][6]=1;
    m_arrow_7_5[13][6]=1;

    // m_arrow_15
    for (int j=2; j<6; ++j) {
        m_arrow_15[j][9]=1;
        m_arrow_15[j][10]=1;
    }
    for (int j=6; j<8; ++j) {
        m_arrow_15[j][8]=1;
        m_arrow_15[j][9]=1;
    }
    for (int j=8; j<11; ++j) {
        m_arrow_15[j][7]=1;
        m_arrow_15[j][8]=1;
    }
    for (int j=11; j<14; ++j) {
        m_arrow_15[j][6]=1;
        m_arrow_15[j][7]=1;
    }
    m_arrow_15[4][8]=1;
    m_arrow_15[5][8]=1;
    m_arrow_15[5][7]=1;
    m_arrow_15[5][11]=1;

    // m_arrow_22_5
    for (int j=2; j<6; ++j) {
        m_arrow_22_5[j][10]=1;
        m_arrow_22_5[j][11]=1;
    }
    for (int j=3; j<8; ++j) {
        m_arrow_22_5[j][8]=1;
        m_arrow_22_5[j][9]=1;
    }
    m_arrow_22_5[5][8]=0;

    for (int j=8; j<10; ++j) {
        m_arrow_22_5[j][7]=1;
        m_arrow_22_5[j][8]=1;
    }
    for (int j=10; j<12; ++j) {
        m_arrow_22_5[j][6]=1;
        m_arrow_22_5[j][7]=1;
    }
    for (int j=12; j<14; ++j) {
        m_arrow_22_5[j][5]=1;
        m_arrow_22_5[j][6]=1;
    }
    m_arrow_22_5[5][12]=1;

    // m_arrow_30
    for (int j=3; j<6; ++j) {
        m_arrow_30[j][8]=1;
        m_arrow_30[j][9]=1;
        m_arrow_30[j][10]=1;
    }
    for (int j=6; j<9; ++j) {
        m_arrow_30[j][7]=1;
        m_arrow_30[j][8]=1;
    }
    for (int j=9; j<12; ++j) {
        m_arrow_30[j][5]=1;
        m_arrow_30[j][6]=1;
    }
    m_arrow_30[11][4]=1;
    m_arrow_30[12][4]=1;
    m_arrow_30[12][5]=1;
    m_arrow_30[8][6]=1;
    m_arrow_30[9][7]=1;
    m_arrow_30[2][10]=1;
    m_arrow_30[5][11]=1;
    m_arrow_30[4][7]=1;

    // m_arrow_37_5
    for (int j=3; j<6; ++j) {
        m_arrow_37_5[j][9]=1;
        m_arrow_37_5[j][10]=1;
        m_arrow_37_5[j][11]=1;
        m_arrow_37_5[j][12]=1;
    }
    for (int j=6; j<8; ++j) {
        m_arrow_37_5[j][8]=1;
        m_arrow_37_5[j][9]=1;
    }
    for (int j=8; j<11; ++j) {
        m_arrow_37_5[j][6]=1;
        m_arrow_37_5[j][7]=1;
    }
    for (int j=11; j<13; ++j) {
        m_arrow_37_5[j][4]=1;
        m_arrow_37_5[j][5]=1;
    }
    m_arrow_37_5[12][3]=1;
    m_arrow_37_5[13][3]=1;
    m_arrow_37_5[13][4]=1;
    m_arrow_37_5[11][6]=1;
    m_arrow_37_5[10][5]=1;
    m_arrow_37_5[8][8]=1;
    m_arrow_37_5[7][7]=1;
    m_arrow_37_5[6][12]=1;
    m_arrow_37_5[6][10]=1;
    m_arrow_37_5[3][8]=1;
    m_arrow_37_5[2][10]=1;
    m_arrow_37_5[2][11]=1;

    // m_arrow_45
    for (int j=5, i=9; j<13; ++j, --i) {
        m_arrow_45[j][i]=1;
        m_arrow_45[j+1][i]=1;
        m_arrow_45[j+2][i]=1;
    }
    m_arrow_45[14][2]=1;
    m_arrow_45[2][9]=1;
    m_arrow_45[6][10]=1;
    m_arrow_45[6][13]=1;

    for (int j=2; j<6; ++j) {
        for (int i=10; i<14; ++i) {
            m_arrow_45[j][i]=1;
        }
    }

    // m_arrow_52_5
    for (int j=3; j<8; ++j) {
        for (int i=10; i<14; ++i) {
            m_arrow_52_5[j][i]=1;
        }
    }
    m_arrow_52_5[7][11]=0;
    m_arrow_52_5[4][9]=1;
    m_arrow_52_5[6][9]=1;
    m_arrow_52_5[8][12]=1;

    for (int j=7; j<9; ++j) {
        for (int i=7; i<10; ++i) {
            m_arrow_52_5[j][i]=1;
        }
    }
    m_arrow_52_5[8][6]=1;
    m_arrow_52_5[9][7]=1;

    for (int j=9; j<11; ++j) {
        for (int i=4; i<7; ++i) {
            m_arrow_52_5[j][i]=1;
        }
    }
    m_arrow_52_5[10][3]=1;
    m_arrow_52_5[11][4]=1;

    for (int j=11; j<13; ++j) {
        for (int i=2; i<4; ++i) {
            m_arrow_52_5[j][i]=1;
        }
    }

    // m_arrow_60
    for (int j=3; j<6; ++j) {
        for (int i=11; i<14; ++i) {
            m_arrow_60[j][i]=1;
        }
    }
    for (int j=5; j<7; ++j) {
        m_arrow_60[j][10]=1;
        m_arrow_60[j][11]=1;
    }
    for (int j=6; j<8; ++j) {
        m_arrow_60[j][8]=1;
        m_arrow_60[j][9]=1;
    }
    for (int j=7; j<9; ++j) {
        m_arrow_60[j][7]=1;
        m_arrow_60[j][8]=1;
    }
    for (int j=8; j<10; ++j) {
        m_arrow_60[j][5]=1;
        m_arrow_60[j][6]=1;
    }
    for (int j=9; j<11; ++j) {
        m_arrow_60[j][4]=1;
        m_arrow_60[j][5]=1;
    }
    for (int j=10; j<12; ++j) {
        m_arrow_60[j][2]=1;
        m_arrow_60[j][3]=1;
    }
    m_arrow_60[2][10]=1;
    m_arrow_60[6][13]=1;

    // m_arrow_67_5
    for (int j=3; j<6; ++j) {
        for (int i=11; i<14; ++i) {
            m_arrow_67_5[j][i]=1;
        }
    }
    for (int j=5; j<7; ++j) {
        m_arrow_67_5[j][10]=1;
        m_arrow_67_5[j][11]=1;
    }
    for (int j=6; j<8; ++j) {
        m_arrow_67_5[j][8]=1;
        m_arrow_67_5[j][9]=1;
    }
    for (int j=7; j<9; ++j) {
        m_arrow_67_5[j][6]=1;
        m_arrow_67_5[j][7]=1;
    }
    for (int j=8; j<10; ++j) {
        m_arrow_67_5[j][4]=1;
        m_arrow_67_5[j][5]=1;
    }
    for (int j=9; j<11; ++j) {
        m_arrow_67_5[j][2]=1;
        m_arrow_67_5[j][3]=1;
    }
    m_arrow_67_5[3][10]=1;
    m_arrow_67_5[6][13]=1;

    // m_arrow_75
    for (int j=6; j<9; ++j) {
        for (int i=8; i<13; ++i) {
            m_arrow_75[j][i]=1;
        }
    }
    m_arrow_75[6][8]=0;
    m_arrow_75[8][12]=0;
    m_arrow_75[5][9]=1;
    m_arrow_75[9][9]=1;
    m_arrow_75[10][9]=1;
    m_arrow_75[9][10]=1;
    m_arrow_75[7][13]=1;

    for (int j=8; j<10; ++j) {
        for (int i=5; i<8; ++i) {
            m_arrow_75[j][i]=1;
        }
    }
    for (int j=9; j<11; ++j) {
        for (int i=2; i<5; ++i) {
            m_arrow_75[j][i]=1;
        }
    }

    // m_arrow_82_5
    for (int j=6; j<8; ++j) {
        for (int i=9; i<14; ++i) {
            m_arrow_82_5[j][i]=1;
        }
    }
    for (int j=7; j<9; ++j) {
        for (int i=6; i<12; ++i) {
            m_arrow_82_5[j][i]=1;
        }
    }

    for (int j=8; j<10; ++j) {
        for (int i=2; i<7; ++i) {
            m_arrow_82_5[j][i]=1;
        }
    }
    m_arrow_82_5[5][9]=1;
    m_arrow_82_5[5][10]=1;
    m_arrow_82_5[9][9]=1;

    // m_arrow_90
    for (int i=2; i<14; ++i) {
        m_arrow_90[7][i]=1;
        m_arrow_90[8][i]=1;
    }
    for (int i=8; i<12; ++i) {
        m_arrow_90[6][i]=1;
        m_arrow_90[9][i]=1;
    }
    for (int i=8; i<10; ++i) {
        m_arrow_90[5][i]=1;
        m_arrow_90[10][i]=1;
    }

}

OverlaySymbols::~OverlaySymbols()
{}
