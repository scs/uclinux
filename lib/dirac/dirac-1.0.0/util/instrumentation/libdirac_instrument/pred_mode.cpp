/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: pred_mode.cpp,v 1.7 2008/06/19 10:39:59 tjdwave Exp $ $Name: Dirac_1_0_0 $
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

#include <util/instrumentation/libdirac_instrument/pred_mode.h>
using namespace dirac_instr;
using namespace dirac;

// constructor
DrawPredMode::DrawPredMode(Picture & picture, DrawPictureMotionParams & draw_params, const TwoDArray<PredMode> & mode)
:
    DrawOverlay(picture, draw_params),
    m_mode(mode)
{}

// destructor
DrawPredMode::~DrawPredMode()
{}

// colours a motion vector block according to prediction picture
void DrawPredMode::DrawBlock(int j, int i)
{
    int power = 0, U = 0, V = 0;

    // get prediction mode
    if (m_mode[j][i] == dirac::INTRA)
        power=100; // red
    else if (m_mode[j][i] == dirac::REF1_ONLY)
        power=250; // blue
    else if (m_mode[j][i] == dirac::REF2_ONLY)
        power=50; // yellow
    else if (m_mode[j][i] == dirac::REF1AND2)
        power=0; // green

    GetPowerUV(power, U, V);
    DrawMvBlockUV(j, i, U, V);
}

// displays colours representing prediction references
void DrawPredMode::DrawLegend()
{
    // blank background
    for (int ypx=m_draw_params.PicY()-65; ypx<m_draw_params.PicY(); ++ypx)
    {
        for (int xpx=7; xpx>=0; --xpx)
            m_picture.Data(Y_COMP)[ypx][xpx]=0;
    }

    int U=0, V=0;
    
    GetPowerUV(100, U, V); // intra
    DrawBlockUV((m_draw_params.PicY()/m_draw_params.ChromaFactorY())-1-(64/m_draw_params.ChromaFactorY())+1, 0, U, V);
    DrawBlockUV((m_draw_params.PicY()/m_draw_params.ChromaFactorY())-1-(56/m_draw_params.ChromaFactorY())+1, 0, U, V);

    GetPowerUV(250, U, V); // ref 1
    DrawBlockUV((m_draw_params.PicY()/m_draw_params.ChromaFactorY())-1-(48/m_draw_params.ChromaFactorY())+1, 0, U, V);
    DrawBlockUV((m_draw_params.PicY()/m_draw_params.ChromaFactorY())-1-(40/m_draw_params.ChromaFactorY())+1, 0, U, V);    

    GetPowerUV(50, U, V); // ref 2
    DrawBlockUV((m_draw_params.PicY()/m_draw_params.ChromaFactorY())-1-(32/m_draw_params.ChromaFactorY())+1, 0, U, V);
    DrawBlockUV((m_draw_params.PicY()/m_draw_params.ChromaFactorY())-1-(24/m_draw_params.ChromaFactorY())+1, 0, U, V);

    GetPowerUV(0, U, V); // ref 1 and 2
    DrawBlockUV((m_draw_params.PicY()/m_draw_params.ChromaFactorY())-1-(16/m_draw_params.ChromaFactorY())+1, 0, U, V);
    DrawBlockUV((m_draw_params.PicY()/m_draw_params.ChromaFactorY())-1-(8/m_draw_params.ChromaFactorY())+1, 0, U, V);

    // black horizontal lines
    for (int xpx=15; xpx>=0; --xpx)
    {
        m_picture.Data(Y_COMP)[m_draw_params.PicY()-65][xpx]=0;
        m_picture.Data(Y_COMP)[m_draw_params.PicY()-49][xpx]=0;
        m_picture.Data(Y_COMP)[m_draw_params.PicY()-33][xpx]=0;
    }

    for (int xpx=31; xpx>=0; --xpx)
    {
        m_picture.Data(Y_COMP)[m_picture.Data(Y_COMP).LastY()-16][xpx]=0;
    }

    // draw labels
    DrawCharacter(m_symbols.LetterI(), m_draw_params.PicY()-64, 8);
    DrawCharacter(m_symbols.Number1(), m_draw_params.PicY()-48, 8);
    DrawCharacter(m_symbols.Number2(), m_draw_params.PicY()-32, 8);
    DrawCharacter(m_symbols.Number1(), m_draw_params.PicY()-16, 8);
    DrawCharacter(m_symbols.SymbolPlus(), m_draw_params.PicY()-16, 16);
    DrawCharacter(m_symbols.Number2(), m_draw_params.PicY()-16, 24);

    // blank background
    for (int ypx=(m_draw_params.PicY()/m_draw_params.ChromaFactorY())-1-(16/m_draw_params.ChromaFactorY());
        ypx<=m_picture.Data(U_COMP).LastY(); ++ypx)
    {
        // no chrominance
        for (int xpx=(32/m_draw_params.MvYBlockX())-1; xpx>=(16/m_draw_params.ChromaFactorX()); --xpx)
        {
            m_picture.Data(U_COMP)[ypx][xpx]=0;
            m_picture.Data(V_COMP)[ypx][xpx]=0;
        }
    }
}
