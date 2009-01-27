/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: sad.cpp,v 1.8 2008/06/19 10:39:59 tjdwave Exp $ $Name: Dirac_1_0_0 $
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

#include <util/instrumentation/libdirac_instrument/sad.h>
using namespace dirac_instr;
using namespace dirac;

// constructor
DrawSad::DrawSad(Picture & picture, DrawPictureMotionParams & draw_params, const TwoDArray<MvCostData> & cost, const TwoDArray<PredMode> & mode, 
                 int scale)
:
    DrawOverlay(picture, draw_params),
    m_scale(scale),
    m_cost(cost),
    m_mode(mode)
{}

// destructor
DrawSad::~DrawSad()
{}

// colours a motion vector block appropriately and indicates intra coding using a white box
void DrawSad::DrawBlock(int j, int i)
{
    // get U and V for motion vector block
    int U = 0, V = 0;
    int value = int(m_cost[j][i].SAD / (double(m_scale) / 250));
    GetPowerUV(value, U, V);
    DrawMvBlockUV(j, i, U, V);

    // if intra, draw white box round block
    if (m_mode[j][i]==dirac::INTRA)
    {
        int yidx = (j*m_draw_params.MvYBlockY());
        int xidx = (i*m_draw_params.MvYBlockX());
        for (int ypx=0; ypx<m_draw_params.MvYBlockY(); ++ypx)
        {
            if ((yidx+ypx)>=m_picture.Data(Y_COMP).LengthY() ||
                (xidx+m_draw_params.MvYBlockX()-1)>= m_picture.Data(Y_COMP).LengthX())
                break;
            m_picture.Data(Y_COMP)[(j*m_draw_params.MvYBlockY())+ypx][(i*m_draw_params.MvYBlockX())] = 250;
            m_picture.Data(Y_COMP)[(j*m_draw_params.MvYBlockY())+ypx][(i*m_draw_params.MvYBlockX())+m_draw_params.MvYBlockX()-1] = 250;
        }// ypx

        for (int xpx=0; xpx<m_draw_params.MvYBlockX(); ++xpx)
        {
            if ((yidx+m_draw_params.MvYBlockY()-1)>=m_picture.Data(Y_COMP).LengthY() ||
                (xidx+xpx)>= m_picture.Data(Y_COMP).LengthX())
                break;
            m_picture.Data(Y_COMP)[(j*m_draw_params.MvYBlockY())][(i*m_draw_params.MvYBlockX())+xpx] = 250;
            m_picture.Data(Y_COMP)[(j*m_draw_params.MvYBlockY())+m_draw_params.MvYBlockY()-1][(i*m_draw_params.MvYBlockX())+xpx] = 250;
        }// xpx
    }
}

// displays power bar legend
void DrawSad::DrawLegend()
{
    DrawPowerBar(0, m_scale);
}
