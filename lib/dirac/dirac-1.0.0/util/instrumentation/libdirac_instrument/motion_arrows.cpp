/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: motion_arrows.cpp,v 1.8 2008/06/19 10:39:59 tjdwave Exp $ $Name: Dirac_1_0_0 $
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

#include <util/instrumentation/libdirac_instrument/motion_arrows.h>
using namespace dirac_instr;
using namespace dirac;

// constructor
DrawMotionArrows::DrawMotionArrows(Picture & picture, DrawPictureMotionParams & draw_params,
                                   const MvArray & mv, int mv_scale)
:
    DrawOverlay(picture, draw_params),
    m_mv_scale(mv_scale),
    m_blocks_per_arrow_y(0),
    m_blocks_per_arrow_x(0),
    m_mv(mv)
{}

// destructor
DrawMotionArrows::~DrawMotionArrows()
{}

// manages drawing of arrows, dependent on size of motion vector block
void DrawMotionArrows::DrawBlock(int j, int i)
{
    // no chroma in picture
    for (int y=j*m_draw_params.MvUVBlockY(); y<(j+1)*m_draw_params.MvUVBlockY(); ++y)
    {
        if (y >= m_picture.Data(U_COMP).LengthY() || y >= m_picture.Data(V_COMP).LengthY())
            break;
        for (int x=i*m_draw_params.MvUVBlockX(); x<(i+1)*m_draw_params.MvUVBlockX(); ++x)
        {
            if (x >= m_picture.Data(U_COMP).LengthX() || x >= m_picture.Data(V_COMP).LengthX())
                break;
            m_picture.Data(U_COMP)[y][x] = 0;
            m_picture.Data(V_COMP)[y][x] = 0;
        }
    }

    // reset
    m_blocks_per_arrow_y = 0;
    m_blocks_per_arrow_x = 0;

    int group_x = 0;
    int group_y = 0;

    // build group of motion vector blocks larger than 16 x 16
    while (group_x < 16)
    {
        group_x += m_draw_params.MvYBlockX();
        ++m_blocks_per_arrow_x;
    }
    while (group_y < 16)
    {
        group_y += m_draw_params.MvYBlockY();
         ++m_blocks_per_arrow_y;
    }

    // calculate offset for TL corner of arrow
    int offset_x = 0;
    int offset_y = 0;
            
    if (group_x != 16)
        offset_x = int( (group_x - 16) / 2 );
    if (group_y != 16)
        offset_y = int( (group_y - 16) / 2 );

    // draw arrow if this block is TL corner of arrow
    if ( (j == 0 || (j % m_blocks_per_arrow_y) == 0) && ((i == 0 || (i % m_blocks_per_arrow_x) == 0 )) &&
        (j*m_draw_params.MvYBlockY()+offset_y+15 <= m_picture.Data(Y_COMP).LengthY()) &&
        (i*m_draw_params.MvYBlockX()+offset_x+15 <= m_picture.Data(Y_COMP).LengthX()) )
    {
        DrawArrow(j, i, (j*m_draw_params.MvYBlockY())+offset_y, (i*m_draw_params.MvYBlockX())+offset_x);
    }
}

// draws a single 16 x 16 pixel arrow, taking the mean of motion vectors
void DrawMotionArrows::DrawArrow(int j, int i, int y_pos, int x_pos)
{
    // find average motion vector for block group
    int x_sum = 0, y_sum = 0;

    // loop over motion vector group
    for (int y=j; y<j+m_blocks_per_arrow_y; ++y)
    {
        for (int x=i; x<i+m_blocks_per_arrow_x; ++x)
        {
            x_sum += m_mv[y][x].x;
            y_sum -= m_mv[y][x].y;
        }
    }

    double x_avg = x_sum / (m_blocks_per_arrow_x * m_blocks_per_arrow_x * m_mv_scale);
    double y_avg = y_sum / (m_blocks_per_arrow_y * m_blocks_per_arrow_y * m_mv_scale);

    // get absolute angle
    double angle = std::atan(std::abs(x_avg) / std::abs(y_avg)) * (360 / 6.82);

    // arrow arrays representing angles 0 ~ 90 degrees are stored, therefore need to flip
    // them around if the angle is negative
    if (angle > -3.75 && angle <= 3.75)
        m_symbols.Arrow(m_symbols.Arrow0());

    else if ((angle > 3.75 && angle <= 11.25) || (angle < -3.75 && angle >= -11.25))
        m_symbols.Arrow(m_symbols.Arrow7_5());

    else if ((angle > 11.25 && angle <= 18.75) || (angle < -11.25 && angle >= -18.75))
        m_symbols.Arrow(m_symbols.Arrow15());

    else if ((angle > 18.75 && angle <= 26.25) || (angle < -18.75 && angle >= -26.25))
        m_symbols.Arrow(m_symbols.Arrow22_5());

    else if ((angle > 26.25 && angle <= 33.75) || (angle < -26.25 && angle >= -33.75))
        m_symbols.Arrow(m_symbols.Arrow30());

    else if ((angle > 33.75 && angle <= 41.25) || (angle < -33.75 && angle >= -41.25))
        m_symbols.Arrow(m_symbols.Arrow37_5());

    else if ((angle > 41.25 && angle <= 48.75) || (angle < -41.25 && angle >= -48.75))
        m_symbols.Arrow(m_symbols.Arrow45());

    else if ((angle > 48.75 && angle <= 56.25) || (angle < -48.75 && angle >= -56.25))
        m_symbols.Arrow(m_symbols.Arrow52_5());

    else if ((angle > 56.25 && angle <= 63.75) || (angle < -56.25 && angle >= -63.75))
        m_symbols.Arrow(m_symbols.Arrow60());

    else if ((angle > 63.75 && angle <= 71.25) || (angle < -63.75 && angle >= -71.25))
        m_symbols.Arrow(m_symbols.Arrow67_5());

    else if ((angle > 71.25 && angle <= 78.75) || (angle < -71.25 && angle >= -78.75))
        m_symbols.Arrow(m_symbols.Arrow75());

    else if ((angle > 78.75 && angle <= 86.25) || (angle < -78.75 && angle >= -86.25))
        m_symbols.Arrow(m_symbols.Arrow82_5());

    else if ((angle > 86.25 && angle <= 90) || (angle < -86.25 && angle >= -90))
        m_symbols.Arrow(m_symbols.Arrow90());

    bool flipH = false, flipV = false;

    // check sign
    if (x_avg < 0)
        flipH=true;

    if (y_avg < 0)
        flipV=true;

    // no motion
    if (y_avg == 0 && x_avg == 0)
        m_symbols.Arrow(m_symbols.ArrowNull());

    // special case if angle is exactly 0 or 90
    else if (y_avg == 0)
        m_symbols.Arrow(m_symbols.Arrow90());

    else if (x_avg == 0)
        m_symbols.Arrow(m_symbols.Arrow0());

    if (flipH && !flipV)
    {
        for (int ypx=0; ypx<16; ++ypx)
        {
            for (int xpx=0; xpx<16; ++xpx)
            {
                m_picture.Data(Y_COMP)[(y_pos)+ypx][(x_pos) + xpx] += m_symbols.Arrow()[ypx][15-xpx] * 256;
            }// xpx
        }// ypx
    }
    else if (!flipH && flipV)
    {
        for (int ypx=0; ypx<16; ++ypx)
        {
            for (int xpx=0; xpx<16; ++xpx)
            {
                m_picture.Data(Y_COMP)[(y_pos) + ypx][(x_pos) + xpx] += m_symbols.Arrow()[15-ypx][xpx] * 256;
            }// xpx
        }// ypx
    }
    else if (flipH && flipV)
    {
        for (int ypx=0; ypx<16; ++ypx)
        {
            for (int xpx=0; xpx<16; ++xpx)
            {
                m_picture.Data(Y_COMP)[(y_pos) + ypx][(x_pos) + xpx] += m_symbols.Arrow()[15-ypx][15-xpx] * 256;
            }// xpx
        }// ypx
    }
    else
    {
        for (int ypx=0; ypx<16; ++ypx)
        {
            for (int xpx=0; xpx<16; ++xpx)
            {
                m_picture.Data(Y_COMP)[(y_pos) + ypx][(x_pos) + xpx] += m_symbols.Arrow()[ypx][xpx] * 256;
            }// xpx
        }// ypx
    }
}

// no appropriate legend for overlay
void DrawMotionArrows::DrawLegend()
{}
