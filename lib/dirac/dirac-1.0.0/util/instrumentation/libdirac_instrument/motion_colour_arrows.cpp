/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: motion_colour_arrows.cpp,v 1.7 2008/06/19 10:39:59 tjdwave Exp $ $Name: Dirac_1_0_0 $
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

#include <util/instrumentation/libdirac_instrument/motion_colour_arrows.h>
using namespace dirac_instr;
using namespace dirac;

// constructor
DrawMotionColourArrows::DrawMotionColourArrows(Picture & picture, DrawPictureMotionParams & draw_params,
                                               const MvArray & mv, int mv_scale, int mv_clip)
:
    DrawMotionArrows(picture, draw_params, mv, mv_scale),
    m_mv_clip(mv_clip)
{}

// destructor
DrawMotionColourArrows::~DrawMotionColourArrows()
{}

// manages call to DrawMotionArrows::DrawArrow() and colours motion vector blocks
void DrawMotionColourArrows::DrawBlock(int j, int i)
{
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

        // find average motion vector for block group
        int x_sum = 0, y_sum = 0;

        for (int y=j; y<j+m_blocks_per_arrow_y; ++y)
        {
            for (int x=i; x<i+m_blocks_per_arrow_x; ++x)
            {
                x_sum += m_mv[y][x].x;
                y_sum -= m_mv[y][x].y;
            }
        }

        double x_avg = x_sum / (m_blocks_per_arrow_y * m_blocks_per_arrow_y * m_mv_scale);
        double y_avg = y_sum / (m_blocks_per_arrow_x * m_blocks_per_arrow_x * m_mv_scale);
        double power = (250 / m_mv_clip) * std::sqrt((x_avg*x_avg)+(y_avg*y_avg));

        int U = 0, V = 0;
        GetPowerUV((int)power, U, V);

        for (int y=j; y<j+m_blocks_per_arrow_y; ++y)
        {
            for (int x=i; x<i+m_blocks_per_arrow_x; ++x)
            {
                DrawMvBlockUV(y, x, U, V);
            }
        }
    }
}

// draws power bar colour legend
void DrawMotionColourArrows::DrawLegend()
{
    DrawPowerBar(0, m_mv_clip);
}
