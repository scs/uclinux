/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: draw_overlay.cpp,v 1.10 2008/06/19 10:39:59 tjdwave Exp $ $Name: Dirac_1_0_0 $
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

#include <util/instrumentation/libdirac_instrument/draw_overlay.h>
using namespace dirac_instr;
using namespace dirac;

// constructor
DrawOverlay::DrawOverlay(Picture & picture, DrawPictureMotionParams & draw_params)
:
    m_picture(picture),
    m_draw_params(draw_params)
{}

// destructor
DrawOverlay::~DrawOverlay()
{}

// calculates U and V from a value ranging 0 ~ 250 (normalising is carried out in calling function)
void DrawOverlay::GetPowerUV(int power, int & U, int & V)
{
    // first convert power into RGB values
    // ranging 0 ~ 125
    float R = 0, G = 0, B = 0;

    // check which region value is located
    if (power < 50)
    {
        B = 0;
        G = 250;
        R = 5 * power;
    }
    else if (power >= 50 && power < 100)
    {
        R = 250;
        B = 0;
        G = 250 - (5 * (power - 50));
    }
    else if (power >= 100 && power < 150)
    {
        R = 250;
        G = 0;
        B = 5 * (power - 100);
    }
    else if (power >= 150 && power < 200)
    {
        B = 250;
        G = 0;
        R = 250 - (5 * (power - 150));
    }
    else if (power >= 200 && power < 250)
    {
        B = 250;
        R = 0;
        G = 5 * (power - 200);
    }
    else if (power >= 250)
    {
        B = 250;
        R = 0;
        G = 250;
    }

    R *= 0.25;
    G *= 0.25;
    B *= 0.25;

    // now convert RGB to UV
    float Y=(0.3*R)+(0.59*G)+(0.11*B);
    U=int(B-Y);
    V=int(R-Y);
}

// draws power bar legend
void DrawOverlay::DrawPowerBar(int min, int max)
{
    // loop over rows
    for (int ypx=40; ypx<m_draw_params.PicY(); ++ypx)
    {
        // black line
        m_picture.Data(Y_COMP)[ypx][5]=0;

        for (int xpx=0; xpx<5; ++xpx)
            m_picture.Data(Y_COMP)[ypx][xpx]=0; // grey background
    }

    // draw colour on line by line basis
    for (int ypx=40/m_draw_params.ChromaFactorY(); ypx<(m_draw_params.PicY()/m_draw_params.ChromaFactorY()); ++ypx)
    {
        // find equivalent power value
        double power = (250 * (((m_draw_params.PicY()/m_draw_params.ChromaFactorY())) - (40/m_draw_params.ChromaFactorY()) - ypx) /
                        (m_draw_params.PicY()/m_draw_params.ChromaFactorY())-(40/m_draw_params.ChromaFactorY()));

        // get U V values for power
        int U=0, V=0;
        GetPowerUV((int)power, U, V);

        for (int xpx=0; xpx<=4/m_draw_params.ChromaFactorX(); ++xpx)
        {
            m_picture.Data(U_COMP)[ypx][xpx]=U;
            m_picture.Data(V_COMP)[ypx][xpx]=V;
        }
    }

    // draw min and max labels
    DrawValue(min, m_draw_params.PicY()-16, 0);
    DrawValue(max, 40, 8);
    DrawCharacter(m_symbols.SymbolGreater(), 40, 0);
}

// draws a 8x16 character in luma
void DrawOverlay::DrawCharacter(const PicArray & ch, int y_offset, int x_offset)
{
    // loop over samples in 8x16 block
    for (int y=y_offset, y_ch=0; y<y_offset+16; ++y, ++y_ch)
    {
        for (int x=x_offset, x_ch=0; x<x_offset+8; ++x, ++x_ch)
        {
            m_picture.Data(Y_COMP)[y][x]=ch[y_ch][x_ch]*255-128;
        }// x
    }// y

    // remove chroma from digit
    for (int ypx=y_offset/m_draw_params.ChromaFactorY(); ypx<(y_offset+16)/m_draw_params.ChromaFactorY(); ++ypx)
    {
        for (int xpx=x_offset/m_draw_params.ChromaFactorX(); xpx<(x_offset+8)/m_draw_params.ChromaFactorX(); ++xpx)
        {
            m_picture.Data(U_COMP)[ypx][xpx]=0;
            m_picture.Data(V_COMP)[ypx][xpx]=0;
        }// xpx
    }// ypx
}

// draws value in luma
void DrawOverlay::DrawValue(int number, int y_offset, int x_offset)
{
    int digits = 0;
    // number of digits in picture number
    if (number < 10)
        digits = 1;
    else if (number >= 10 && number < 100)
        digits=2;
    else if (number >= 100 && number < 1000)
        digits=3;
    else if (number >= 1000 && number < 10000)
        digits=4;
    else if (number >= 10000 && number < 100000)
        digits=5;

    // loop over digits
    for (int digit=digits; digit>0; --digit)
    {
        int value = 0;

        // get digit, largest first
        if (digit == 5)
            value = (int)number/10000;
        else if (digit == 4)
            value = (int)number/1000;
        else if (digit == 3)
            value = (int)number/100;
        else if (digit == 2)
            value = (int)number/10;
        else if (digit == 1)
            value = number;

        // set arrow to correct number PicArray
        if (value == 0)
            DrawCharacter(m_symbols.Number0(), y_offset, x_offset);
        else if (value == 1)
            DrawCharacter(m_symbols.Number1(), y_offset, x_offset);
        else if (value == 2)
            DrawCharacter(m_symbols.Number2(), y_offset, x_offset);
        else if (value == 3)
            DrawCharacter(m_symbols.Number3(), y_offset, x_offset);
        else if (value == 4)
            DrawCharacter(m_symbols.Number4(), y_offset, x_offset);
        else if (value == 5)
            DrawCharacter(m_symbols.Number5(), y_offset, x_offset);
        else if (value == 6)
            DrawCharacter(m_symbols.Number6(), y_offset, x_offset);
        else if (value == 7)
            DrawCharacter(m_symbols.Number7(), y_offset, x_offset);
        else if (value == 8)
            DrawCharacter(m_symbols.Number8(), y_offset, x_offset);
        else if (value == 9)
            DrawCharacter(m_symbols.Number9(), y_offset, x_offset);

        // remove most significant digit
        if (digit == 5)
            number -= value * 10000;
        else if (digit == 4)
            number -= value * 1000;
        else if (digit == 3)
            number -= value * 100;
        else if (digit == 2)
            number -= value * 10;

        x_offset+=8;
    }
}

// draws both reference picture numbers
void DrawOverlay::DrawReferenceNumbers(int ref1, int ref2)
{
    // draw letters: 'R1:' and 'R2:' on consecutive lines
    DrawCharacter(m_symbols.LetterR(), 16, 0);
    DrawCharacter(m_symbols.LetterR(), 32, 0);
    DrawCharacter(m_symbols.Number1(), 16, 8);
    DrawCharacter(m_symbols.Number2(), 32, 8);
    DrawCharacter(m_symbols.SymbolColon(), 16, 16);
    DrawCharacter(m_symbols.SymbolColon(), 32, 16);

    if (ref1==NO_REF)
        DrawCharacter(m_symbols.SymbolMinus(), 16, 24);
    else
        DrawValue(ref1, 16, 24);
    if (ref2==NO_REF)
        DrawCharacter(m_symbols.SymbolMinus(), 32, 24);
    else
        DrawValue(ref2, 32, 24);
}

// draws picture number
void DrawOverlay::DrawPictureNumber(int pnum)
{
    DrawCharacter(m_symbols.LetterF(), 0, 0);
    DrawValue(pnum, 0, 8);
}

// draws used reference picture number
void DrawOverlay::DrawReferenceNumber(int ref, int ref_picture)
{
    DrawCharacter(m_symbols.LetterR(), 16, 0);
    DrawCharacter(m_symbols.SymbolColon(), 16, 16);
    
    if (ref==1)
        DrawCharacter(m_symbols.Number1(), 16, 8);
    else if (ref==2)
        DrawCharacter(m_symbols.Number2(), 16, 8);
    
    if (ref_picture==-1)
        DrawCharacter(m_symbols.SymbolMinus(), 16, 24);
    else
        DrawValue(ref_picture, 16, 24);
}

// colours a single block, referenced by motion vector
void DrawOverlay::DrawMvBlockUV(int ymv, int xmv, int U, int V)
{
    // loop over chroma samples in block
    for (int y=0; y<m_draw_params.MvUVBlockY(); ++y)
    {
        int y_idx = (ymv*m_draw_params.MvUVBlockY())+y;
        if (y_idx >= m_picture.Data(U_COMP).LengthY() || 
            y_idx >= m_picture.Data(V_COMP).LengthY())
            break;
        for (int x=0; x<m_draw_params.MvUVBlockX(); ++x)
        {
            int x_idx = (xmv*m_draw_params.MvUVBlockX())+x;
            if (x_idx >= m_picture.Data(U_COMP).LengthX() || 
                x_idx >= m_picture.Data(V_COMP).LengthX())
                break;
              
            //m_picture.Data(U_COMP)[(ymv*m_draw_params.MvUVBlockY())+y][(xmv*m_draw_params.MvUVBlockX())+x]=U;
            //m_picture.Data(V_COMP)[(ymv*m_draw_params.MvUVBlockY())+y][(xmv*m_draw_params.MvUVBlockX())+x]=V;
            m_picture.Data(U_COMP)[y_idx][x_idx]=U;
            m_picture.Data(V_COMP)[y_idx][x_idx]=V;
        }// xpx
    }// ypx
}

// colours an 8x8 block, referenced by TL chroma pixel
void DrawOverlay::DrawBlockUV(int ypx, int xpx, int U, int V)
{
    // loop over chroma samples in block
    for (int y=ypx; y<ypx+(8/m_draw_params.ChromaFactorY()); ++y)
    {
        for (int x=xpx; x<xpx+(8/m_draw_params.ChromaFactorX()); ++x)
        {
            m_picture.Data(U_COMP)[y][x]=U;
            m_picture.Data(V_COMP)[y][x]=V;
        }// xpx
    }// ypx
}
