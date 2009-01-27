/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: overlay.cpp,v 1.12 2008/08/27 00:18:55 asuraparaju Exp $ $Name: Dirac_1_0_0 $
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

#include <util/instrumentation/libdirac_instrument/overlay.h>

using namespace dirac_instr;

using namespace dirac;

// constructor
Overlay::Overlay (const OverlayParams & overlayparams, Picture & picture)
:
    m_oparams(overlayparams),
    m_picture(picture)
{
    CalculateFactors(picture.GetPparams().CFormat());
}

// destructor - doesn't do anything!
Overlay::~Overlay ()
{}

// process intra picture
void Overlay::ProcessPicture()
{
    // if a mid-grey background is selected instead of the original luma, do that
    if (m_oparams.Background()==0)
    {
        for (int j=0; j<=m_picture.Data(Y_COMP).LastY(); ++j)
        {
            for (int i=0; i<=m_picture.Data(Y_COMP).LastX(); ++i)
                m_picture.Data(Y_COMP)[j][i]=0;
        }
    }

    // set chroma arrays to zero
    for (int j=0; j<m_picture.Data(U_COMP).LengthY(); ++j)
    {
        for (int i=0; i<m_picture.Data(U_COMP).LengthX(); ++i)
        {
            m_picture.Data(U_COMP)[j][i]=0;
            m_picture.Data(V_COMP)[j][i]=0;
        }
    }

    // in order to draw picture number and 'I' label, create a dummy DrawPredMode object
    // and call appropriate functions. Not the most elegant!
    PicturePredParams predparams;
    predparams.SetXNumBlocks(1);
    predparams.SetYNumBlocks(1);
    predparams.SetXNumMB(1);
    predparams.SetYNumMB(1);
    MEData me_data(predparams);
    DrawPredMode dummy(m_picture, m_draw_params, me_data.Mode());
    dummy.DrawPictureNumber(m_picture.GetPparams().PictureNum());
    dummy.DrawCharacter(dummy.Symbols().LetterI(), 16, 0);
}

// process motion-compensated picture
void Overlay::ProcessPicture(const MEData & me_data, const OLBParams & block_params)
{
    m_draw_params.SetMvYBlockY(block_params.Ybsep());
    m_draw_params.SetMvYBlockX(block_params.Xbsep());
    m_draw_params.SetMvUVBlockY(block_params.Ybsep()/m_draw_params.ChromaFactorY());
    m_draw_params.SetMvUVBlockX(block_params.Xbsep()/m_draw_params.ChromaFactorX());
    m_draw_params.SetPicY(m_picture.Data(Y_COMP).LengthY());
    m_draw_params.SetPicX(m_picture.Data(Y_COMP).LengthX());

    //std::cerr<<std::endl<<"Pic: "<<m_draw_params.PicY()<<" "<<m_draw_params.PicX();

    PadPicture(me_data);

    // if a mid-grey background is selected instead of the original luma, do that
    if (m_oparams.Background()==0)
    {
        for (int j=0; j<=m_picture.Data(Y_COMP).LastY(); ++j)
        {
            for (int i=0; i<=m_picture.Data(Y_COMP).LastX(); ++i)
                m_picture.Data(Y_COMP)[j][i]=0;
        }
    }

    // set up references
    if (m_oparams.Reference() == 2 && (m_picture.GetPparams().Refs().size() < 2 || m_picture.GetPparams().Refs()[0] == m_picture.GetPparams().Refs()[1]))
    {
        m_ref = NO_REF;
        m_mv_scale = 1;
    }
    else
    {
        m_ref = m_picture.GetPparams().Refs()[m_oparams.Reference()-1];
        m_mv_scale = std::abs(m_picture.GetPparams().PictureNum()-m_picture.GetPparams().Refs()[m_oparams.Reference()-1]); // scale motion vectors for temporal difference
    }

    // now do the overlaying!
    DoOverlay(me_data);
}

// manages the overlaying process dependent on the command-line options
void Overlay::DoOverlay(const MEData & me_data)
{
    // Overlay Class Structure
    // =======================
    //                                      +-------------+
    //                                      | DrawOverlay |
    //                                      +-------------+
    //                                         | | | | |
    //                                         | | | | +------------------------------+
    //           +-----------------------------+ | | +---------------+                |
    //           |                   +-----------+ +--+              |                |
    //           |                   |                |              |                |
    // +------------------+ +------------------+ +---------+ +---------------+ +--------------+
    // | DrawMotionColour | | DrawMotionArrows | | DrawSad | | DrawSplitMode | | DrawPredMode |
    // +------------------+ +------------------+ +---------+ +---------------+ +--------------+
    //                               |
    //                               |
    //                  +------------------------+
    //                  | DrawMotionColourArrows |
    //                  +------------------------+
    //
    // In order to create a new overlay, sub-class DrawOverlay and override DrawBlock() and DrawLegend() functions

    // create poitner to DrawOverlay object
    DrawOverlay * draw_overlay_ptr = NULL;

    MvArray mv_diff( me_data.Vectors(m_oparams.Reference()).LengthY(),
                     me_data.Vectors(m_oparams.Reference()).LengthX());

    // choose appropriate object dependent on command line option
    switch (m_oparams.Option())
    {
        case motion_arrows :
            draw_overlay_ptr = new DrawMotionArrows(m_picture, m_draw_params,
                                                    me_data.Vectors(m_oparams.Reference()), m_mv_scale);
            break;

        case motion_colour_arrows :
            draw_overlay_ptr = new DrawMotionColourArrows(m_picture, m_draw_params,
                                                          me_data.Vectors(m_oparams.Reference()), m_mv_scale,
                                                          m_oparams.MvClip());
            break;

        case motion_colour :
            draw_overlay_ptr = new DrawMotionColour(m_picture, m_draw_params,
                                                    me_data.Vectors(m_oparams.Reference()),
                                                    m_mv_scale, m_oparams.MvClip());
            break;

        case SAD :
            draw_overlay_ptr = new DrawSad(m_picture, m_draw_params, me_data.PredCosts(m_oparams.Reference()),
                                           me_data.Mode(), m_oparams.SADClip());
            break;

        case split_mode :
            draw_overlay_ptr = new DrawSplitMode(m_picture, m_draw_params, me_data.MBSplit());
            break;

        case pred_mode :
            draw_overlay_ptr = new DrawPredMode(m_picture, m_draw_params, me_data.Mode());
            break;

        case gm_arrows :
            draw_overlay_ptr = new DrawMotionArrows(m_picture,
                                                    m_draw_params,
                                                    me_data.GlobalMotionVectors(m_oparams.Reference()),
                                                    m_mv_scale);
            break;

        case gm_colour_arrows :
            draw_overlay_ptr = new DrawMotionColourArrows(m_picture,
                                                          m_draw_params,
                                                          me_data.GlobalMotionVectors(m_oparams.Reference()),
                                                          m_mv_scale,
                                                          m_oparams.MvClip());
            break;

        case gm_colour :
            draw_overlay_ptr = new DrawMotionColour(m_picture,
                                                    m_draw_params,
                                                    me_data.GlobalMotionVectors(m_oparams.Reference()),
                                                    m_mv_scale,
                                                    m_oparams.MvClip());

            break;

        case gm_diff_arrows :
            
            GlobalMotionDifference( me_data, mv_diff );
            
            draw_overlay_ptr = new DrawMotionArrows(m_picture,
                                                    m_draw_params,
                                                    mv_diff,
                                                    m_mv_scale);
            break;

        case gm_diff_colour_arrows :

            GlobalMotionDifference( me_data, mv_diff );
            
            draw_overlay_ptr = new DrawMotionColourArrows(m_picture,
                                                          m_draw_params,
                                                          mv_diff,
                                                          m_mv_scale,
                                                          m_oparams.MvClip());
            break;

        case gm_diff_colour :

            GlobalMotionDifference( me_data, mv_diff );
            
            draw_overlay_ptr = new DrawMotionColour(m_picture,
                                                    m_draw_params,
                                                    mv_diff,
                                                    m_mv_scale,
                                                    m_oparams.MvClip());

            break;

        case gm_inliers :
            draw_overlay_ptr = new DrawGMInliers(m_picture, m_draw_params, me_data.GlobalMotionInliers(m_oparams.Reference()));
            
            break;
    }
    
    // if we are trying to overlay information which does not exist because picture only
    // has a single reference, remove chroma and display picture number and legend
    if (m_ref==-1 && m_oparams.Option() != pred_mode && m_oparams.Option() != split_mode)
    {
        for (int y=0; y<m_picture.Data(U_COMP).LengthY(); ++y)
        {
            for (int x=0; x<m_picture.Data(U_COMP).LengthX(); ++x)
            {
                m_picture.Data(U_COMP)[y][x] = 0;
                m_picture.Data(V_COMP)[y][x] = 0;
            }
        }
        
        if (m_oparams.Legend())
            draw_overlay_ptr->DrawLegend();
            
        draw_overlay_ptr->DrawPictureNumber(m_picture.GetPparams().PictureNum());        
        draw_overlay_ptr->DrawReferenceNumber(m_oparams.Reference(), m_ref);
    }
    // otherwise, loop over motion vector blocks and draw as appropriate to overlay
    else
    {
        // carry out overlay on block by block basis
        for (int j=0; j<me_data.Vectors(1).LengthY(); ++j)
        {
            for (int i=0; i<me_data.Vectors(1).LengthX(); ++i)
            {
                draw_overlay_ptr->DrawBlock(j, i); 
            }
            
        }

        if (m_oparams.Legend())
            draw_overlay_ptr->DrawLegend();
            
        draw_overlay_ptr->DrawPictureNumber(m_picture.GetPparams().PictureNum());

        if (m_oparams.Option() == pred_mode || m_oparams.Option() == split_mode)
            draw_overlay_ptr->DrawReferenceNumbers(m_picture.GetPparams().Refs()[0], m_picture.GetPparams().Refs()[1]);
        else
            draw_overlay_ptr->DrawReferenceNumber(m_oparams.Reference(), m_ref);
    }
    if (draw_overlay_ptr)
        delete draw_overlay_ptr;
}

// calculates the resolution factor between chroma and luma samples
void Overlay::CalculateFactors(const ChromaFormat & cformat)
{
    if (cformat == format422)
    {
        m_draw_params.SetChromaFactorY(1);
        m_draw_params.SetChromaFactorX(2);
    }
    else if (cformat == format420)
    {
        m_draw_params.SetChromaFactorY(2);
        m_draw_params.SetChromaFactorX(2);
    }
    else if (cformat == format444)
    {
        m_draw_params.SetChromaFactorY(1);
        m_draw_params.SetChromaFactorX(1);
    }
    else
    {
        m_draw_params.SetChromaFactorY(1);
        m_draw_params.SetChromaFactorX(1);
    }
}

// calculate if picture requires padding due to requirement of integer number of macroblocks
void Overlay::PadPicture(const MEData & me_data)
{
    int picture_x = m_picture.Data(Y_COMP).LengthX();
    int picture_y = m_picture.Data(Y_COMP).LengthY();

    // copy picture components
    PicArray Ydata(m_picture.Data(Y_COMP));
    PicArray Udata(m_picture.Data(U_COMP));
    PicArray Vdata(m_picture.Data(V_COMP));

    // if there is not an integer number of macroblocks horizontally, pad until there is
    if (m_picture.Data(Y_COMP).LengthX() % me_data.MBSplit().LengthX() != 0)
    {
        do
        {
            ++picture_x;
        }
        while (picture_x % me_data.MBSplit().LengthX() != 0);       
    }

    // if there is not an integer number of macroblocks vertically, pad until there is
    if (m_picture.Data(Y_COMP).LengthX() % me_data.MBSplit().LengthY() != 0)
    {
        do
        {
            ++picture_y;
        }
        while (picture_y % me_data.MBSplit().LengthY() != 0);
    }

    // if padding was required in either horizontal or vertical, adjust picture size and reload component data
    if (m_picture.Data(Y_COMP).LengthX() % me_data.MBSplit().LengthX() != 0 || m_picture.Data(Y_COMP).LengthY() % me_data.MBSplit().LengthY() != 0)
    {
        m_picture.Data(Y_COMP).Resize(picture_y, picture_x);
        m_picture.Data(U_COMP).Resize(picture_y / m_draw_params.ChromaFactorY(), picture_x / m_draw_params.ChromaFactorX());
        m_picture.Data(V_COMP).Resize(picture_y / m_draw_params.ChromaFactorY(), picture_x / m_draw_params.ChromaFactorX());
       
        for (int j=0; j<Ydata.LengthY(); ++j)
        {
            for (int i=0; i<Ydata.LengthX(); ++i)
            {
                m_picture.Data(Y_COMP)[j][i]=Ydata[j][i];
            }
            // pad the columns on the rhs using the edge value
            for (int i=Ydata.LengthX(); i <  m_picture.Data(Y_COMP).LengthX(); ++i)
                m_picture.Data(Y_COMP)[j][i] = m_picture.Data(Y_COMP)[j][Ydata.LengthX()-1];
        }
        // do the padded lines using the last true line
        for (int j=Ydata.LengthY(); j<m_picture.Data(Y_COMP).LengthY(); ++j)
        {
            //std::cerr << "Processing row " << j  << std::endl;
            for (int i=0; i <  m_picture.Data(Y_COMP).LengthX(); ++i)
            {
                m_picture.Data(Y_COMP)[j][i] = m_picture.Data(Y_COMP)[Ydata.LengthY()-1][i];
            }
        }
        
        for (int j=0; j<Udata.LengthY(); ++j)
        {
            for (int i=0; i<Udata.LengthX(); ++i)
            {
                m_picture.Data(U_COMP)[j][i]=Udata[j][i];
                m_picture.Data(V_COMP)[j][i]=Vdata[j][i];
            }
            // pad the columns on the rhs using the edge value
            for (int i=Udata.LengthX(); i <  m_picture.Data(U_COMP).LengthX(); ++i)
            {
                m_picture.Data(U_COMP)[j][i] = m_picture.Data(U_COMP)[j][Udata.LengthX()-1];
                m_picture.Data(V_COMP)[j][i] = m_picture.Data(V_COMP)[j][Udata.LengthX()-1];
            }
        }
        // do the padded lines using the last true line
        for (int j=Udata.LengthY(); j<m_picture.Data(U_COMP).LengthY(); ++j)
        {
            //std::cerr << "Processing row " << j  << std::endl;
            for (int i=0; i <  m_picture.Data(U_COMP).LengthX(); ++i)
            {
                m_picture.Data(U_COMP)[j][i] = m_picture.Data(U_COMP)[Udata.LengthY()-1][i];
                m_picture.Data(V_COMP)[j][i] = m_picture.Data(V_COMP)[Udata.LengthY()-1][i];
            }
        }

    }

}

void Overlay::GlobalMotionDifference(const MEData & me_data, MvArray & mv_diff)
{
    for (int y=0; y<mv_diff.LengthY(); ++y)
    {
        for (int x=0; x<mv_diff.LengthX(); ++x)
        {
            mv_diff[y][x].x = me_data.Vectors(m_oparams.Reference())[y][x].x
                              - me_data.GlobalMotionVectors(m_oparams.Reference())[y][x].x;
            mv_diff[y][x].y = me_data.Vectors(m_oparams.Reference())[y][x].y
                              - me_data.GlobalMotionVectors(m_oparams.Reference())[y][x].y;
        }
    }


}
