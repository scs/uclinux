/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: motion_comp_test.cpp,v 1.17 2008/08/27 01:06:05 asuraparaju Exp $ $Name: Dirac_1_0_0 $
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
* The Original Code is Steve Bearcroft's code.
*
* The Initial Developer of the Original Code is Steve Bearcroft.
* Portions created by the Initial Developer are Copyright (C) 2004.
* All Rights Reserved.
*
* Contributor(s): Steve Bearcroft (Original Author)
*                 Anuradha Suraparaju
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
#include "core_suite.h"
#include "motion_comp_test.h"
#include "frames_test.h"

#include <libdirac_common/picture.h>
#include <libdirac_common/picture_buffer.h>
#include <libdirac_common/mot_comp.h>
using namespace dirac;

#include <memory>

//NOTE: ensure that the suite is added to the default registry in
//cppunit_testsuite.cpp
CPPUNIT_TEST_SUITE_NAMED_REGISTRATION (MotionCompTest, coreSuiteName());

#define X_SIZE  352
#define Y_SIZE  288

MotionCompTest::MotionCompTest()
{
}

MotionCompTest::~MotionCompTest()
{
}

void MotionCompTest::setUp()
{
}

void MotionCompTest::tearDown()
{
}


MvData* setupMV1Data(const PicturePredParams& ppp, int mv_x, int mv_y, PredMode mode)
{
    MvData* mv_data = new MvData(ppp, 2);
    MvArray& arr = mv_data->Vectors(1);
    for (int i =arr.FirstY(); i <= arr.LastY(); i++)
    {
        for (int j =arr.FirstX(); j <= arr.LastX(); j++)
        {
            arr[i][j].x = mv_x;
            arr[i][j].y = mv_y;
            mv_data->Mode()[i][j] = mode;
        }
    }
    return mv_data;
}

void setupMV2Data(MvData* mv_data, int mv_x, int mv_y)
{
    MvArray& arr = mv_data->Vectors(2);
    for (int i =arr.FirstY(); i <= arr.LastY(); i++)
    {
        for (int j =arr.FirstX(); j <= arr.LastX(); j++)
        {
            arr[i][j].x = mv_x;
            arr[i][j].y = mv_y;
        }
    }
}

void MotionCompTest::testZeroMotionComp()
{
    for (int i = 0; i < 4; ++i)
    {
        testZeroMotionComp(static_cast<MVPrecisionType>(i));
    }
}

void MotionCompTest::testZeroMotionComp(MVPrecisionType precision)
{
    PictureBuffer pbuffer;
    CodecParams cp(VIDEO_FORMAT_CIF, INTER_PICTURE, 1, true);
    PicturePredParams &ppp = cp.GetPicPredParams();
    OLBParams bparams(12, 12, 8, 8);

    ppp.SetMVPrecision(precision);
    ppp.SetBlockSizes(bparams, format420 );
    ppp.SetXNumMB( X_SIZE / ppp.LumaBParams(0).Xbsep() );
    ppp.SetYNumMB( Y_SIZE / ppp.LumaBParams(0).Ybsep() );
    ppp.SetYNumMB( Y_SIZE / ppp.LumaBParams(0).Ybsep() );

    ppp.SetXNumBlocks( 4*ppp.XNumMB() );
    ppp.SetYNumBlocks( 4*ppp.YNumMB() );

    // MotionCompensator mc( cp );
    
    MvData* mv_data = setupMV1Data(ppp, 0, 0, REF1_ONLY);

    PictureParams pp(format420, X_SIZE, Y_SIZE, 8, 8);

    pp.SetPicSort(PictureSort::IntraRefPictureSort());
    pp.SetPictureNum(0);
    pbuffer.PushPicture(pp);
    PicturesTest::setupPicture(pbuffer.GetPicture(0),0);

    pp.SetPicSort(PictureSort::InterRefPictureSort());
    pp.SetPictureNum(1);
    pp.Refs().push_back(0);
    pbuffer.PushPicture(pp);
    PicturesTest::zeroPicture(pbuffer.GetPicture(1));

    pp.SetPictureNum(2);
    pbuffer.PushPicture(pp);
    PicturesTest::zeroPicture(pbuffer.GetPicture(2));

    Picture* ref_pics[2] = { &pbuffer.GetPicture(1), &pbuffer.GetPicture(2) };

    // mc.CompensatePicture(ADD, pbuffer, 1, *mv_data);
    MotionCompensator::CompensatePicture(ppp, ADD, *mv_data, &pbuffer.GetPicture(0), ref_pics );

    // MotionCompensator mc2( cp );

    //too many rounding errors for this to be exactly true;
    //CPPUNIT_ASSERT (PicturesTest::equalPictures (pbuffer.GetPicture(0), pbuffer.GetPicture(1)));
    // mc2.CompensatePicture(SUBTRACT, pbuffer, 1, *mv_data);
    MotionCompensator::CompensatePicture(ppp, SUBTRACT, *mv_data, &pbuffer.GetPicture(0), ref_pics );

    CPPUNIT_ASSERT (PicturesTest::equalPictures (pbuffer.GetPicture(2), pbuffer.GetPicture(1)));
    delete mv_data;
}

void MotionCompTest::testAddandSubMotionComp()
{
    for (int i = 0; i < 4; ++i)
    {
        testAddandSubMotionComp(static_cast<MVPrecisionType>(i));
    }
}

void MotionCompTest::testAddandSubMotionComp(MVPrecisionType precision)
{
    PictureBuffer pbuffer;
    CodecParams cp(VIDEO_FORMAT_CIF, INTER_PICTURE, 1, true);
    PicturePredParams &ppp = cp.GetPicPredParams();
    OLBParams bparams(12, 12, 8, 8);
    ppp.SetMVPrecision(precision);
    ppp.SetBlockSizes(bparams, format420 );
    ppp.SetXNumMB( X_SIZE / ppp.LumaBParams(0).Xbsep() );
    ppp.SetYNumMB( Y_SIZE / ppp.LumaBParams(0).Ybsep() );

    ppp.SetXNumBlocks( 4*ppp.XNumMB() );
    ppp.SetYNumBlocks( 4*ppp.YNumMB() );

    
    MvData* mv_data = setupMV1Data(ppp, 5, 5, REF1_ONLY);

    PictureParams pp(format420, X_SIZE, Y_SIZE, 8, 8);

    pp.SetPicSort(PictureSort::IntraRefPictureSort());
    pp.SetPictureNum(0);
    pbuffer.PushPicture(pp);
    PicturesTest::setupPicture(pbuffer.GetPicture(0),0);

    pp.SetPicSort(PictureSort::InterRefPictureSort());
    pp.SetPictureNum(1);
    pp.Refs().push_back(0);
    pbuffer.PushPicture(pp);
    PicturesTest::zeroPicture(pbuffer.GetPicture(1));

    pp.SetPictureNum(2);
    pbuffer.PushPicture(pp);
    PicturesTest::zeroPicture(pbuffer.GetPicture(2));

    Picture* ref_pics[2] = { &pbuffer.GetPicture(1), &pbuffer.GetPicture(2) };

    // MotionCompensator mc( cp );
    // mc.CompensatePicture(ADD, pbuffer, 1, *mv_data);
    MotionCompensator::CompensatePicture(ppp, ADD, *mv_data, &pbuffer.GetPicture(0), ref_pics );

    // MotionCompensator mc2( cp );
    // mc2.CompensatePicture(SUBTRACT, pbuffer, 1, *mv_data);
    MotionCompensator::CompensatePicture(ppp, SUBTRACT, *mv_data, &pbuffer.GetPicture(0), ref_pics );

    CPPUNIT_ASSERT (PicturesTest::equalPictures (pbuffer.GetPicture(2), pbuffer.GetPicture(1)));
    delete mv_data;
}

void MotionCompTest::testL2_picture()
{
    for (int i = 0; i < 4; ++i)
    {
        testL2_picture(static_cast<MVPrecisionType>(i));
    }
}

void MotionCompTest::testL2_picture(MVPrecisionType precision)
{
    PictureBuffer pbuffer;
    CodecParams cp(VIDEO_FORMAT_CIF, INTER_PICTURE, 1, true);
    PicturePredParams &ppp = cp.GetPicPredParams();
    OLBParams bparams(12, 12, 8, 8);
    ppp.SetMVPrecision(precision);
    ppp.SetBlockSizes(bparams, format420 );
    ppp.SetXNumMB( X_SIZE / ppp.LumaBParams(0).Xbsep() );
    ppp.SetYNumMB( Y_SIZE / ppp.LumaBParams(0).Ybsep() );

    ppp.SetXNumBlocks( 4*ppp.XNumMB() );
    ppp.SetYNumBlocks( 4*ppp.YNumMB() );

    
    MvData* mv_data = setupMV1Data(ppp, 5, 5, REF1_ONLY);

    PictureParams pp(format420, X_SIZE, Y_SIZE, 8, 8);

    pp.SetPicSort(PictureSort::IntraRefPictureSort());
    pp.SetPictureNum(0);
    pbuffer.PushPicture(pp);
    PicturesTest::setupPicture(pbuffer.GetPicture(0),0);

    pp.SetPicSort(PictureSort::InterNonRefPictureSort());
    pp.SetPictureNum(1);
    pp.Refs().push_back(0);
    pbuffer.PushPicture(pp);
    PicturesTest::zeroPicture(pbuffer.GetPicture(1));

    pp.SetPictureNum(2);
    pbuffer.PushPicture(pp);
    PicturesTest::zeroPicture(pbuffer.GetPicture(2));

    Picture* ref_pics[2] = { &pbuffer.GetPicture(1), &pbuffer.GetPicture(2) };

    // MotionCompensator mc( cp );
    // mc.CompensatePicture(ADD, pbuffer, 1, *mv_data);
    MotionCompensator::CompensatePicture(ppp, ADD, *mv_data, &pbuffer.GetPicture(0), ref_pics );

    // MotionCompensator mc2( cp );
    // mc2.CompensatePicture(SUBTRACT, pbuffer, 1, *mv_data);
    MotionCompensator::CompensatePicture(ppp, SUBTRACT, *mv_data, &pbuffer.GetPicture(0), ref_pics );

    CPPUNIT_ASSERT (PicturesTest::equalPictures (pbuffer.GetPicture(2), pbuffer.GetPicture(1)));
    delete mv_data;
}


void MotionCompTest::testI_picture()
{
    PictureBuffer pbuffer;
    CodecParams cp(VIDEO_FORMAT_CIF, INTER_PICTURE, 2, true);
    PicturePredParams &ppp = cp.GetPicPredParams();
    OLBParams bparams(12, 12, 8, 8);
    ppp.SetBlockSizes(bparams, format420 );
    ppp.SetXNumMB( X_SIZE / ppp.LumaBParams(0).Xbsep() );
    ppp.SetYNumMB( Y_SIZE / ppp.LumaBParams(0).Ybsep() );

    ppp.SetXNumBlocks( 4*ppp.XNumMB() );
    ppp.SetYNumBlocks( 4*ppp.YNumMB() );


    
    MvData* mv_data = setupMV1Data(ppp, 5, 5, REF1_ONLY);

    PictureParams pp(format420, X_SIZE, Y_SIZE, 8, 8);

    pp.SetPicSort(PictureSort::IntraRefPictureSort());
    pp.SetPictureNum(0);
    pbuffer.PushPicture(pp);
    PicturesTest::setupPicture(pbuffer.GetPicture(0),0);

    pp.SetPicSort(PictureSort::IntraRefPictureSort());
    pp.SetPictureNum(1);
    pp.Refs().push_back(0);
    pbuffer.PushPicture(pp);
    PicturesTest::setupPicture(pbuffer.GetPicture(1),0);

    Picture* ref_pics[2] = { &pbuffer.GetPicture(1), &pbuffer.GetPicture(1) };

    // MotionCompensator mc( cp );
    // mc.CompensatePicture(ADD, pbuffer, 1, *mv_data);
    MotionCompensator::CompensatePicture(ppp, ADD, *mv_data, &pbuffer.GetPicture(0), ref_pics );

    CPPUNIT_ASSERT (PicturesTest::equalPictures (pbuffer.GetPicture(0), pbuffer.GetPicture(1)));
    delete mv_data;
}


void MotionCompTest::testRef2()
{
    for (int i = 0; i < 4; ++i)
    {
        testRef2(static_cast<MVPrecisionType>(i));
    }
}

void MotionCompTest::testRef2(MVPrecisionType precision)
{
    PictureBuffer pbuffer;
    CodecParams cp(VIDEO_FORMAT_CIF, INTER_PICTURE, 2, true);
    PicturePredParams &ppp = cp.GetPicPredParams();
    OLBParams bparams(12, 12, 8, 8);
    ppp.SetMVPrecision(precision);
    ppp.SetBlockSizes(bparams, format420 );
    ppp.SetXNumMB( X_SIZE / ppp.LumaBParams(0).Xbsep() );
    ppp.SetYNumMB( Y_SIZE / ppp.LumaBParams(0).Ybsep() );

    ppp.SetXNumBlocks( 4*ppp.XNumMB() );
    ppp.SetYNumBlocks( 4*ppp.YNumMB() );


    
    MvData* mv_data = setupMV1Data(ppp, 5, 5, REF2_ONLY);
    setupMV2Data(mv_data, 0, 0);

    PictureParams pp(format420, X_SIZE, Y_SIZE, 8, 8);

    pp.SetPicSort(PictureSort::IntraRefPictureSort());
    pp.SetPictureNum(0);
    pbuffer.PushPicture(pp);
    PicturesTest::setupPicture(pbuffer.GetPicture(0),0);

    pp.SetPicSort(PictureSort::InterRefPictureSort());
    pp.SetPictureNum(1);
    pp.Refs().push_back(2);
    pp.Refs().push_back(0);
    pbuffer.PushPicture(pp);
    PicturesTest::zeroPicture(pbuffer.GetPicture(1));

    pp.SetPictureNum(2);
    pbuffer.PushPicture(pp);
    PicturesTest::zeroPicture(pbuffer.GetPicture(2));

    Picture* ref_pics[2] = { &pbuffer.GetPicture(1), &pbuffer.GetPicture(2) };

    // MotionCompensator mc( cp );
    // mc.CompensatePicture(ADD, pbuffer, 1, *mv_data);
    MotionCompensator::CompensatePicture(ppp, ADD, *mv_data, &pbuffer.GetPicture(0), ref_pics );

    //too many rounding errors for this to be exactly true;
    //CPPUNIT_ASSERT (PicturesTest::equalPictures (pbuffer.GetPicture(0), pbuffer.GetPicture(1)));

    // MotionCompensator mc2( cp );
    // mc2.CompensatePicture(SUBTRACT, pbuffer, 1, *mv_data);
    MotionCompensator::CompensatePicture(ppp, SUBTRACT, *mv_data, &pbuffer.GetPicture(0), ref_pics );

    CPPUNIT_ASSERT (PicturesTest::equalPictures (pbuffer.GetPicture(2), pbuffer.GetPicture(1)));
    delete mv_data;
}

void MotionCompTest::testRef1and2()
{
    for (int i = 0; i < 4; ++i)
    {
        testRef1and2(static_cast<MVPrecisionType>(i));
    }
}

void MotionCompTest::testRef1and2(MVPrecisionType precision)
{
    PictureBuffer pbuffer;
    CodecParams cp(VIDEO_FORMAT_CIF, INTER_PICTURE, 2, true);
    PicturePredParams &ppp = cp.GetPicPredParams();
    OLBParams bparams(12, 12, 8, 8);
    ppp.SetMVPrecision(precision);
    ppp.SetBlockSizes(bparams, format420 );
    ppp.SetXNumMB( X_SIZE / ppp.LumaBParams(0).Xbsep() );
    ppp.SetYNumMB( Y_SIZE / ppp.LumaBParams(0).Ybsep() );

    ppp.SetXNumBlocks( 4*ppp.XNumMB() );
    ppp.SetYNumBlocks( 4*ppp.YNumMB() );
    
    MvData* mv_data = setupMV1Data(ppp, 5, 5, REF1_ONLY);
    setupMV2Data(mv_data, 5, 5);

    MvData* mv_data1 = setupMV1Data(ppp, 7, 3, REF2_ONLY);
    setupMV2Data(mv_data1, 7, 3);

    MvData* mv_data2 = setupMV1Data(ppp, 5, 5, REF1AND2);
    setupMV2Data(mv_data2, 7, 3);

    PictureParams pp(format420, X_SIZE, Y_SIZE, 8, 8);

    pp.SetPicSort(PictureSort::IntraRefPictureSort());
    pp.SetPictureNum(0);
    pbuffer.PushPicture(pp);
    PicturesTest::setupPicture(pbuffer.GetPicture(0),0);

    pp.SetPicSort(PictureSort::IntraRefPictureSort());
    pp.SetPictureNum(1);
    pbuffer.PushPicture(pp);
    PicturesTest::setupPicture(pbuffer.GetPicture(1),50);

    pp.SetPicSort(PictureSort::InterRefPictureSort());
    pp.SetPictureNum(2);
    pp.Refs().push_back(0);
    pp.Refs().push_back(1);
    pbuffer.PushPicture(pp);
    PicturesTest::zeroPicture(pbuffer.GetPicture(2));

    pp.SetPictureNum(3);
    pbuffer.PushPicture(pp);
    PicturesTest::zeroPicture(pbuffer.GetPicture(3));

    //MotionCompensator mc( cp );
    
    Picture* ref_pics[2];
    ref_pics[0] = &pbuffer.GetPicture(0);
    ref_pics[1] = &pbuffer.GetPicture(1);

    //mc.CompensatePicture(ADD, pbuffer, 2, *mv_data);
    MotionCompensator::CompensatePicture(ppp, ADD, *mv_data, &pbuffer.GetPicture(2), ref_pics);

    //MotionCompensator mc2( cp );

    //mc2.CompensatePicture(ADD, pbuffer, 2, *mv_data1);
    MotionCompensator::CompensatePicture(ppp, ADD, *mv_data1, &pbuffer.GetPicture(2), ref_pics);

    // MotionCompensator mc3( cp );

    // mc3.CompensatePicture(ADD, pbuffer, 3, *mv_data2);
    MotionCompensator::CompensatePicture(ppp, ADD, *mv_data2, &pbuffer.GetPicture(3), ref_pics);

    //MotionCompensator mc4( cp );

    //mc4.CompensatePicture(ADD, pbuffer, 3, *mv_data2);
    MotionCompensator::CompensatePicture(ppp, ADD, *mv_data2, &pbuffer.GetPicture(3), ref_pics);

    CPPUNIT_ASSERT (PicturesTest::almostEqualPictures (pbuffer.GetPicture(2), pbuffer.GetPicture(3), 5    ));
    delete mv_data;
    delete mv_data1;
    delete mv_data2;
}
