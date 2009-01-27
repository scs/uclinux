/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: frames_test.cpp,v 1.9 2008/06/19 10:36:32 tjdwave Exp $ $Name: Dirac_1_0_0 $
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
#include "frames_test.h"
#include "arrays_test.h"

#include <libdirac_common/picture.h>
using namespace dirac;

#include <memory>

//NOTE: ensure that the suite is added to the default registry in
//cppunit_testsuite.cpp
CPPUNIT_TEST_SUITE_NAMED_REGISTRATION (PicturesTest, coreSuiteName());

void PicturesTest::setupPicture (Picture& picture, int start_val)
{
    setupPicArray(picture.Data(Y_COMP), start_val);
    setupPicArray(picture.Data(U_COMP), start_val);
    setupPicArray(picture.Data(V_COMP), start_val);
}

bool PicturesTest::setupPicArray (PicArray &arr, int start_val)
{
    char value =start_val; // use char to limit values to 8 bits
    int err_count = 0;
    int i, j;
    for ( i =arr.FirstY(); i <= arr.LastY(); i++)
    {
        for ( j =arr.FirstX(); j <= arr.LastX(); j++)
        {
            arr[i][j] = ++value;
        }
    }
    value = start_val;
    for ( i =arr.FirstY(); i <= arr.LastY(); i++)
    {
        for ( j =arr.FirstX(); j <= arr.LastX(); j++)
        {
            ++value;
            if (arr[i][j] != value)
                err_count++;
        }
    }
    CPPUNIT_ASSERT_EQUAL (err_count, 0);
    return true;
}

void PicturesTest::zeroPicture (Picture& picture)
{
    zeroPicArray(picture.Data(Y_COMP));
    zeroPicArray(picture.Data(U_COMP));
    zeroPicArray(picture.Data(V_COMP));
}

bool PicturesTest::zeroPicArray (PicArray &arr)
{
    short value =0;
    int err_count = 0;
    int i, j;
    for ( i =arr.FirstY(); i <= arr.LastY(); i++)
    {
        for ( j =arr.FirstX(); j <= arr.LastX(); j++)
        {
            arr[i][j] = value;
        }
    }
    value = 0;
    for ( i =arr.FirstY(); i <= arr.LastY(); i++)
    {
        for ( j =arr.FirstX(); j <= arr.LastX(); j++)
        {
            if (arr[i][j] != value)
                err_count++;
        }
    }
    CPPUNIT_ASSERT_EQUAL (err_count, 0);
    return true;
}


bool PicturesTest::equalPicArrays (const PicArray &lhs, const PicArray &rhs)
{
    CPPUNIT_ASSERT_EQUAL (lhs.CSort(), rhs.CSort());
    CPPUNIT_ASSERT_EQUAL (lhs.LengthX(), rhs.LengthX());
    CPPUNIT_ASSERT_EQUAL (lhs.LengthY(), rhs.LengthY());
    CPPUNIT_ASSERT_EQUAL (lhs.FirstX(), rhs.FirstX());
    CPPUNIT_ASSERT_EQUAL (lhs.FirstY(), rhs.FirstY());
    CPPUNIT_ASSERT_EQUAL (lhs.LastX(), rhs.LastX() );
    CPPUNIT_ASSERT_EQUAL (lhs.LastY(), rhs.LastY() );

    for (int i =lhs.FirstY(); i <= lhs.LastY(); i++)
    {
        ValueType * lshRow = lhs[i];
        ValueType * rshRow = rhs[i];
        for (int j =lhs.FirstX(); j <= lhs.LastX(); j++)
        {
            if (!( lshRow[j] == rshRow[j]))
            {
                return false;
            }
        }
    }

    return true;
}


bool PicturesTest::almostEqualPicArrays (const PicArray &lhs, const PicArray &rhs, int allowedError)
{
    CPPUNIT_ASSERT_EQUAL (lhs.CSort(), rhs.CSort());
    CPPUNIT_ASSERT_EQUAL (lhs.LengthX(), rhs.LengthX());
    CPPUNIT_ASSERT_EQUAL (lhs.LengthY(), rhs.LengthY());
    CPPUNIT_ASSERT_EQUAL (lhs.FirstX(), rhs.FirstX());
    CPPUNIT_ASSERT_EQUAL (lhs.FirstY(), rhs.FirstY());
    CPPUNIT_ASSERT_EQUAL (lhs.LastX(), rhs.LastX() );
    CPPUNIT_ASSERT_EQUAL (lhs.LastY(), rhs.LastY() );

    for (int i =lhs.FirstY(); i <= lhs.LastY(); i++)
    {
        ValueType * lshRow = lhs[i];
        ValueType * rshRow = rhs[i];
        for (int j =lhs.FirstX(); j <= lhs.LastX(); j++)
        {
            if ( allowedError < std::abs(lshRow[j] - rshRow[j]))
            {
                return false;
            }
        }
    }

    return true;
}

bool PicturesTest::equalPictures (const Picture &lhs, const Picture &rhs)
{
    CPPUNIT_ASSERT_EQUAL (lhs.GetPparams().CFormat(), rhs.GetPparams().CFormat() );
    CPPUNIT_ASSERT (equalPicArrays(lhs.Data(Y_COMP), rhs.Data(Y_COMP)));
    CPPUNIT_ASSERT (equalPicArrays(lhs.Data(U_COMP), rhs.Data(U_COMP)));
    CPPUNIT_ASSERT (equalPicArrays(lhs.Data(V_COMP), rhs.Data(V_COMP)));
    CPPUNIT_ASSERT_EQUAL (lhs.GetPparams().LumaDepth(), rhs.GetPparams().LumaDepth() );
    CPPUNIT_ASSERT_EQUAL (lhs.GetPparams().ChromaDepth(), rhs.GetPparams().ChromaDepth() );

    return true;
}

bool PicturesTest::almostEqualPictures (const Picture &lhs, const Picture &rhs, int allowedError)
{
    CPPUNIT_ASSERT_EQUAL (lhs.GetPparams().CFormat(), rhs.GetPparams().CFormat() );
    CPPUNIT_ASSERT (almostEqualPicArrays(lhs.Data(Y_COMP), rhs.Data(Y_COMP), allowedError));
    CPPUNIT_ASSERT (almostEqualPicArrays(lhs.Data(U_COMP), rhs.Data(U_COMP), allowedError));
    CPPUNIT_ASSERT (almostEqualPicArrays(lhs.Data(V_COMP), rhs.Data(V_COMP), allowedError));

    return true;
}

PicturesTest::PicturesTest()
{
}

PicturesTest::~PicturesTest()
{
}

void PicturesTest::setUp()
{
}

void PicturesTest::tearDown()
{
}

void PicturesTest::testConstructor()
{
    PictureParams p_params(format444, 20, 30, 8, 8);
    Picture picture(p_params);

    CPPUNIT_ASSERT_EQUAL (20, picture.Data(Y_COMP).LengthX());
    CPPUNIT_ASSERT_EQUAL (30, picture.Data(Y_COMP).LengthY());
    CPPUNIT_ASSERT_EQUAL (20, picture.Data(Y_COMP).LastX() - picture.Data(Y_COMP).FirstX() + 1);
    CPPUNIT_ASSERT_EQUAL (30, picture.Data(Y_COMP).LastY() - picture.Data(Y_COMP).FirstY() + 1);
}

void PicturesTest::testDefaultPictureParams()
{
    PictureParams p_params;
    Picture picture(p_params);

    CPPUNIT_ASSERT_EQUAL (0, picture.Data(Y_COMP).LengthX());
    CPPUNIT_ASSERT_EQUAL (0, picture.Data(Y_COMP).LengthY());
    CPPUNIT_ASSERT_EQUAL (0, picture.Data(Y_COMP).FirstX());
    CPPUNIT_ASSERT_EQUAL (0, picture.Data(Y_COMP).FirstY());
    CPPUNIT_ASSERT_EQUAL (-1, picture.Data(Y_COMP).LastX());
    CPPUNIT_ASSERT_EQUAL (-1, picture.Data(Y_COMP).LastY());
}

void PicturesTest::testCopyConstructor()
{
    PictureParams p_params(format444, 20, 30, 8, 8);
    Picture picture(p_params);
    setupPicture(picture, 0);
    
    Picture picture_copy(picture);
    CPPUNIT_ASSERT (equalPictures (picture, picture_copy));
}

void PicturesTest::testAssignment()
{
    PictureParams p_params(format444, 20, 30, 8, 8);
    Picture picture(p_params);
    setupPicture(picture, 0);

    PictureParams p_params_copy(format444, 10, 10, 8, 8);
    Picture picture_copy(p_params_copy);

    picture_copy = picture;

    CPPUNIT_ASSERT (equalPictures (picture, picture_copy));
}

