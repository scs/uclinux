/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: arrays_test.cpp,v 1.3 2008/05/27 01:29:55 asuraparaju Exp $ $Name: Dirac_1_0_0 $
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
* Contributor(s): Anuradha Suraparaju (Original Author), Thomas Davies
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
#include "arrays_test.h"
#include <memory>

//NOTE: ensure that the suite is added to the default registry in
//cppunit_testsuite.cpp
CPPUNIT_TEST_SUITE_NAMED_REGISTRATION (TwoDArraysTest, coreSuiteName());

void setup2DArray (TwoDArray<int> &arr, int dimx, int dimy, int start_val)
{
    arr.Resize(dimx, dimy);
    int value =start_val;
    int err_count = 0;
    for (int i =arr.FirstY(); i <= arr.LastY(); i++)
    {
        for (int j =arr.FirstX(); j <= arr.LastX(); j++)
        {
            arr[i][j] = ++value;
        }
    }
    value = start_val;
    for (int i =arr.FirstY(); i <= arr.LastY(); i++)
    {
        for (int j =arr.FirstX(); j <= arr.LastX(); j++)
        {
            ++value;
            if (arr[i][j] != value)
                err_count++;
        }
    }
    CPPUNIT_ASSERT_EQUAL (err_count, 0);
}

TwoDArraysTest::TwoDArraysTest()
{
}

TwoDArraysTest::~TwoDArraysTest()
{
}

void TwoDArraysTest::setUp()
{
}

void TwoDArraysTest::tearDown()
{
}

void TwoDArraysTest::testConstructor()
{
    TwoDArray<int> work_data(20, 30);

    CPPUNIT_ASSERT_EQUAL (work_data.LengthY(), 20);
    CPPUNIT_ASSERT_EQUAL (work_data.LengthX(), 30);
    CPPUNIT_ASSERT_EQUAL (work_data.LastX() - work_data.FirstX() + 1, 30);
    CPPUNIT_ASSERT_EQUAL (work_data.LastY() - work_data.FirstY() + 1, 20);
}

void TwoDArraysTest::testValueConstructor()
{
    const double val( -17.329 );
    TwoDArray<double> work_data(20, 30 , val );

    CPPUNIT_ASSERT_EQUAL (work_data.LengthY(), 20);
    CPPUNIT_ASSERT_EQUAL (work_data.LengthX(), 30);
    CPPUNIT_ASSERT_EQUAL (work_data.LastX() - work_data.FirstX() + 1, 30);
    CPPUNIT_ASSERT_EQUAL (work_data.LastY() - work_data.FirstY() + 1, 20);

    bool test_val (true);
    for (int j=work_data.FirstY() ; j<=work_data.LastY() ; ++j)
    {
        for (int i=work_data.FirstX() ; i<=work_data.LastX() ; ++i)
        {
            if ( work_data[j][i] != val )
                test_val = false;
        }// i
    }// j

    CPPUNIT_ASSERT( test_val == true );    
}


void TwoDArraysTest::testDefaultConstructor()
{
    TwoDArray<int> work_data;

    CPPUNIT_ASSERT_EQUAL (work_data.LengthX(), 0);
    CPPUNIT_ASSERT_EQUAL (work_data.LengthY(), 0);
    CPPUNIT_ASSERT_EQUAL (work_data.FirstX(), 0);
    CPPUNIT_ASSERT_EQUAL (work_data.FirstY(), 0);
    CPPUNIT_ASSERT_EQUAL (work_data.LastX(), -1);
    CPPUNIT_ASSERT_EQUAL (work_data.LastY(), -1);
}

void TwoDArraysTest::testCopyConstructor()
{
    TwoDArray<int> work_data;
    setup2DArray (work_data, 20, 30, 0);
    
    TwoDArray<int> work_copy(work_data);
    bool ret_val = equalArrays<int> (work_data, work_copy);
    CPPUNIT_ASSERT (ret_val == true);
}

void TwoDArraysTest::testAssignment()
{
    TwoDArray<int> work_data;
    setup2DArray (work_data, 20, 30, 0);

    TwoDArray<int> work_copy;

    work_copy = work_data;
    bool ret_val = equalArrays (work_data, work_copy);
    CPPUNIT_ASSERT (ret_val == true);
}

void TwoDArraysTest::testResize()
{
    TwoDArray<int> work_data(20, 30);

    CPPUNIT_ASSERT_EQUAL (work_data.LengthX(), 30);
    CPPUNIT_ASSERT_EQUAL (work_data.LengthY(), 20);
    CPPUNIT_ASSERT_EQUAL (work_data.LastX() - work_data.FirstX() + 1, 30);
    CPPUNIT_ASSERT_EQUAL (work_data.LastY() - work_data.FirstY() + 1, 20);
    work_data.Resize(30, 20);
    CPPUNIT_ASSERT_EQUAL (work_data.LengthX(), 20);
    CPPUNIT_ASSERT_EQUAL (work_data.LengthY(), 30);
    CPPUNIT_ASSERT_EQUAL (work_data.LastX() - work_data.FirstX() + 1, 20);
    CPPUNIT_ASSERT_EQUAL (work_data.LastY() - work_data.FirstY() + 1, 30);
}
