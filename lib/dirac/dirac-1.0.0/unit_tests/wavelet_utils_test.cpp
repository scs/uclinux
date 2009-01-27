/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: wavelet_utils_test.cpp,v 1.3 2007/07/26 12:53:59 tjdwave Exp $ $Name: Dirac_1_0_0 $
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
* Contributor(s): Thomas Davies (Original Author)
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
#include "wavelet_utils_test.h"
#include <libdirac_common/wavelet_utils.h>
#include "arrays_test.h"
#include <memory>

using namespace dirac;

//NOTE: ensure that the suite is added to the default registry in
//cppunit_testsuite.cpp
CPPUNIT_TEST_SUITE_NAMED_REGISTRATION (WaveletTransformTest, coreSuiteName());

void WaveletTransformTest::initPicData( PicArray& pic_data )
{
    for (int j=pic_data.FirstY() ; j<=pic_data.LastY() ; ++j)
    {
       for (int i=pic_data.FirstX() ; i<=pic_data.LastX() ; ++i)
       {
           pic_data[j][i] = (((i-j) % 13)*1024)/13;       
       }// i
    }// j
}


WaveletTransformTest::WaveletTransformTest()
{
}

WaveletTransformTest::~WaveletTransformTest()
{
}

void WaveletTransformTest::setUp()
{
}

void WaveletTransformTest::tearDown()
{
}

void WaveletTransformTest::testConstructor()
{
    // Nothing to test as no public methods/variables affected by the constructor

}

void WaveletTransformTest::testTransformInvertibility()
{
    // Test the transform
    const int depth( 1 );

    // Initialise a picture and a copy
    PicArray pic_data( 512 , 512 );
    initPicData( pic_data );

    PicArray copy_data( pic_data );

    // Array for storing the coefficients
    CoeffArray coeff_data( pic_data.LengthY(), pic_data.LengthX() );

    for (int i=0 ; i< NUM_WLT_FILTERS; ++i)
    {
        WaveletTransform wtransform( depth , (WltFilter) i );

        // Go forward and back - we should be back where we started
        wtransform.Transform( FORWARD , pic_data, coeff_data );
        wtransform.Transform( BACKWARD , pic_data, coeff_data );

        bool test_val = equalArrays<ValueType>( pic_data , copy_data );

        CPPUNIT_ASSERT ( test_val == true );
    }// i
}
