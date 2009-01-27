/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: wavelet_utils_test.h,v 1.1 2004/11/22 13:07:28 asuraparaju Exp $ $Name: Dirac_1_0_0 $
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

#ifndef WAVELET_UTILS_TEST_H
#define WAVELET_UTILS_H
#include <cppunit/extensions/HelperMacros.h>
#include <libdirac_common/common.h>

using dirac::PicArray;

class WaveletTransformTest : public CPPUNIT_NS::TestFixture
{
  CPPUNIT_TEST_SUITE( WaveletTransformTest );
  CPPUNIT_TEST( testConstructor );
  CPPUNIT_TEST( testTransformInvertibility );
  CPPUNIT_TEST_SUITE_END();

public:
  WaveletTransformTest();
  virtual ~WaveletTransformTest();

  virtual void setUp();
  virtual void tearDown();

  void testConstructor();
  void testTransformInvertibility();

private:

  void initPicData( PicArray& pic_data );

private:
};
#endif
