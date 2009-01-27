/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: motion_comp_test.h,v 1.4 2008/02/05 03:14:58 asuraparaju Exp $ $Name: Dirac_1_0_0 $
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
* Contributor(s): Steven Bearcroft (Original Author)
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
#ifndef MOTION_COMP_TEST_H
#define MOTION_COMP_TEST_H
#include <cppunit/extensions/HelperMacros.h>
#include <libdirac_common/common_types.h>

class MotionCompTest : public CPPUNIT_NS::TestFixture
{
    
  CPPUNIT_TEST_SUITE( MotionCompTest );
  CPPUNIT_TEST( testZeroMotionComp );
  CPPUNIT_TEST( testAddandSubMotionComp );
  CPPUNIT_TEST( testL2_picture );
  CPPUNIT_TEST( testI_picture );
  CPPUNIT_TEST( testRef2 );
  CPPUNIT_TEST( testRef1and2 );
  CPPUNIT_TEST_SUITE_END();

public:
  MotionCompTest();
  virtual ~MotionCompTest();

  virtual void setUp();
  virtual void tearDown();

  void testZeroMotionComp();
  void testAddandSubMotionComp();
  void testL2_picture();
  void testI_picture();
  void testRef2();
  void testRef1and2();
private:
  MotionCompTest( const MotionCompTest &copy );
  void operator =( const MotionCompTest &copy );
private:
  void testZeroMotionComp(MVPrecisionType precision);
  void testAddandSubMotionComp(MVPrecisionType precision);
  void testL2_picture(MVPrecisionType precision);
  void testRef2(MVPrecisionType precision);
  void testRef1and2(MVPrecisionType precision);
};
#endif
