/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: frames_test.h,v 1.2 2008/02/05 03:14:57 asuraparaju Exp $ $Name: Dirac_1_0_0 $
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
#ifndef FRAMES_TEST_H
#define FRAMES_TEST_H
#include <cppunit/extensions/HelperMacros.h>
#include <libdirac_common/picture.h>
#include <libdirac_common/common.h>
using dirac::Picture;
using dirac::PicArray;

class PicturesTest : public CPPUNIT_NS::TestFixture
{
    
  CPPUNIT_TEST_SUITE( PicturesTest );
  CPPUNIT_TEST( testConstructor );
//  CPPUNIT_TEST( testDefaultFParam );
  CPPUNIT_TEST( testCopyConstructor );
  CPPUNIT_TEST( testAssignment );
  CPPUNIT_TEST_SUITE_END();

public:
  PicturesTest();
  virtual ~PicturesTest();

  virtual void setUp();
  virtual void tearDown();

  void testConstructor();
  void testDefaultPictureParams();
  void testCopyConstructor();
  void testAssignment();

  static void setupPicture (Picture& picture, int start_val);
  static void zeroPicture (Picture& picture);
  static bool zeroPicArray (PicArray &arr);
  static bool equalPicArrays (const PicArray &lhs, const PicArray &rhs);
  static bool almostEqualPicArrays (const PicArray &lhs, const PicArray &rhs, int allowedError);
  static bool equalPictures (const Picture &lhs, const Picture &rhs);
  static bool almostEqualPictures (const Picture &lhs, const Picture &rhs, int allowedError);
  static bool setupPicArray (PicArray &arr, int start_val);
private:
  PicturesTest( const PicturesTest &copy );
  void operator =( const PicturesTest &copy );
private:
};
#endif
