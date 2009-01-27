/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: arrays_test.h,v 1.3 2008/05/27 01:29:55 asuraparaju Exp $ $Name: Dirac_1_0_0 $
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

#ifndef ARRAYS_TEST_H
#define ARRAYS_TEST_H
#include <cppunit/extensions/HelperMacros.h>
#include <libdirac_common/arrays.h>
using dirac::TwoDArray;

template <class T>
bool equalArrays (const TwoDArray<T> &lhs, const TwoDArray<T> &rhs)
{
    CPPUNIT_ASSERT_EQUAL (lhs.LengthX(), rhs.LengthX());
    CPPUNIT_ASSERT_EQUAL (lhs.LengthY(), rhs.LengthY());
    CPPUNIT_ASSERT_EQUAL (lhs.FirstX(), rhs.FirstX());
    CPPUNIT_ASSERT_EQUAL (lhs.FirstY(), rhs.FirstY());
    CPPUNIT_ASSERT_EQUAL (lhs.LastX(), rhs.LastX() );
    CPPUNIT_ASSERT_EQUAL (lhs.LastY(), rhs.LastY() );

    for (int i =lhs.FirstY(); i <= lhs.LastY(); i++)
    {
        for (int j =lhs.FirstX(); j <= lhs.LastX(); j++)
        {
            if ( lhs[i][j] != rhs[i][j] )
                return false;
        }
    }

    return true;
}

class TwoDArraysTest : public CPPUNIT_NS::TestFixture
{

  CPPUNIT_TEST_SUITE( TwoDArraysTest );
  CPPUNIT_TEST( testConstructor );
  CPPUNIT_TEST( testValueConstructor );
  CPPUNIT_TEST( testDefaultConstructor );
  CPPUNIT_TEST( testCopyConstructor );
  CPPUNIT_TEST( testAssignment );
  CPPUNIT_TEST( testResize );
  CPPUNIT_TEST_SUITE_END();

public:
  TwoDArraysTest();
  virtual ~TwoDArraysTest();

  virtual void setUp();
  virtual void tearDown();

  void testConstructor();
  void testValueConstructor();
  void testDefaultConstructor();
  void testCopyConstructor();
  void testAssignment();
  void testResize();

private:
  TwoDArraysTest( const TwoDArraysTest &copy );
  void operator =( const TwoDArraysTest &copy );
private:
};
#endif
