/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: bitmap.h,v 1.3 2004/06/30 16:44:52 asuraparaju Exp $ $Name: Dirac_1_0_0 $
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
* Contributor(s):
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

/***********************************************************************
File bitmap.h

Defines bitmap header class for uncompressed image IO.
Bitmap files are native to Windows on X86 and usually have a file
extension .BMP.

This class only supports uncompressed bitmaps using
24 bits per pixel.These are the common form of .BMP file.

I have tried to make the class platform independent - no guarantee.

At present the only useful parameters from the header seem to be the
width and height of the bitmap.

The bitmap format used (24bit uncompressed)is as follows:

BitMapFileHeader:   14 bytes
    signature:       2 bytes    Always 'BM'
    fileSize:        4 bytes    File size in bytes
    reserved:        2 bytes
    reserved:        2 bytes
    dataOffset:      4 bytes    Offset of raster data from beginning of file

BitMapInfoHeader:   40 bytes
    size:            4 bytes    Size of InfoHeader = 40
    width:           4 bytes    Bitmap width (pixels)
    height:          4 bytes    Bitmap height (pixels)
    planes:          2 bytes    Number of planes = 1
    bitCount:        2 bytes    Bits per pixel = 24
    compression:     4 bytes    Type of compression = 0 (no compression)
    imageSize:       4 bytes    Bytes of raster image data (including pading)
                                = 0 (valid for uncompressed)
    xPixelsPerM      4 bytes    Horizontal pixels per metre (meaningless) = 0
    yPixelsPerM      4 bytes    Vertical pixels per metre (meaningless) = 0
    coloursUsed      4 bytes    Number of colours used = 0
    coloursImportant 4 bytes    Number of important colours = 0

BitMapLine:         multiple of 4 bytes = height*4*((3*width + 3)/4)
    width*BGRTriple 3*Width bytes
    padding         Up to 3 bytes

BGRTriple:           3 bytes
    blue:            1 byte
    green:           1 byte
    red:             1 byte

Original author: Tim Borer
*********************************************************************/

#ifndef dirac_utilities_bitmap
#define dirac_utilities_bitmap

#include <iosfwd>

namespace dirac_vu { //dirac video utilities namespace

    class BitmapHeader {
    public:
        BitmapHeader() {}                   //used for reading bitmaps
        BitmapHeader(int x, int y): w(x), h(y) {}
        int width() const {
            return w; }
        void width(int x) {
            w = x;}
        int height() const {
            return h; }
        void height(int y) {
            h = y; }
        //Size of one picture line, in bytes, including padding
        int lineBufferSize() const {
            return 4*((3*w + 3)/4); }
        friend std::ostream& operator<<(std::ostream& stream,
                                        const BitmapHeader& header) {
            return header.putTo(stream); }
        friend std::istream& operator>>(std::istream& stream,
                                        BitmapHeader& header) {
            return header.getFrom(stream); }
    private:
        std::ostream& putTo(std::ostream& output) const;
        std::istream& getFrom(std::istream& input);
        int w;
        int h;
    };

}  // end namespace dirac_vu

#endif // dirac_utilities_bitmap
