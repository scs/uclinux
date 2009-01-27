/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: bitmap.cpp,v 1.3 2004/06/30 16:44:52 asuraparaju Exp $ $Name: Dirac_1_0_0 $
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
* Tim Borer (Original Author)
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

#include <ostream>
#include <istream>

#include <iostream>

#include "bitmap.h"

namespace {

    //Funtions to read and write a sequence of little endian bytes,
    //stored in a byte array,
    //to/from an integer in an endian independent way.
    //Functions assume ints are at least 4 bytes.

    int read2bytes(const char* bytes) {
        int value=0;
        value |= (*(bytes+1))& 0xff;
        value <<= 8;
        value |= ( (*bytes)& 0xff );
        return value; }

    int read4bytes(const char* bytes) {
        int value=0;
        value |= (*(bytes+3))& 0xff;
        value <<= 8;
        value |= (*(bytes+2))& 0xff;
        value <<= 8;
        value |= (*(bytes+1))& 0xff;
        value <<= 8;
        value |= ( (*bytes)& 0xff );
        return value; }

    void write2bytes(char* bytes, int value) {
        (*bytes) = value & 0xff;
        value >>= 8;
        (*(bytes+1)) = value & 0xff;
        value >>= 8;
        }

    void write4bytes(char* bytes, int value) {
        (*bytes) = value & 0xff;
        value >>= 8;
        (*(bytes+1)) = value & 0xff;
        value >>= 8;
        (*(bytes+2)) = value & 0xff;
        value >>= 8;
        (*(bytes+3)) = value & 0xff;
        value >>= 8;
        }

} //end anonymous namespace

namespace dirac_vu { //dirac video utilities namespace

    std::ostream& BitmapHeader::putTo(std::ostream& output) const {
        //Define variables for bitmap parameters
        const char signature[2] = { 'B', 'M' };
        const int dataOffset = 54;
        const int fileSize = dataOffset + height()*lineBufferSize();
        const int reserved = 0;
        const int size = 40;
        const int planes = 1;
        const int bitCount = 24;
        const int compression = 0;
        const int imageSize = 0;
        const int xPixelsPerM = 0, yPixelsPerM = 0;
        const int coloursUsed = 0 ;
        const int coloursImportant = 0;
        //Define buffer to read bytes into.
        const int bufferSize = 54;
        char buffer[bufferSize];
        //Write header parameters into buffer
        *buffer = signature[0];
        *(buffer+1) = signature[1];
        write4bytes(buffer+2, fileSize);
        write4bytes(buffer+6, reserved);
        write4bytes(buffer+10, dataOffset);
        write4bytes(buffer+14, size);
        write4bytes(buffer+18, width());
        write4bytes(buffer+22, height());
        write2bytes(buffer+26, planes);
        write2bytes(buffer+28, bitCount);
        write4bytes(buffer+30, compression);
        write4bytes(buffer+34, imageSize);
        write4bytes(buffer+38, xPixelsPerM);
        write4bytes(buffer+42, yPixelsPerM);
        write4bytes(buffer+46, coloursUsed);
        write4bytes(buffer+50, coloursImportant);
        //Do pre & post processing by creating a sentry object
        std::ostream::sentry s(output);
        //Check all is well for output
        if (!s) {
            output.setstate(std::ios::failbit);
            return output; }
        //Use stream buffer directly for efficiency
        std::streambuf& outbuf = *output.rdbuf();
        if (outbuf.sputn(buffer, bufferSize) < bufferSize) {
            output.setstate(std::ios::eofbit);
            output.setstate(std::ios::failbit); }
        return output; }

    std::istream& BitmapHeader::getFrom(std::istream& input) {
        //Define variables for bitmap parameters
        char signature[2];
        int fileSize;
        int dataOffset;
        int size;
        int planes;
        int bitCount;
        int compression;
        int imageSize;
        int xPixelsPerM, yPixelsPerM;
        int coloursUsed;
        int coloursImportant;
        //Define buffer to read bytes into.
        const int bufferSize = 54;
        char buffer[bufferSize];
        //Ensure pre & post processing by constructing a sentry object
        //The "true" parameter means "don't ignore leading whitespace"
        std::istream::sentry s(input, true);
        //Check that all is well for input to start
        if (!s) {
            input.setstate(std::ios::failbit);
            return input; }
        //Use stream buffer directly to avoid the overhead of sentry
        //objects created by the unformatted stream I/O functions
        //First create a reference to the input stream buffer
        std::streambuf& inbuf = *input.rdbuf();
        if (inbuf.sgetn(buffer, bufferSize) < bufferSize) {
            input.setstate(std::ios_base::eofbit);
            input.setstate(std::ios_base::failbit); }
        signature[0]=*buffer;
        signature[1]=*(buffer+1);
        if ( (signature[0]!='B') || (signature[1]!='M') ) input.setstate(std::ios::failbit);
        fileSize = read4bytes(buffer+2);
        dataOffset= read4bytes(buffer+10);
        //Reposition input buffer to skip over extra header data if necessary
        //Should check success of operation (see The C++ Stand Lib, Josuttis, p665)
        if (dataOffset>54) inbuf.pubseekoff(dataOffset-54, std::ios_base::cur, std::ios_base::in);
        size = read4bytes(buffer+14);
        w = read4bytes(buffer+18);
        h = read4bytes(buffer+22);
        if ( fileSize != (dataOffset + height()*lineBufferSize()) ) input.setstate(std::ios::failbit);
        planes = read2bytes(buffer+26);
        if ( planes != 1 ) input.setstate(std::ios::failbit);
        bitCount = read2bytes(buffer+28);
        if ( bitCount != 24 ) input.setstate(std::ios::failbit);
        compression = read4bytes(buffer+30);
        if ( compression != 0 ) input.setstate(std::ios::failbit);
        imageSize = read4bytes(buffer+34);
        xPixelsPerM = read4bytes(buffer+38);
        yPixelsPerM = read4bytes(buffer+42);
        coloursUsed = read4bytes(buffer+46);
        coloursImportant = read4bytes(buffer+50);
        return input; }

}  // end namespace dirac_vu

