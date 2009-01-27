/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: YUV420pt75filter.cpp,v 1.1 2008/08/14 02:35:04 asuraparaju Exp $ $Name: Dirac_1_0_0 $
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

/*****************************************************************
File YUV420toRGB.cpp

Utility for converting a sequence of frames, stored in a single
file in raw YUV420 format, to a single output file in which they are
stored in RGB format.
This utility is a filter taking input on stdin and generating its
output on stdout.
Input YUV420 is a planar format which stores the Y component of each frame,
as a sequence of bytes, followed by the U component followed by the V
component. That is the colour component are multiplexed framewise,
rather than pixel wise or in some other way. In YUV420 format the
U and V colour components are subsampled 2:1 horizontally and
2:1 vertically.
The output raw RGB format is simply a sequence of byte triples
representing the red, green and blue components of each pixel.

Original author: Tim Borer
****************************************************************/

#include <stdlib.h> //Contains EXIT_SUCCESS, EXIT_FAILURE
#include <iostream> //For cin, cout, cerr
#include <algorithm> //For fill_n
using std::cout;
using std::cin;
using std::cerr;
using std::clog;
using std::endl;
using std::ios_base;
using std::fill_n;

#include "setstdiomode.h"
using namespace dirac_vu;


unsigned char filter( unsigned char *buffer, const int pos, const int len,
int *filter, const int fil_len, const int shift)
{
    const int offset = fil_len/2;

    int val = 1<<(shift-1);
    int x;
    for (int i=0; i<fil_len; ++i)
    {
        x = pos-(i-offset);
        x = ( x>(len-1) ? (len-1) : ( val<0 ? 0 : val ) );
        val += int(buffer[pos-(i-offset)])*filter[i];
    }
    val >>= shift;
    val = ( val>255 ? 255 : ( val<0 ? 0 : val ) );

    return (unsigned char) val;

}

void filter_line_pt75( unsigned char *in_buffer,
                       unsigned char *out_buffer, const int count)
{
    const int length = count*4;

    // Phase 0 filter
    int p0[12] = {0,-1,5,36,-311,856,2926,856,-311,36,5,-1};
    // Phase 1 filter
    int p1[12] = {0,-3,25,-40,-269,1805,2609,107,-181,45,-2,0};
    // Phase 2 filter
    int p2[12] = {0,-2,45,-181,107,2609,1805,-269,-40,25,-3,0};// right??

    // Do all 3 output phases at once
    int k=0;
    for (int i=0; i<count; ++i)
    {
        out_buffer[3*i] = filter(in_buffer, k++, length, p2, 12, 12);
        k++;
        out_buffer[3*i+1] = filter(in_buffer, k++, length, p0, 12, 12);
        out_buffer[3*i+2] = filter(in_buffer, k++, length, p1, 12, 12);

    }// i
}

int main(int argc, char * argv[] ) {

    if (argc != 4) {
        cout << "\"YUV420pt75filter\" command line format is:" << endl;
        cout << "    Argument 1: width (pixels) e.g. 720" << endl;
        cout << "    Argument 2: height (lines) e.g. 576" << endl;
        cout << "    Argument 2: number of frames e.g. 3" << endl;
        cout << "    Example: YUV420pt75filter <foo >bar 720 576 3" << endl;
        cout << "        converts 3 frames, of 720x576 pixels, from file foo to file bar" << endl;
        return EXIT_SUCCESS; }

    //Get command line arguments
    const int Ywidth = atoi(argv[1]);
    const int Yheight = atoi(argv[2]);
    const int frames = atoi(argv[3]);

    //Set standard input and standard output to binary mode.
    //Only relevant for Windows (*nix is always binary)
    if ( setstdinmode(std::ios_base::binary) == -1 ) {
        cerr << "Error: could not set standard input to binary mode" << endl;
        return EXIT_FAILURE; }
    if ( setstdoutmode(std::ios_base::binary) == -1 ) {
        cerr << "Error: could not set standard output to binary mode" << endl;
        return EXIT_FAILURE; }

    //Allocate memory for input and output buffers.
    const int YBufferSize = Yheight*Ywidth;
    unsigned char *YBuffer = new unsigned char[YBufferSize];
    const int UVwidth = Ywidth/2;
    const int UVheight = Yheight/2;
    const int UVBufferSize = UVheight*UVwidth;
    unsigned char *UBuffer = new unsigned char[UVBufferSize];
    unsigned char *VBuffer = new unsigned char[UVBufferSize];

    const int YwidthDn = (3*Ywidth)/4;
    const int YheightDn = Yheight;
    const int YBufferSizeOut = YheightDn*YwidthDn;
    unsigned char *YBufferOut = new unsigned char[YBufferSizeOut];
    const int UVwidthDn = YwidthDn/2;
    const int UVheightDn = YheightDn/2;
    const int UVBufferSizeOut = UVheightDn*UVwidthDn;
    unsigned char *UBufferOut = new unsigned char[UVBufferSizeOut];
    unsigned char *VBufferOut = new unsigned char[UVBufferSizeOut];

    //Create references for input and output stream buffers.
    //IO is via stream buffers for efficiency
    std::streambuf& inbuf = *(cin.rdbuf());
    std::streambuf& outbuf = *(cout.rdbuf());

    for (int frame=0; frame<frames; ++frame) {

        //Read frames of Y then U then V components
        if ( inbuf.sgetn(reinterpret_cast<char*>(YBuffer), YBufferSize) < YBufferSize ) {
            cerr << "Error: failed to read Y component of frame " << frame << endl;
            return EXIT_FAILURE; }
        if ( inbuf.sgetn(reinterpret_cast<char*>(UBuffer), UVBufferSize) < UVBufferSize ) {
            cerr << "Error: failed to read U component of frame " << frame << endl;
            return EXIT_FAILURE; }
        if ( inbuf.sgetn(reinterpret_cast<char*>(VBuffer), UVBufferSize) < UVBufferSize ) {
            cerr << "Error: failed to read V component of frame " << frame << endl;
            return EXIT_FAILURE; }

        int in_pos, out_pos;
        for (int j=0; j<Yheight; ++j)
        {
            in_pos = j*Ywidth;
            out_pos = j*YwidthDn;
            filter_line_pt75(YBuffer+in_pos,YBufferOut+out_pos, Ywidth/4);
        }// j

        for (int j=0; j<UVheight; ++j)
        {
            in_pos = j*UVwidth;
            out_pos = j*UVwidthDn;
            filter_line_pt75(UBuffer+in_pos,UBufferOut+out_pos, UVwidth/4);
            filter_line_pt75(VBuffer+in_pos,VBufferOut+out_pos, UVwidth/4);
        }// j

        //Write frames of YUV
        if ( outbuf.sputn(reinterpret_cast<char*>(YBufferOut), YBufferSizeOut) < YBufferSizeOut ) {
            cerr << "Error: failed to write frame " << frame << endl;
            return EXIT_FAILURE; }
        if ( outbuf.sputn(reinterpret_cast<char*>(UBufferOut), UVBufferSizeOut) < UVBufferSizeOut ) {
            cerr << "Error: failed to write frame " << frame << endl;
            return EXIT_FAILURE; }
        if ( outbuf.sputn(reinterpret_cast<char*>(VBufferOut), UVBufferSizeOut) < UVBufferSizeOut ) {
            cerr << "Error: failed to write frame " << frame << endl;
            return EXIT_FAILURE; }
    }

    delete [] VBufferOut;
    delete [] UBufferOut;
    delete [] YBufferOut;
    delete [] VBuffer;
    delete [] UBuffer;
    delete [] YBuffer;

    return EXIT_SUCCESS;
}
