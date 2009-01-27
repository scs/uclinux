/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: RGBtoUYVY.cpp,v 1.4 2008/05/27 01:29:55 asuraparaju Exp $ $Name: Dirac_1_0_0 $
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
File RGBtoUYVY.cpp

Utility for converting a sequence of frames, stored in a single
file in raw RGB format, to a single output file in which they are
stored in UYVY format.
This utility is a filter taking input on stdin and generating its
output on stdout.
Raw RGB format is simply a sequence of byte triples representing the
red, green and blue components of each pixel.
UYVY stores the 422 YUV image with the U/V components interleaved
with the Y components. It is a sequence of sets of 4 bytes containing
U, Y, V, Y components of two horizontally adjacent pixels. The U/V
components are co-sited with the first luminance sample. In 422 YUV
format the U and V colour components are subsampled 2:1 horizontally.

Original author: Tim Borer
****************************************************************/

#include <stdlib.h> //Contains EXIT_SUCCESS, EXIT_FAILURE
#include <iostream> //For cin, cout, cerr
using std::cout;
using std::cin;
using std::cerr;
using std::clog;
using std::endl;
using std::ios_base;

#include "setstdiomode.h"
using namespace dirac_vu;

int main(int argc, char * argv[] ) {

    if (argc != 4) {
        cout << "\"RGBtoUYVY\" command line format is:" << endl;
        cout << "    Argument 1: width (pixels) e.g. 720" << endl;
        cout << "    Argument 2: height (lines) e.g. 576" << endl;
        cout << "    Argument 3: number of frames e.g. 3" << endl;
        cout << "    Example: RGBtoUYVY <foo >bar 720 576 3" << endl;
        cout << "        converts 3 frames, of 720x576 pixels, from file foo to file bar" << endl;
        return EXIT_SUCCESS; }

    //Get command line arguments
    int width = atoi(argv[1]);
    int height = atoi(argv[2]);
    int frames = atoi(argv[3]);

    //Set standard input and standard output to binary mode.
    //Only relevant for Windows (*nix is always binary)
    if ( setstdinmode(std::ios_base::binary) == -1 ) {
        cerr << "Error: could not set standard input to binary mode" << endl;
        return EXIT_FAILURE; }
    if ( setstdoutmode(std::ios_base::binary) == -1 ) {
        cerr << "Error: could not set standard output to binary mode" << endl;
        return EXIT_FAILURE; }

    //Allocate memory for input and output buffers.
    const int RGBBufferSize = 3*height*width;
    unsigned char *RGBBuffer = new unsigned char[RGBBufferSize];
    const int YUVBufferSize = height*width*2;
    unsigned char *YUVBuffer = new unsigned char[YUVBufferSize];

    //Define some working variables and arrays
    //Define buffers for filtering (width+2 to allow filtering edges)
    unsigned char *YLine = new unsigned char[width];
    unsigned char *ULine = (new unsigned char[width+2])+1;
    unsigned char *VLine = (new unsigned char[width+2])+1;
    ULine[-1]=ULine[width]=128;
    VLine[-1]=VLine[width]=128;
    int R, G, B;
    int Y, U, V;
    int Y1, Y2;

    //Create references for input and output stream buffers.
    //IO is via stream buffers for efficiency
    std::streambuf& inbuf = *(cin.rdbuf());
    std::streambuf& outbuf = *(cout.rdbuf());

    for (int frame=0; frame<frames; ++frame) {

        clog << "Processing frame " << (frame+1) << "\r";
            
        //Read frames of RGB
        if ( inbuf.sgetn(reinterpret_cast<char*>(RGBBuffer), RGBBufferSize) < RGBBufferSize ) {
            cerr << "Error: failed to read frame " << frame << endl;
            return EXIT_FAILURE; }

        for (int line=0; line<height; ++line) {

            int RGBIndex = 3*width*line;
            for (int pixel=0; pixel<width; ++pixel) {

                R = RGBBuffer[RGBIndex++];
                G = RGBBuffer[RGBIndex++];
                B = RGBBuffer[RGBIndex++];

                //Convert RGB to YUV
                Y = (( 66*R + 129*G +  25*B + 128)>>8)+ 16;
                U = ((-38*R -  74*G + 112*B + 128)>>8)+128;
                V = ((112*R -  94*G -  18*B + 128)>>8)+128;

                //Copy YUV to line buffers prior to filtering
                YLine[pixel] = Y;
                ULine[pixel] = U;
                VLine[pixel] = V;
            }

            int YUVIndex = width*line*2;
            for (int pixel=0; pixel<width; pixel+=2) {

                //Filter line
                U = ((ULine[pixel-1]+2*ULine[pixel]+ULine[pixel+1]+2)>>2);
                Y1 = YLine[pixel];
                V = ((VLine[pixel-1]+2*VLine[pixel]+VLine[pixel+1]+2)>>2);
                Y2 = YLine[pixel+1];

                //Clip and copy YUV to output buffer
                YUVBuffer[YUVIndex++] = static_cast<unsigned char>( (U<0) ? 0 : ((U>255) ? 255 : U) );
                YUVBuffer[YUVIndex++] = static_cast<unsigned char>( (Y1<0) ? 0 : ((Y1>255) ? 255 : Y1) );
                YUVBuffer[YUVIndex++] = static_cast<unsigned char>( (V<0) ? 0 : ((V>255) ? 255 : V) );
                YUVBuffer[YUVIndex++] = static_cast<unsigned char>( (Y2<0) ? 0 : ((Y2>255) ? 255 : Y2) );
            }
        }

        //Write frames of YUV
        if ( outbuf.sputn(reinterpret_cast<char*>(YUVBuffer), YUVBufferSize) < YUVBufferSize ) {
            cerr << "Error: failed to write frame " << frame << endl;
            return EXIT_FAILURE; }
    }

    delete [] (&VLine[-1]);
    delete [] (&ULine[-1]);
    delete [] YLine;
    delete [] YUVBuffer;
    delete [] RGBBuffer;

    return EXIT_SUCCESS;
}
