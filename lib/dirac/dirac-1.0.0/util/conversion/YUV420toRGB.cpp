/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: YUV420toRGB.cpp,v 1.4 2004/12/01 14:13:17 timborer Exp $ $Name: Dirac_1_0_0 $
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

int main(int argc, char * argv[] ) {

    if (argc != 4) {
        cout << "\"YUV420toRGB\" command line format is:" << endl;
        cout << "    Argument 1: width (pixels) e.g. 720" << endl;
        cout << "    Argument 2: height (lines) e.g. 576" << endl;
        cout << "    Argument 2: number of frames e.g. 3" << endl;
        cout << "    Example: YUV420toRGB <foo >bar 720 576 3" << endl;
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
    const int YBufferSize = height*width;
    unsigned char *YBuffer = new unsigned char[YBufferSize];
    const int UVBufferSize = height*width/4;
    unsigned char *UBuffer = new unsigned char[UVBufferSize];
    unsigned char *VBuffer = new unsigned char[UVBufferSize];
    const int RGBBufferSize = 3*height*width;
    unsigned char *RGBBuffer = new unsigned char[RGBBufferSize];

    //Define some working variables and arrays
    //Define buffers for filtering (additional height & width allows filtering edges)
    const int UVHeight=height+2;
    const int UVWidth=width+2;
    const int UVImageSize = UVHeight*UVWidth;
    int *UImage = (new int[UVImageSize])+UVWidth+1;
    int *VImage = (new int[UVImageSize])+UVWidth+1;
    int R, G, B;
    int Y, U, V;

    //Create references for input and output stream buffers.
    //IO is via stream buffers for efficiency
    std::streambuf& inbuf = *(cin.rdbuf());
    std::streambuf& outbuf = *(cout.rdbuf());

    for (int frame=0; frame<frames; ++frame) {

        clog << "Processing frame " << (frame+1) << "\r";

        fill_n(&UImage[-(UVWidth+1)], UVImageSize, 0);
        fill_n(&VImage[-(UVWidth+1)], UVImageSize, 0);

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

        //Copy (sub-sampled) UV components to image buffer.
        for (int line=0; line<height; line+=2) {
            int UVIndex = width*line/4;
            for (int pixel=0; pixel<width; pixel+=2) {
                UImage[line*UVWidth+pixel] = UBuffer[UVIndex]-128;
                VImage[line*UVWidth+pixel] = VBuffer[UVIndex++]-128;
            }
        }

        //Vertically interpolate the UV samples
        for (int line=1; line<height; line+=2) {
            for (int pixel=0; pixel<width; pixel+=2) {
                UImage[line*UVWidth+pixel] = ((UImage[(line-1)*UVWidth+pixel]+
                        2*UImage[line*UVWidth+pixel]+UImage[(line+1)*UVWidth+pixel]+1)>>1);
                VImage[line*UVWidth+pixel] = ((VImage[(line-1)*UVWidth+pixel]+
                        2*VImage[line*UVWidth+pixel]+VImage[(line+1)*UVWidth+pixel]+1)>>1);
            }
        }

        for (int line=0; line<height; ++line) {

            int YIndex = width*line;
            int RGBIndex = 3*width*line;
            for (int pixel=0; pixel<width; ++pixel) {

                //Copy Y value and  filter UV values.
                Y = YBuffer[YIndex++] - 16;
                U = (UImage[line*UVWidth+pixel-1]+2*UImage[line*UVWidth+pixel]+UImage[line*UVWidth+pixel+1]+1)>>1;
                V = (VImage[line*UVWidth+pixel-1]+2*VImage[line*UVWidth+pixel]+VImage[line*UVWidth+pixel+1]+1)>>1;

                //Matrix YUV to RGB
                R = ((298*Y         + 409*V + 128)>>8);
                G = ((298*Y - 100*U - 208*V + 128)>>8);
                B = ((298*Y + 516*U         + 128)>>8);

                //Clip RGB Values
                RGBBuffer[RGBIndex++] =
                    static_cast<unsigned char>( (R<0) ? 0 : ((R>255) ? 255 : R) );
                RGBBuffer[RGBIndex++] =
                    static_cast<unsigned char>( (G<0) ? 0 : ((G>255) ? 255 : G) );
                RGBBuffer[RGBIndex++] =
                    static_cast<unsigned char>( (B<0) ? 0 : ((B>255) ? 255 : B) );
            }
        }
        
        //Write frames of RGB
        if ( outbuf.sputn(reinterpret_cast<char*>(RGBBuffer), RGBBufferSize) < RGBBufferSize ) {
            cerr << "Error: failed to write frame " << frame << endl;
            return EXIT_FAILURE; }
    }

    delete [] (&VImage[-(UVWidth+1)]);
    delete [] (&UImage[-(UVWidth+1)]);
    delete [] RGBBuffer;
    delete [] VBuffer;
    delete [] UBuffer;
    delete [] YBuffer;

    return EXIT_SUCCESS;
}
