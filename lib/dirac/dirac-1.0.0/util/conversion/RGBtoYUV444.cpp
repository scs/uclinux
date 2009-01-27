/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: RGBtoYUV444.cpp,v 1.3 2004/06/30 16:44:51 asuraparaju Exp $ $Name: Dirac_1_0_0 $
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
File RGBtoYUV444.cpp

Utility for converting a sequence of frames, stored in a single
file in raw RGB format, to a single output file in which they are
stored in YUV444 format.
This utility is a filter taking input on stdin and generating its
output on stdout.
Raw RGB format is simply a sequence of byte triples representing the
red, green and blue components of each pixel.
YUV444 is a planar format which stores the Y component of each frame,
as a sequence of bytes, followed by the U component followed by the V
component. That is the colour component are multiplexed framewise,
rather than pixel wise or in some other way.

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
        cout << "\"RGBtoYUV444\" command line format is:" << endl;
        cout << "    Argument 1: width (pixels) e.g. 720" << endl;
        cout << "    Argument 2: height (lines) e.g. 576" << endl;
        cout << "    Argument 3: number of frames e.g. 3" << endl;
        cout << "    Example: RGBtoYUV444 720 576 3" << endl;
        cout << "        converts 3 frames, of 720x576 pixels on stdin to stdout" << endl;
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

    //Allocate memory for input and output line buffers.
    //Conversion takes place a line at a time
    const int inBufferSize = 3*height*width;
    unsigned char *RGBBuffer = new unsigned char[inBufferSize];
    const int outBufferSize = height*width;
    unsigned char *YBuffer = new unsigned char[outBufferSize];
    unsigned char *UBuffer = new unsigned char[outBufferSize];
    unsigned char *VBuffer = new unsigned char[outBufferSize];
    int R, G, B;
    int Y, U, V;

    //Create references for input and output stream buffers.
    //IO is via stream buffers for efficiency
    std::streambuf& inbuf = *(cin.rdbuf());
    std::streambuf& outbuf = *(cout.rdbuf());

    for (int frame=0; frame<frames; ++frame) {

        clog << "Processing frame " << frame << "\r";
            
        //Read frames of RGB
        if ( inbuf.sgetn(reinterpret_cast<char*>(RGBBuffer), inBufferSize) < inBufferSize ) {
            cerr << "Error: failed to read frame " << (frame+1) << endl;
            return EXIT_FAILURE; }

        for (int line=0; line<height; ++line) {
            int RGBBufferIndex = 3*width*line;
            int YUVBufferIndex = width*line;
            for (int pixel=0; pixel<width; ++pixel) {

                R = RGBBuffer[RGBBufferIndex++];
                G = RGBBuffer[RGBBufferIndex++];
                B = RGBBuffer[RGBBufferIndex++];

                //Convert RGB to YUV
                Y = (( 66*R + 129*G +  25*B + 128)>>8)+ 16;
                U = ((-38*R -  74*G + 112*B + 128)>>8)+128;
                V = ((112*R -  94*G -  18*B + 128)>>8)+128;

                //Clip YUV values
                YBuffer[YUVBufferIndex] = static_cast<unsigned char>( (Y<0) ? 0 : ((Y>255) ? 255 : Y) );
                UBuffer[YUVBufferIndex] = static_cast<unsigned char>( (U<0) ? 0 : ((U>255) ? 255 : U) );
                VBuffer[YUVBufferIndex++] = static_cast<unsigned char>( (V<0) ? 0 : ((V>255) ? 255 : V) );
            }
        }

        //Write frames of Y then U then V components
        if ( outbuf.sputn(reinterpret_cast<char*>(YBuffer), outBufferSize) < outBufferSize ) {
            cerr << "Error: failed to write Y component of frame " << frame << endl;
            return EXIT_FAILURE; }
        if ( outbuf.sputn(reinterpret_cast<char*>(UBuffer), outBufferSize) < outBufferSize ) {
            cerr << "Error: failed to write U component of frame " << frame << endl;
            return EXIT_FAILURE; }
        if ( outbuf.sputn(reinterpret_cast<char*>(VBuffer), outBufferSize) < outBufferSize ) {
            cerr << "Error: failed to write V component of frame " << frame << endl;
            return EXIT_FAILURE; }
    }

    delete [] VBuffer;
    delete [] UBuffer;
    delete [] YBuffer;
    delete [] RGBBuffer;

    return EXIT_SUCCESS;
}
