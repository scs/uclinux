/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: BMPtoRGB.cpp,v 1.3 2004/06/30 16:44:51 asuraparaju Exp $ $Name: Dirac_1_0_0 $
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
File BMPtoRGB.cpp

Utility for converting 24 bit bitmap (.bmp) files to raw RGB format.
Raw RGB format is simply a sequence of byte triples representing the
red, green and blue components of each pixel.

Original author: Tim Borer
****************************************************************/

#include <stdlib.h> //Contains EXIT_SUCCESS, EXIT_FAILURE
#include <iostream> //For cin, cout, cerr
#include <sstream>
#include <iomanip>
#include <fstream>
#include <string>
using std::cout;
using std::cin;
using std::cerr;
using std::clog;
using std::endl;
using std::string;
using std::setfill;
using std::setw;
using std::string;
using std::ostringstream;
using std::ifstream;
using std::ios_base;

#include "setstdiomode.h"
#include "bitmap.h"
using namespace dirac_vu;

//Define a function to construct a file name from
//a prefix, frame number and file extension.
string makeFileName(const string& prefix,
                    const string& postfix,
                    int noDigits,
                    int frameNumber) {
    ostringstream out;
    out << prefix;
    out << setfill('0') << setw(noDigits) << frameNumber;
    out << postfix;
    return out.str(); }

int main(int argc, char * argv[] ) {

    if (argc != 6) {
        cout << "\"BMPtoRGB\" command line format is:" << endl;
        cout << "    Argument 1: file prefix e.g. foo" << endl;
        cout << "    Argument 2: file postfix e.g. .BMP" << endl;
        cout << "    Argument 3: number of digits e.g. 3" << endl;
        cout << "    Argument 4: first frame: e.g. 60" << endl;
        cout << "    Argument 5: number of frames: e.g. 8" << endl;
        cout << "    Example: BMP2Raw foo .BMP 3 60 8" << endl;
        cout << "        converts foo060.BMP to foo067.BMP into stream on stdout" << endl;
        return EXIT_SUCCESS; }

    //Get command line arguments
    string prefix = argv[1];
    string postfix = argv[2];
    int noDigits = atoi(argv[3]);
    int firstFrame = atoi(argv[4]);
    int frames = atoi(argv[5]);

    //Set standard input and standard output to binary mode.
    //Only relevant for Windows (*nix is always binary)
    if ( setstdoutmode(std::ios_base::binary) == -1 ) {
        cerr << "Error: could not set standard output to binary mode" << endl;
        return EXIT_FAILURE; }

    for (int frame = firstFrame; frame<(firstFrame+frames); ++frame) {

        ifstream input;
        string fileName;

        //Open input file in binary mode.
        fileName = makeFileName(prefix, postfix, noDigits, frame);
        input.open(fileName.c_str(), ios_base::in|ios_base::binary);
        if (!input) {
            cerr << "Error: failed to open input file " << fileName << endl;
            return 0; }
        else
            clog << "Processing frame " << fileName << "\r";

        //Read bitmap header
        BitmapHeader header;
        input >> header;
        if (!input) {
            cerr << "Error: failed to read bitmap header" << endl;
            return EXIT_FAILURE; }
        
        //Read pixel data, line by line (to maximise cache occupancy).
        const int width = header.width();
        const int height = header.height();
        const int inBufferSize = header.lineBufferSize();
        unsigned char *lineBuffer = new unsigned char[inBufferSize];
        unsigned char *RGBArray = new unsigned char[3*height*width];

        //Start reading at bottom (bitmaps are stored upside down!)
        std::streambuf& inbuf = *(input.rdbuf());
        for (int line=(height-1); line>=0; --line) {
            if ( (inbuf.sgetn(reinterpret_cast<char*>(lineBuffer), inBufferSize)) < inBufferSize ) {
                cerr << "Error: failed to read line " << line << endl;
                return EXIT_FAILURE; }
            int bufferOffset = 0;
            int RGBOffset = 3*line*width;
            unsigned char R, G, B;
            for (register int pixel=0; pixel<width; ++pixel) {
                
                //Read RGB values
                B = lineBuffer[bufferOffset++];
                G = lineBuffer[bufferOffset++];
                R = lineBuffer[bufferOffset++];

                //Store RGB values
                RGBArray[RGBOffset++] = R;
                RGBArray[RGBOffset++] = G;
                RGBArray[RGBOffset++] = B;

            } //end pixel loop
        } //end line loop

        input.close(); //End reading input frame


    //Write whole frame of RGB pixel data
    std::streambuf& outbuf = *(cout.rdbuf());
    const int outBufferSize = 3*height*width;
    if ( (outbuf.sputn(reinterpret_cast<char*>(RGBArray), outBufferSize)) < outBufferSize ) {
            cerr << "Error: failed to write frame " << frame << endl;
            return EXIT_FAILURE; }

        delete [] RGBArray;
        delete [] lineBuffer;

    } //end frame loop

    return EXIT_SUCCESS;
}
