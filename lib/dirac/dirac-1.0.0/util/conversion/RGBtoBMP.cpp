/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: RGBtoBMP.cpp,v 1.3 2004/06/30 16:44:51 asuraparaju Exp $ $Name: Dirac_1_0_0 $
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
File RGBtoBMP.cpp

Utility for converting a sequence of frames, stored in a single
file in raw RGB format, to a sequence of multiple .BMP files.
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
using std::ofstream;
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

    if (argc != 8) {
        cout << "\"RGBtoBMP\" command line format is:" << endl;
        cout << "    Argument 1: file prefix e.g. foo" << endl;
        cout << "    Argument 2: file postfix e.g. .BMP" << endl;
        cout << "    Argument 3: number of digits e.g. 3" << endl;
        cout << "    Argument 4: first frame: e.g. 60" << endl;
        cout << "    Argument 5: number of frames: e.g. 8" << endl;
        cout << "    Argument 6: width of frame (pixels): e.g. 720" << endl;
        cout << "    Argument 7: height of frame (lines): e.g. 576" << endl;
        cout << "    Example: RGBtoBMP foo .BMP 3 60 8 720 576" << endl;
        cout << "        converts stdin into files foo060.BMP to foo067.BMP" << endl;
        return EXIT_SUCCESS; }

    //Set standard input to binary mode.
    //Only relevant for Windows (*nix is always binary)
    if ( setstdinmode(std::ios_base::binary) == -1 ) {
        cerr << "Error: could not set standard input to binary mode" << endl;
        return EXIT_FAILURE; }

    //Get command line arguments
    const string prefix = argv[1];
    const string postfix = argv[2];
    const int noDigits = atoi(argv[3]);
    const int firstFrame = atoi(argv[4]);
    const int frames = atoi(argv[5]);
    const int width = atoi(argv[6]);
    const int height = atoi(argv[7]);

    //Create bitmap header and allocate memory for input (frame) and
    //output (line) buffers.
    const int inBufferSize = 3*height*width;
    unsigned char *RGBArray = new unsigned char[inBufferSize];
    const BitmapHeader header(width, height);
    const int outBufferSize = header.lineBufferSize();
    unsigned char *lineBuffer = new unsigned char[outBufferSize];

    for (int frame = firstFrame; frame<(firstFrame+frames); ++frame) {

        //Read next RGB input frame
        std::streambuf& inbuf = *(cin.rdbuf());
        if ( (inbuf.sgetn(reinterpret_cast<char*>(RGBArray), inBufferSize)) < inBufferSize ) {
            cerr << "Error: failed to read frame " << frame << endl;
            return EXIT_FAILURE; }

        //Open output file in binary mode.
        ofstream output;
        string fileName;
        fileName = makeFileName(prefix, postfix, noDigits, frame);
        output.open(fileName.c_str(), ios_base::out|ios_base::binary);
        if (!output) {
            cerr << "Error: failed to open output file " << fileName << endl;
            return 0; }
        else
            clog << "Processing frame " << fileName << "\r";

        //Write bitmap header
        output << header;
        if (!output) {
            cerr << "Error: failed to write bitmap header for frame" << frame << endl;
            return EXIT_FAILURE; }

        //Write pixel data line by line
        //(starting at the botom of the frame because bitmaps are stored upside down!)
        std::streambuf& outbuf = *(output.rdbuf());
        for (int line=(height-1); line>=0; --line) {
            int bufferOffset = 0;
            int RGBOffset = 3*line*width;
            unsigned char R, G, B;
            for (register int pixel=0; pixel<width; ++pixel) {

                //read RGB values
                R = RGBArray[RGBOffset++];
                G = RGBArray[RGBOffset++];
                B = RGBArray[RGBOffset++];
                
                //Store RGB values
                lineBuffer[bufferOffset++] = B;
                lineBuffer[bufferOffset++] = G;
                lineBuffer[bufferOffset++] = R;

            } //end pixel loop
            if ( (outbuf.sputn(reinterpret_cast<char*>(lineBuffer), outBufferSize)) < outBufferSize ) {
                cerr << "Error: failed to write line " << line << ", frame " << frame << endl;
                return EXIT_FAILURE; }
        } //end line loop

        output.close(); //End reading input frame

    } //end frame loop

    delete [] RGBArray;
    delete [] lineBuffer;

    return EXIT_SUCCESS;
}
