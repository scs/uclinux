/* ***** BEGIN LICENSE BLOCK *****
*
* $Id: instrmain.cpp,v 1.15 2008/01/15 04:36:24 asuraparaju Exp $ $Name: Dirac_1_0_0 $
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
* Contributor(s): Chris Bowley (Original Author)
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

#include <iostream>
#include <fstream>
#include <sstream>
#include <libdirac_common/cmd_line.h>
using namespace dirac;

#include <util/instrumentation/process_sequence.h>
using namespace dirac_instr;

using namespace std;

static void DisplayHelp()
{
    cout << "\nInstrumentation display for DIRAC wavelet video coder";
    cout << "\n=====================================================";
    cout << "\n";
    cout << "\nUsage: progname -<flag1> [<flag_val>] ... <input1> <input2> ...";
    cout << "\nIn case of multiple assignment to the same parameter, the last holds.";
    cout << "\n";
    cout << "\nName                 Type   I/O Default Value Description";
    cout << "\n====                 ====   === ============= ===========";
    cout << "\ninput                string  I  [ required ]  Input file name";
    cout << "\noutput               string  I  [ required ]  Output file name";
    cout << "\n";
    cout << "\nmotion_colour        bool    I  true          Display motion vectors using colour wheel";
    cout << "\nmotion_arrows        bool    I  false         Display motion vectors as arrows";
    cout << "\nmotion_colour_arrows bool    I  false         Display motion vectors as arrows with colour size";
    cout << "\nsplit_mode           bool    I  false         Display macroblock splitting mode";
    cout << "\nsad                  bool    I  false         Display block SAD values";
    cout << "\npred_mode            bool    I  false         Display block prediction mode";
    cout << "\nglobal_inliers       bool    I  false         Display global motion inlier mask";
    cout << "\n";
    cout << "\nno_bg                bool    I  false         Display over grey background";
    cout << "\nno_legend            bool    I  false         Do not display colour legend";
    cout << "\n";
    cout << "\nglobal               bool    I  false         Display global motion";
    cout << "\nglobal_diff          bool    I  false         Display global motion error";
    cout << "\nclip                 int     I  25 / 10000    Clip for max value motion vector / SAD overlays";
    cout << "\nref                  int     I  1             Reference frame";
    cout << "\nstart                int     I  0             Frame number at which process starts";
    cout << "\nend                  int     I  end           Frame number at which process stops";
    cout << "\nbuffer               int     I  50            Size of internal buffer for motion data";
    cout << "\n";
    cout << "\nverbose              bool    I  false         Display information during process";
}

bool ReadInstrumentationHeader (std::istream &in, SourceParams& srcparams, bool &field_coding)
{
    if (! in )
        return false;

    int temp_int;
    bool temp_bool;

    in >> temp_int;
    srcparams.SetCFormat( (ChromaFormat)temp_int );

    in >> temp_int;
    srcparams.SetXl( temp_int );

    in >> temp_int;
    srcparams.SetYl( temp_int );

    in >> temp_int;
    srcparams.SetSourceSampling( temp_int );

    in >> temp_bool;
    srcparams.SetTopFieldFirst( temp_bool );

    int num, denom;
    in >> num;
    in >> denom;
    srcparams.SetFrameRate( num, denom );

    in >> num;
    in >> denom;
    srcparams.SetPixelAspectRatio( num, denom );
    
    in >> field_coding;
    return true;
}


int main (int argc, char* argv[])
{
    // read command line options
    string input,output;
    int ref = 1;              // use reference 1
    bool verbose = false;
    int start = 0, stop = -1;
    int buffer = 50;

    // set defaults
    OverlayParams oparams;
    oparams.SetOption(motion_colour);   // motion vector colour wheel
    oparams.SetReference(1);            // reference 1
    oparams.SetBackground(true);        // background on
    oparams.SetLegend(true);            // legend on
    oparams.SetMvClip(25);              // motion vector clip = 25
    oparams.SetSADClip(10000);          // SAD clip = 10000

    // create a list of boolean options
    set<string> bool_opts;
    bool_opts.insert("verbose");
    bool_opts.insert("no_bg");
    bool_opts.insert("no_legend");
    bool_opts.insert("motion_colour");
    bool_opts.insert("motion_arrows");
    bool_opts.insert("motion_colour_arrows");
    bool_opts.insert("split_mode");
    bool_opts.insert("sad");
    bool_opts.insert("pred_mode");
    bool_opts.insert("global");
    bool_opts.insert("global_diff");
    bool_opts.insert("global_inliers");

    // parse command line options
    CommandLine args(argc,argv,bool_opts);

    // need at least 3 arguments - the program name, an input and an output
    if (argc < 3)
    {
        DisplayHelp();
        exit(1);
    }
    else
    {
        // do required inputs
        if (args.GetInputs().size() == 2)
        {
            input=args.GetInputs()[0];
            output=args.GetInputs()[1];
        }

        // check we have real inputs
        if ((input.length() == 0) || (output.length() == 0))
        {
            DisplayHelp();
            exit(1);
        }

        // now process presets
        for (vector<CommandLine::option>::const_iterator opt = args.GetOptions().begin();
            opt != args.GetOptions().end(); ++opt)
        {
            if (opt->m_name == "motion_arrows")
                oparams.SetOption(motion_arrows);

            else if (opt->m_name == "motion_colour_arrows")
                oparams.SetOption(motion_colour_arrows);

            else if (opt->m_name == "motion_colour")
                oparams.SetOption(motion_colour);

            else if (opt->m_name == "split_mode")
                oparams.SetOption(split_mode);

            else if (opt->m_name == "sad")
                oparams.SetOption(SAD);

            else if (opt->m_name == "pred_mode")
                oparams.SetOption(pred_mode);

            else if (opt->m_name == "global_inliers")
                oparams.SetOption(gm_inliers);

            if (opt->m_name == "no_bg")
                oparams.SetBackground(false);

            if (opt->m_name == "no_legend")
                oparams.SetLegend(false);

            if (opt->m_name == "verbose")
                verbose = true;

            if (opt->m_name == "global")
            {
                if (oparams.Option() == motion_arrows)
                    oparams.SetOption(gm_arrows);

                if (oparams.Option() == motion_colour_arrows)
                    oparams.SetOption(gm_colour_arrows);

                if (oparams.Option() == motion_colour)
                    oparams.SetOption(gm_colour);
            }

            if (opt->m_name == "global_diff")
            {
                if (oparams.Option() == motion_arrows
                    || oparams.Option() == gm_arrows)
                    oparams.SetOption(gm_diff_arrows);

                if (oparams.Option() == motion_colour_arrows
                    || oparams.Option() == gm_colour_arrows)
                    oparams.SetOption(gm_diff_colour_arrows);

                if (oparams.Option() == motion_colour
                    || oparams.Option() == gm_colour)
                    oparams.SetOption(gm_diff_colour);
            }

        }

        // parameters
        for (vector<CommandLine::option>::const_iterator opt = args.GetOptions().begin();
            opt != args.GetOptions().end(); ++opt)
        {
            if (opt->m_name == "ref")
            {
                ref = strtoul(opt->m_value.c_str(),NULL,10);

                if (ref==2)
                    oparams.SetReference(2);
                else
                    oparams.SetReference(1);
            } // m_name

            if (opt->m_name == "clip")
            {
                if (oparams.Option() == SAD)
                {
                    oparams.SetSADClip(strtoul(opt->m_value.c_str(),NULL,10));
                    // ensure value is +ve
                    if (oparams.SADClip() <= 0)
                        oparams.SetSADClip(10000);
                }
                else
                {
                    oparams.SetMvClip(strtoul(opt->m_value.c_str(),NULL,10));
                    // ensure value is +ve
                    if (oparams.MvClip() <= 0)
                        oparams.SetMvClip(25);
                }
            } // m_name

            if (opt->m_name == "start")
            {
                start = strtoul(opt->m_value.c_str(),NULL,10);
            } // m_name

            if (opt->m_name == "stop")
            {
                stop = strtoul(opt->m_value.c_str(),NULL,10);
            } // m_name

            if (opt->m_name == "buffer")
            {
                buffer = strtoul(opt->m_value.c_str(),NULL,10);
            } // m_name
        } // opt
    } // args > 3

    // read motion data from file
    if (verbose) cerr << endl << "Opening motion data file ";
    char mv_file[FILENAME_MAX];
    strcpy(mv_file, input.c_str());
    strcat(mv_file, ".imt");
    if (verbose) cerr << mv_file;
    ifstream in(mv_file, ios::in);

    if (!in)
    {
        cerr << endl << "Failed to open sequence motion data file. Exiting." << endl;
        exit(EXIT_FAILURE);
    }

    SourceParams srcparams;
    bool field_coding; // true if material has been coded as fields and not frames
    ReadInstrumentationHeader (in, srcparams, field_coding);
    SourceParams out_srcparams(srcparams);

    // Create objects for input and output picture sequences
    char yuv_file[FILENAME_MAX];
    strcpy(yuv_file, input.c_str());
    strcat(yuv_file, ".localdec.yuv");
    // hack hack - set interlace flag in source params to field_coding
    // so that the Frame Parameters are set correctly.
    srcparams.SetSourceSampling(field_coding);
    FileStreamInput inputpic(yuv_file, srcparams, field_coding);

    if (field_coding)
        out_srcparams.SetYl(out_srcparams.Yl()>>1);
    FileStreamOutput outputpic(output.c_str(), out_srcparams, false);

    if (verbose) cerr << " ... ok" << endl << "Processing sequence...";
    // *** process the sequence ***
    ProcessSequence process(oparams, inputpic, outputpic, in, verbose, buffer, srcparams);
    process.DoSequence(start, stop);
    if (verbose) cerr << endl << "Done sequence." << endl;
    return 0;
}


