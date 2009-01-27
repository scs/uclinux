 /* ***** BEGIN LICENSE BLOCK *****
 *
 * $Id: encmain.cpp,v 1.79 2008/08/14 02:31:37 asuraparaju Exp $ $Name: Dirac_1_0_0 $
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
 * Contributor(s): Thomas Davies (Original Author),
 *                 Scott R Ladd,
 *                 Anuradha Suraparaju,
 *                 Andrew Kennedy,
 *                 David Flynn,
 *                 Johannes Reinhardt,
 *                 Myo Tun (Brunel University)
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

#include <time.h>
#include <iostream>
#include <limits>
#include <fstream>
#include <set>
#include <cmath>
#include <ctime>
#include <cassert>
#include <string>
#include <libdirac_encoder/dirac_encoder.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstdlib>
#include <cstring>
#include <climits>

using namespace std;

const int VIDEO_BUFFER_SIZE = 32*1024*1024;
unsigned char video_buf[VIDEO_BUFFER_SIZE];

static void display_help()
{
    cout << "\nDIRAC wavelet video coder.";
    cout << "\n";
    cout << "\nUsage: progname -<flag1> [<flag1_val>] ... <input> <output>";
    cout << "\nIn case of multiple assignment to the same parameter, the last holds.";
    cout << "\n";
    cout << "\nName              Type             Default Value Description";
    cout << "\n====              ====             ============= ===========                                       ";
    cout << "\nQSIF525           bool    false         Use QSIF compression presets";
    cout << "\nQCIF              bool    false         Use QCIF compression presets";
    cout << "\nSIF525            bool    false         Use SIF compression presets";
    cout << "\nCIF               bool    false         Use CIF compression presets";
    cout << "\n4CIF              bool    false         Use 4CIF compression presets";
    cout << "\n4SIF525           bool    false         Use 4SIF compression presets";
    cout << "\nSD480I60          bool    false         Use SD-480 compression presets";
    cout << "\nSD576I50          bool    false         Use SD-576 compression presets";
    cout << "\nHD720P60          bool    false         Use HD-720P60 compression presets";
    cout << "\nHD720P50          bool    false         Use HD-720P50 compression presets";
    cout << "\nHD1080I60         bool    false         Use HD-1080I60 compression presets";
    cout << "\nHD1080I50         bool    false         Use HD-1080I50 compression presets";
    cout << "\nHD1080P60         bool    false         Use HD-1080P60 compression presets";
    cout << "\nHD1080P50         bool    false         Use HD-1080P50 compression presets";
    cout << "\nUHDTV4K60         bool    false         Use UHDTV 4K60 compression presets";
    cout << "\nUHDTV4K50         bool    false         Use UHDTV 4K50 compression presets";
    cout << "\nUHDTV8K60         bool    false         Use UHDTV 8K60 compression presets";
    cout << "\nUHDTV8K50         bool    false         Use UHDTV 8K50 compression presets";
    cout << "\nDC2K24            bool    false         Use DIGITAL CINEMA 2K compression presets";
    cout << "\nDC4K24           bool    false          Use DIGITAL CINEMA 4K compression presets";
    cout << "\nfull_search     ulong ulong  0UL 0UL         Use full search motion estimation";
    cout << "\nwidth             ulong   Preset        Width of frame";
    cout << "\nheight            ulong   Preset        Length of frame";
    cout << "\nheight            ulong   Preset        Length of frame";
    cout << "\ncformat           string  YUV444P       Chroma Sampling Format (YUV444P YUV422P YUV420P)";
    cout << "\nfr                ulong   Preset        Frame rate(s) (e.n or e/n format)";
    cout << "\nsource_sampling   string  progressive   source material type either progressive or interlaced";
    cout << "\nstart             ulong   0UL           Frame number to start encoding from";
    cout << "\nstop              ulong   EOF           Frame number after which encoding finishes";
    cout << "\nfield_coding      bool    false         Set picture coding type to field coding. Default coding type is by frames";
    cout << "\nL1_sep            ulong   0UL           Separation of L1 frames";
    cout << "\nnum_L1            ulong   0UL           Number of L1 frames";
    cout << "\nxblen             ulong   0UL           Overlapping block horizontal length";
    cout << "\nyblen             ulong   0UL           Overlapping block vertical length";
    cout << "\nxbsep             ulong   0UL           Overlapping block horizontal separation";
    cout << "\nybsep             ulong   0UL           Overlapping block vertical separation";
    cout << "\ncpd               ulong   0UL           Perceptual weighting - vertical cycles per deg.";
    cout << "\nqf                float   0.0F          Overall quality factor (>0, typically: 7=medium, 9=high)";
    cout << "\ntargetrate        ulong   0UL           Target Bit Rate in Kbps";
    cout << "\nlossless          bool    false         Lossless coding (overrides qf)";
    cout << "\niwlt_filter       string  DD9_7         Intra frame Transform Filter (DD9_7 LEGALL5_3 DD13_7 HAAR0 HAAR1 FIDELITY DAUB9_7)";
    cout << "\nrwlt_filter       string  LEGALL5_3     Inter frame Transform Filter (DD9_7 LEGALL5_3 DD13_7 HAAR0 HAAR1 FIDELITY DAUB9_7)";
    cout << "\nwlt_depth         ulong   4             Transform Depth";
    cout << "\nmulti_quants      bool    false         Use multiple quantisers";
    cout << "\nmv_prec           string  false         MV Pixel Precision (1, 1/2, 1/4, 1/8)";
    cout << "\nno_spartition     bool    false         Do not use spatial partitioning while coding transform data";
    cout << "\nprefilter         string/int NO_PF 0    Prefilter input giving filter name (NO_PF, CWM, RECTLP, DIAGLP) and strength (0-10)";
    cout << "\nuse_vlc           bool    false         Use VLC for entropy coding of coefficients";
    cout << "\nlocal             bool    false         Write diagnostics & locally decoded video";
    cout << "\nverbose           bool    false         Verbose mode";
    cout << "\nh|help            bool    false         Display help message";
    cout << "\ninput             string  [ required ]  Input file name";
    cout << "\noutput            string  [ required ]  Output file name [May not be '-']";
    cout << endl;
}



bool WritePicData (std::ofstream &fdata, dirac_encoder_t *encoder)
{
    dirac_sourceparams_t &sparams = encoder->enc_ctx.src_params;
    dirac_framebuf_t &fbuf = encoder->dec_buf;
    bool ret_stat = true;

    if (encoder->decoded_frame_avail)
    {
        ios::iostate oldExceptions = fdata.exceptions();
        fdata.exceptions (ios::failbit | ios::badbit);
        try
        {
            assert (fbuf.buf[0] != 0);
            fdata.write ((char *)fbuf.buf[0], sparams.width*sparams.height);
            assert (fbuf.buf[1] != 0);
            assert (fbuf.buf[2] != 0);
            fdata.write ((char *)fbuf.buf[1],
            sparams.chroma_width*sparams.chroma_height);
            fdata.write ((char *)fbuf.buf[2],
            sparams.chroma_width*sparams.chroma_height);
        }
        catch (...)
        {
            std::cout << "Incomplete frame " << std::endl;
            ret_stat = false;
        }
        fdata.exceptions (oldExceptions);
    }
    return ret_stat;
}

bool WriteDiagnosticsHeader (std::ofstream &fdata, dirac_encoder_t *encoder)
{
    bool ret_stat = true;
    dirac_sourceparams_t &srcparams = encoder->enc_ctx.src_params;
    ios::iostate oldExceptions = fdata.exceptions();
    fdata.exceptions (ios::failbit | ios::badbit);

    try
    {
        fdata << srcparams.chroma << std::endl;
        fdata << srcparams.width << std::endl;
        fdata << srcparams.height << std::endl;
        fdata << srcparams.source_sampling << std::endl;
        fdata << srcparams.topfieldfirst << std::endl;
        fdata << srcparams.frame_rate.numerator << std::endl;
        fdata << srcparams.frame_rate.denominator << std::endl;
        fdata << srcparams.pix_asr.numerator << std::endl;
        fdata << srcparams.pix_asr.denominator << std::endl;
        fdata << encoder->enc_ctx.enc_params.picture_coding_mode << std::endl;
    }

    catch (...)
    {
        std::cerr << "Error writing sequence info in diagnostics file." << std::endl;
        ret_stat =  false;
    }
    fdata.exceptions (oldExceptions);
    return ret_stat;
}

bool WriteDiagnosticsData (std::ofstream &fdata, dirac_encoder_t *encoder)
{
    dirac_instr_t &instr = encoder->instr;
    bool ret_stat = true;

    if (encoder->instr_data_avail)
    {
        ios::iostate oldExceptions = fdata.exceptions();
        fdata.exceptions (ios::failbit | ios::badbit);
        try
        {
            fdata << std::endl << "[frame:" << instr.pnum << "]";
            if (instr.ptype == INTRA_PICTURE)
            {
                fdata << ">intra" << std::endl;
                return true;
            }

            fdata << ">mo_comp";
            fdata << std::endl << std::endl << instr.num_refs << " ";
            for (int i=0; i<instr.num_refs; ++i)
            {
                fdata << instr.refs[i] << " ";
            }
            fdata << instr.ybsep << " " << instr.xbsep << " ";
            fdata << instr.mb_ylen << " " << instr.mb_xlen << " ";
            fdata << instr.mv_ylen << " " << instr.mv_xlen
                    << std::endl << std::endl ;
            for (int j=0; j<instr.mb_ylen; j++)
            {
                for (int i=0; i<instr.mb_xlen; i++)
                    fdata << instr.mb_split_mode[j*instr.mb_xlen + i] << " ";
                fdata << std::endl;
            }
            fdata << std::endl;

            for (int j=0; j<instr.mb_ylen; j++)
            {
                for (int i=0; i<instr.mb_xlen; i++)
                    fdata << instr.mb_costs[j*instr.mb_xlen + i] << " ";
                fdata << std::endl;
            }
            fdata << std::endl;

            for (int j=0; j<instr.mv_ylen; j++)
            {
                for (int i=0; i<instr.mv_xlen; i++)
                    fdata << instr.pred_mode[j*instr.mv_xlen + i] << " ";
                fdata << std::endl;
            }
            fdata << std::endl;

            for (int j=0; j<instr.mv_ylen; j++)
            {
                for (int i=0; i<instr.mv_xlen; i++)
                    fdata << instr.intra_costs[j*instr.mv_xlen + i] << " ";
                fdata << std::endl;
            }
            fdata << std::endl;

            if (instr.num_refs > 1)
            {
                for (int j=0; j<instr.mv_ylen; j++)
                {
                    for (int i=0; i<instr.mv_xlen; i++)
                    {
                        fdata << instr.bipred_costs[j*instr.mv_xlen + i].SAD
                        <<" " << instr.bipred_costs[j*instr.mv_xlen + i].mvcost
                        << " ";;
                    }
                    fdata << std::endl;
                }
            }
            fdata << std::endl;

            for (int j=0; j<instr.mv_ylen; j++)
            {
                for (int i=0; i<instr.mv_xlen; i++)
                    fdata << instr.dc_ycomp[j*instr.mv_xlen + i] << " ";
                fdata << std::endl;
            }

            // FIXME: always expects 3 components
            fdata << std::endl;
            for (int j=0; j<instr.mv_ylen; j++)
            {
                for (int i=0; i<instr.mv_xlen; i++)
                    fdata << instr.dc_ucomp[j*instr.mv_xlen + i] << " ";
                fdata << std::endl;
            }
            fdata << std::endl;
            for (int j=0; j<instr.mv_ylen; j++)
            {
                for (int i=0; i<instr.mv_xlen; i++)
                    fdata << instr.dc_vcomp[j*instr.mv_xlen + i] << " ";
                fdata << std::endl;
            }

            for (int k = 0; k < instr.num_refs; k++)
            {
                fdata << std::endl;
                for (int j=0; j<instr.mv_ylen; j++)
                {
                    for (int i=0; i<instr.mv_xlen; i++)
                    {
                        fdata << instr.mv[k][j*instr.mv_xlen + i].x
                        <<" " << instr.mv[k][j*instr.mv_xlen + i].y
                        << " ";;
                    }
                    fdata << std::endl;
                }
                fdata << std::endl;
                for (int j=0; j<instr.mv_ylen; j++)
                {
                    for (int i=0; i<instr.mv_xlen; i++)
                    {
                        fdata << instr.pred_costs[k][j*instr.mv_xlen + i].SAD
                        <<" " << instr.pred_costs[k][j*instr.mv_xlen + i].mvcost
                        << " ";;
                    }
                    fdata << std::endl;
                }
                fdata << std::endl;
            }
        }
        catch (...)
        {
            std::cout << "Error writing diagnostics data" << std::endl;
            ret_stat = false;
        }
        fdata.exceptions (oldExceptions);
    }
    return ret_stat;
}

bool ReadPicData (std::ifstream &fdata, unsigned char *buffer, int frame_size)
{
    bool ret_stat = true;

    ios::iostate oldExceptions = fdata.exceptions();
    fdata.exceptions (ios::failbit | ios::badbit);
    try
    {
        fdata.read ((char *)buffer, frame_size);
    }
    catch (...)
    {
        ret_stat = false;
    }
    fdata.exceptions (oldExceptions);
    return ret_stat;
}

bool Skip (std::ifstream &fdata, int start_frame, int frame_size)
{
    bool ret_stat = true;
    ios::iostate oldExceptions = fdata.exceptions();
    fdata.exceptions (ios::failbit | ios::badbit);
    try
    {
       unsigned char* buffer = new unsigned char[frame_size];
       for (int i=0; i<start_frame; ++i)
       ReadPicData(fdata, buffer, frame_size);
       delete[] buffer;
    }
    catch (...)
    {
        std::cerr << "Skipping of first "<< start_frame << " frames failed"
                  << std::endl;
        ret_stat = false;
    }
    fdata.exceptions (oldExceptions);
    return ret_stat;
}

int GetFrameBufferSize (const dirac_encoder_context_t &enc_ctx)
{
    int xl = enc_ctx.src_params.width;
    int yl = enc_ctx.src_params.height;

    int size;

    switch (enc_ctx.src_params.chroma)
    {
    case format420:
        size = (xl*yl*3)/2;
        break;
    case format422:
        size = (xl*yl)*2;
        break;
    case format444:
        size = (xl*yl)*3;
        break;
    default:
        size = xl * yl;
        break;
    }
    return size;
}
const string ChromaToString (dirac_chroma_t chroma)
{
    switch (chroma)
    {
    case format422:
        return string("YUV422P");

    case format444:
        return string("YUV444P");

    case format420:
        return string("YUV420P");

    default:
        break;
    }

    return string("Unknown");
}

const string PrefilterToString(dirac_prefilter_t pf)
{
    switch (pf)
    {
    case CWM:
        return string("CWM");
    case RECTLP:
        return string("RECTLP");
    case DIAGLP:
        return string("DIAGLP");
    default:
        return string("NO_PF");
    };

}

dirac_chroma_t StringToChroma (const char* chroma)
{
    if (strcmp(chroma, "YUV444P") == 0)
        return format444;
    else if (strcmp(chroma, "YUV422P") == 0)
        return format422;
    else if (strcmp(chroma, "YUV420P") == 0)
        return format420;
    else
        return formatNK;
}

const string MvPrecisionToString (MVPrecisionType mv_type)
{
    switch (mv_type)
    {
    case MV_PRECISION_PIXEL:
        return string("Pixel");
    case MV_PRECISION_HALF_PIXEL:
        return string("Half Pixel");
    case MV_PRECISION_QUARTER_PIXEL:
        return string("Quarter Pixel");
    case MV_PRECISION_EIGHTH_PIXEL:
        return string("Eighth Pixel");
    default:
        return string("Undefined");
    }
}

const string TransformFilterToString (WltFilter wf)
{
    switch (wf)
    {
    case DD9_7:
        return string("DD9_7");
    case LEGALL5_3:
        return string("LEGALL5_3");
    case DD13_7:
        return string("DD13_7");
    case HAAR0:
        return string("HAAR0");
    case HAAR1:
        return string("HAAR1");
    case FIDELITY:
        return string("FIDELITY");
    case DAUB9_7:
        return string("DAUB9_7");
    default:
        return string("Undefined");
    }
}

WltFilter StringToTransformFilter (string wf)
{
    if( wf=="DD9_7" )
        return DD9_7;
    else if( wf=="LEGALL5_3" )
        return LEGALL5_3;
    else if( wf=="DD13_7" )
        return DD13_7;
    else if( wf=="HAAR0" )
        return HAAR0;
    else if( wf=="HAAR1" )
        return HAAR1;
    else if( wf=="FIDELITY" )
        return FIDELITY;
    else if( wf=="DAUB9_7" )
        return DAUB9_7;
    else
        return filterNK;
}

void display_codec_params(dirac_encoder_context_t &enc_ctx)
{
    std::cout << "Source parameters : " << std::endl;
    std::cout << "\theight=" << enc_ctx.src_params.height;
    std::cout << " width=" << enc_ctx.src_params.width << std::endl;
    std::cout << "\tchroma=" << ChromaToString(enc_ctx.src_params.chroma) << std::endl;
    std::cout << "\tframe rate=" << enc_ctx.src_params.frame_rate.numerator;
    std::cout << "/" << enc_ctx.src_params.frame_rate.denominator << std::endl;
    std::cout << "Encoder parameters : " << std::endl;
    std::cout << "\tquality factor=" << enc_ctx.enc_params.qf << std::endl;
    std::cout << "\tGOP parameters : num_L1="  << enc_ctx.enc_params.num_L1;
    if (enc_ctx.enc_params.num_L1 != 0)
    {
        std::cout << " L1_sep=" << enc_ctx.enc_params.L1_sep << std::endl;
        std::cout << "\tBlock parameters : xblen="  << enc_ctx.enc_params.xblen;
        std::cout << " yblen=" << enc_ctx.enc_params.yblen;
        std::cout << " xbsep=" << enc_ctx.enc_params.xbsep;
        std::cout << " ybsep=" << enc_ctx.enc_params.ybsep << std::endl;
        std::cout << " \tMV Precision=" << MvPrecisionToString(enc_ctx.enc_params.mv_precision) << std::endl;
        std::cout << " \tInter Frame Transform Filter=" << TransformFilterToString(enc_ctx.enc_params.inter_wlt_filter) << std::endl;
    }
    else
        std::cout << " (I-frame only coding)" << std::endl;
    std::cout << " \tIntra Frame Transform Filter=" << TransformFilterToString(enc_ctx.enc_params.intra_wlt_filter) << std::endl;
    std::cout << " \tWavelet depth=" << enc_ctx.enc_params.wlt_depth << std::endl;
    std::cout << " \tSpatial Partitioning=" << (enc_ctx.enc_params.spatial_partition ? "true" : "false") << std::endl;
    std::cout << " \tMultiple Quantisers=" << (enc_ctx.enc_params.multi_quants ? "true" : "false") << std::endl;
    std::cout << " \tPrefilter=" << PrefilterToString(enc_ctx.enc_params.prefilter) << std::endl;
    std::cout << " \tField coding=" << (enc_ctx.enc_params.picture_coding_mode == 1? "true" : "false") << std::endl;
    std::cout << " \tLossless Coding=" << (enc_ctx.enc_params.lossless ? "true" : "false") << std::endl;
    std::cout << " \tEntropy Coding=" << (enc_ctx.enc_params.using_ac ? "Arithmetic Coding" : "Variable Length Coding") << std::endl;
}

int start_pos = 0;
int end_pos = -1;
bool verbose = false;
bool nolocal = true;
int fields_factor = 1;

bool parse_command_line(dirac_encoder_context_t& enc_ctx, int argc, char **argv)
{
            /**********  command line parameter parsing*********/

    // An array indicating whether a parameter has been parsed
    bool* parsed = new bool[argc];

    // Program name has been parsed
    parsed[0] = true;

    // No other parameters
    for (int i=1 ; i<argc ; ++i )
        parsed[i] = false;

    // The start and end-points of the parts of the file to be coded
    // (end_pos set to -1 means code to the end)

    memset (&enc_ctx, 0, sizeof(dirac_encoder_context_t));

   //Now do the options
   // Checking for presets. Assume custom by default
    dirac_encoder_presets_t preset = VIDEO_FORMAT_CUSTOM;
    for (int i = 1; i < argc; i++)
    {
        if ( strcmp(argv[i], "-help") == 0  ||
             strcmp(argv[i], "-h") == 0)
        {
            display_help();
            exit(EXIT_SUCCESS);
        }
        else if ( strcmp (argv[i], "-QSIF525") == 0 )
        {
            preset = VIDEO_FORMAT_QSIF525;
            parsed[i] = true;
        }
        else if ( strcmp (argv[i], "-QCIF") == 0 )
        {
            preset = VIDEO_FORMAT_QCIF;
            parsed[i] = true;
        }
        else  if ( strcmp (argv[i], "-SIF525") == 0 )
        {
            preset = VIDEO_FORMAT_SIF525;
            parsed[i] = true;
        }
        else if ( strcmp (argv[i], "-CIF") == 0 )
        {
            preset = VIDEO_FORMAT_CIF;
            parsed[i] = true;
        }
        else if ( strcmp (argv[i], "-4CIF") == 0 )
        {
            preset = VIDEO_FORMAT_4CIF;
            parsed[i] = true;
        }
        else if ( strcmp (argv[i], "-4SIF525") == 0 )
        {
            preset = VIDEO_FORMAT_4SIF525;
            parsed[i] = true;
        }
        else if ( strcmp (argv[i], "-SD480I60") == 0 )
        {
            preset = VIDEO_FORMAT_SD_480I60;
            parsed[i] = true;
        }
        else if ( strcmp (argv[i], "-SD576I50") == 0 )
        {
            preset = VIDEO_FORMAT_SD_576I50;
            parsed[i] = true;
        }
        else if ( strcmp (argv[i], "-HD720P60") == 0 )
        {
            preset = VIDEO_FORMAT_HD_720P60;
            parsed[i] = true;
        }
        else if ( strcmp (argv[i], "-HD720P50") == 0 )
        {
            preset = VIDEO_FORMAT_HD_720P50;
            parsed[i] = true;
        }
        else if ( strcmp (argv[i], "-HD1080I60") == 0 )
        {
            preset = VIDEO_FORMAT_HD_1080I60;
            parsed[i] = true;
        }
        else if ( strcmp (argv[i], "-HD1080I50") == 0 )
        {
            preset = VIDEO_FORMAT_HD_1080I50;
            parsed[i] = true;
        }
        else if ( strcmp (argv[i], "-HD1080P60") == 0 )
        {
            preset = VIDEO_FORMAT_HD_1080P60;
            parsed[i] = true;
        }
        else if ( strcmp (argv[i], "-HD1080P50") == 0 )
        {
            preset = VIDEO_FORMAT_HD_1080P50;
            parsed[i] = true;
        }
        else if ( strcmp (argv[i], "-UHDTV4K60") == 0 )
        {
            preset = VIDEO_FORMAT_UHDTV_4K60;
            parsed[i] = true;
        }
        else if ( strcmp (argv[i], "-UHDTV4K50") == 0 )
        {
            preset = VIDEO_FORMAT_UHDTV_4K50;
            parsed[i] = true;
        }
        else if ( strcmp (argv[i], "-UHDTV8K60") == 0 )
        {
            preset = VIDEO_FORMAT_UHDTV_8K60;
            parsed[i] = true;
        }
        else if ( strcmp (argv[i], "-UHDTV8K50") == 0 )
        {
            preset = VIDEO_FORMAT_UHDTV_8K50;
            parsed[i] = true;
        }
        else if ( strcmp (argv[i], "-DC2K24") == 0 )
        {
            preset = VIDEO_FORMAT_DIGI_CINEMA_2K24;
            parsed[i] = true;
        }
        else if ( strcmp (argv[i], "-DC4K24") == 0 )
        {
            preset = VIDEO_FORMAT_DIGI_CINEMA_4K24;
            parsed[i] = true;
        }
    }

    // initialise the encoder context
    dirac_encoder_context_init (&enc_ctx, preset);

    //now go over again and override presets with other values
    for(int i=1; i < argc; )
    {
        if ( strcmp(argv[i], "-width") == 0 )
        {
            parsed[i] = true;
            i++;
            enc_ctx.src_params.width =
                strtoul(argv[i],NULL,10);
            parsed[i] = true;
        }
        else if ( strcmp(argv[i], "-height") == 0 )
        {
            parsed[i] = true;
            i++;
            enc_ctx.src_params.height =
                strtoul(argv[i],NULL,10);
            parsed[i] = true;
        }
        else if ( strcmp(argv[i], "-cformat") == 0 )
        {
            parsed[i] = true;
            i++;
            enc_ctx.src_params.chroma = StringToChroma (argv[i]);
            if (enc_ctx.src_params.chroma == formatNK)
            {
                cerr << "Unsupported chroma format" << argv[i] << endl;
                parsed[i] = false;
            }
            else
                parsed[i] = true;
        }
        else if ( strcmp(argv[i], "-fr") == 0 )
        {
            parsed[i] = true;
            i++;
            if(strncmp(argv[i], "59.94", 5)==0)
            {
                parsed[i] = true;
                enc_ctx.src_params.frame_rate.numerator=60000;
                enc_ctx.src_params.frame_rate.denominator=1001;
            }
            else if(strncmp(argv[i], "23.98", 5)==0)
            {
                parsed[i] = true;
                enc_ctx.src_params.frame_rate.numerator=24000;
                enc_ctx.src_params.frame_rate.denominator=1001;
            }
            else if(strncmp(argv[i], "29.97", 5)==0)
            {
                parsed[i] = true;
                enc_ctx.src_params.frame_rate.numerator=30000;
                enc_ctx.src_params.frame_rate.denominator=1001;
            }
            //test for decimal format
            else if(strcspn(argv[i], ".")!=strlen(argv[i]))
            {
                parsed[i] = true;
                // look for whole number
                char* num_token = strtok(argv[i], ".");
                int whole = strtoul(num_token,NULL,10);
                int decimal=0;
                int decimal_length=0;

                // look for decimal part
                num_token = strtok(NULL, "");
                if(num_token)
                {
                    decimal_length=strlen(num_token);
                    decimal=strtoul(num_token, NULL, 10);
                }
                // calculate amount to raise to whole number
                int multiply = (int)std::pow(10.0, decimal_length);
                enc_ctx.src_params.frame_rate.numerator =
                    decimal == 0 ? whole : (multiply*whole)+decimal;
                enc_ctx.src_params.frame_rate.denominator =
                    decimal == 0 ? 1 : multiply;

            }
            else
            {
                parsed[i] = true;
                // assume e/d format
                char* token = strtok(argv[i], "/");
                enc_ctx.src_params.frame_rate.numerator =
                strtoul(token,NULL,10);
                enc_ctx.src_params.frame_rate.denominator = 1;

                token = strtok(NULL, "");
                if(token)
                    enc_ctx.src_params.frame_rate.denominator =
                    strtoul(token, NULL, 10);
             }
        }
        else if ( strcmp(argv[i], "-source_sampling") == 0 )
        {
            parsed[i] = true;
            i++;
            parsed[i]= true;
            if (!strcmp(argv[i], "progressive"))
                enc_ctx.src_params.source_sampling = 0;
            else if (!strcmp(argv[i], "interlaced"))
                enc_ctx.src_params.source_sampling = 1;
            else
            {
                cerr << "source_sampling should either be interlaced or progressive" << endl;
                parsed[i] = false;
            }
        }
        else if ( strcmp(argv[i], "-field_coding") == 0 )
        {
            parsed[i] = true;
            enc_ctx.enc_params.picture_coding_mode =  1;
            fields_factor = 2;
        }
        else if ( strcmp(argv[i], "-qf") == 0 )
        {
            parsed[i] = true;
            i++;
            enc_ctx.enc_params.qf =  atof(argv[i]);
            parsed[i] = true;
        }
        else if ( strcmp(argv[i], "-full_search") == 0 )
        {
            parsed[i] = true;
            enc_ctx.enc_params.full_search =  1;
            i++;

            enc_ctx.enc_params.x_range_me = strtoul(argv[i],NULL,10);
            parsed[i] = true;

            i++;
            enc_ctx.enc_params.y_range_me = strtoul(argv[i],NULL,10);
            parsed[i] = true;

        }
        else if ( strcmp(argv[i], "-targetrate") == 0 )
        {
            parsed[i] = true;
            i++;
            enc_ctx.enc_params.trate = strtoul(argv[i],NULL,10);
            parsed[i] = true;
        }
        else if ( strcmp(argv[i], "-lossless") == 0 )
        {
            parsed[i] = true;
            enc_ctx.enc_params.lossless = true;
        }
        else if ( strcmp(argv[i], "-L1_sep") == 0 )
        {
            parsed[i] = true;
            i++;
            enc_ctx.enc_params.L1_sep =
                strtoul(argv[i],NULL,10);
            parsed[i] = true;
        }
        else if ( strcmp(argv[i], "-num_L1") == 0 )
        {
            parsed[i] = true;
            i++;
            enc_ctx.enc_params.num_L1 =
                strtoul(argv[i],NULL,10);
            parsed[i] = true;
        }
        else if ( strcmp(argv[i], "-xblen") == 0 )
        {
            parsed[i] = true;
            i++;
            enc_ctx.enc_params.xblen =
                strtoul(argv[i],NULL,10);
            parsed[i] = true;
        }
        else if ( strcmp(argv[i], "-yblen") == 0 )
        {
            parsed[i] = true;
            i++;
             enc_ctx.enc_params.yblen =
                 strtoul(argv[i],NULL,10);
            parsed[i] = true;
        }
        else if ( strcmp(argv[i], "-xbsep") == 0 )
        {
            parsed[i] = true;
            i++;
             enc_ctx.enc_params.xbsep =
                 strtoul(argv[i],NULL,10);
            parsed[i] = true;
        }
        else if ( strcmp(argv[i], "-ybsep") == 0 )
        {
            parsed[i] = true;
            i++;
             enc_ctx.enc_params.ybsep =
                 strtoul(argv[i],NULL,10);
            parsed[i] = true;
        }
        else if ( strcmp(argv[i], "-cpd") == 0 )
        {
            parsed[i] = true;
            i++;
             enc_ctx.enc_params.cpd =
                 strtoul(argv[i],NULL,10);
            parsed[i] = true;
        }
        else if ( strcmp(argv[i], "-use_vlc") == 0 )
        {
            parsed[i] = true;
            enc_ctx.enc_params.using_ac = false;
        }
        else if ( strcmp(argv[i], "-verbose") == 0 )
        {
            parsed[i] = true;
            verbose = true;
        }
        else if ( strcmp(argv[i], "-local") == 0 )
        {
            parsed[i] = true;
            nolocal = false;
        }
        else if ( strcmp(argv[i], "-start") == 0 )
        {
            parsed[i] = true;
            i++;
            start_pos = strtoul(argv[i],NULL,10);
            parsed[i] = true;
        }
        else if ( strcmp(argv[i], "-stop") == 0 )
        {
            parsed[i] = true;
            i++;
            end_pos = strtoul(argv[i],NULL,10);
            parsed[i] = true;
        }
        else if ( strcmp(argv[i], "-multi_quants") == 0 )
        {
            parsed[i] = true;
            enc_ctx.enc_params.multi_quants = true;
        }
        else if ( strcmp(argv[i], "-no_spartition") == 0 )
        {
            parsed[i] = true;
            enc_ctx.enc_params.spatial_partition = false;
        }
        else if ( strcmp(argv[i], "-prefilter") == 0 )
        {
            parsed[i] = true;
            i++;
            if(strcmp(argv[i], "DIAGLP")==0)
            {
                parsed[i] = true;
                enc_ctx.enc_params.prefilter = DIAGLP;
                i++;
                enc_ctx.enc_params.prefilter_strength =
                strtoul(argv[i],NULL,10);
                parsed[i] = true;
            }
            else if(strcmp(argv[i], "RECTLP")==0)
            {
                parsed[i] = true;
                enc_ctx.enc_params.prefilter = RECTLP;
                i++;
                enc_ctx.enc_params.prefilter_strength =
                strtoul(argv[i],NULL,10);
                parsed[i] = true;
            }
            else if(strcmp(argv[i], "CWM")==0)
            {
                parsed[i] = true;
                enc_ctx.enc_params.prefilter = CWM;
                i++;
                enc_ctx.enc_params.prefilter_strength =
                strtoul(argv[i],NULL,10);
                parsed[i] = true;
            }
            else if(strcmp(argv[i], "NO_PF")==0)
            {
                parsed[i] = true;
                enc_ctx.enc_params.prefilter = NO_PF;
                i++;
                enc_ctx.enc_params.prefilter_strength =
                strtoul(argv[i],NULL,10);
                parsed[i] = true;
            }
        }
        else if ( strcmp(argv[i], "-wlt_depth") == 0 )
        {
            parsed[i] = true;
            i++;
            enc_ctx.enc_params.wlt_depth = strtoul(argv[i],NULL,10);
#if defined(HAVE_MMX)
            if(enc_ctx.enc_params.wlt_depth > 4)
                cerr << "Exceeds maximum transform depth ";
           else
                parsed[i] = true;
#else
           parsed[i] = true;
#endif
        }
        else if ( strcmp(argv[i], "-iwlt_filter") == 0 )
        {
            parsed[i] = true;
            i++;
            WltFilter wf = StringToTransformFilter(string(argv[i]));
            if (wf == filterNK)
                cerr << "Unrecognised Intra Wavelet Filter " << argv[i];
            else
                parsed[i] = true;
            enc_ctx.enc_params.intra_wlt_filter = wf;
        }
        else if ( strcmp(argv[i], "-rwlt_filter") == 0 )
        {
            parsed[i] = true;
            i++;
            WltFilter wf = StringToTransformFilter(argv[i]);
            if (wf == filterNK)
                cerr << "Unrecognised Intra Wavelet Filter " << argv[i];
            else
                parsed[i] = true;
            enc_ctx.enc_params.inter_wlt_filter = wf;
        }
        else if ( strcmp(argv[i], "-mv_prec") == 0 )
        {
            parsed[i]=true;
            ++i;
            if(strcmp(argv[i], "1/2")==0)
            {
                parsed[i] = true;
                enc_ctx.enc_params.mv_precision = MV_PRECISION_HALF_PIXEL;
            }
            else if(strcmp(argv[i], "1/4")==0)
            {
                parsed[i] = true;
                enc_ctx.enc_params.mv_precision = MV_PRECISION_QUARTER_PIXEL;
            }
            else if(strcmp(argv[i], "1/8")==0)
            {
                parsed[i] = true;
                enc_ctx.enc_params.mv_precision = MV_PRECISION_EIGHTH_PIXEL;
            }
            else if(strncmp(argv[i], "1", 3)==0)
            {
                parsed[i] = true;
                enc_ctx.enc_params.mv_precision = MV_PRECISION_PIXEL;
            }
        }
        i++;
    }//opt

    // FIXME: currently only supporting vlc coding for iframe-only
    // sequences
    if (enc_ctx.enc_params.num_L1 != 0 && enc_ctx.enc_params.using_ac == 0)
    {
        std::cerr<<std::endl<<"Entropy coding of coefficient data using VLC currently enabled for i-frame only sequences only"<<std::endl;
        return false;
    }

    // check we have parsed everything
    bool all_parsed = true;
    for (int i=0 ; i<argc-2 ; ++i)
    {
        if ( !parsed[i] )
        {
            all_parsed = false;
            std::cerr<<std::endl<<"Unknown option "<<argv[i];
        }
    }
    if ( !all_parsed )
    {
        display_help();
        return false;
    }

    /* check that we have been suplied with input and output files */
    if(argc < 2 || parsed[argc-2] || parsed[argc-1]) {
        display_help();
        std::cerr<<std::endl<<"Insufficient arguments"<<std::endl;
        return false;
    }


    delete[] parsed;

    return true;
}

int main (int argc, char* argv[])
{
    // the variables we'll read parameters into
    dirac_encoder_context_t enc_ctx;

    if (!parse_command_line(enc_ctx, argc, argv))
        return EXIT_FAILURE;

    //output name for the bitstream
    string input,output;

    /*********************************************************************************/

    // last two arguments must be file names
    if (argv[argc-1][0] == '-')
    {
        display_help();
        exit(1);
    }

    if (argv[argc-2][0] == '-')
        input = "/dev/stdin";
    else
        input = argv[argc-2];

    output=argv[argc-1];

    //check we have real inputs
    if ((input.length() == 0) || (output.length() ==0))
    {
        display_help();
        exit(1);
    }


    if ( input==output )
    {
        std::cerr << "Input and output file names must be different" << std::endl;
        exit(1);
    }

    if ( verbose )
        display_codec_params(enc_ctx);



  /********************************************************************/
    //next do picture file stuff

    // Open uncompressed data file
    std::string input_name_yuv = input;
    std::ifstream
       ip_pic_ptr (input_name_yuv.c_str(), std::ios::in | std::ios::binary);
    if (!ip_pic_ptr)
    {
        std::cerr << std::endl <<
            "Can't open input data file: " << input_name_yuv << std::endl;
        return EXIT_FAILURE;
    }



   /********************************************************************/
    //open the bitstream file
     std::ofstream outfile(output.c_str(),std::ios::out | std::ios::binary);    //bitstream output

    // open the decoded ouput file
    std::ofstream *outyuv = NULL, *outimt = NULL;

    if (nolocal == false)
    {
        std::string output_name_yuv = output + ".localdec.yuv";
        std::string output_name_imt = output + ".imt";

        outyuv = new std::ofstream(output_name_yuv.c_str(),std::ios::out | std::ios::binary);

      // open the diagnostics ouput file
        outimt = new std::ofstream(output_name_imt.c_str(),std::ios::out | std::ios::binary);
    }

   /********************************************************************/
    //do the work!!

    // Determine buffer size
    int frame_size = GetFrameBufferSize (enc_ctx);
    unsigned char *frame_buf = new unsigned char [frame_size];

    if ( end_pos == -1 )
        end_pos = INT_MAX;

    /* don't try and skip frames if they aren't any to skip, eg
     * this won't work on nonseekable filehandles. */
    if (start_pos && !Skip( ip_pic_ptr, start_pos, frame_size ))
    {
        return EXIT_FAILURE;
    };

    dirac_encoder_t  *encoder;

    if (nolocal)
    {
        enc_ctx.decode_flag = 0;
        enc_ctx.instr_flag = 0;
    }
    else
    {
        enc_ctx.decode_flag = 1;
        enc_ctx.instr_flag = 1;
    }

    encoder = dirac_encoder_init( &enc_ctx, verbose );

    if (!encoder)
    {
        std::cerr << "Unrecoverable Error: dirac_encoder_init failed. "
                  << std::endl;
        return EXIT_FAILURE;
    }


    if (outimt)
       WriteDiagnosticsHeader ( *outimt, encoder );


    int frames_loaded = 0;
    dirac_encoder_state_t state;

    clock_t start_t, stop_t;
    start_t = clock();

    bool go = true;
    do
    {
        if (frames_loaded <= (end_pos - start_pos) &&
            ReadPicData( ip_pic_ptr, frame_buf, frame_size ) == true)
        {
            if (dirac_encoder_load( encoder, frame_buf, frame_size ) < 0)
            {
                std::cerr << "dirac_encoder_load failed: Unrecoverable Encoder Error. Quitting..."
                          << std::endl;
                return EXIT_FAILURE;
            }
            frames_loaded++;
        }
        else
        {
           // push end of stream
           dirac_encoder_end_sequence( encoder );
        }
        do
        {
            encoder->enc_buf.buffer = video_buf;
            encoder->enc_buf.size = VIDEO_BUFFER_SIZE;
            state = dirac_encoder_output ( encoder );
            switch (state)
            {
            case ENC_STATE_AVAIL:
                assert (encoder->enc_buf.size > 0);

                outfile.write((char *)encoder->enc_buf.buffer,
                              encoder->enc_buf.size);
                break;

            case ENC_STATE_BUFFER:
                break;
            case ENC_STATE_EOS:
                outfile.write((char *)encoder->enc_buf.buffer,
                encoder->enc_buf.size);
                go = false;
                break;
            case ENC_STATE_INVALID:
                std::cerr << "Invalid state. Unrecoverable Encoder Error. Quitting..."
                          << std::endl;
                return EXIT_FAILURE;
            default:
                std::cerr << "Unknown Encoder state" << endl;
                break;
            }

            WritePicData (*outyuv, encoder);
            WriteDiagnosticsData (*outimt, encoder);

        } while (state == ENC_STATE_AVAIL);

    } while (go);

    stop_t = clock();

    if ( verbose )
        std::cout << "The resulting bit-rate at "
                  << (double)encoder->enc_ctx.src_params.frame_rate.numerator/
                     encoder->enc_ctx.src_params.frame_rate.denominator
                  << "Hz is " << encoder->enc_seqstats.bit_rate
                  << " bits/sec." << std::endl;

    if ( verbose )
        std::cout<<"Time per frame: "<<
           (double)(stop_t-start_t)/(double)(CLOCKS_PER_SEC*frames_loaded);
        std::cout<<std::endl<<std::endl;

   /********************************************************************/

     // close the encoder
    dirac_encoder_close( encoder );
     // close the bitstream file
    outfile.close();
     // close the decoded output file
    if (outyuv)
    {
        outyuv->close();
        delete outyuv;
    }

     // close the decoded output header file
     if (outimt)
     {
        outimt->close();
        delete outimt;
     }
    // close the pic data file
    ip_pic_ptr.close();

    // delete frame buffer
    delete [] frame_buf;

    return EXIT_SUCCESS;


}
