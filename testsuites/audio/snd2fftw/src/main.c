/*
   main.c
   */

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <math.h>
#include <sndfile.h>
#include <fftw3.h>
#include "getopt.h"

static const char APP_OPTS[] = "?hc:vi:o:s:n:w3l";
static const sf_count_t FRAMES_PER_BLOCK = 1000;
static const sf_count_t DEF_WINDOW_SIZE = 256;

// error descriptions
static const char ERR_NO_INPUT_FILE[] = "Input file missing.\n";
static const char ERR_W_AND_3_TOGETHER[] = "Options -w and -3 are exclusive.\n";
static const char ERR_BAD_CHANNEL_NUMBER[] = "Bad channel number: %d.\n";
static const char ERR_BAD_SEEK[] = "Seek out of file.\n";
static const char ERR_CANNOT_SEEK[] = "Unable to seek to given position.\n";
static const char ERR_NOT_ENOUGH_MEMORY[] = "Unable to allocate memory.\n";
static const char ERR_WHILE_READING_DATA[] = "Error while reading audio data.\n";
static const char ERR_FAIL_TO_INITIALIZE_PLAN[] = "Fail to initialize FFTW plan.\n";
static const char ERR_CANNOT_OPEN_OUTPUT_FILE[] = "Fail to open output file.\n";

static void about( void )
{
    fprintf( stderr, "snd2fftw v0.3 by roed@onet.\n\n" );
    fprintf( stderr, "This tool reads audio file as array of real numbers an computes DFT on it.\n" );
    fprintf( stderr, "Additionaly audio samples may be dumped.\n" );
    fprintf( stderr, "Text stream produced by this tool may be easly used with GNU Plot.\n");
    fprintf( stderr, "Usage:" );
    fprintf( stderr, "\tsnd2fftw [-v] [-w] [-3] [-l] [-s pos] [-n samples][-c channels] -i infile [-o outfile] [-h]\n\n" );
    fprintf( stderr, "-c channel\t:select channel number in multichannel audio file\n" );
    fprintf( stderr, "-i infile\t:select input file, input file must be given\n" );
    fprintf( stderr, "-o outfile\t:select output file (stdout by default)\n" );
    fprintf( stderr, "-s pos\t:seek to specified position in samples (no seek by default)\n" );
    fprintf( stderr, "-n samples\ttake specified number of samples to DFT analyze\n" );
    fprintf( stderr, "-3\t\t:split audio files to small portions and do DFT analyze on them, this produces 3D plot \n" );
    fprintf( stderr, "-w\t\t:dump audio samples, do not DFT dransform\n" );
    fprintf( stderr, "-l\t\t:generate \"locale friendly\" text stream\n" );
    fprintf( stderr, "-v\t\t:be verbose\n" );
    fprintf( stderr, "-h\t\t:prints this help\n" );
}

static void dump_audio_data(
        FILE* fOut,
        double* data,
        sf_count_t samples,
        int channel,
        int channels,
        int samplerate,
        sf_count_t total_samples )
{
    sf_count_t i;

    for( i=1; i<samples; i++ )
    {
        fprintf( fOut, "%lf\t%lf\n",
                (double)( total_samples + i ) / (double)samplerate,
                data[ i * channels + channel ] );
    }
}

static double imabs( fftw_complex cpx )
{
    return sqrt( ( cpx[0] * cpx[0] ) + ( cpx[1] * cpx[1] ) );
}

static void dump_fft_data_3(
        FILE* fOut,
        fftw_complex* data,
        sf_count_t samples,
        double samplerate,
        sf_count_t total_samples )
{
    sf_count_t i;
    sf_count_t samples2;
    double time_pos;

    samples2 = samples / 2;
    time_pos = (double)total_samples / samplerate;

    for( i=0; i<samples2; i++ )
    {
        fprintf( fOut, "%lf\t%lf\t%lf\n",
                time_pos,
                (double)i * samplerate / (double)samples,
                imabs( data[i] ) / 2.0
               );
    }
    fprintf( fOut, "\n" );
}

static void dump_fft_data(
        FILE* fOut,
        double samplerate,
        sf_count_t samples,
        fftw_complex* data )
{
    sf_count_t i;
    sf_count_t samples2;

    samples2 = samples/2;
    for( i=0; i<samples2; i++ )
    {
        fprintf( fOut, "%lf\t%lf\n",
                (double)i * samplerate / (double)samples,
                imabs( data[i] ) / 2.0
               );
    }
}

int main(int argc, char *argv[])
{
    char cOpt;
    char* pszParam;

    // input data
    int bVerbose;
    int bSamples;
    int nChannel;
    sf_count_t nSeekPosition;
    sf_count_t nDftSamples;
    int b3d;
    int bLocale;
    char* pszInputFile;
    char* pszOutputFile;

    SF_INFO info_in;
    SNDFILE* fIn;
    FILE* fOut;
    sf_count_t nRead;
    double* fftw_in;
    fftw_complex* fftw_out;
    fftw_plan snd_plan;
    sf_count_t n;

    // default values
    bVerbose = 0;
    bSamples = 0;
    nChannel = 0;
    nSeekPosition = 0;
    nDftSamples = -1;
    b3d = 0;
    bLocale = 0;
    pszInputFile = NULL;
    pszOutputFile = NULL;

    fftw_in = NULL;
    fftw_out = NULL;
    snd_plan = NULL;

    while ( cOpt = GetOption( argc, argv, APP_OPTS, &pszParam ) )
    {
        switch( cOpt )
        {
            case 'c':
                if ( pszParam ) nChannel = atoi( pszParam );
                break;

            case 'i':
                if ( pszParam ) pszInputFile = pszParam;
                break;

            case 'o':
                if ( pszParam ) pszOutputFile = pszParam;
                break;

            case 'v':
                bVerbose = 1;
                break;

            case 'w':
                bSamples = 1;
                break;

            case 's':
                //vivi del if ( pszParam ) nSeekPosition = _atoi64( pszParam );
                if ( pszParam ) nSeekPosition = atoi( pszParam );
                break;

            case 'n':
                //vivi del if ( pszParam ) nDftSamples = _atoi64( pszParam );
                if ( pszParam ) nDftSamples = atoi( pszParam );
                break;

            case '3':
                b3d = 1;
                break;

            case 'l':
                bLocale = 1;
                break;

            case '?':
            case 'h':
                about();
                exit(0);
                break;

            default:
                fprintf( stderr, "Bad options.\n" );
                exit(1);
                break;
        }
    }

    /*vivi del
      if ( bLocale )
      { // default OEM locale
      setlocale( LC_ALL, ".OCP" );
      }
      */

    //veryfying input data
    if ( pszInputFile == NULL ) {
        fprintf( stderr, ERR_NO_INPUT_FILE );
        return 1;
    }

    if ( b3d && bSamples ) {
        fprintf( stderr, ERR_W_AND_3_TOGETHER );
        return 1;
    }

    fIn = sf_open( pszInputFile, SFM_READ, &info_in );
    if ( !fIn ) {
        fprintf( stderr, "Unable to open input file \"%s\".\n", pszInputFile );
        sf_error( NULL );
        return 1;
    }

    if ( bVerbose )
    {
        SF_FORMAT_INFO format_info;

        fprintf( stderr, "File: %s\n", pszInputFile );

        format_info.format = info_in.format ;
        sf_command( fIn, SFC_GET_FORMAT_INFO, &format_info, sizeof(format_info) );
        fprintf( stderr, "Format: %d - %s\n",
                format_info.format, format_info.name);
        fprintf( stderr, "Sample rate: %d\n", info_in.samplerate );
        fprintf( stderr, "Channels: %d\n", info_in.channels );
        fprintf( stderr, "Samples: %ld\n", info_in.frames );
    }

    if ( (nChannel<0) || (nChannel >= info_in.channels) )
    {
        fprintf( stderr, ERR_BAD_CHANNEL_NUMBER, nChannel );
        sf_close( fIn );
        return 1;
    }

    if ( nSeekPosition >= info_in.frames )
    {
        fprintf( stderr, ERR_BAD_SEEK );
        sf_close( fIn );
        return 1;
    }

    n = sf_seek( fIn, nSeekPosition, SEEK_SET );
    if ( n == -1 )
    {
        fprintf( stderr, ERR_CANNOT_SEEK, nSeekPosition );
        sf_error( fIn );
        sf_close( fIn );
        return 1;
    }

    if ( b3d )
    {
        if ( ( nDftSamples == -1 ) || ( nDftSamples > (info_in.frames - n) ) )
        {
            nDftSamples = DEF_WINDOW_SIZE;
        }
    }
    else
    {
        if ( ( nDftSamples == -1 ) || ( nDftSamples > (info_in.frames - n) ) )
        {
            nDftSamples = info_in.frames - n;
        }
    }

    if ( bVerbose )
    {
        fprintf( stderr, "Taking %ld samples.\n", nDftSamples );
    }

    if ( bSamples )
    {
        double* pBuffer;
        sf_count_t nTotalRead;

        if ( bVerbose )
        {
            fprintf( stderr, "Dumping audio samples.\n" );
        }

        if ( pszOutputFile != NULL )
        {
            if ( bVerbose )
            {
                fprintf( stderr, "Opening output file.\n" );
            }
            fOut = fopen( pszOutputFile, "wt" );
            if ( !fOut )
            {
                fprintf( stderr, ERR_CANNOT_OPEN_OUTPUT_FILE, pszOutputFile );
                return 3;
            }
        }
        else
        {
            fOut = stdout;
        }

        pBuffer = malloc( sizeof(double) * info_in.channels * FRAMES_PER_BLOCK );
        if ( !pBuffer )
        {
            fprintf( stderr, ERR_NOT_ENOUGH_MEMORY );
            sf_close( fIn );
            if ( pszOutputFile != NULL )
            {
                fclose( fOut );
            }
            return 2;
        }

        nTotalRead = 0;
        do
        {
            n = ( (nDftSamples-nTotalRead) < FRAMES_PER_BLOCK )?
                (nDftSamples-nTotalRead) : FRAMES_PER_BLOCK;

            nRead = sf_readf_double( fIn, pBuffer, n );
            dump_audio_data(
                    fOut,
                    pBuffer, nRead,
                    nChannel,
                    info_in.channels, info_in.samplerate,
                    nTotalRead );
            nTotalRead += nRead;
        }
        while( n == FRAMES_PER_BLOCK );

        if ( pszOutputFile != NULL )
        {
            fclose( fOut );
        }
        free( pBuffer );

        if ( bVerbose )
        {
            fprintf( stderr, "snd2fftw done.\n" );
        }
        return 0;
    }

    if ( bVerbose )
    {
        fprintf( stderr, "Creating output buffer.\n" );
    }

    // output - complex data
    fftw_out = fftw_malloc( sizeof(fftw_complex) * nDftSamples );
    if ( !fftw_out )
    {
        fprintf( stderr, ERR_NOT_ENOUGH_MEMORY );
        sf_close( fIn );
        return 2;
    }

    if ( bVerbose )
    {
        fprintf( stderr, "Reading data from file.\n" );
    }

    fftw_in = fftw_malloc( sizeof(double) * nDftSamples * info_in.channels );
    if ( !fftw_in )
    {
        fprintf( stderr, ERR_NOT_ENOUGH_MEMORY );
        fftw_free( fftw_out );
        sf_close( fIn );
        return 2;
    }

    if ( b3d ) {
        // 3d
        sf_count_t nTotalRead;

        if ( bVerbose ) {
            fprintf( stderr, "Creating FFTW plan.\n" );
        }

        snd_plan = fftw_plan_dft_r2c_1d(
                nDftSamples,
                fftw_in, fftw_out,
                FFTW_FORWARD );

        if ( !snd_plan )
        {
            fprintf( stderr, ERR_FAIL_TO_INITIALIZE_PLAN );
            fftw_free( fftw_in );
            fftw_free( fftw_out );
            return 2;
        }

        if ( pszOutputFile != NULL )
        {
            if ( bVerbose )
            {
                fprintf( stderr, "Opening output file.\n" );
            }

            fOut = fopen( pszOutputFile, "wt" );
            if ( !fOut )
            {
                fprintf( stderr, ERR_CANNOT_OPEN_OUTPUT_FILE );
                fftw_destroy_plan( snd_plan );
                fftw_free( fftw_in );
                fftw_free( fftw_out );
                return 3;
            }
        }
        else
        {
            fOut = stdout;
        }

        nTotalRead = 0;
        do
        {
            nRead = sf_readf_double( fIn, fftw_in, nDftSamples );

            if ( info_in.channels != 0 )
            {
                for( n=0; n<nRead; n++ )
                {
                    fftw_in[n] = fftw_in[ n * info_in.channels + nChannel ];
                }
            }

            if ( nRead < nDftSamples )
            {
                if ( bVerbose )
                {
                    fprintf( stderr, "Last block have %ld samples.\n", nRead );
                }
                for( n=nRead; n<nDftSamples; n++ )
                {
                    fftw_in[n] = 0.0;
                }
            }

            if ( bVerbose )
            {
                fprintf( stderr, "Executing FFTW plan.\n" );
            }
            fftw_execute( snd_plan );

            if ( bVerbose )
            {
                fprintf( stderr, "Dumping results.\n" );
            }

            // dumping
            dump_fft_data_3( fOut,
                    fftw_out,
                    nDftSamples,
                    (double)info_in.samplerate,
                    nTotalRead );

            nTotalRead += nRead;
        }
        while( nRead == nDftSamples );

        if ( pszOutputFile != NULL ) {
            fclose( fOut );
        }

        if ( bVerbose ) {
            fprintf( stderr, "Destroying plan.\n" );
        }
        fftw_destroy_plan( snd_plan );
        fftw_free( fftw_in );
    } else {
        //2d
        nRead = sf_readf_double( fIn, fftw_in, nDftSamples );
        if ( nRead != nDftSamples )
        {
            fprintf( stderr, ERR_WHILE_READING_DATA );
            fftw_free( fftw_in );
            fftw_free( fftw_out );
            sf_close( fIn );
            return 2;
        }

        // input data
        if ( info_in.channels != 0 )
        {
            sf_count_t i;

            for( i=0; i<nDftSamples; i++ )
            {
                fftw_in[ i ] = fftw_in[ i * info_in.channels + nChannel ];
            }
        }

        if ( bVerbose )
        {
            fprintf( stderr, "Closing audio file.\n" );
        }
        sf_close( fIn );

        if ( bVerbose ) {
            fprintf( stderr, "Creating FFTW plan.\n" );
        }

        snd_plan = fftw_plan_dft_r2c_1d(
                nDftSamples,
                fftw_in, fftw_out,
                FFTW_FORWARD );

        if ( !snd_plan )
        {
            fprintf( stderr, ERR_FAIL_TO_INITIALIZE_PLAN );
            fftw_free( fftw_in );
            fftw_free( fftw_out );
            return 2;
        }

        if ( bVerbose )
        {
            fprintf( stderr, "Executing FFTW plan.\n" );
        }
        fftw_execute( snd_plan );

        if ( bVerbose )
        {
            fprintf( stderr, "Destroying plan.\n" );
        }
        fftw_destroy_plan( snd_plan );
        fftw_free( fftw_in );

        if ( bVerbose )
        {
            fprintf( stderr, "Dumping results.\n" );
        }

        if ( pszOutputFile != NULL )
        {
            if ( bVerbose )
            {
                fprintf( stderr, "Opening output file.\n" );
            }

            fOut = fopen( pszOutputFile, "wt" );
            if ( !fOut )
            {
                fprintf( stderr, ERR_CANNOT_OPEN_OUTPUT_FILE );
                fftw_free( fftw_out );
                return 3;
            }
        }
        else
        {
            fOut = stdout;
        }

        dump_fft_data(
                fOut,
                (double)info_in.samplerate,
                nDftSamples,
                fftw_out );

        if ( pszOutputFile != NULL ) {
            fclose( fOut );
        }
    }

    if ( bVerbose ) {
        fprintf( stderr, "snd2fftw done.\n" );
    }
    fftw_free( fftw_out );
    return 0;
}
