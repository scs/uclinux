/*****************************************************************************
*
* Copyright (C) 2004, Analog Devices. All Rights Reserved
*
* FILE ndso.c
* PROGRAMMER(S): Michael Hennerich (Analog Devices Inc.)
*
*
* DATE OF CREATION: Sept. 10th 2004
*
* SYNOPSIS:
*
*
* CAUTION:     you may need to change ioctl's in order to support other ADCs.
******************************************************************************
* MODIFICATION HISTORY:
* Sept 10, 2004   adsp-spiadc.c Created.
******************************************************************************
* 
* This program is free software; you can distribute it and/or modify it
* under the terms of the GNU General Public License (Version 2) as
* published by the Free Software Foundation.
*
* This program is distributed in the hope it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
* FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
* for more details.
*
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 59 Temple Place - Suite 330, Boston MA 02111-1307, USA.
*
*****************************************************************************/

#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#ifdef TM_IN_SYS_TIME
#include <sys/time.h>
#else
#include <time.h>
#endif

#include "adsp-spiadc.h"
#include "cgivars.h"
#include "htmllib.h"
#include "ndso.h"
#include "dac.h"

static s_info sinfo;

void display_on_framebuffer(s_info *info)
{
	if (!info->framebuffer)
		return;

	if (vfork() == 0) {
		char img[256];
		snprintf(img, sizeof(img), "/home/httpd/img%s.png", info->pREMOTE_ADDR);
		execlp("pngview", "pngview", "-q", img, NULL);
		printf("<br>Hmm, could not run pngview, that's odd ...<br>\n");
		_exit(-1);
	}
}

int
main ()
{
  char **postvars = NULL;	/* POST request data repository */
  char **getvars = NULL;	/* GET request data repository */
  int form_method;		/* POST = 1, GET = 0 */

  s_info *info = &sinfo;

  form_method = getRequestMethod ();


  if (form_method == POST)
    {
      getvars = getGETvars ();
      postvars = getPOSTvars ();
    }
  else if (form_method == GET)
    {
      getvars = getGETvars ();
    }

  MakeSessionFiles (info);

  ParseRequest (form_method, getvars, postvars, info);

  CheckRequest (form_method, getvars, postvars, info);

  switch (info->run)
    {

    case ACQUIRE:
      AllocateMemory (form_method, getvars, postvars, info);
      Sample (form_method, getvars, postvars, info);
      MakeFileInit (form_method, getvars, postvars, info);
      if (info->sdisplay.tdom)
	{
	  MakeFileSamples (form_method, getvars, postvars, info);
	}
      else
	{
	  MakeFileFrequencySamples (form_method, getvars, postvars, info);
	}
      system (info->pGNUPLOT);
      DoHTML (form_method, getvars, postvars, info);
      free (info->samples);
      display_on_framebuffer(info);
      break;

    case REPLOT:
      MakeFileInit (form_method, getvars, postvars, info);
      system (info->pGNUPLOT);
      DoHTML (form_method, getvars, postvars, info);
      display_on_framebuffer(info);
      break;

    case MULTIMETER:
      info->stime_s.samples = 20;
      AllocateMemory (form_method, getvars, postvars, info);
      Sample (form_method, getvars, postvars, info);
      DoHTML (form_method, getvars, postvars, info);
      free (info->samples);
      break;

    case SHOWSAMPLES:
      AllocateMemory (form_method, getvars, postvars, info);
      Sample (form_method, getvars, postvars, info);
      DoHTML (form_method, getvars, postvars, info);
      free (info->samples);
      break;

    case GNUPLOT_FILES:
      DoHTML (form_method, getvars, postvars, info);
      break;

    default:

      break;
    }

  CleanupSessionFiles (info);
  exit (0);
}


int
Sample (int form_method, char **getvars, char **postvars, s_info * info)
{

  int errval, baud, sclk;


//        info->fd0 = open("/dev/spi",O_RDONLY);
  info->fd0 = open ("/dev/spi", O_RDWR);

  if (info->fd0 < 0)
    {
      NDSO_Error (SPIOPEN, form_method, getvars, postvars, info);
    }

  ioctl (info->fd0, CMD_SPI_GET_SYSTEMCLOCK, &sclk);

  /* Calculate required Baud Rate */
  baud = (unsigned short) (sclk / (34 * info->stime_s.sps));
  ioctl (info->fd0, CMD_SPI_SET_BAUDRATE, baud);	// Set baud rate SCK = HCLK/(2*SPIBAUD)
  /* Calculate real Baud Rate */
  info->stime_s.sps = sclk / ((2 * 16 + 2) * baud);

  ioctl (info->fd0, CMD_SPI_SET_TRIGGER_MODE, info->strigger.mode);
  ioctl (info->fd0, CMD_SPI_SET_TRIGGER_SENSE, info->strigger.sense);
  ioctl (info->fd0, CMD_SPI_SET_TRIGGER_EDGE, info->strigger.edge);
  ioctl (info->fd0, CMD_SPI_SET_SKFS, 2);

  ioctl (info->fd0, CMD_SPI_SET_TRIGGER_LEVEL,
	 (unsigned short) VoltageToSample (info->strigger.level, info));

  errval = read (info->fd0, info->samples, (info->stime_s.samples * 2));

  close (info->fd0);

  if (errval < 0)
    NDSO_Error (TRIGCOND, form_method, getvars, postvars, info);

  return 0;
}

int
DoHTML (int form_method, char **getvars, char **postvars, s_info * info)
{


  switch (info->run)
    {
    case ACQUIRE:
      htmlHeader ("NDSO Demo Web Page");
      htmlBody ();
      printf ("\n<img border=\"0\" src=\"/img%s.png?id=%s\" align=\"left\">\n",
	      info->pREMOTE_ADDR, itostr (getrand (6), 6, 1, 1));

      if ((info->smeasurements.min || info->smeasurements.max
	   || info->smeasurements.mean) && info->sdisplay.tdom)
	{

	  DoMeasurements (info);

	  if (info->smeasurements.min)
	    printf
	      ("<p style=\"margin-top: 0; margin-bottom: 0\"><font face=\"Courier new\"> Min&nbsp;:%4.3fV</font></p>\n",
	       ((float) info->smeasurements.valuemin) / 1000);
	  if (info->smeasurements.max)
	    printf
	      ("<p style=\"margin-top: 0; margin-bottom: 0\"><font face=\"Courier new\"> Max&nbsp;:%4.3fV</font></p>\n",
	       ((float) info->smeasurements.valuemax) / 1000);
	  if (info->smeasurements.mean)
	    printf
	      ("<p style=\"margin-top: 0; margin-bottom: 0\"><font face=\"Courier new\"> Mean:%4.3fV</font></p>\n",
	       ((float) info->smeasurements.valuemean) / 1000);
	  printf
	    ("<p style=\"margin-top: 0; margin-bottom: 0\"><font face=\"Courier new\"> ______________</font></p>\n");

	}
      break;
    case REPLOT:
      htmlHeader ("NDSO Demo Web Page");
      htmlBody ();
      printf ("\n<img border=\"0\" src=\"/img%s.png?id=%s\" align=\"left\">\n",
	      info->pREMOTE_ADDR, itostr (getrand (6), 6, 1, 1));
      break;
    case MULTIMETER:
      DoDM_HTML_Page (form_method, getvars, postvars, info);
      break;
    case SHOWSAMPLES:
      htmlHeader ("NDSO Demo Web Page");
      htmlBody ();
      PrintSamples (info);
    case GNUPLOT_FILES:
      htmlHeader ("NDSO Demo Web Page");
      htmlBody ();
      DoFiles(info);
      break;
    default:

      break;
    }
  htmlFooter ();
  cleanUp (form_method, getvars, postvars);

  fflush (stdout);

  return 0;
}

int
PrintSamples (s_info * info)
{

  unsigned short number = 0, found = 0, i;
  unsigned short *samples = info->samples;

  printf
    ("<p style=\"margin-top: 0; margin-bottom: 0\"><font face=\"Courier new\">&nbsp;&nbsp;C/C++ Array&nbsp Declaration;  </font></p>\n");
  printf
    ("<p style=\"margin-top: 0; margin-bottom: 0\"><font face=\"Courier new\"> unsigned&nbsp;short&nbsp;samples[%d]&nbsp;=&nbsp;\n{<p style=\"margin-top: 0; margin-bottom: 0\">",
     info->stime_s.samples);

  for (i = 0; i < info->stime_s.samples - 1;)
    {
      found = number / 50;

      number += printf ("%d,", samples[i++]);
      if ((number / 50) > found)
	printf ("<p style=\"margin-top: 0; margin-bottom: 0\">\n");

    }

  printf ("%d}</font></p>\n", samples[i]);
  printf
    ("<p></p>\n<p></p>\n<p style=\"margin-top: 0; margin-bottom: 0\"><font face=\"Courier new\">&nbsp;&nbsp;MATLAB Array&nbsp Declaration;  </font></p>\n");
  printf
    ("<p style=\"margin-top: 0; margin-bottom: 0\"><font face=\"Courier new\">samples&nbsp;=&nbsp;%d\n[<p style=\"margin-top: 0; margin-bottom: 0\">",
     info->stime_s.samples);

  found = 0;
  number = 0;

  for (i = 0; i < info->stime_s.samples - 1;)
    {
      found = number / 40;

      number += printf ("%d&nbsp;", samples[i++]) - 6;
      if ((number / 40) > found)
	printf ("<p style=\"margin-top: 0; margin-bottom: 0\">\n");

    }
  printf ("%d]</font></p>\n", samples[i]);

  return 0;
}

int
NDSO_Error (int errnum, int form_method, char **getvars, char **postvars,
	    s_info * info)
{

  htmlHeader ("NDSO Demo Web Page");
  htmlBody ();

  switch (errnum)
    {

    case SPIOPEN:
      printf ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
	      SPIOPEN);
      printf
	("<p><font face=\"Tahoma\" size=\"7\">Can't open /dev/spi.\n</font></p>");
      printf
	("<p><font face=\"Tahoma\" size=\"7\">- Try again later -\n</font></p>");
      free (info->samples);
      break;
    case FILE_OPEN:
      printf ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
	      FILE_OPEN);
      printf
	("<p><font face=\"Tahoma\" size=\"7\">Can't open FILE.\n</font></p>");
      free (info->samples);
      break;
    case MEMORY:
      printf ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
	      MEMORY);
      printf
	("<p><font face=\"Tahoma\" size=\"7\">Memory allocation error.\n</font></p>");
      free (info->samples);
      break;
    case TRIGCOND:
      printf ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
	      TRIGCOND);
      printf
	("<p><font face=\"Tahoma\" size=\"7\">No Trigger Condition Found.\n</font></p>");
      printf
	("<p><font face=\"Tahoma\" size=\"7\">- Time Out -\n</font></p>");
      free (info->samples);
      break;
    case TRIGGER_LEVEL:
      printf ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
	      TRIGGER_LEVEL);
      printf
	("<p><font face=\"Tahoma\" size=\"7\">Trigger Level outside specified range: [%d] < Level < [%d] \n</font></p>",
	 (short) SampleToVoltage (0, info),
	 (short) SampleToVoltage (GetMaxSampleValue (info), info));
      break;
    case SAMPLE_RATE:
      printf ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
	      SAMPLE_RATE);
      printf
	("<p><font face=\"Tahoma\" size=\"7\">Sample Rate outside specified range: [%d] < Rate < [%d] \n</font></p>",
	 MINSAMPLERATE,
	 hw_device_table[info->sinput.type][MAX_SAMPLERATE].arg);
      break;
    case SAMPLE_DEPTH:
      printf ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
	      SAMPLE_DEPTH);
      printf
	("<p><font face=\"Tahoma\" size=\"7\">Sample Depth outside specified range: [%d] < Depth < [%d] \n</font></p>",
	 MINNUMSAMPLES, MAXNUMSAMPLES);
      break;
    case SIZE_RATIO:
      printf ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
	      SIZE_RATIO);
      printf
	("<p><font face=\"Tahoma\" size=\"7\">Size Ratio contains invalid characters r exceeds maximum Size Ratio < [%d]\n</font></p>",MAXSIZERATIO);
      break;
    case RANGE:
      printf ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
	      RANGE);
      printf
	("<p><font face=\"Tahoma\" size=\"7\">Specified Range is invalid or out of range.\n</font></p>");
      break;
    case FILE_OPEN_SAMPLES:
      printf ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
	      FILE_OPEN_SAMPLES);
      printf
	("<p><font face=\"Tahoma\" size=\"7\">Can't open SAMPLE FILE for REPLOT.\n</font></p>");
      break;
    case EMPTY_PLOT:
      printf ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
	      EMPTY_PLOT);
      printf
	("<p><font face=\"Tahoma\" size=\"7\">Empty Plot increase upper Range.\n</font></p>");
      break;
    case TIME_OUT:
      printf ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
	      TIME_OUT);
      printf
	("<p><font face=\"Tahoma\" size=\"7\">Ratio between Sample Depth and Sample Rate will exceed Timeout criteria [%d sec].\n</font></p>", TIMEOUT);
      break;
    default:
      printf
	("<p><font face=\"Tahoma\" size=\"7\">ERROR[UNDEF]:\n</font></p>");
      printf
	("<p><font face=\"Tahoma\" size=\"7\">undefined ERROR: \n</font></p>");
      break;
    }

  htmlFooter ();
  cleanUp (form_method, getvars, postvars);
  CleanupSessionFiles (info);
  fflush (stdout);

  exit (1);
};


int
AllocateMemory (int form_method, char **getvars, char **postvars,
		s_info * info)
{

  info->samples = malloc (info->stime_s.samples * 2);

  if (info->samples == NULL)
    {
      NDSO_Error (MEMORY, form_method, getvars, postvars, info);
    }

  return 0;

}

int
ParseRequest (int form_method, char **getvars, char **postvars, s_info * info)
{

  int i;

  /*Preset checkbox settings */
  info->sdisplay.set_grid = 0;
  info->sdisplay.axis = 0;
  info->smeasurements.min = 0;
  info->smeasurements.max = 0;
  info->smeasurements.mean = 0;
  info->sdisplay.fftexludezero = 0;
  info->sdisplay.fftscaled = 0;
  info->framebuffer = 0;


  if (form_method == POST)
    {


      /* Parse Request */
      for (i = 0; postvars[i]; i += 2)
	{

	  if (strncmp (postvars[i], "D3", 2) == 0)
	    {
	      info->strigger.mode = str2num (postvars[i + 1]);
	    }
	  else if (strncmp (postvars[i], "D1", 2) == 0)
	    {
	      info->strigger.sense = str2num (postvars[i + 1]);
	    }
	  else if (strncmp (postvars[i], "R1", 2) == 0)
	    {
	      info->strigger.edge = str2num (postvars[i + 1]);
	    }
	  else if (strncmp (postvars[i], "T1", 2) == 0)
	    {
	      info->strigger.level = (short) str2num (postvars[i + 1]);
	    }
	  else if (strncmp (postvars[i], "D5", 2) == 0)
	    {
	      info->svertical.vdiv = i + 1;
	    }
	  else if (strncmp (postvars[i], "T2", 2) == 0)
	    {
	      info->stime_s.sps = str2num (postvars[i + 1]);
	    }
	  else if (strncmp (postvars[i], "T3", 2) == 0)
	    {
	      info->stime_s.samples = str2num (postvars[i + 1]);
	    }
	  else if (strncmp (postvars[i], "D8", 2) == 0)
	    {
	      info->stime_s.fsamples = str2num (postvars[i + 1]);
	    }
	  else if (strncmp (postvars[i], "set_grid", 8) == 0)
	    {
	      info->sdisplay.set_grid = 1;
	    }
	  else if (strncmp (postvars[i], "axis", 4) == 0)
	    {
	      info->sdisplay.axis = 1;
	    }
	  else if (strncmp (postvars[i], "linestyle", 9) == 0)
	    {
	      info->sdisplay.style = i + 1;
	    }
	  else if (strncmp (postvars[i], "color", 5) == 0)
	    {
	      info->sdisplay.color = i + 1;
	    }
	  else if (strncmp (postvars[i], "xrangeS", 7) == 0)
	    {
	      info->sdisplay.xrange = i + 1;
	    }
	  else if (strncmp (postvars[i], "xrangeE", 7) == 0)
	    {
	      info->sdisplay.xrange1 = i + 1;
	    }
	  else if (strncmp (postvars[i], "logscale", 8) == 0)
	    {
	      info->sdisplay.logscale = i + 1;
	    }
	  else if (strncmp (postvars[i], "size_ratio", 10) == 0)
	    {
	      info->sdisplay.size_ratio = i + 1;
	    }
	  else if (strncmp (postvars[i], "smooth", 6) == 0)
	    {
	      info->sdisplay.smooth = i + 1;
	    }
	  else if (strncmp (postvars[i], "C7", 2) == 0)
	    {
	      info->sdisplay.fftexludezero = 1;
	    }
	  else if (strncmp (postvars[i], "C8", 2) == 0)
	    {
	      info->sdisplay.fftscaled = 1;
	    }
	  else if (strncmp (postvars[i], "R3", 2) == 0)
	    {
	      info->sdisplay.tdom = str2num (postvars[i + 1]);
	    }
	  else if (strncmp (postvars[i], "C4", 2) == 0)
	    {
	      info->smeasurements.min = 1;
	    }
	  else if (strncmp (postvars[i], "C5", 2) == 0)
	    {
	      info->smeasurements.max = 1;
	    }
	  else if (strncmp (postvars[i], "C6", 2) == 0)
	    {
	      info->smeasurements.mean = 1;
	    }
	  else if (strncmp (postvars[i], "R2", 2) == 0)
	    {
	      info->sinput.mode = str2num (postvars[i + 1]);
	    }
	  else if (strncmp (postvars[i], "D9", 2) == 0)
	    {
	      info->sinput.type = str2num (postvars[i + 1]);
	    }
	  else if (strncmp (postvars[i], "B1", 2) == 0)
	    {
	      info->run = ACQUIRE;
	    }
	  else if (strncmp (postvars[i], "B5", 2) == 0)
	    {
	      info->run = REPLOT;
	    }
	  else if (strncmp (postvars[i], "B4", 2) == 0)
	    {
	      info->run = SHOWSAMPLES;
	    }
	  else if (strncmp (postvars[i], "B6", 2) == 0)
	    {
	      info->run = GNUPLOT_FILES;
	    }
	  else if (strncmp (postvars[i], "B3", 2) == 0)
	    {
	      info->run = MULTIMETER;
	    }
	  else if (strncmp (postvars[i], "FB", 2) == 0)
	    {
	      info->framebuffer = str2num (postvars[i + 1]);
	    }

	}

    }

  if (!info->sdisplay.tdom)
    info->stime_s.samples = 1 << info->stime_s.fsamples;
  return 0;
};




int
CheckRequest (int form_method, char **getvars, char **postvars, s_info * info)
{


  if (info->strigger.level >
      (short) SampleToVoltage (GetMaxSampleValue (info), info)
      || info->strigger.level < (short) SampleToVoltage (0, info))
    NDSO_Error (TRIGGER_LEVEL, form_method, getvars, postvars, info);

  if (info->stime_s.sps >
      (hw_device_table[info->sinput.type][MAX_SAMPLERATE].arg)
      || (info->stime_s.sps <= MINSAMPLERATE))
    NDSO_Error (SAMPLE_RATE, form_method, getvars, postvars, info);

  if (info->stime_s.samples > MAXNUMSAMPLES
      || info->stime_s.samples <= MINNUMSAMPLES)
    NDSO_Error (SAMPLE_DEPTH, form_method, getvars, postvars, info);

  if ((info->stime_s.samples/info->stime_s.sps) > TIMEOUT)
    NDSO_Error (TIME_OUT, form_method, getvars, postvars, info);

  if(atof(postvars[info->sdisplay.size_ratio]) <= 0 
    || atof(postvars[info->sdisplay.size_ratio]) >= MAXSIZERATIO)
      NDSO_Error (SIZE_RATIO, form_method, getvars, postvars, info);

  if (!info->sdisplay.tdom)
    if (info->sdisplay.fftscaled)
      if (!(postvars[info->sdisplay.xrange][0] == '*' &&
        postvars[info->sdisplay.xrange1][0] == '*'))
          if((info->stime_s.sps / info->stime_s.samples) > 
            str2num (postvars[info->sdisplay.xrange1]))
              NDSO_Error (EMPTY_PLOT, form_method, getvars, postvars, info);

  if (str2num (postvars[info->sdisplay.xrange]) < 0)
    NDSO_Error (RANGE, form_method, getvars, postvars, info);

  if (str2num (postvars[info->sdisplay.xrange1]) < 0)
    NDSO_Error (RANGE, form_method, getvars, postvars, info);

  if (!(postvars[info->sdisplay.xrange][0] == '*' &&
    postvars[info->sdisplay.xrange1][0] == '*'))
    if (atof(postvars[info->sdisplay.xrange1]) <= 
      atof(postvars[info->sdisplay.xrange])) 
        NDSO_Error (RANGE, form_method, getvars, postvars, info);

  if (info->run == REPLOT)
    {
      switch (info->sdisplay.tdom)
	{
	case FREQ_DOM:

	  info->pFile_fsamples = fopen (info->pFILENAME_F_OUT, "r");

	  if (info->pFile_fsamples == NULL)
	    {
	      NDSO_Error (FILE_OPEN_SAMPLES, form_method, getvars, postvars,
			  info);
	    }

	  fclose (info->pFile_fsamples);
	  break;

	case TIME_DOM:
	  info->pFile_samples = fopen (info->pFILENAME_T_OUT, "r");

	  if (info->pFile_samples == NULL)
	    {
	      NDSO_Error (FILE_OPEN_SAMPLES, form_method, getvars, postvars,
			  info);
	    }
	  fclose (info->pFile_samples);
	  break;

	default:
	  break;
	}
    }

  return 0;
}

int
MakeFileSamples (int form_method, char **getvars, char **postvars,
		 s_info * info)
{

  int i, res, ref;
  float time, value, modi;
  unsigned short *samples = info->samples;

  /* calculate modifier */

  time = 0;
  modi = 1000 / (float) info->stime_s.sps;
  res = hw_device_table[info->sinput.type][DAC_RESOLUTION].arg;
  ref = hw_device_table[info->sinput.type][REF_VOLTAGE].arg;
  /* open file for write */

  info->pFile_samples = fopen (info->pFILENAME_T_OUT, "w");

  if (info->pFile_samples == NULL)
    {
      NDSO_Error (FILE_OPEN, form_method, getvars, postvars, info);
    }

  /* print header information */

  fprintf (info->pFile_samples,
	   "# File Samples generated by NDSO t : U(t)\n");
  fprintf (info->pFile_samples, "# res = %d ref = %d \n", res, ref);

  /* print samples */

  for (i = 0; i < info->stime_s.samples; i++)
    {

      if (info->sinput.mode)
	value = (float) samples[i] * ref / (1000 * res);
      else
	value = (float) (samples[i] - (res / 2)) * ref / (1000 * res);

      fprintf (info->pFile_samples, "%f %f\n", time, value);
      time += modi;
    }

  /* close file */

  fclose (info->pFile_samples);

  return 0;

}

int
MakeFileFrequencySamples (int form_method, char **getvars, char **postvars,
			  s_info * info)
{

  int i;
  short *real = info->samples;
  short *imag;
  /* calculate modifier */


  /* Alocate memory for the imaginary part */

  imag = malloc (info->stime_s.samples * 2);

  if (imag == NULL)
    {
      NDSO_Error (MEMORY, form_method, getvars, postvars, info);
    }


  /* Zero out imag and scale real */

  for (i = 0; i < info->stime_s.samples; i++)
    {
      //real[i]=iscale(real[i],1,1);
      imag[i] = 0;
    }

  /* Calculate FFT */


  fix_fft (real, imag, info->stime_s.fsamples, 0);


  /* open file for write */

  info->pFile_fsamples = fopen (info->pFILENAME_F_OUT, "w");

  if (info->pFile_fsamples == NULL)
    {
      NDSO_Error (FILE_OPEN, form_method, getvars, postvars, info);
    }

  /* print header information */

  fprintf (info->pFile_fsamples,
	   "# File Samples generated by NDSO FFT Order %d Sample %d #x : Re[x] : Im[x]\n",
	   info->stime_s.fsamples, info->stime_s.samples);

  /* print samples */

  for (i = info->sdisplay.fftexludezero;
       i < (info->stime_s.samples / (1 + info->sdisplay.fftscaled)); i++)
    {

      fprintf (info->pFile_fsamples, "%d %d %d\n", i, real[i], imag[i]);
    }

  /* close file */

  free (imag);
  fclose (info->pFile_fsamples);

  return 0;

}

int
MakeFileInit (int form_method, char **getvars, char **postvars, s_info * info)
{

  /* open file for write */

  info->pFile_init = fopen (info->pFILENAME_GNUPLT, "w");

  if (info->pFile_init == NULL)
    {
      NDSO_Error (FILE_OPEN, form_method, getvars, postvars, info);
    }

  /* print header information */

  fprintf (info->pFile_init, "#GNUPLOT File generated by NDSO\n");
  fprintf (info->pFile_init, "set term png\nset output \"../img%s.png\"\n",
	   info->pREMOTE_ADDR);

  /* print commands */

  if (info->sdisplay.set_grid)
    fprintf (info->pFile_init, "set grid\n");

  if (info->sdisplay.axis)
    fprintf (info->pFile_init, "set xzeroaxis lt 2 lw 4\n");

  if (info->sdisplay.logscale)
    fprintf (info->pFile_init, "set %s\n", postvars[info->sdisplay.logscale]);

  if (info->sdisplay.style)
    fprintf (info->pFile_init, "set data style %s\n",
	     postvars[info->sdisplay.style]);

  if (info->sdisplay.size_ratio)
    fprintf (info->pFile_init, "set size %s\n",
	     postvars[info->sdisplay.size_ratio]);

  fprintf (info->pFile_init, "set xrange [%s:%s]\n",
	   postvars[info->sdisplay.xrange], postvars[info->sdisplay.xrange1]);

  if (info->sdisplay.tdom)
    {

      if (postvars[info->svertical.vdiv][0] != 'X')
	fprintf (info->pFile_init, "set ytics %s\n",
		 postvars[info->svertical.vdiv]);

      fprintf (info->pFile_init,
	       "set xlabel \"%d Samples @ %d Samples/s                t/ms->\"\n",
	       info->stime_s.samples, info->stime_s.sps);
      fprintf (info->pFile_init, "set ylabel \"Volt\" \n");

      if (str2num (postvars[info->sdisplay.smooth]))
	{

	  fprintf (info->pFile_init,
		   "plot  \"%s\" smooth %s notitle \nexit\n",
		   info->pFILENAME_T_OUT, postvars[info->sdisplay.smooth]);
	}
      else
	{
	  fprintf (info->pFile_init,
		   "plot  \"%s\" notitle %s  \nexit\n",
		   info->pFILENAME_T_OUT, postvars[info->sdisplay.color]);
	}
    }
  else
    {

      fprintf (info->pFile_init, "set ylabel \"Magnitude\" \n");

      if (info->sdisplay.fftscaled)
	{
	  fprintf (info->pFile_init,
		   "set xlabel \"%d point FFT @ %d Samples/s               f/Hz->\"\n",
		   info->stime_s.samples, info->stime_s.sps);
	  fprintf (info->pFile_init,
		   "plot  \"%s\" using ($1*%d/%d):(sqrt($2*$2+$3*$3)) notitle %s  \nexit\n",
		   info->pFILENAME_F_OUT, info->stime_s.sps,
		   info->stime_s.samples, postvars[info->sdisplay.color]);
	}
      else
	{
	  fprintf (info->pFile_init,
		   "set xlabel \"%d point FFT @ %d Samples/s               f->\"\n",
		   info->stime_s.samples, info->stime_s.sps);
	  fprintf (info->pFile_init,
		   "plot  \"%s\" using 1:(sqrt($2*$2+$3*$3)) notitle %s  \nexit\n",
		   info->pFILENAME_F_OUT, postvars[info->sdisplay.color]);
	}
    }

  /* close file */

  fclose (info->pFile_init);

  return 0;
};



int
DoDM_HTML_Page (int form_method, char **getvars, char **postvars,
		s_info * info)
{

  char bar[44];
  unsigned char Cntr;
  unsigned short *samples = info->samples;

  bar[0] = '<';
  for (Cntr = 1;
       Cntr < (abs ((short) SampleToVoltage (samples[10], info)) / 100);
       Cntr++)
    bar[Cntr] = '|';
  for (; Cntr < 42; Cntr++)
    bar[Cntr] = '_';
  bar[42] = '>';
  bar[43] = '\0';

  printf (VALUE_FRAME,
	  ((float) ((short) SampleToVoltage (samples[10], info))) / 1000);

  printf
    ("<p><font face=\"Courier New\" size=\"1\"> %s </font></p>\n  </body>\n</html>\n",
     bar);

  return 0;
};


int
DoMeasurements (s_info * info)
{

  int i, min, max, mean;
  unsigned short val, count;
  unsigned short *samples = info->samples;

  if (info->smeasurements.min || info->smeasurements.max
      || info->smeasurements.mean)
    {

      /* Calculate measurements */

      min = samples[0];
      max = samples[0];
      mean = 0;
      count = info->stime_s.samples;

      for (i = 0; i < info->stime_s.samples; i++)
	{
	  val = samples[i];

	  if (val < min)
	    min = val;
	  if (val > max)
	    max = val;
	  mean += val;

	};

      info->smeasurements.valuemin = (short) SampleToVoltage (min, info);
      info->smeasurements.valuemax = (short) SampleToVoltage (max, info);
      info->smeasurements.valuemean =
	(short) SampleToVoltage (mean / count, info);

    }

  return 0;
};

char *
itostr (u_int iNumber, u_char cDigits, u_char cMode, u_char cDec_mode)
{
  static char cBuffer[31];
  char c, cMod;
  u_int iDivisor = 10;

  if (cDigits > 30)
    {
      cBuffer[0] = '\0';
    }
  else
    {
      if (iNumber)
	{
	  switch (cMode)
	    {
	    case OUT_BIN:
	      iDivisor = 2;
	      break;

	    case OUT_DEC:
	      iDivisor = 10;
	      break;

	    case OUT_HEX:
	      iDivisor = 16;
	      break;
	    }

	  for (c = cDigits; c > 0; c--)
	    {
	      cMod = iNumber % iDivisor;
	      if (cMode == OUT_HEX)
		{
		  if (cMod > 9)
		    cBuffer[c - 1] = cMod + 55;
		  else
		    cBuffer[c - 1] = cMod + 48;
		}
	      else
		{
		  if (cMode == OUT_DEC)
		    {
		      if ((!iNumber) && (cDec_mode))
			cBuffer[c - 1] = ' ';
		      else
			cBuffer[c - 1] = cMod + 48;
		    }
		  else
		    cBuffer[c - 1] = cMod + 48;
		}
	      iNumber /= iDivisor;
	    }

	  cBuffer[cDigits] = '\0';
	}
      else
	{
	  if ((cMode == OUT_DEC) && (cDec_mode))
	    {
	      for (c = 0; c < cDigits; c++)
		cBuffer[(unsigned char) c] = ' ';
	      cBuffer[cDigits - 1] = '0';
	      cBuffer[cDigits] = '\0';
	    }
	  else
	    {
	      for (c = 0; c < cDigits; c++)
		cBuffer[(unsigned char) c] = '0';
	      cBuffer[(unsigned char) c] = '\0';
	    }
	}
    }

  return (cBuffer);
};


int
getrand (int max)
{

  int j;
  struct timeval tv;

  if (gettimeofday (&tv, NULL) != 0)
    {
      printf ("Error getting time\n");
    }

  srand (tv.tv_sec);
  j = 1 + (int) ((float) max * rand () / (23457 + 1.0));

  return j;
};

/* str2num */
int
str2num (char *str)
{
  int num = 0;
  int i = 0, ilen;

  if (str == NULL)
    return -1;
  ilen = strlen (str);

  if (str[0] == '*' && str[1] == 0)
    return 1;

  for (i = 0; i < ilen; i++)
    {
      if (str[i] == '.' || str[i] == '-')
	i++;			// ignore dot and sign

      if (str[i] > 57 || str[i] < 48)
	return -1;
      num = num * 10 + (str[i] - 48);
    }
  return (str[0] == '-' ? (-1) * num : num);
};

void
MakeSessionFiles (s_info * info)
{
  char str[80];
  
/* Generate File Names Based on the REMOTE IP ADDR */
    info->pREMOTE_ADDR = strdup (getRemoteAddr ());

  info->pGNUPLOT =
    strdup (strcat (strcpy (str, CALL_GNUPLOT), info->pREMOTE_ADDR));
  info->pFILENAME_T_OUT =
    strdup (strcat (strcpy (str, FILENAME_T_OUT), info->pREMOTE_ADDR));
  info->pFILENAME_F_OUT =
    strdup (strcat (strcpy (str, FILENAME_F_OUT), info->pREMOTE_ADDR));
  info->pFILENAME_GNUPLT =
    strdup (strcat (strcpy (str, FILENAME_GNUPLT), info->pREMOTE_ADDR));

  return;
};

void
CleanupSessionFiles (s_info * info)
{
  free (info->pREMOTE_ADDR);
  free (info->pFILENAME_T_OUT);
  free (info->pFILENAME_F_OUT);
  free (info->pFILENAME_GNUPLT);
  free (info->pGNUPLOT);

  return;
};

int
SampleToVoltage (unsigned short value, s_info * info)
{
  unsigned int res, ref;
  int voltage;

  res = hw_device_table[info->sinput.type][DAC_RESOLUTION].arg;
  ref = hw_device_table[info->sinput.type][REF_VOLTAGE].arg;

  if (info->sinput.mode)
    voltage = value * ref / res;	// DC
  else
    voltage = (value - (res / 2)) * ref / res;	//AC

  return voltage;
};

int
VoltageToSample (short voltage, s_info * info)
{
  unsigned int res, ref;
  int value;

  res = hw_device_table[info->sinput.type][DAC_RESOLUTION].arg;
  ref = hw_device_table[info->sinput.type][REF_VOLTAGE].arg;

  if (info->sinput.mode)
    value = voltage * res / ref;	// DC
  else
    value = (voltage * res / ref) + (res / 2);	//AC

  return value;
};

int
GetMaxSampleValue (s_info * info)
{
  return (hw_device_table[info->sinput.type][DAC_RESOLUTION].arg);
};

void
DoFiles (s_info * info)
{

  printf
    ("<hr>\n<menu>\n");

	  info->pFile_samples = fopen (info->pFILENAME_T_OUT, "r");
	  if (info->pFile_samples)
	    {
	  	fclose (info->pFile_samples);
	    printf
	      ("  <li><font face=\"Arial Black\"><a href=\"t_samples.txt_%s\">Time Samples</a></font></li>\n",
	      info->pREMOTE_ADDR);
	    }

	  info->pFile_init = fopen (info->pFILENAME_GNUPLT, "r");
	  if (info->pFile_init)
	    {
	  	fclose (info->pFile_init);
	    printf
	      ("  <li><font face=\"Arial Black\"><a href=\"gnu.plt_%s\">Gnuplot File</a></font></li>\n",
	      info->pREMOTE_ADDR);
	    }

	  info->pFile_fsamples = fopen (info->pFILENAME_F_OUT, "r");
	  if (info->pFile_fsamples)
	    {
	  	fclose (info->pFile_fsamples);
	    printf
	      ("<li><font face=\"Arial Black\"><a href=\"f_samples.txt_%s\">Frequency Samples</a></font></li>\n",
	      info->pREMOTE_ADDR);
	    }

	  if ((info->pFile_fsamples == NULL) && (info->pFile_samples == NULL) &&  (info->pFile_init == NULL))
	    printf
	      ("  <li><font face=\"Arial Black\">No Files available from %s</font></li>\n",
	      info->pREMOTE_ADDR);

  printf
    ("</menu>\n<hr>\n");

  return;
};



