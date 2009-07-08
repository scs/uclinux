/*
 *
 *	  Rev:			$Id$
 *	  Revision:		$Revision$
 *	  Source:		$Source$
 *	  Created:		Aug 21 13:05:01 CEST 2005
 *	  Author:		Michael	Hennerich
 *	  mail:			hennerich@blackfin.uclinux.org
 *	  Description:	Arbitrary Waveform Generator
 *
 *	 Copyright (C) 2005	Michael	Hennerich 
 *
 *	 This program is free software;	you	can	redistribute it	and/or modify
 *	 it	under the terms	of the GNU General Public License as published by
 *	 the Free Software Foundation; either version 2	of the License,	or
 *	 (at your option) any later	version.
 *
 *	 This program is distributed in	the	hope that it will be useful,
 *	 but WITHOUT ANY WARRANTY; without even	the	implied	warranty of
 *	 MERCHANTABILITY or	FITNESS	FOR	A PARTICULAR PURPOSE.  See the
 *	 GNU General Public	License	for	more details.
 *
 *	 You should	have received a	copy of	the	GNU	General	Public License
 *	 along with	this program; if not, write	to the Free	Software
 *	 Foundation, Inc., 59 Temple Place,	Suite 330, Boston, MA  02111-1307  USA
 *
 *
 ****************************************************************************
 * MODIFICATION	HISTORY:
 ***************************************************************************/

#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <linux/ioctl.h>
#include <errno.h>
#include <unistd.h>
#include <strings.h>
#include <sys/time.h>
#include <string.h>


#include "readsamples.h"
#include "cgivars.h"
#include "htmllib.h"
#include "spiadc.h"
#include "dac.h"

void calc_frequency(int form_method, char **getvars, char **postvars, float frequency);
void capture(int , char	**,	char **);
int	getrand(int);
char* itostr  (	 u_int	,  u_char  ,  u_char  ,	u_char);
void display(int form_method, char **getvars, char **postvars);
int check_request (int form_method, char **getvars, char **postvars);
int error(int errnum, int form_method, char **getvars, char **postvars);
int sample (int form_method, char **getvars, char **postvars);
int make_file_init (int form_method, char **getvars, char **postvars);


#define FULLSCALE 	    (4096-1)
#define ZERO	  		2048

#define MAXAMP	  		10
#define MINAMP			-10
#define MAXDCOFFSET 	10
#define MINDCOFFSET 	-10
#define MAXDUTYCYCLE 	100
#define MINDUTYCYCLE 	0
#define MINSAMPLES 		2
#define MAXSAMPLES 		10000

#define	FILENAME_OUT	"img.bmp"
#define FILENAME_GNUPLT "gnuplot.plt"
#define FILENAME_SAMPLES "samples.txt"

typedef	struct cgi_info
{
	unsigned int cmd;
	unsigned int framebuffer;
	unsigned int choice;
	unsigned int unitfreq;
	float unitamp;
	float unitdco;
	unsigned short time2run;

	float DCoffset;
	float amplitude;
	float frequency;
	float phase;
	float dutycycle;
	float symmetry;

	unsigned spi_hz;
	unsigned short samples_cnt;
   unsigned short *samples;

}cgi_info_t;


static cgi_info_t cgiinfo;

enum
{
  RUN, CALC, STOP
};

enum
{
  SINE, RECT, NOISE, SAWTOOTH, TRIANGLE, PULSE, CUSTOM
};

enum
{
  ERR_DCOFFSET, ERR_AMP, ERR_OUTOFRANGE, ERR_DUTYCYCLE, ERR_FREQUENCY, ERR_SPI, ERR_MEMORY, ERR_FILE
};

int	main(void)
{
	char **postvars	= NULL;	/* POST	request	data repository	*/
	char **getvars = NULL; /* GET request data repository */
	int	form_method; /*	POST = 1, GET =	0 */
	int	i;


	form_method	= getRequestMethod();


	if(form_method == POST)	{
		getvars	= getGETvars();
		postvars = getPOSTvars();
	} else if(form_method == GET) {
		getvars	= getGETvars();
	}

/* Parse Request */

	if(form_method == POST)	{

/*Preset checkbox settings*/

for	(i=0; postvars[i]; i+= 2) {

	if(strncmp(postvars[i],	"CH1",2) ==	0){	cgiinfo.choice	=	 atoi(postvars[i +	1]); } else
	if(strncmp(postvars[i],	"TR",2) ==	0){	cgiinfo.time2run	=atoi(postvars[i +	1]); } else
	if(strncmp(postvars[i],	"UF",2) ==	0){	cgiinfo.unitfreq	=atoi(postvars[i +	1]); } else
	if(strncmp(postvars[i],	"UA",2) ==	0){	cgiinfo.unitamp		=atof(postvars[i +	1]); } else
	if(strncmp(postvars[i],	"UD",2) ==	0){	cgiinfo.unitdco		=atof(postvars[i +	1]); } else
	if(strncmp(postvars[i],	"O1", 2) ==	0){	cgiinfo.DCoffset	= atof(postvars[i +	1]); } else
	if(strncmp(postvars[i],	"A1", 2) ==	0){	cgiinfo.amplitude	= atof(postvars[i +	1]); } else
	if(strncmp(postvars[i],	"F1", 2) ==	0){	cgiinfo.frequency	= atof(postvars[i +	1]); } else
	if(strncmp(postvars[i],	"S1", 2) ==	0){	cgiinfo.symmetry	= atof(postvars[i +	1]); } else
	if(strncmp(postvars[i],	"P1", 2) ==	0){	cgiinfo.phase		= atof(postvars[i +	1]); } else
	if(strncmp(postvars[i],	"D1", 2) ==	0){	cgiinfo.dutycycle	= atof(postvars[i +	1]); } else
	if(strncmp(postvars[i],	"B2", 2) ==	0){	cgiinfo.cmd	= RUN; } else
	if(strncmp(postvars[i],	"B1", 2) ==	0){	cgiinfo.cmd	= CALC;	} else
	if(strncmp(postvars[i],	"B3", 2) ==	0){	cgiinfo.cmd	= STOP; } else
	if(strncmp(postvars[i],	"FB", 2) ==	0){	cgiinfo.framebuffer = atof(postvars[i + 1]); }

	}
}

	cgiinfo.DCoffset	*= cgiinfo.unitdco;
    cgiinfo.amplitude	*= cgiinfo.unitamp;
	cgiinfo.frequency	*= cgiinfo.unitfreq;

	switch(cgiinfo.cmd)
	{
		case CALC:
		calc_frequency(form_method, getvars, postvars, cgiinfo.frequency);
  		check_request (form_method, getvars, postvars);
		make_file_init(form_method, getvars, postvars);
		system ("/bin/gnuplot /home/httpd/cgi-bin/gnuplot.plt");
		capture(form_method, getvars, postvars);
		break;

		case RUN:
		calc_frequency(form_method, getvars, postvars, cgiinfo.frequency);
		sample(form_method, getvars, postvars);
		display(form_method, getvars, postvars);
		break;

		case STOP:

		break;

		default:
		break;
	}

  exit(0);

};


void calc_frequency(int form_method, char **getvars, char **postvars, float frequency) {

int fd0, sclk, spi_div, samples;
float sps;

fd0 = open ("/dev/spi", O_RDWR);
  if (fd0 < 0)
    {
      error(ERR_SPI, form_method, getvars, postvars);
    }

  ioctl (fd0, CMD_SPI_GET_SYSTEMCLOCK, &sclk);
  close(fd0);

	for(spi_div = 2; spi_div < 65535; spi_div++)
	 {

	  /* Calculate required Baud Rate */
	  if ((sclk % (sclk / spi_div)) > 0)
		spi_div++;

	  sps = sclk / ((2 * 16 + 2) * spi_div);
	  samples = (unsigned int) (sps / frequency);
	  if( samples < MAXSAMPLES ) break;

	 }

	if ((sclk % (sclk / spi_div)) > 0)
		spi_div++;


	  cgiinfo.spi_hz = (sclk / (2 * spi_div));
	  cgiinfo.samples_cnt= samples;

 return;
}

void display_on_framebuffer(void)
{
	if (!cgiinfo.framebuffer)
		return;

	if (vfork() == 0) {
		execlp("pngview", "pngview", "-q", "/home/httpd/img.png", NULL);
		printf("<br>Hmm, could not run pngview, that's odd ...<br>\n");
		_exit(-1);
	}
}

void capture(int form_method, char **getvars, char **postvars)
{

	htmlHeaderNocache("AWG Demo	Web	Page");
	htmlBody();

		printf("\n<img border=\"0\"	src=\"/img.png?id=%s\" align=\"left\">\n",itostr	(getrand(6)	,6,1,1));

	htmlFooter();
	fflush(stdout);
	cleanUp(form_method, getvars, postvars);

	display_on_framebuffer();

  return;
}

void display(int form_method, char **getvars, char **postvars)
{

	htmlHeaderNocache("AWG Demo	Web	Page");
	htmlBody();


	printf("\n<img border=\"0\"	src=\"/img.png?id=%s\" align=\"left\">\n",itostr	(getrand(6)	,6,1,1));
	printf ("<p><font face=\"Tahoma\" size=\"7\">DONE\n</font></p>");


	htmlFooter();
	fflush(stdout);

	cleanUp(form_method, getvars, postvars);

	display_on_framebuffer();

  return;
}

int
make_file_init (int form_method, char **getvars, char **postvars)
{

  /* open file for write */

  FILE *pFile_init;

  pFile_init = fopen (FILENAME_GNUPLT, "w");

  if (pFile_init < 0)
    {
      error(ERR_FILE, form_method, getvars, postvars);
    }

  /* print header information */

  fprintf (pFile_init, "#GNUPLOT File generated by AWG\n");
  fprintf (pFile_init, "set term png\nset output \"../img.png\"\n");
  /* print commands */
  fprintf (pFile_init, "set grid\nset xtics 0\n");
  fprintf (pFile_init, "amp(a)=(a/%d*%d)\n",MAXAMP,ZERO);
  fprintf (pFile_init, "dc_off(a)=%d+(a/%d*%d)\n",ZERO,MAXAMP,ZERO);
  fprintf (pFile_init, "adj(a)=a-(0.5*%f)\n",cgiinfo.amplitude);
  fprintf (pFile_init, "adj_dc_off(a)=%d+((a-(0.5*%f))/%d*%d)\n",ZERO,cgiinfo.amplitude,MAXAMP,ZERO);
  fprintf (pFile_init,
	       "set xlabel \"%d Samples Frequency %f Hz                t/ms->\"\n",
	       cgiinfo.samples_cnt, cgiinfo.frequency);
  fprintf (pFile_init, "set ylabel \"Volt\" \n");
  fprintf (pFile_init, "set samples 300 \n");

switch(cgiinfo.choice)
 {
 	case SINE:
  		fprintf (pFile_init, "plot [0:2*pi] %f +  %f*0.5*sin(x) notitle\n",cgiinfo.DCoffset,cgiinfo.amplitude);
		 break;
	case NOISE:
        fprintf (pFile_init, "plot [0:2*pi] %f + %f*2*(rand(0)-0.5) notitle\n",cgiinfo.DCoffset,cgiinfo.amplitude);
		 break;
	case RECT:
        fprintf (pFile_init, "plot [0:100] x < %f ? %f-(0.5)*%f : %f + (0.5)*%f notitle\n",cgiinfo.dutycycle,cgiinfo.DCoffset,cgiinfo.amplitude,cgiinfo.DCoffset,cgiinfo.amplitude);
		break;
	case SAWTOOTH:
        fprintf (pFile_init, "plot [0:100] x < %f ? adj(%f)+(%f/%f)*x : adj(%f)+(%f/(100-%f))*(x-%f) notitle\n",cgiinfo.dutycycle,cgiinfo.DCoffset,cgiinfo.amplitude,cgiinfo.dutycycle,cgiinfo.DCoffset,cgiinfo.amplitude,cgiinfo.dutycycle,cgiinfo.dutycycle);
		 break;
	case TRIANGLE:
        fprintf (pFile_init, "m(x) = adj(%f)+(%f/%f)*x \n",cgiinfo.DCoffset,cgiinfo.amplitude,cgiinfo.dutycycle);
        fprintf (pFile_init, "m2(x) = adj(%f)+((%f/(100-%f))*x)\n",cgiinfo.DCoffset,cgiinfo.amplitude,cgiinfo.dutycycle);
        fprintf (pFile_init, "plot [0:100] x < %f ? m(x) : m2(100-x) notitle\n",cgiinfo.dutycycle);
 		break;
 }
/***************************************************/

  fprintf (pFile_init, "set term table\nset output \"%s\"\n",FILENAME_SAMPLES);

  /* print commands */

  fprintf (pFile_init, "set samples %d \n",cgiinfo.samples_cnt);

switch(cgiinfo.choice)
 {
 	case SINE:
  		fprintf (pFile_init, "plot [0:2*pi] dc_off(%f)+amp(%f)*0.5*sin(x)\n",cgiinfo.DCoffset,cgiinfo.amplitude);
		 break;
	case NOISE:
        fprintf (pFile_init, "plot [0:2*pi] dc_off(%f)+amp(%f)*2*(rand(0)-0.5)\n",cgiinfo.DCoffset,cgiinfo.amplitude);
		 break;
	case RECT:
        fprintf (pFile_init, "plot [0:100] x < %f ? dc_off(%f)-0.5*amp(%f) : dc_off(%f) + 0.5*amp(%f) notitle\n",cgiinfo.dutycycle,cgiinfo.DCoffset,cgiinfo.amplitude,cgiinfo.DCoffset,cgiinfo.amplitude);
		 break;
 	case SAWTOOTH:
        fprintf (pFile_init, "plot [0:100] x < %f ? adj_dc_off(%f)+amp(%f/%f)*x : adj_dc_off(%f)+amp(%f/(100-%f))*(x-%f) notitle\n",cgiinfo.dutycycle,cgiinfo.DCoffset,cgiinfo.amplitude,cgiinfo.dutycycle,cgiinfo.DCoffset,cgiinfo.amplitude,cgiinfo.dutycycle,cgiinfo.dutycycle);
		 break;
	case TRIANGLE:
        fprintf (pFile_init, "m(x) = adj_dc_off(%f)+amp((%f/%f)*x) \n",cgiinfo.DCoffset,cgiinfo.amplitude,cgiinfo.dutycycle);
        fprintf (pFile_init, "m2(x) = adj_dc_off(%f)+amp((%f/(100-%f))*x)\n",cgiinfo.DCoffset,cgiinfo.amplitude,cgiinfo.dutycycle);
        fprintf (pFile_init, "plot [0:100] x < %f ? m(x) : m2(100-x) notitle\n",cgiinfo.dutycycle);
 		break;
 }
  fprintf (pFile_init, "exit\n");

  /* close file */

  fclose (pFile_init);

  return 0;
};



int
check_request (int form_method, char **getvars, char **postvars)
{

	  if (cgiinfo.DCoffset > MAXDCOFFSET || cgiinfo.DCoffset < MINDCOFFSET)
      	    error(ERR_DCOFFSET, form_method, getvars, postvars);
      if (cgiinfo.amplitude > MAXAMP || cgiinfo.amplitude < 0)
      	    error(ERR_AMP, form_method, getvars, postvars);
	  if ((cgiinfo.DCoffset + 0.5*cgiinfo.amplitude) > MAXAMP || (cgiinfo.DCoffset - 0.5*cgiinfo.amplitude) < MINAMP )
      	    error(ERR_OUTOFRANGE, form_method, getvars, postvars);
	  if (cgiinfo.dutycycle > MAXDUTYCYCLE || cgiinfo.dutycycle < MINDUTYCYCLE)
      	    error(ERR_DUTYCYCLE, form_method, getvars, postvars);

	  if (cgiinfo.samples_cnt < MINSAMPLES)
      	    error(ERR_FREQUENCY, form_method, getvars, postvars);

  return 0;
}

int
error(int errnum, int form_method, char **getvars, char **postvars)
{

  htmlHeader ("AWG Error");
  htmlBody ();

  switch (errnum)
    {

    case ERR_SPI:
      printf ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
	      ERR_SPI);
      printf
	("<p><font face=\"Tahoma\" size=\"7\">Can't open /dev/spi.\n</font></p>");
      printf
	("<p><font face=\"Tahoma\" size=\"7\">- Try again later -\n</font></p>");
      break;
    case ERR_FILE:
      printf ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
	      ERR_FILE);
      printf
	("<p><font face=\"Tahoma\" size=\"7\">Can't open FILE.\n</font></p>");
      break;
    case ERR_MEMORY:
      printf ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
	      ERR_MEMORY);
      printf
	("<p><font face=\"Tahoma\" size=\"7\">Memory allocation error.\n</font></p>");
      break;

     case ERR_DCOFFSET:
      printf ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
	      ERR_DCOFFSET);
      printf
	("<p><font face=\"Tahoma\" size=\"7\">DC Offset out of Range %d < Val < %d .\n</font></p>",MINDCOFFSET,MAXDCOFFSET);
      break;
     case ERR_AMP:
      printf ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
	      ERR_AMP);
      printf
	("<p><font face=\"Tahoma\" size=\"7\">Amplitude out of Range %d < Val < %d .\n</font></p>", MINAMP,MAXAMP);
      break;
     case ERR_OUTOFRANGE:
      printf ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
	      ERR_OUTOFRANGE);
      printf
	("<p><font face=\"Tahoma\" size=\"7\"> Out of Range +/- %d Volt.\n</font></p>",MAXAMP);
      break;
     case ERR_DUTYCYCLE:
      printf ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
	      ERR_DUTYCYCLE);
      printf
	("<p><font face=\"Tahoma\" size=\"7\">Duty Cycle out of Range %d < Val < %d .\n</font></p>",MINDUTYCYCLE,MAXDUTYCYCLE);
      break;
      case ERR_FREQUENCY:
      printf ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
	      ERR_FREQUENCY);
      printf
	("<p><font face=\"Tahoma\" size=\"7\">Frequency out of Range\n</font></p>");
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
  fflush (stdout);

  exit (1);
};


int
sample (int form_method, char **getvars, char **postvars)
{

  int errval,fd0;
  unsigned short i;
  unsigned short def[]={6144,6144};

  fd0 = open ("/dev/spi", O_RDWR);

  if (fd0 < 0)
      error (ERR_SPI, form_method, getvars, postvars);

  ioctl (fd0, CMD_SPI_SET_BAUDRATE, cgiinfo.spi_hz);
  ioctl (fd0, CMD_SPI_SET_WRITECONTINUOUS, 1);

	cgiinfo.samples = malloc (cgiinfo.samples_cnt * 2);
	  if (cgiinfo.samples == NULL)
	      error (ERR_MEMORY, form_method, getvars, postvars);

	errval = read_config(FILENAME_SAMPLES, cgiinfo.samples);
	  if (errval < 0){
	  	  free(cgiinfo.samples);
	      error (ERR_FILE, form_method, getvars, postvars);
		}

	for(i=0;i<cgiinfo.samples_cnt;i++){
    	cgiinfo.samples[i]= (unsigned short) ((unsigned short)cgiinfo.samples[i]| 0x1000);}

    errval = write (fd0, cgiinfo.samples, cgiinfo.samples_cnt * 2);

  	sleep(cgiinfo.time2run);
  ioctl (fd0, CMD_SPI_SET_WRITECONTINUOUS, 0);
	write (fd0,def, 2);
  close (fd0);
  free(cgiinfo.samples);

  return 0;
}

#define	OUT_DEC	1		//Converts the number based	on the decimal format
#define	OUT_BIN	2		// Converts	the	number based on	the	binary format
#define	OUT_HEX	3		//Converts the number based	on the hexadecimal format

char *
itostr (u_int iNumber, u_char cDigits, u_char cMode, u_char	cDec_mode)
{
  static char cBuffer[31];
  char c, cMod;
  u_int	iDivisor = 10;

  if (cDigits >	30)
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

	  for (c = cDigits;	c >	0; c--)
		{
		  cMod = iNumber % iDivisor;
		  if (cMode	== OUT_HEX)
		{
		  if (cMod > 9)
			cBuffer[c -	1] = cMod +	55;
		  else
			cBuffer[c -	1] = cMod +	48;
		}
		  else
		{
		  if (cMode	== OUT_DEC)
			{
			  if ((!iNumber) &&	(cDec_mode))
			cBuffer[c -	1] = ' ';
			  else
			cBuffer[c -	1] = cMod +	48;
			}
		  else
			cBuffer[c -	1] = cMod +	48;
		}
		  iNumber /= iDivisor;
		}

	  cBuffer[cDigits] = '\0';
	}
	  else
	{
	  if ((cMode ==	OUT_DEC) &&	(cDec_mode))
		{
		  for (c = 0; c	< cDigits; c++)
		cBuffer[(unsigned char)	c] = ' ';
		  cBuffer[cDigits -	1] = '0';
		  cBuffer[cDigits] = '\0';
		}
	  else
		{
		  for (c = 0; c	< cDigits; c++)
		cBuffer[(unsigned char)	c] = '0';
		  cBuffer[(unsigned	char) c] = '\0';
		}
	}
	}

  return (cBuffer);
};


int
getrand	(int max)
{

  int j;
  struct timeval tv;

  if (gettimeofday (&tv, NULL) != 0)
	{
	  printf ("Error getting time\n");
	}

  srand	(tv.tv_sec);
  j	= 1	+ (int)	((float) max * rand	() / (23457	+ 1.0));

  return j;
};

