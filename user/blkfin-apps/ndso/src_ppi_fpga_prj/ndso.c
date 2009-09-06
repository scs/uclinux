/*****************************************************************************
*
* Copyright (C) 2004-2009, Analog Devices. All Rights Reserved
*
* FILE ndso.c
* PROGRAMMER(S): Michael Hennerich (Analog Devices Inc.)
*
*
*
* SYNOPSIS:
*
*
* CAUTION:     you may need to change ioctl's in order to support other ADCs.
******************************************************************************
* MODIFICATION HISTORY:
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

#include "cgivars.h"
#include "htmllib.h"
#include "ndso.h"

static s_info sinfo;

void start_server(int form_method, char **getvars, char **postvars,
		  s_info * info)
{

	if (vfork() == 0) {

		int fd;
		for (fd = 0; fd < 10; fd++)
			close(fd);

		fd = open("/dev/null", O_RDWR);

		if (fd >= 0) {
			if (fd != 0) {
				dup2(fd, 0);
				close(fd);
			}
			dup2(0, 1);
			dup2(0, 2);
		}

		execlp("/bin/fpga_netd", "fpga_netd", info->pREMOTE_ADDR,
		       postvars[info->server.adc_port],
		       postvars[info->server.ctl_port],
		       postvars[info->server.dac_port], NULL);

		printf
		    ("<br>Hmm, could not run fpga_netd, that's odd ...<br>\n");
		_exit(-1);

	} else {
		exit(0);
	}
}

void stop_server(int form_method, char **getvars, char **postvars,
		 s_info * info)
{
	system("/bin/killall fpga_netd");
}

int main()
{
	char **postvars = NULL;	/* POST request data repository */
	char **getvars = NULL;	/* GET request data repository */
	int form_method;	/* POST = 1, GET = 0 */
	s_info *info = &sinfo;

	form_method = getRequestMethod();

	if (form_method == POST) {
		getvars = getGETvars();
		postvars = getPOSTvars();
	} else if (form_method == GET) {
		getvars = getGETvars();
	}

	MakeSessionFiles(info);
	ParseRequest(form_method, getvars, postvars, info);
	CheckRequest(form_method, getvars, postvars, info);

	switch (info->run) {

	case ACQUIRE:
		AllocateMemory(form_method, getvars, postvars, info);
		MakeFileInit(info, form_method, getvars, postvars);
		MakeFileSamples(form_method, getvars, postvars, info);
		free(info->samples);
		system(info->pGNUPLOT);
		DoHTML(info, form_method, getvars, postvars);
		break;

	case REPLOT:
		MakeFileInit(info, form_method, getvars, postvars);
		system(info->pGNUPLOT);
		DoHTML(info, form_method, getvars, postvars);
		break;

	case START_SERVER:
		stop_server(form_method, getvars, postvars, info);
		DoHTML(info, form_method, getvars, postvars);
		AllocateMemory(form_method, getvars, postvars, info);
		MakeFileSamples(form_method, getvars, postvars, info);
		free(info->samples);
		start_server(form_method, getvars, postvars, info);
		break;

	case STOP_SERVER:
		DoHTML(info, form_method, getvars, postvars);
		stop_server(form_method, getvars, postvars, info);
		break;

	case MULTIMETER:
		break;

	case SHOWSAMPLES:
		break;

	case GNUPLOT_FILES:
		DoHTML(info, form_method, getvars, postvars);
		break;

	default:

		break;
	}

	cleanUp(form_method, getvars, postvars);
	CleanupSessionFiles(info);
	exit(0);
}

int DoHTML(s_info * info, int form_method, char **getvars, char **postvars)
{

	htmlHeaderExpires("Lidar Web Page");
	htmlBody();

	switch (info->run) {
	case ACQUIRE:
	case REPLOT:
		printf
		    ("\n<img border=\"0\" src=\"/img%s.png?id=%d\" align=\"left\">\n",
		     info->pREMOTE_ADDR, getrand(6));
		break;

	case STOP_SERVER:
		printf
		    ("<b><font face=\"Arial Black\"> STOP Server Request from: %s</b><br><br> %s</font><br><br>\n",
		     getenv("REMOTE_ADDR"), getenv("HTTP_USER_AGENT"));

		break;
	case START_SERVER:

		printf
		    ("<b><font face=\"Arial Black\"> Request from %s:</b><br><br> %s</font><br><br>\n",
		     getenv("REMOTE_ADDR"), getenv("HTTP_USER_AGENT"));

		printf
		    ("<b><font face=\"Arial Black\"> %s now streaming to:</b><br><br> IP-ADDR:  %s <br>ADC Port# %s <br>DAC Port# %s <br>CTL Port# %s </font>\n",
		     "fpga_netd", info->pREMOTE_ADDR,
		     postvars[info->server.adc_port],
		     postvars[info->server.dac_port],
		     postvars[info->server.ctl_port]);

		break;

	case MULTIMETER:
		break;
	case SHOWSAMPLES:
		break;
	case GNUPLOT_FILES:
		DoFiles(info);
		break;
	default:

		break;
	}
	htmlFooter();
	fflush(stdout);
	return 0;
}

int
NDSO_Error(int errnum, int form_method, char **getvars, char **postvars,
	   s_info * info)
{

	htmlHeader("NDSO Demo Web Page");
	htmlBody();

	switch (errnum) {

	case PPIOPEN:
		printf
		    ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
		     PPIOPEN);
		printf
		    ("<p><font face=\"Tahoma\" size=\"7\">Can't open /dev/ppi.\n</font></p>");
		printf
		    ("<p><font face=\"Tahoma\" size=\"7\">- Try again later -\n</font></p>");
		free(info->samples);
		break;
	case FILE_OPEN:
		printf
		    ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
		     FILE_OPEN);
		printf
		    ("<p><font face=\"Tahoma\" size=\"7\">Can't open FILE.\n</font></p>");
		free(info->samples);
		break;
	case MEMORY:
		printf
		    ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
		     MEMORY);
		printf
		    ("<p><font face=\"Tahoma\" size=\"7\">Memory allocation error.\n</font></p>");
		free(info->samples);
		break;
	case SAMPLE_DEPTH:
		printf
		    ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
		     SAMPLE_DEPTH);
		printf
		    ("<p><font face=\"Tahoma\" size=\"7\">Sample Depth outside specified range: [%d] < Depth < [%d] \n</font></p>",
		     MINNUMSAMPLES, MAXNUMSAMPLES);
		break;
	case SIZE_RATIO:
		printf
		    ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
		     SIZE_RATIO);
		printf
		    ("<p><font face=\"Tahoma\" size=\"7\">Size Ratio contains invalid characters r exceeds maximum Size Ratio < [%d]\n</font></p>",
		     MAXSIZERATIO);
		break;
	case RANGE:
		printf
		    ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
		     RANGE);
		printf
		    ("<p><font face=\"Tahoma\" size=\"7\">Specified Range is invalid or out of range.\n</font></p>");
		break;
	case FILE_OPEN_SAMPLES:
		printf
		    ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
		     FILE_OPEN_SAMPLES);
		printf
		    ("<p><font face=\"Tahoma\" size=\"7\">Can't open SAMPLE FILE for REPLOT.\n</font></p>");
		break;
	case EMPTY_PLOT:
		printf
		    ("<p><font face=\"Tahoma\" size=\"7\">ERROR[%d]:\n</font></p>",
		     EMPTY_PLOT);
		printf
		    ("<p><font face=\"Tahoma\" size=\"7\">Empty Plot increase upper Range.\n</font></p>");
		break;
	default:
		printf
		    ("<p><font face=\"Tahoma\" size=\"7\">ERROR[UNDEF]:\n</font></p>");
		printf
		    ("<p><font face=\"Tahoma\" size=\"7\">undefined ERROR: \n</font></p>");
		break;
	}

	htmlFooter();
	cleanUp(form_method, getvars, postvars);
	CleanupSessionFiles(info);
	fflush(stdout);

	exit(0);
};

int
AllocateMemory(int form_method, char **getvars, char **postvars, s_info * info)
{

	info->samples = malloc(info->stime_s.samples * sizeof(int));

	if (info->samples == NULL) {
		NDSO_Error(MEMORY, form_method, getvars, postvars, info);
	}

	return 0;
}

int
ParseRequest(int form_method, char **getvars, char **postvars, s_info * info)
{
	int i;

	/*Preset checkbox settings */
	info->sdisplay.set_grid = 0;
	info->sdisplay.axis = 0;
	info->rawfiles = 0;

	if (form_method == POST) {

		/* Parse Request */
		for (i = 0; postvars[i]; i += 2) {

			if (strncmp(postvars[i], "D5", 2) == 0) {
				info->svertical.vdiv = i + 1;
			} else if (strncmp(postvars[i], "T2", 2) == 0) {
				info->stime_s.sps = atoi(postvars[i + 1]);
			} else if (strncmp(postvars[i], "T3", 2) == 0) {
				info->stime_s.samples = atoi(postvars[i + 1]);
			} else if (strncmp(postvars[i], "D8", 2) == 0) {
				info->stime_s.fsamples = atoi(postvars[i + 1]);
			} else if (strncmp(postvars[i], "set_grid", 8) == 0) {
				info->sdisplay.set_grid = 1;
			} else if (strncmp(postvars[i], "axis", 4) == 0) {
				info->sdisplay.axis = 1;
			} else if (strncmp(postvars[i], "linestyle", 9) == 0) {
				info->sdisplay.style = i + 1;
			} else if (strncmp(postvars[i], "color", 5) == 0) {
				info->sdisplay.color = i + 1;
			} else if (strncmp(postvars[i], "xrangeS", 7) == 0) {
				info->sdisplay.xrange = i + 1;
			} else if (strncmp(postvars[i], "xrangeE", 7) == 0) {
				info->sdisplay.xrange1 = i + 1;
			} else if (strncmp(postvars[i], "logscale", 8) == 0) {
				info->sdisplay.logscale = i + 1;
			} else if (strncmp(postvars[i], "size_ratio", 10) == 0) {
				info->sdisplay.size_ratio = i + 1;
			} else if (strncmp(postvars[i], "smooth", 6) == 0) {
				info->sdisplay.smooth = i + 1;
			} else if (strncmp(postvars[i], "R3", 2) == 0) {
				info->sdisplay.tdom = atoi(postvars[i + 1]);
			} else if (strncmp(postvars[i], "P1", 2) == 0) {
				info->server.adc_port = i + 1;
			} else if (strncmp(postvars[i], "P2", 2) == 0) {
				info->server.dac_port = i + 1;
			} else if (strncmp(postvars[i], "P3", 2) == 0) {
				info->server.ctl_port = i + 1;
			} else if (strncmp(postvars[i], "B8", 2) == 0) {
				info->run = START_SERVER;
			} else if (strncmp(postvars[i], "B9", 2) == 0) {
				info->run = STOP_SERVER;
			} else if (strncmp(postvars[i], "B1", 2) == 0) {
				info->run = ACQUIRE;
			} else if (strncmp(postvars[i], "B5", 2) == 0) {
				info->run = REPLOT;
			} else if (strncmp(postvars[i], "B4", 2) == 0) {
				info->run = SHOWSAMPLES;
			} else if (strncmp(postvars[i], "B6", 2) == 0) {
				info->run = GNUPLOT_FILES;
			} else if (strncmp(postvars[i], "FB", 2) == 0) {
				info->rawfiles = atoi(postvars[i + 1]);
			}
		}
	}

	if (!info->sdisplay.tdom)
		info->stime_s.samples = 1 << info->stime_s.fsamples;
	return 0;
};

int
CheckRequest(int form_method, char **getvars, char **postvars, s_info * info)
{

	if (info->stime_s.samples > MAXNUMSAMPLES
	    || info->stime_s.samples <= MINNUMSAMPLES)
		NDSO_Error(SAMPLE_DEPTH, form_method, getvars, postvars, info);

	if (atof(postvars[info->sdisplay.size_ratio]) <= 0
	    || atof(postvars[info->sdisplay.size_ratio]) >= MAXSIZERATIO)
		NDSO_Error(SIZE_RATIO, form_method, getvars, postvars, info);

	if (atoi(postvars[info->sdisplay.xrange]) < 0)
		NDSO_Error(RANGE, form_method, getvars, postvars, info);

	if (atoi(postvars[info->sdisplay.xrange1]) < 0)
		NDSO_Error(RANGE, form_method, getvars, postvars, info);

	if (!(postvars[info->sdisplay.xrange][0] == '*' &&
	      postvars[info->sdisplay.xrange1][0] == '*'))
		if (atof(postvars[info->sdisplay.xrange1]) <=
		    atof(postvars[info->sdisplay.xrange]))
			NDSO_Error(RANGE, form_method, getvars, postvars, info);

	if (info->run == REPLOT) {
		switch (info->sdisplay.tdom) {
		case FREQ_DOM:

			info->pFile_rawsamples =
			    fopen(info->pFILENAME_RAW_OUT, "r");

			if (info->pFile_rawsamples == NULL) {
				NDSO_Error(FILE_OPEN_SAMPLES, form_method,
					   getvars, postvars, info);
			}

			fclose(info->pFile_rawsamples);
			break;

		case TIME_DOM:
			info->pFile_samples = fopen(info->pFILENAME_T_OUT, "r");

			if (info->pFile_samples == NULL) {
				NDSO_Error(FILE_OPEN_SAMPLES, form_method,
					   getvars, postvars, info);
			}
			fclose(info->pFile_samples);
			break;

		default:
			break;
		}
	}

	return 0;
}

int
MakeFileSamples(int form_method, char **getvars, char **postvars, s_info * info)
{

	int i, ret;
	int *samples = info->samples;

	/* calculate modifier */

	info->pFile_samples = fopen(info->pFILENAME_T_OUT, "w");

	if (info->pFile_samples == NULL) {
		NDSO_Error(FILE_OPEN, form_method, getvars, postvars, info);
	}

	if (info->rawfiles)
		ret = sample_and_calc(samples, info->stime_s.samples,
				    info->pFILENAME_RAW_OUT);
	else
		ret = sample_and_calc(samples, info->stime_s.samples, NULL);

	if (ret)
		NDSO_Error(PPIOPEN, form_method, getvars, postvars, info);

	for (i = 0; i < info->stime_s.samples; i++) {
		fprintf(info->pFile_samples, "%f %f\n", i * 12.5,
			(float)samples[i]);
	}

	/* close file */

	fclose(info->pFile_samples);

	return 0;

}

int
MakeFileInit(s_info * info, int form_method, char **getvars, char **postvars)
{

	/* open file for write */

	info->pFile_init = fopen(info->pFILENAME_GNUPLT, "w");

	if (info->pFile_init == NULL) {
		NDSO_Error(FILE_OPEN, form_method, getvars, postvars, info);
	}

	/* print header information */
	fprintf(info->pFile_init, "#GNUPLOT File generated by NDSO\n");
	fprintf(info->pFile_init, "set term png\nset output \"../img%s.png\"\n",
		info->pREMOTE_ADDR);

	/* print commands */

	if (info->sdisplay.set_grid)
		fprintf(info->pFile_init, "set grid\n");

	if (info->sdisplay.axis)
		fprintf(info->pFile_init, "set xzeroaxis lt 2 lw 4\n");

	if (info->sdisplay.logscale)
		fprintf(info->pFile_init, "# %d logscale =  %x\n",
			info->sdisplay.logscale,
			postvars[info->sdisplay.logscale]);

	if (info->sdisplay.logscale)
		fprintf(info->pFile_init, "set %s\n",
			postvars[info->sdisplay.logscale]);

	if (info->sdisplay.style)
		fprintf(info->pFile_init, "set data style %s\n",
			postvars[info->sdisplay.style]);

	if (info->sdisplay.size_ratio)
		fprintf(info->pFile_init, "set size %s\n",
			postvars[info->sdisplay.size_ratio]);

	fprintf(info->pFile_init, "set xrange [%s:%s]\n",
		postvars[info->sdisplay.xrange],
		postvars[info->sdisplay.xrange1]);

	if (info->sdisplay.tdom) {

		if (postvars[info->svertical.vdiv][0] != 'X')
			fprintf(info->pFile_init, "set ytics %s\n",
				postvars[info->svertical.vdiv]);

		fprintf(info->pFile_init,
			"set xlabel \"%d Samples @ 80 MSPS                t/ns->\"\n",
			info->stime_s.samples);

		fprintf(info->pFile_init, "set ylabel \"Mag\" \n");

		if (atoi(postvars[info->sdisplay.smooth])) {

			fprintf(info->pFile_init,
				"plot  \"%s\" smooth %s notitle \nexit\n",
				info->pFILENAME_T_OUT,
				postvars[info->sdisplay.smooth]);
		} else {
			fprintf(info->pFile_init,
				"plot  \"%s\" notitle %s  \nexit\n",
				info->pFILENAME_T_OUT,
				postvars[info->sdisplay.color]);
		}
	}

	/* close file */

	fclose(info->pFile_init);

	return 0;
};

int getrand(int max)
{

	int j;
	struct timeval tv;

	if (gettimeofday(&tv, NULL) != 0) {
		printf("Error getting time\n");
	}

	srand(tv.tv_sec);
	j = 1 + (int)((float)max * rand() / (23457 + 1.0));

	return j;
};

void MakeSessionFiles(s_info * info)
{
	char str[80];

/* Generate File Names Based on the REMOTE IP ADDR */
	info->pREMOTE_ADDR = strdup(getRemoteAddr());

	info->pGNUPLOT =
	    strdup(strcat(strcpy(str, CALL_GNUPLOT), info->pREMOTE_ADDR));
	info->pFILENAME_T_OUT =
	    strdup(strcat(strcpy(str, FILENAME_T_OUT), info->pREMOTE_ADDR));
	info->pFILENAME_RAW_OUT =
	    strdup(strcat(strcpy(str, FILENAME_RAW_OUT), info->pREMOTE_ADDR));
	info->pFILENAME_GNUPLT =
	    strdup(strcat(strcpy(str, FILENAME_GNUPLT), info->pREMOTE_ADDR));

	return;
};

void CleanupSessionFiles(s_info * info)
{
	free(info->pREMOTE_ADDR);
	free(info->pFILENAME_T_OUT);
	free(info->pFILENAME_RAW_OUT);
	free(info->pFILENAME_GNUPLT);
	free(info->pGNUPLOT);

	return;
};

void DoFiles(s_info * info)
{
	int rand = getrand(6);
	printf("<hr>\n<menu>\n");

	info->pFile_samples = fopen(info->pFILENAME_T_OUT, "r");
	if (info->pFile_samples) {
		fclose(info->pFile_samples);
		printf
		    ("  <li><font face=\"Arial Black\"><a href=\"t_samples.txt_%s?id=%d\">Time Samples</a></font></li>\n",
		     info->pREMOTE_ADDR, rand);
	}

	info->pFile_init = fopen(info->pFILENAME_GNUPLT, "r");
	if (info->pFile_init) {
		fclose(info->pFile_init);
		printf
		    ("  <li><font face=\"Arial Black\"><a href=\"gnu.plt_%s?id=%d\">Gnuplot File</a></font></li>\n",
		     info->pREMOTE_ADDR, rand);
	}

	info->pFile_rawsamples = fopen(info->pFILENAME_RAW_OUT, "r");
	if (info->pFile_rawsamples) {
		fclose(info->pFile_rawsamples);
		printf
		    ("<li><font face=\"Arial Black\"><a href=\"raw_samples.txt_%s?id=%d\">Raw Samples</a></font></li>\n",
		     info->pREMOTE_ADDR, rand);
	}

	if ((info->pFile_rawsamples == NULL) && (info->pFile_samples == NULL)
	    && (info->pFile_init == NULL))
		printf
		    ("  <li><font face=\"Arial Black\">No Files available from %s</font></li>\n",
		     info->pREMOTE_ADDR);

	printf("</menu>\n<hr>\n");

	return;
};
