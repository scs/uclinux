/*
 *
 *	  Rev:			$Id: fcd.c,v 1.2 2007/12/17 07:28:09 mberner Exp $
 *	  Revision:		$Revision: 1.2 $
 *	  Source:		$Source: /cvs/ferag/BogenerkennungsImplementation/uclinux-dist/user/blkfin-apps/ppifcd-cgi-lcv/src/fcd.c,v $
 *	  Created:		Do Apr 21 11:02:09 CEST	2005
 *	  Author:		Michael	Hennerich
 *	  mail:			hennerich@blackfin.uclinux.org
 *	  Description:	PPI	frame capture driver test code
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


#ifdef TM_IN_SYS_TIME
#include <sys/time.h>
#else
#include <time.h>
#endif

#include "cgivars.h"
#include "htmllib.h"
#include "pflags.h"
#include "adsp-ppifcd.h"
#include "getSinglePic.h"

extern int i2c_write_register(char * , unsigned	char , unsigned	char , unsigned	short );
extern int i2c_read_register(char *	, unsigned char	, unsigned char	);
extern int i2c_dump_register(char *	, unsigned char	, unsigned short , unsigned	short );
extern int i2c_scan_bus(char * );
int	set_gpio(char *	, char*	);
void capture(int , char	**,	char **);
void reset_reg(int , char **, char **);
void prg_reg(int , char	**,	char **);
int	getrand(int);
char* itostr  (	 u_int	,  u_char  ,  u_char  ,	u_char);
int	WriteIMG (char *, unsigned long);
//extern void cfa2rgb( unsigned	char *,	unsigned char *	);
void MI350_init(void);


#define	I2C_DEVICE		"/dev/i2c-0"

/****************************************************************************/
#undef MT9M001
#define MT9V022
/****************************************************************************/
#ifdef MT9M001
#define	DEVID			0x5D
#define	WIDTH			1280
#define	HEIGHT			1024
#endif

//#define	MICRON_STANDBY	"/dev/pf8"
#define	MICRON_TRIGGER	"/dev/pf3"
#define	MICRON_LED	"/dev/ph6"
//#define	FS3		"/dev/pf3"

#undef USETRIGGER

/****************************************************************************/
#ifdef MT9V022
#define DEVID (0xb8>>1)
#define	WIDTH			752
#define	HEIGHT			480
#endif
/****************************************************************************/
 
#define	IMAGESIZE		(WIDTH * HEIGHT)

#define	LSB_WIDTH		(WIDTH	& 0xFF)
#define	MSB_WIDTH		((WIDTH	>> 8) &	0xFF)
#define	LSB_HEIGHT		(HEIGHT	 & 0xFF)
#define	MSB_HEIGHT		((HEIGHT >>	8) & 0xFF)
#define	BPP				8

#define	FILENAME_OUT	"/home/httpd/pics/img.bmp"


typedef	struct cgi_info
{
	unsigned int cmd;
	unsigned int reg;
	unsigned int val;

}cgi_info_t;

static cgi_info_t cgiinfo;

enum
{
  CAPTURE, PRGREG, RESETREG, RAW
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

		if(strncmp(postvars[i],	"D1", 2) == 0){	cgiinfo.reg = atoi(postvars[i +	1]); } else
		if(strncmp(postvars[i],	"T1", 2) == 0){	cgiinfo.val = atoi(postvars[i +	1]); } else
		if(strncmp(postvars[i],	"B1", 2) == 0){	cgiinfo.cmd = CAPTURE; } else
		if(strncmp(postvars[i],	"B4", 2) == 0){	cgiinfo.cmd = RAW; } else	
		if(strncmp(postvars[i],	"B2", 2) == 0){	cgiinfo.cmd = RESETREG;	} else
		if(strncmp(postvars[i],	"B3", 2) == 0){	cgiinfo.cmd = PRGREG; };

		}
	}

	//set_gpio(MICRON_STANDBY, "0");
	/* Open /dev/video0, uCam device */
	fd = open("/dev/video0", O_RDONLY, 0);
	if (fd == -1) {
	  fprintf(stderr, "Could not open /dev/video0 : %d \n", errno);
	  exit(-1);
	}
	switch(cgiinfo.cmd)
	{
		case CAPTURE:
		capture(form_method, getvars, postvars);
		break;

		case RESETREG:
		reset_reg(form_method, getvars,	postvars);
		break;

		case PRGREG:
		prg_reg(form_method, getvars, postvars);
		break;
	
		case RAW:
		captureRaw(form_method, getvars, postvars);
		

		default:
		break;
	}

	//set_gpio(MICRON_STANDBY, "1");
	if(fd && fd != -1)
	  close(fd);

  exit(0);

};

void prg_reg(int form_method, char **getvars, char **postvars)
{
  int ret;
  struct reg_info reg;


/*			htmlHeader("FCD	Write I2C Reg");
			htmlBody();
			printf("<p><font face=\"Tahoma\" size=\"7\">Wrote Register[0x%X] = 0x%X	\n</font></p>",(unsigned char)cgiinfo.reg,(unsigned	short)cgiinfo.val);
			htmlFooter();
			cleanUp(form_method, getvars, postvars);

			fflush(stdout);
*/
  reg.addr = cgiinfo.reg;
  reg.value = cgiinfo.val;

  ret = ioctl(fd, CAM_SCAMREG, &reg);
  if(ret < 0)
    fprintf(stderr, "Writing register failed!\n");

  // DEBUG
  ret = ioctl(fd, CAM_GCAMREG, &reg);
  if(ret < 0)
    fprintf(stderr, "Reading register failed!\n");

  if(reg.value != cgiinfo.val)
    fprintf(stderr, "Value was not fully accepted by register (0x%02X instead of 0x%0x2X).\n", reg.value, cgiinfo.val);

  //	i2c_write_register(I2C_DEVICE,DEVID,(unsigned char)cgiinfo.reg,(unsigned short)cgiinfo.val);
  	capture(form_method, getvars, postvars);

  return;
}

void reset_reg(int form_method,	char **getvars,	char **postvars)
{
	/* Set CMOS Sensor Init Parameters */

	/* Reset first */
	i2c_write_register(I2C_DEVICE,DEVID,0x0C,1);	
	/* Turn on Snapshot mode (set bit 4 high) */	
	//char tmp = 0;
	//tmp = i2c_read_register(I2C_DEVICE,DEVID,0x07);	
	/* bit8=0 for sequential readout */	
	i2c_write_register(I2C_DEVICE,DEVID,0x07,0x398);

	/* Color mode (0x0F set bit 2) */
	//i2c_write_register(I2C_DEVICE,DEVID,0x0F,0x15);
	i2c_write_register(I2C_DEVICE,DEVID,0x0F,0x11); //off (c.f. mt9v032.c driver)
		
	/* Mirror: Row Flip */
	i2c_write_register(I2C_DEVICE,DEVID,0x0D,0x0320);

	/* Set AGC/AEC */
	//i2c_write_register(I2C_DEVICE,DEVID,0xAF,0x0); //Disable both
	i2c_write_register(I2C_DEVICE,DEVID,0xAF,0x3); //Enable both

	/* Set Gain and Exposure */
	//i2c_write_register(I2C_DEVICE,DEVID,0x35,33); /* Analog Gain 16-64*/	
	//i2c_write_register(I2C_DEVICE,DEVID,0x0b,480);/* Total Shutter Width 1-480 */

	/* Set Noise Correction */
	//i2c_write_register(I2C_DEVICE,DEVID, 0x70 , 0x14); //Disable
	i2c_write_register(I2C_DEVICE,DEVID, 0x70 , 0x34); //Enable

	capture(form_method, getvars, postvars);

  return;
}

void capture(int form_method, char **getvars, char **postvars)
{

	/* Write some HTTP and HTML stuff to the browser at the	far end */
	htmlHeaderNocache("FCD Demo Web Page");
	htmlBody();

	getSinglePic(FILENAME_OUT, 1);
	
	printf("\n<img border=\"0\" src=\"../pics/img.bmp?id=%s\" width=\"%d\" \
	  height=\"%d\" align=\"left\">\n",itostr(getrand(6),6,1,1),WIDTH,HEIGHT);

	htmlFooter();
	fflush(stdout);

	cleanUp(form_method, getvars, postvars);
  return;
}

void captureRaw(int form_method, char **getvars, char **postvars)
{

	/* Write some HTTP and HTML stuff to the browser at the	far end */
	htmlHeaderNocache("FCD Demo Web Page");
	htmlBody();

	getSinglePic(FILENAME_OUT, 0);
	
	printf("\n<img border=\"0\" src=\"../pics/img.bmp?id=%s\" width=\"%d\" \
	  height=\"%d\" align=\"left\">\n",itostr(getrand(6),6,1,1),WIDTH,HEIGHT);

	htmlFooter();
	fflush(stdout);

	cleanUp(form_method, getvars, postvars);
  return;
}


int set_gpio(char * flag, char*	value)
{
	int	fd0;

	fd0	= open(flag, O_RDWR,0);
	if (fd0	== -1) {
		printf("%s open	error %d\n",flag,errno);
		return -1;
	}

		ioctl(fd0, SET_FIO_DIR,	OUTPUT);
		ioctl(fd0, SET_FIO_POLAR, 0);
		ioctl(fd0, SET_FIO_EDGE, 0);
		ioctl(fd0, SET_FIO_BOTH, 0);
		ioctl(fd0, SET_FIO_INEN, 0);

	write(fd0,value,sizeof("0"));

	close(fd0);

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

