/* Generate a header file for a particular 
   single or double frequency */

#include <stdio.h>
#include <math.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#define CLIP 32635
#define BIAS 0x84

/* Dial frequency tables */
typedef struct
{
char    chr;    /* character representation */
float   f1;     /* first freq */
float   f2;     /* second freq */
} ZAP_DIAL;
 
ZAP_DIAL dtmf_dial[] = {
{ '0',941.0,1336.0 },
{ '1',697.0,1209.0 },
{ '2',697.0,1336.0 },
{ '3',697.0,1477.0 },
{ '4',770.0,1209.0 },
{ '5',770.0,1336.0 },
{ '6',770.0,1477.0 },
{ '7',852.0,1209.0 },
{ '8',852.0,1336.0 },
{ '9',852.0,1477.0 },
{ '*',941.0,1209.0 },
{ '#',941.0,1477.0 },
{ 'A',697.0,1633.0 },
{ 'B',770.0,1633.0 },
{ 'C',852.0,1633.0 },
{ 'D',941.0,1633.0 },
{ 0,0,0 }
} ;
 
ZAP_DIAL mf_dial[] = {
{ '0',1300.0,1500.0 },
{ '1',700.0,900.0 },
{ '2',700.0,1100.0 },
{ '3',900.0,1100.0 },
{ '4',700.0,1300.0 },
{ '5',900.0,1300.0 },
{ '6',1100.0,1300.0 },
{ '7',700.0,1500.0 },
{ '8',900.0,1500.0 },
{ '9',1100.0,1500.0 },
{ '*',1100.0,1700.0 }, /* KP */
{ '#',1500.0,1700.0 }, /* ST */
{ 'A',900.0,1700.0 }, /* ST' */
{ 'B',1300.0,1700.0}, /* ST'' */
{ 'C',700.0,1700.0}, /* ST''' */
{ 0,0,0 }
} ;                                                                             

unsigned char
linear2ulaw(sample)
short sample; {
  static int exp_lut[256] = {0,0,1,1,2,2,2,2,3,3,3,3,3,3,3,3,
                             4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,4,
                             5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
                             5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
                             6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
                             6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
                             6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
                             6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
                             7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
                             7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
                             7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
                             7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
                             7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
                             7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
                             7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
                             7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7};
  int sign, exponent, mantissa;
  unsigned char ulawbyte;
 
  /* Get the sample into sign-magnitude. */
  sign = (sample >> 8) & 0x80;          /* set aside the sign */
  if (sign != 0) sample = -sample;              /* get magnitude */
  if (sample > CLIP) sample = CLIP;             /* clip the magnitude */
 
  /* Convert from 16 bit linear to ulaw. */
  sample = sample + BIAS;
  exponent = exp_lut[(sample >> 7) & 0xFF];
  mantissa = (sample >> (exponent + 3)) & 0x0F;
  ulawbyte = ~(sign | (exponent << 4) | mantissa);
#ifdef ZEROTRAP
  if (ulawbyte == 0) ulawbyte = 0x02;   /* optional CCITT trap */
#endif
 
  return(ulawbyte);
}                                                                                            

#define LEVEL -10

int process(FILE *f, char *label, ZAP_DIAL z[])
{
	char c;
	float gain;
	int fac1, init_v2_1, init_v3_1,
	    fac2, init_v2_2, init_v3_2;

	while(z->chr) {
		c = z->chr;
		if (c == '*')
			c = 's';
		if (c == '#')
			c ='p';
		/* Bring it down 6 dbm */
		gain = pow(10.0, (LEVEL - 3.14) / 20.0) * 65536.0 / 2.0;

		fac1 = 2.0 * cos(2.0 * M_PI * (z->f1 / 8000.0)) * 32768.0;
		init_v2_1 = sin(-4.0 * M_PI * (z->f1 / 8000.0)) * gain;
		init_v3_1 = sin(-2.0 * M_PI * (z->f1 / 8000.0)) * gain;
		
		fac2 = 2.0 * cos(2.0 * M_PI * (z->f2 / 8000.0)) * 32768.0;
		init_v2_2 = sin(-4.0 * M_PI * (z->f2 / 8000.0)) * gain;
		init_v3_2 = sin(-2.0 * M_PI * (z->f2 / 8000.0)) * gain;

		fprintf(f, "\t /* %s_%c */ { %d, %d, %d, %d, %d, %d, DEFAULT_DTMF_LENGTH, &%s_silence }, \n", label, c,
			fac1, init_v2_1, init_v3_1, 
			fac2, init_v2_2, init_v3_2,
			label);
		
		z++;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	FILE *f;
	
	if ((f = fopen("tones.h", "w"))) {
		fprintf(f, "/* DTMF and MF tones used by the Tormenta Driver, in static tables.\n"
				   "   Generated automatically from gendigits.  Do not edit by hand.  */\n"); 
		fprintf(f, "static struct zt_tone dtmf_tones[16] = {\n");
		process(f, "dtmf", dtmf_dial);
		fprintf(f, "};\n\n");
		fprintf(f, "static struct zt_tone mfv1_tones[15] = {\n");
		process(f, "mfv1", mf_dial);
		fprintf(f, "};\n\n");
		fprintf(f, "/* END tones.h */\n");
		fclose(f);
	} else {
		fprintf(stderr, "Unable to open tones.h for writing\n");
		return 1;
	}

	return 0;
}   
