/* ------------ Defines ------------ */


#define FILENAME_T_OUT "/home/httpd/cgi-bin/t_samples.txt"
#define FILENAME_F_OUT "/home/httpd/cgi-bin/f_samples.txt"
#define FILENAME_GNUPLT "/home/httpd/cgi-bin/gnu.plt"
#define FILENAME_VALUE "/home/httpd/cgi-bin/value.htm"

#define INLINE_FRAME "Content-type: text/html\n\n<html>\n\n<head>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=windows-1252\">\n<META HTTP-EQUIV=\"PRAGMA\" CONTENT=\"NO-CACHE\"><meta http-equiv=\"Expires\" CONTENT=\"-1\">\n<title>\n</title>\n</head>\n<body>\n<p>&nbsp;<H1>Digital Multimeter</H1>\n<p>\n<iframe name=\"I1\" width=\"367\" height=\"180\" scrolling=\"no\"  border=\"0\" frameborder=\"0\" src=\"value.htm\">\nYour browser does not support inline frames or is currently configured not to display inline frames.\n</iframe></p>\n</body>\n</html>\n"
#define VALUE_FRAME "\n<html>\n<head>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=windows-1252\">\n<title></title></head><body> <p><font face=\"Tahoma\" size=\"10\">%d mVolt</font></p>\n"


#define AC_MODE_DC_OFFSET 	2048

#define MAXTRIGGERLEVEL 	4096
#define MINTRIGGERLEVEL 	0
#define MAXSAMPLERATE 		1000000
#define MINSAMPLERATE 		1
#define MAXNUMSAMPLES 		4000
#define MINNUMSAMPLES 		4


#define DEBUG 				0


#define OUT_DEC 1		//Converts the number based on the decimal format
#define OUT_BIN 2		// Converts the number based on the binary format
#define OUT_HEX 3		//Converts the number based on the hexadecimal format

#ifndef fixed
#define fixed short
#endif


/* ------------ Structs ------------ */

typedef struct
{
  unsigned short mode;
  unsigned short sense;
  unsigned short edge;
  unsigned short level;
} trigger;


typedef struct
{
  unsigned short vdiv;
//      int voffset;
} vertical;


typedef struct
{
  unsigned short set_grid;
  unsigned short axis;
  unsigned short style;
  unsigned short linestyle;
  unsigned short color;
  unsigned short logscale;
  unsigned short size_ratio;
  unsigned short xrange;
  unsigned short xrange1;
  unsigned short smooth;
  unsigned short tdom;
  unsigned short fftscaled;
  unsigned short fftexludezero;
} display;

typedef struct
{
  unsigned short min;
  unsigned short max;
  unsigned short mean;
  unsigned short valuemin;
  unsigned short valuemax;
  unsigned short valuemean;
} measurements;


typedef struct
{
  unsigned short mode;
  unsigned short type;

} input;

typedef struct
{
  unsigned int sps;
  unsigned int samples;
  unsigned int fsamples;
} time_set;

typedef struct
{
  trigger strigger;
  display sdisplay;
  vertical svertical;
  measurements smeasurements;
  input sinput;
  time_set stime_s;
  unsigned short run;
  int fd0;
  FILE *pFile_samples;
  FILE *pFile_fsamples;
  FILE *pFile_init;
  unsigned short *samples;
} s_info;




/* ------------ Enums ------------ */



enum
{
  ACQUIRE, REPLOT, MULTIMETER, SHOWSAMPLES
};				/* what program we want to run */

enum
{
  SPIOPEN, FILE_OPEN, MEMORY, TRIGCOND, TRIGGER_LEVEL, SAMPLE_RATE,
    SAMPLE_DEPTH, SIZE_RATIO, RANGE
};



/* ------------ some globals ------------ */



/* ------------ function prototypes ------------ */

int DoDM_HTML_Page (int, char **, char **, s_info *);
int ParseRequest (int, char **, char **, s_info *);
int CheckRequest (int, char **, char **, s_info *);
int Sample (int, char **, char **, s_info *);
int DoHTML (int, char **, char **, s_info *);
int NDSO_Error (int, int, char **, char **, s_info *);
int AllocateMemory (int, char **, char **, s_info *);
int MakeFileSamples (int, char **, char **, s_info *);
int MakeFileFrequencySamples (int, char **, char **, s_info *);
int MakeFileInit (int, char **, char **, s_info *);
int PrintSamples (s_info *);
int str2num (char *);
int getrand (int);
char *itostr (u_int, u_char, u_char, u_char);
int DoMeasurements (s_info *);

extern int fix_fft (fixed *, fixed *, int, int);
extern int iscale (int, int, int);
extern void window (fixed *, int);
extern int gettimeofday (struct timeval *, void *);
