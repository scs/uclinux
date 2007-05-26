/* ------------ Defines ------------ */

#define DEBUG 				0

#define CALL_GNUPLOT "/bin/gnuplot /home/httpd/cgi-bin/gnu.plt_"
#define FILENAME_T_OUT "/home/httpd/cgi-bin/t_samples.txt_"
#define FILENAME_F_OUT "/home/httpd/cgi-bin/f_samples.txt_"
#define FILENAME_GNUPLT "/home/httpd/cgi-bin/gnu.plt_"


#define VALUE_FRAME "\n<html>\n<head>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=windows-1252\">\n<title></title></head><body> <p><font face=\"Tahoma\" size=\"10\">%4.3f Volt</font></p>\n"

#define MINSAMPLERATE 		1     //Samples per second
#define MAXNUMSAMPLES 		4000  //Samples per second 
#define MINNUMSAMPLES 		4     //Number of samples
#define MAXSIZERATIO		4     //relative to the default size
#define TIMEOUT				10    //seconds

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
  short level;
} trigger;


typedef struct
{
  unsigned short vdiv;
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
  short valuemin;
  short valuemax;
  short valuemean;
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
  int framebuffer;
  FILE *pFile_samples;
  FILE *pFile_fsamples;
  FILE *pFile_init;
  char *pFILENAME_T_OUT;
  char *pFILENAME_F_OUT; 
  char *pFILENAME_GNUPLT;
  char *pGNUPLOT;
  char *pREMOTE_ADDR; 
  unsigned short *samples;
} s_info;




/* ------------ Enums ------------ */



enum
{
  ACQUIRE, REPLOT, MULTIMETER, SHOWSAMPLES, GNUPLOT_FILES
};				/* what program we want to run */

enum
{
  SPIOPEN, FILE_OPEN, MEMORY, TRIGCOND, TRIGGER_LEVEL, SAMPLE_RATE,
    SAMPLE_DEPTH, SIZE_RATIO, RANGE, FILE_OPEN_SAMPLES, EMPTY_PLOT, TIME_OUT
};

enum
{
 FREQ_DOM, TIME_DOM
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
void MakeSessionFiles (s_info *);
void CleanupSessionFiles (s_info *);
int str2num (char *);
int getrand (int);
char *itostr (u_int, u_char, u_char, u_char);
int DoMeasurements (s_info *);
int SampleToVoltage (unsigned short value, s_info * );
int VoltageToSample (short , s_info * );
int GetMaxSampleValue (s_info * );
void DoFiles (s_info * );

extern int fix_fft (fixed *, fixed *, int, int);
extern int iscale (int, int, int);
extern void window (fixed *, int);
extern int gettimeofday (struct timeval *, void *);
