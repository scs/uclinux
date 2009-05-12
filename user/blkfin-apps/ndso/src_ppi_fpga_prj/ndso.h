/* ------------ Defines ------------ */

#define DEBUG 				0

#define CALL_GNUPLOT "/bin/gnuplot /home/httpd/cgi-bin/gnu.plt_"
#define FILENAME_T_OUT "/home/httpd/cgi-bin/t_samples.txt_"
#define FILENAME_RAW_OUT "/home/httpd/cgi-bin/raw_samples.txt_"
#define FILENAME_GNUPLT "/home/httpd/cgi-bin/gnu.plt_"

#define SERVERAPP	"fpga_netd"

#define VALUE_FRAME "\n<html>\n<head>\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=windows-1252\">\n<title></title></head><body> <p><font face=\"Tahoma\" size=\"10\">%4.3f Volt</font></p>\n"

#define MINSAMPLERATE 		1	//Samples per second
#define MAXNUMSAMPLES 		4097	//Samples per second
#define MINNUMSAMPLES 		4	//Number of samples
#define MAXSIZERATIO		4	//relative to the default size
#define TIMEOUT				10	//seconds

#ifndef fixed
#define fixed short
#endif

/* ------------ Structs ------------ */

typedef struct {
	unsigned short vdiv;
} vertical;

typedef struct {
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
} display;

typedef struct {
	unsigned int sps;
	unsigned int samples;
	unsigned int fsamples;
} time_set;

typedef struct {
	unsigned int adc_port;
	unsigned int dac_port;
	unsigned int ctl_port;
} net_server;

typedef struct {
	display sdisplay;
	vertical svertical;
	time_set stime_s;
	net_server server;
	unsigned short run;
	int fd0;
	int rawfiles;
	FILE *pFile_samples;
	FILE *pFile_rawsamples;
	FILE *pFile_init;
	char *pFILENAME_T_OUT;
	char *pFILENAME_RAW_OUT;
	char *pFILENAME_GNUPLT;
	char *pGNUPLOT;
	char *pREMOTE_ADDR;
	int *samples;
} s_info;

/* ------------ Enums ------------ */

enum {
	ACQUIRE, REPLOT, MULTIMETER, SHOWSAMPLES, GNUPLOT_FILES, START_SERVER,
	    STOP_SERVER
};				/* what program we want to run */

enum {
	PPIOPEN, FILE_OPEN, MEMORY, TRIGCOND, TRIGGER_LEVEL, SAMPLE_RATE,
	SAMPLE_DEPTH, SIZE_RATIO, RANGE, FILE_OPEN_SAMPLES, EMPTY_PLOT, TIME_OUT
};

enum {
	FREQ_DOM, TIME_DOM
};

/* ------------ some globals ------------ */

/* ------------ function prototypes ------------ */

int DoDM_HTML_Page(int, char **, char **, s_info *);
int ParseRequest(int, char **, char **, s_info *);
int CheckRequest(int, char **, char **, s_info *);
int Sample(int, char **, char **, s_info *);
int DoHTML(s_info *, int, char **, char **);
int NDSO_Error(int, int, char **, char **, s_info *);
int AllocateMemory(int, char **, char **, s_info *);
int MakeFileSamples(int, char **, char **, s_info *);
int MakeFileRawSamples(int, char **, char **, s_info *);
int MakeFileInit(s_info *, int, char **, char **);
int PrintSamples(s_info *);
void MakeSessionFiles(s_info *);
void CleanupSessionFiles(s_info *);
int getrand(int);
char *itostr(u_int, u_char, u_char, u_char);
int DoMeasurements(s_info *);
void DoFiles(s_info *);
