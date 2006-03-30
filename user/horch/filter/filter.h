

#define TRUE       1
#define FALSE      0

#define MAX_RANGE  50u       /* Maximale Anzahl von Filter-Bereichen */
#define RANGE_MIN  0u        /* Minimaler Wert für eine Bereichsgrenze */
#define RANGE_MAX  0x1FFFFFFFul    /* Maximaler Wert für eine Message ID */

#define MAX_LEN_PARA_STRING 256  // Zulässige Länge eines Parameterstrings
#define ERROR_FILTERPARAMETER "\n\rFilterparameter fehlerhaft!\n\r"

/* parameter for filter_init() */
#define FILTER_REMOVE	(-1)

extern int debug;	/* global debug flag */


void filter_init( int number ); //Init
void f_array_h(int client);           // Ausgabe Filterarray
int filter(const unsigned char client, const unsigned long int id);    // Filterroutine
int read_fp_string(unsigned char client, char *fp_string);  // Routine zur Auswertung des Parameter-
				// strings -f...
void u_char_cpy(char *res,char *sc,char seek_char);    // Stringroutine

/* Testversion, write to fp_string, no overflow check */
void getFilterParams( unsigned char client, char *fp_string, int unused ); 
