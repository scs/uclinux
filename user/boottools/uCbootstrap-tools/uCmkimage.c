/*
 * uCmkimage.c:
 *
 *      Prepend an image header to a binary image file destined
 *      for a platform running Arcturus Networks' uCbootstrap
 *      bootloader.
 *
 * (c) 2004 Arcturus Networks Inc. by
 *     Michael Leslie <mleslie@arcturusnetworks.com>
 *
 * Note that this needs to be made to ensure that the values
 * written to the header are little-endian
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"
#include "uCheader.h"


#define DBG(a1, a2...) if (opt_debug) fprintf(stderr, a1, ##a2)

/****** data declarations: **************************************************/

char *opt_filename = NULL;    /* image filename to load */
char *opt_outfilename = NULL; /* image filename to load */
int   opt_stdin       = 0;    /* read image from stdin instead of filesystem */
char *opt_name;               /* image filename or ID */
char *opt_datecode;           /* image date code */

int   opt_quiet = 0;          /* do not print anything to the screen */
int   opt_debug = 0;

int           header_size;  /* after which data begins */
int           data_size;    /* size of image in bytes */
char          datecode[12]; /* output of 'date -I': "yyyy-mm-dd" */
unsigned char md5sum[16];   /* binary md5sum of data */

uCimage_header header;


FILE *infile, *outfile;
#define BUFFERSIZE 65536
char buf[BUFFERSIZE];

/****** function prototypes: ************************************************/

int parse_args(int argc, char *argv[]);
void usage(void);


/****** main(): *************************************************************/

int main (int argc, char *argv[])
{
	unsigned int       i;
	unsigned int       n = 0;
	unsigned int       size = 0;
	struct MD5Context  md5c;


	if (parse_args (argc, argv))
		if (!opt_quiet)
			usage();

	/* Initialize MD5 module: */
	MD5Init(&md5c);


	/* Initialize various header data: ***************************/

	/* set magic in header */
	for (i=0;i<sizeof(header.magic);i++)
		header.magic[i] = UCHEADER_MAGIC[i];

	/* set header size */
	header.header_size = sizeof(uCimage_header);

	/* set header date code */
	strncpy (header.datecode, opt_datecode, sizeof(header.datecode));

	/* set header name */
	strncpy (header.name, opt_name, sizeof(header.name));


	/* Open input and output files: ******************************/
	if (opt_stdin)
		infile = stdin;
	else
		infile = fopen (opt_filename, "r");

	if (infile == NULL) {
		fprintf (stderr, "FATAL: could not open %s\n", opt_filename);
		exit(1);
	}

	outfile = fopen (opt_outfilename, "w");
	if (outfile == NULL) {
		fprintf (stderr, "FATAL: could not open %s\n", opt_outfilename);
		exit(1);
	}

	/* Write header and image file to output, compute MD5: ******/
	/* write header: */
	fwrite (&header, sizeof(header), 1, outfile);

	/* copy image and do MD5: */
	while (!feof(infile)) {
		n = fread (buf, 1, BUFFERSIZE, infile);
		size += n;
		MD5Update (&md5c, buf, n);
		fwrite (buf, 1, n, outfile);
	}
	/* write image size to header: */
	header.data_size = size;

	/* copy MD5 to header: */
	MD5Final (header.md5sum, &md5c);


	/* rewind output file to update header: */
	rewind (outfile);
	/* rewrite header: */
	fwrite (&header, sizeof(header), 1, outfile);


	if (!opt_stdin)
		fclose (infile);
	fclose (outfile);

	return (0);
}


/****** function declarations: **********************************************/

/*
 * parse_args(int argc, char *argv[])
 *
 * Parse command line arguments and set corresponding
 * opt_xxx variables.
 *
 */
int parse_args(int argc, char *argv[])
{
	int i;
	int err = 0;
	char * argvp;

	if (argc < 2)
		return (1);


	for (i=1;i<argc;i++) {
		if (argv[i][0] == '-') {
			argvp = argv[i] + 1;

			if (!*argvp) {
				if (i < argc-1)
					return 1; /* no option */
				else {
					opt_stdin = 1;
					opt_filename = "-";
				}
			}


			while(*argvp) {
				switch (*argvp++)
					{
					case 'f': opt_filename    = argv[++i]; break;
					case 'o': opt_outfilename = argv[++i]; break;

					case 't': opt_datecode    = argv[++i]; break;
					case 'n': opt_name        = argv[++i]; break;

					case 's':
						opt_stdin    = 1;
						opt_filename = "-";
						break;

					case 'h': return 1;
					case 'q': opt_quiet = 1; break;
					case 'd': opt_debug = 1; break;


					default:
						if (!opt_quiet)
							fprintf (stderr,
									 "Error: Unknown option \"%s\" - Aborting.\n\n",
									 argv[i]);
						return 1;
					}
			}

		} else
			opt_filename = argv[i];
	}

	/* print out options if debug enabled: */
	DBG("opt_name        = \"%s\"\n", opt_name);
	DBG("opt_filename    = %s\n",  opt_filename);
	DBG("opt_outfilename = %s\n",  opt_outfilename);


	if(!opt_filename) {
		if (!opt_quiet)
			fprintf(stderr, "Error: No image given.\n");
		err = 1; 	
	}


	if (err) return 1;

	if (!opt_quiet) {
		fprintf (stderr, "Prepend header to: \"%s\"\n", opt_filename);
	}
	return (0);
}



void usage()
{
	fprintf (stderr,
"usage: uCmkimage [options] <image filename>\n"
"\n"
"       Prepend an image header to a binary image file destined\n"
"       for a platform running Arcturus Networks' uCbootstrap\n"
"       bootloader.\n"
"\n"
);
	fprintf(stderr,
"Options:\n"
"\t-f <filename>\tinput image filename\n"
"\t-o <filename>\toutput image filename\n"
"\t-t <date code - %d chars>\n"
"\t-n <image name or ID - %d chars>\n"
"\t-s\tRead image file from stdin\n"
"\t-h\tthis help information\n"
"\t-d\tprint debugging message\n"
			"\t-q\tdo it quietly, no output to the screen\n\n",
			sizeof(header.datecode),
			sizeof(header.name)
			
);
	exit(1);
}




/****************************************************************************/

/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
