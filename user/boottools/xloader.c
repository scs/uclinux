/*
 * xloader
 *
 * A replacement for ramloader and flashloader, since the loading mechanism
 * is identical and the difference is just in which call to make to the
 * uCbootloader
 *
 * (c) Michael Leslie <mleslie@arcturusnetworks.com>,
 *     Arcturus Networks Inc. 2002
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/stat.h>
#include <string.h>
#include <asm/uCbootstrap.h>
#include "flash.h"

/****** data declarations: **************************************************/

int   opt_ramloader = 0;    /* invoke ramloader */
int   opt_flashloader = 0;  /* invoke flashloader */
int   opt_quiet = 0;        /* do not print anything to the screen */
int   opt_debug = 0;        /* print debug info here and in uCbootloader */
#define DBG(a1, a2...) if (opt_debug) fprintf(stderr, a1, ##a2)
char *opt_filename = NULL;  /* filename to load */
int   opt_4k = 0;           /* Use old 4K-based version */
int   opt_secondflash = 0;  /* write to second flash device */


int   flags;
mnode_t m;

/* memory data structures: */

#define BUFFERSIZE 4096
void **chain;
int    links;

#define CARSIZE (65536 - 128)
void **train;
int    cars;

/****** function prototypes: ************************************************/

int parse_args(int argc, char *argv[]);
void usage(void);

_bsc2(int,program,void *,a1,int,a2)
_bsc2(int,program2,void *,a1,int,a2)
_bsc2(int,ramload,void *,a1,int,a2)

int load_image (char *filename);     /* malloc, sort, and read 64K blocks */
int load_image_4k (char *filename);  /* malloc and read 4K blocks */
int sort_pointers (void **train, int cars);



/****** main(): *************************************************************/

int main (int argc, char *argv[])
{

	if (parse_args (argc, argv))
		usage();

	if (!opt_4k) {
		if (load_image (opt_filename))
			exit (-1);
	} else {
		if (load_image_4k (opt_filename))
			exit (-1);
	}

	/* flags = PGM_EXEC_AFTER | */
	flags = PGM_RESET_AFTER |
		(opt_debug?(PGM_DEBUG):0);

	if (opt_ramloader)
		ramload(&m, flags);
	else if (opt_flashloader) {
		if (opt_secondflash)
			program2(&m, flags | PGM_ERASE_FIRST);
		else
			program(&m, flags | PGM_ERASE_FIRST);
	}

	/* not reached, PGM_EXEC_AFTER starts the new kernel */
	return -1;

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
	char *c;
	int i;
	int err = 0;
	char * argvp;

	/* fprintf (stderr, "argv[0] = \"%s\"\n", argv[0]); */
	c = (char *)strrchr (argv[0], '/');
	if (c == NULL) c = argv[0];
	else           c++;

	if (argc < 2)
		return (1);

	if (!strcmp (c, "ramloader"))
		opt_ramloader = 1;
	else if (!strcmp (c, "flashloader"))
		opt_flashloader = 1;

	for (i=1;i<argc;i++) {
		if (argv[i][0] == '-'){
			argvp = argv[i] + 1;
			if(!*argvp)
				return 1; /* no option */
			while(*argvp) 
				switch (*argvp++)
				{
				case 'd': opt_debug       = 1; break;
				case 'r': opt_ramloader   = 1; break;
				case 'f': opt_flashloader = 1; break;
				case '4': opt_4k          = 1; break;
				case '2': opt_secondflash = 1; break;
				case 'q': opt_quiet       = 1; break;
				case 'h': return 1;

				default:
					fprintf (stderr,
							 "Error: Unknown option \"%s\" - Aborting.\n\n", argv[i]);
					return 1;
				}
			}
		else if (opt_filename){
			fprintf (stderr, "Error: Only one image is allowed - Aborting.\n\n");
			return 1;
		}
		else opt_filename = argv[i];
	}

	/* print out options if debug enabled: */
	DBG("argv[0] = \"%s\"\n", c);
	DBG("opt_ramloader   = %d;\n", opt_ramloader);
	DBG("opt_flashloader = %d;\n", opt_flashloader);
	DBG("opt_quiet       = %d;\n", opt_quiet);
	DBG("opt_debug       = %d;\n", opt_debug);
	DBG("opt_filename    = %s\n",  opt_filename);
	DBG("opt_4k          = %d\n",  opt_4k);
	DBG("opt_secondflash = %d\n",  opt_secondflash);

	/* check the option */
	if(opt_ramloader && opt_flashloader)
	{
		fprintf(stderr, "Error: You cannot use both -r and -f options.\n");
		err = 1; 	
	}
	if(opt_ramloader && opt_secondflash)
	{
		fprintf(stderr, "Error: For ramloader, You cannot use -2 options.\n");
		err = 1; 	
	}
	if(!opt_filename)
	{
		fprintf(stderr, "Error: No image given.\n");
		err = 1; 	
	}

	if (!opt_ramloader && !opt_flashloader) {
		fprintf (stderr, 
				 "Error: neither ramloader (-r) nor flashloader (-f)\n");
		fprintf (stderr,
				 "       selected. Aborting.\n");
		err = 1; 	
	}
	if (err) return 1;

	fprintf (stderr, "Load image file: \"%s\" to %s\n",
			 opt_filename, opt_ramloader?"ram":"flash");

	return (0);
}


void usage()
{
	fprintf (stderr,
"usage: xloader | ramloader | flashloader\n"
"\n"
"       Invoked as \"ramloader\" or \"xloader -r\", this program will\n"
"       load a kernel image into RAM and pass it to uCbootloader for\n"
"       execution.\n"
"       Invoked as \"flashloader\" or \"xloader -f\", it will load a\n"
"       cramfs image and pass it to uCbootloader to be written into\n"
"       flash memory.\n"
"       In both cases, this program *will not return*. Once uCbootloader\n"
"       has been given control, interrupts are disabled, and the new\n"
"       image is booted.\n"
);
	fprintf(stderr,
"Options:\n"
"\t-2\twrite to second flash device(default is the first flash device)\n"
"\t-4\tfor 4k-based block, default 64k-based\n"
"\t-d\tprint debugging message\n"
"\t-f\tinvoke flashloader\n"
"\t-h\tthis help information\n"
"\t-r\tinvoke ramloader\n"
"\t-q\tdo it quietly, no output to the screen\n\n"
);
	exit(1);
}


int load_image (char *filename)
{
	FILE *image;
	struct stat statbuf;
	int filesize, i, j, n;
	int links_per_car, links_over;
	int percent;

	/* stat input file */
	if (stat (filename, &statbuf)) {
		perror ("Error stat()ing image file");
		return (errno);
	}

	/* otherwise, all is still OK: */
	filesize = statbuf.st_size;	

	/* build buffer chain: */
	links = (int) ((filesize + BUFFERSIZE -1) / BUFFERSIZE);
	/* chain = (void *)malloc (links * sizeof (void *)); */

	/* build link train: */
	links_per_car = CARSIZE / BUFFERSIZE;
	cars = 1 + links / links_per_car;

	/* Can we fit the chain into the last car? */
	/* How many links in the last car? */
	links_over = links - (cars - 1) * links_per_car;
	if ((CARSIZE - links_over*BUFFERSIZE) <
		links * sizeof (void *)) {
		/* then the chain can not be placed in the last car;
		 * allocate one more.*/
		cars++;
		links_over = links - (cars - 1) * links_per_car;
		if (links_over < 0) links_over = 0;
	}

	/* allocate the array of cars: */
	/* note: this array can be discarded once the chain of links
	 * has been mapped onto the actual buffers */
	train = (void *)malloc(cars * sizeof (void *));
	if ( train == NULL) {
		fprintf (stderr, "Error allocating train\n");
		return (errno);
	}
	/* allocate the cars: */
	for (i=0;i<cars;i++) {
		train[i] = (void *)malloc(CARSIZE);
		if (train[i] == NULL) {
			fprintf (stderr, "Error allocating car %d\n", i);
			/* before we return, free all allocated memories */
			{ int j;
			  for(j=0;j<i; j++)
				free(train[j]);
			  free(train);
			}  
			return (errno);
		}
	}

	/* sort the cars */
	sort_pointers (train, cars);


	/* map the chain into the last car: */
	chain = (void *)(train[cars-1]) + (links_over * BUFFERSIZE);

	/* allocate links into the cars: */
	for (i=0;i<cars;i++,j++) {
		DBG("\ntrain[%d] = %p cars:\n", i, train[i]);
		for (j=0;j<links_per_car;j++) {
			if (i*links_per_car+j >= links)
				break;
			chain[i*links_per_car+j] = train[i] + (BUFFERSIZE * j);
			DBG("  0x%08x", (unsigned int)chain[i*links_per_car+j]);
		}
	}

	DBG("filesize = %d, links = %d\n", filesize, links);

	DBG("cars = %d, links_per_car = %d, links_over = %d\n", cars, links_per_car, links_over);

	DBG("car[%d] = %p, chain = %p\n", cars-1, train[cars-1], chain);


	/* open image file: */
	image = fopen (filename, "r");
	if (image == NULL) {
		perror ("Error opening image file");
		return (errno);
	}


	/* populate chain with image file: */
	for (i=0;i<cars;i++) {
		if ((i+1)*links_per_car <= links)
			j = links_per_car;
		else
			j = links_over;

		n = fread (train[i], j, BUFFERSIZE, image);

		if (opt_debug)
			fprintf(stderr, "fread %d bytes to car[%d] = %p\n",
					j*BUFFERSIZE, i, train[i]);
		else {
			percent = (((i*links_per_car+j)+1) * 100)/links;
			/* if (percent%10 == 0) */
			fprintf (stderr, "\r%d%%", percent);
		}

		if (n < j) {
			fprintf (stderr, "Error #%d reading from image file\n",
					 ferror (image));
			fclose (image);
			return (-1);
		}
	}
	if (!opt_debug) fprintf (stderr, "\n");


 	fclose (image);
	free(train);

	/* set uCbootloader arguments: */
	m.len = filesize;
	m.offset = (void *)chain;

	return (0);
}

int sort_pointers (void **pointer, int N)
{
	int i, j;
	void *p;

	/* sort pointers */
	for (i=0;i<N;i++) {
		p = pointer[i];
		for (j=i+1;j<N;j++) {
			if ((unsigned long int)pointer[j] < (unsigned long int)p) {
				p          = pointer[j];
				pointer[j] = pointer[i];
				pointer[i] = p;
			}
		}
	}
	return (0);
}



int load_image_4k (char *filename)
{
	FILE *image;
	struct stat statbuf;
	int filesize, i, n;
	int percent;

	/* stat input file */
	if (stat (filename, &statbuf)) {
		perror ("Error stat()ing image file");
		return (errno);
	}

	/* otherwise, all is still OK: */
	filesize = statbuf.st_size;	

	/* build buffer chain: */
	DBG("pointer chain:\n");
	links = filesize / BUFFERSIZE;
	chain = (void *)malloc (links * sizeof (void *));
	for (i=0;i<links;i++) {
		chain[i] = (void *)malloc (BUFFERSIZE);
		DBG("  0x%08x", (unsigned int)chain[i]);
		if (chain[i] == NULL) {
			fprintf (stderr, "Error allocating chain link %d\n", i);
			return (errno);
		}
	}

	DBG("filesize = %d, links = %d\n", filesize, links);

	/* open image file: */
	image = fopen (filename, "r");
	if (image == NULL) {
		perror ("Error opening image file");
		return (errno);
	}


	/* populate chain with image file: */
	for (i=0;i<links;i++) {
		n = fread (chain[i], 1, BUFFERSIZE, image);

		if (opt_debug)
			fprintf(stderr,
					"fread %d bytes to chain[%d] = %p\n", n, i,chain[i]);
		else {
			percent = ((i+1) * 100)/links;
			if (percent%10 == 0)
				fprintf (stderr, "\r%d%%", percent);
		}

		if ((n < BUFFERSIZE) && (BUFFERSIZE*i + n < filesize)) {
			fprintf (stderr, "Error #%d reading from image file\n",
					 ferror (image));
			fclose (image);
			return (-1);
		}
	}
	if (!opt_debug) fprintf (stderr, "\n");

	fclose (image);

	/* set uCbootloader arguments: */
	m.len = filesize;
	m.offset = (void *)chain;

	return (0);
}


/****************************************************************************/

/*
 * Local variables:
 *  c-indent-level: 4
 *  c-basic-offset: 4
 *  tab-width: 4
 * End:
 */
