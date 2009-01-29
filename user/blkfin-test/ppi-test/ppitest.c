#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

#include "ppi.h"

#define LINELEN  16
#define NUMLINES 8
#define	DIM2D	2
#define	MAXROWS	2800
#define	MAXCOLS	3400
#define	MAXIMAGESZ	(MAXROWS * MAXCOLS * sizeof(UINT16) )
#define	FILL_ONLY	1
// on STAMP board some bits are shared with network controller
// all bits can't be transfered without changing CPLD
#define PPIVBITS	0x07FF

typedef unsigned char	UINT8;
typedef unsigned short	UINT16;

char	gPatternID;
UINT16	gPatternVal;
UINT16	gRows;
UINT16	gCols;
UINT16 *gImage = NULL;
int		gImageSize;



typedef struct cfgTableStruct
{
	unsigned int cmd, arg;
} CfgTable;


CfgTable ppiMasterTable1D[] = {
	{ CMD_PPI_PORT_DIRECTION, CFG_PPI_PORT_DIR_TX },  // write
	{ CMD_PPI_PACKING, CFG_PPI_PACK_DISABLE },
	{ CMD_PPI_SKIPPING, CFG_PPI_SKIP_DISABLE },
	{ CMD_PPI_SKIP_ODDEVEN, CFG_PPI_SKIP_ODD },
	{ CMD_PPI_DATALEN, CFG_PPI_DATALEN_14 },
	{ CMD_PPI_CLK_EDGE, CFG_PPI_CLK_EDGE_RISE },
	{ CMD_PPI_TRIG_EDGE, CFG_PPI_TRIG_EDGE_RISE },
	{ CMD_PPI_XFR_TYPE, CFG_PPI_XFR_TYPE_SYNC },
	{ CMD_PPI_PORT_CFG, CFG_PPI_PORT_CFG_SYNC1 },
	{ CMD_PPI_SET_DIMS, CFG_PPI_DIMS_1D },
	{ CMD_PPI_DELAY, 0 }, 
	{ CMD_PPI_GEN_FS12_TIMING_ON_WRITE, 1 }, 
	{ 0, 0 }
},
ppiMasterTable2D[] = {
	{ CMD_PPI_PORT_DIRECTION, CFG_PPI_PORT_DIR_TX },  // write
	{ CMD_PPI_PACKING, CFG_PPI_PACK_DISABLE },
	{ CMD_PPI_SKIPPING, CFG_PPI_SKIP_DISABLE },
	{ CMD_PPI_SKIP_ODDEVEN, CFG_PPI_SKIP_ODD },
	{ CMD_PPI_DATALEN, CFG_PPI_DATALEN_14 },
	{ CMD_PPI_CLK_EDGE, CFG_PPI_CLK_EDGE_RISE },
	{ CMD_PPI_TRIG_EDGE, CFG_PPI_TRIG_EDGE_RISE },
	{ CMD_PPI_XFR_TYPE, CFG_PPI_XFR_TYPE_SYNC },
	{ CMD_PPI_PORT_CFG, CFG_PPI_PORT_CFG_SYNC23 }, 
	{ CMD_PPI_SET_DIMS, CFG_PPI_DIMS_2D },
	{ CMD_PPI_DELAY, 0 }, 
	{ CMD_PPI_GEN_FS12_TIMING_ON_WRITE, 1 }, 
	{ 0, 0 }
},
ppiSlaveTable1D[] = {
	{ CMD_PPI_PORT_DIRECTION, CFG_PPI_PORT_DIR_RX },  // read
	{ CMD_PPI_PACKING, CFG_PPI_PACK_DISABLE },
	{ CMD_PPI_SKIPPING, CFG_PPI_SKIP_DISABLE },
	{ CMD_PPI_SKIP_ODDEVEN, CFG_PPI_SKIP_ODD },
	{ CMD_PPI_DATALEN, CFG_PPI_DATALEN_14 },
	{ CMD_PPI_CLK_EDGE, CFG_PPI_CLK_EDGE_FALL },
	{ CMD_PPI_TRIG_EDGE, CFG_PPI_TRIG_EDGE_RISE },
	{ CMD_PPI_XFR_TYPE, CFG_PPI_XFR_TYPE_NON646 },
	{ CMD_PPI_PORT_CFG, CFG_PPI_PORT_CFG_XSYNC1 },
	{ CMD_PPI_SET_DIMS, CFG_PPI_DIMS_1D },
	{ CMD_PPI_DELAY, 1 }, 
	{ 0, 0 }
},
ppiSlaveTable2D[] = {
	{ CMD_PPI_PORT_DIRECTION, CFG_PPI_PORT_DIR_RX },  // read
	{ CMD_PPI_PACKING, CFG_PPI_PACK_DISABLE },
	{ CMD_PPI_SKIPPING, CFG_PPI_SKIP_DISABLE },
	{ CMD_PPI_SKIP_ODDEVEN, CFG_PPI_SKIP_ODD },
	{ CMD_PPI_DATALEN, CFG_PPI_DATALEN_14 },
	{ CMD_PPI_CLK_EDGE, CFG_PPI_CLK_EDGE_RISE },
	{ CMD_PPI_TRIG_EDGE, CFG_PPI_TRIG_EDGE_RISE },
	{ CMD_PPI_XFR_TYPE, CFG_PPI_XFR_TYPE_NON646 },
	{ CMD_PPI_PORT_CFG, CFG_PPI_PORT_CFG_XSYNC23 },
	{ CMD_PPI_SET_DIMS, CFG_PPI_DIMS_2D },
	{ CMD_PPI_DELAY, 1 }, 
	{ 0, 0 }
};

/*
**	Function:	realloc_image()
**
**	Global Values Affected:
**  allocate image based on maximum gImageSize
**	reset gImageSize based on current values of rows & cols
*/
UINT16 *
realloc_image()
{
	/* allocate image buffer */
	if (!gImage)
		gImage = (UINT16 *)malloc( gRows * gCols * sizeof(UINT16) );

	if ( gImage == NULL ){
		perror("malloc");
	}

	gImageSize = (size_t)(gRows * gCols * sizeof(UINT16));

	printf("new gImageSize( %X ) = 0x%X (%d)\n", gImage, gImageSize, gImageSize );

	return gImage;
}


int
fill_verifyBuffer( UINT16 *buf, UINT16 bufX, UINT16 bufY, 
				char pattern, UINT16 value, UINT8 fill )
{
	UINT16 i = 0;
	UINT16 x = 0;
	UINT16 y = 0;
	int		errorCnt = 0;

	if (fill)
		printf("fillBuffer(%X, %hd, %hd, '%c', 0x%hX)\n", 
				buf, bufX, bufY, pattern, value );

	while ( y < bufY ) {
		x = 0;
		while ( x < bufX ) {
			switch(pattern) {
				case 't':
				case 'T':
					/* tile of alternating row/column numbers */
					if ( x & 1 ){
						if (fill)
							*buf++ = x + 1;
						else
							if( *buf++ != ((x+1) & PPIVBITS) )
								errorCnt++;
					}
					else {
						if (fill)
							*buf++ = y + 1;
						else
							if( *buf++ != ((y+1) & PPIVBITS) )
								errorCnt++;
					}
					break;
				case 's':
				case 'S':
					/* use incremental counting pattern */
					if (fill)
						*buf++ = i++;
					else
						if( *buf++ != (i++ & PPIVBITS) )
							errorCnt++;
					break;
				case 'c':
				case 'C':
					/* use column number */
					if (fill)
						*buf++ = x + 1;	
					else
						if( *buf++ != ((x+1) & PPIVBITS) )
							errorCnt++;
					break;
				case 'r':
				case 'R':
					/* use row number */
					if (fill)
						*buf++ = y + 1;
					else
						if( *buf++ != ((y+1) & PPIVBITS) )
							errorCnt++;
					break;
				case 'v':
				case 'V':
				default:
					/* use supplied value */
					if (fill)
						*buf++ = value;
					else
						if( *buf++ != ( value & PPIVBITS) )
							errorCnt++;
					break;
			}
			x++;
		}
		y++;
	}
	return errorCnt;
}


void
fillBuffer( UINT16 *buf, UINT16 bufX, UINT16 bufY, char pattern, UINT16 value )
{
	fill_verifyBuffer( buf, bufX, bufY, pattern, value, FILL_ONLY);
}


void
showBuffer8( UINT8 *buf, UINT16 bufX, UINT16 bufY, UINT8 mask )
{
	UINT16 x,y = 0;

	while ( y < bufY ) {
		x = 0;
		while ( x < bufX ) {
			if ( x < 16 )  /* only show start of line */
				printf("%4hX ", (UINT16)(*buf & mask) );
			buf++;
			x++;
		}
		if( y < 8 )
			printf("\n");
		else{
			printf("\n....\n");
			break;	/* stop showing lines */
		}
		y++;
	}
}


void
showBuffer( UINT16 *buf, UINT16 bufX, UINT16 bufY, UINT16 mask )
{
	UINT16 x,y = 0;

	while ( y < bufY ) {
		x = 0;
		while ( x < bufX ) {
			if ( x < 16 )  /* only show start of line */
				printf("%4hX ", *buf & mask );
			buf++;
			x++;
		}
		if( y < 8 )  /* only show first 8 lines */
			printf("\n");
		else{
			printf("\n....\n");
			break;	/* stop showing lines */
		}
		y++;
	}
}

int
config_device( int devFD, CfgTable	*table )
{
	int	retval;

	int i = 0;
	// load up appropriate device configuration
	while ( table->cmd ){
		//	fgets( buf, sizeof(buf), stdin );
		retval = ioctl( devFD, table->cmd, table->arg );
		if(retval){
			perror("device ioctl error");
			return(-1);
		}
		//printf("Step %d (ioctl = %d, arg = %d)\n", i, table->cmd, table->arg );
		i++;
		table++;
	}
	return 0;
}

int
beMaster(int ppiFD, UINT16 bufX, UINT16 bufY, int dims)
{
	int	retval;
	UINT16	value = 0;
	int done = 0;
	char	buf[128];
	CfgTable	*table;

	printf("Setting up master...");
#ifdef DEBUG
	ioctl( ppiFD, CMD_PPI_GET_ALLCONFIG, 0);
#endif

	gRows = bufX;
	gCols = bufY;
	gImage = realloc_image();
	if ( gImage == NULL ){
		return(-1);
	}

	/* fill in common values */
	if ( dims == DIM2D ){
		table = ppiMasterTable2D;
		/* 2D configuration */
		retval = ioctl( ppiFD, CMD_PPI_NUMLINES, bufY  );
		if(retval){
			perror("ppi ioctl error");
			return(-1);
		}
		retval = ioctl( ppiFD, CMD_PPI_LINELEN, bufX );
		if(retval){
			perror("ppi ioctl error");
			return(-1);
		}
	}
	else {
		/* 1D configuration */
		table = ppiMasterTable1D;
	}

	config_device( ppiFD, table );
	printf("Master set up complete...further input is transmited to slave\n");
#ifdef DEBUG
	ioctl( ppiFD, CMD_PPI_GET_ALLCONFIG, 0);
#endif

	while ( !done )
	{
		printf("Enter fill pattern [CcQqRrTtVvHh?]:  ");

		if ( fgets( buf, sizeof(buf), stdin ) == NULL ){
			done = 1;
			break;
		}
		switch( buf[0] ) {
			case 'q':
			case 'Q':
				done = 1;
				value = 0xdead;
				gPatternID = 'q';
				break;

			case 'v':
			case 'V':
				gPatternID = 'v';
				printf("\nEnter fill value: ");
				if ( fgets( buf, sizeof(buf), stdin ) == NULL ){
					done = 1;
					break;
				}
				if ( sscanf(buf, "%hx", &value) != 1 ){
					printf("\nError reading value...retry\n");
					continue;
				}
				break;

			case 'h':
			case 'H':
			case '?':
				printf("\nColumn, Row, Sequential, Tile, Value, Help?, Quit\n");
				continue;
				break;

			default:
				gPatternID = buf[0];
		}
				
		fillBuffer( (UINT16 *)gImage, bufX, bufY, gPatternID, value );
		showBuffer( (UINT16 *)gImage, bufX, bufY, 0x0FFF );

		retval = write( ppiFD, gImage, gImageSize );
		if ( retval != gImageSize ){
			perror("ppi write error");
			done = 1;
		}
	}

	printf("Done \n");

	return(0);
}

int
beSlave(int ppiFD, UINT16 bufX, UINT16 bufY, int dims)
{
	int	retval;
	int	done = 0;
	int	bytes_read;
	CfgTable	*table;


	gRows = bufX;
	gCols = bufY;
	realloc_image();
	if ( gImage == NULL ){
		return(-1);
	}

	printf("Setting up slave...to read %d bytes", gImageSize);


	if ( dims == DIM2D ){
		table = ppiSlaveTable2D;
		/* 2D configuration */
		retval = ioctl( ppiFD, CMD_PPI_NUMLINES, bufY  );
		if(retval){
			perror("ppi ioctl error");
			return(-1);
		}
		retval = ioctl( ppiFD, CMD_PPI_LINELEN, bufX );
		if(retval){
			perror("ppi ioctl error");
			return(-1);
		}
	}
	else {
		/* 1D configuration */
		table = ppiSlaveTable1D;
		retval = ioctl( ppiFD, CMD_PPI_XFR_TYPE, CFG_PPI_XFR_TYPE_NO_SYNC );
		if(retval){
			perror("ppi ioctl error");
			return(-1);
		}
		retval = ioctl( ppiFD, CMD_PPI_PORT_CFG, CFG_PPI_PORT_CFG_SYNC1 );
		if(retval){
			perror("ppi ioctl error");
			return(-1);
		}
	}
	config_device( ppiFD, table );

	/* show configuration */
	ioctl( ppiFD, CMD_PPI_GET_ALLCONFIG, 0);

	printf("Slave set up complete...following output is received from master...\n");

	// read image from PPI 
	// print out what is received
	while (!done) {
		bytes_read = read( ppiFD, (char *)gImage, gImageSize );
		if ( (*gImage & 0x07FF) == 0x06ad )
			done = 1;
		else{
			showBuffer( (UINT16 *)gImage, bufX, bufY, 0x0FFF );
		}
	}
	return(0);
}

void
showUsage(char *pgmname)
{
		printf("Usage: %s [master | slave ]\n", pgmname);
}


int
main(int argc,char *argv[])
{
	int	ppiFD;
	char	mode;
	int	retval;
	UINT16	bufX = LINELEN;
	UINT16	bufY = NUMLINES;
	int	dims;
	char	buf[128];

	if (argc < 2){
		showUsage(argv[0]);
		return(1);
	}
	else {
		mode = *argv[1];
	}
	ppiFD = open("/dev/ppi0", O_RDWR);

	if (ppiFD < 0)
	{
		perror("Error opening /dev/ppi");
		return(-1);
	}
	else {
		printf("fd(%d) = open(/dev/ppi)\n", ppiFD );
	}


	switch (mode) {
		case 'm':
		case 'M':
		case 's':
		case 'S':
			printf("Enter Line length (default = %d): \n", LINELEN );
			fgets(buf, sizeof(buf), stdin);
			if ( sscanf(buf, "%hd", &bufX) != 1 )
				bufX = LINELEN;

			printf("Enter number of lines (default = %d): \n", NUMLINES );
			fgets(buf, sizeof(buf), stdin);
			if ( sscanf(buf, "%hd", &bufY) != 1 )
				bufY = NUMLINES;
			break;
		default:
			break;

	}

	// set some default values
	dims = DIM2D;
	gRows = bufY;
	gCols = bufX;

	switch (mode) {
		case	'm':
		case	'M':
			printf("beMaster()\n");
			beMaster(ppiFD, bufX, bufY, dims);
			break;
		case	's':
		case	'S':
			printf("beSlave()\n");
			beSlave(ppiFD, bufX, bufY, dims);
			break;
		default:
			showUsage(argv[0]);
			break;
	}

	if (gImage)
		free(gImage);

	retval = close( ppiFD );
	if(retval)
		perror("ppi close error");

	return (0);

}
