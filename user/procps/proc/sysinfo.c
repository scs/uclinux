/***********************************************************************\
*   Copyright (C) 1992-1998 by Michael K. Johnson, johnsonm@redhat.com *
*                                                                      *
*      This file is placed under the conditions of the GNU Library     *
*      General Public License, version 2, or any later version.        *
*      See file COPYING for information on distribution conditions.    *
\***********************************************************************/

/* File for parsing top-level /proc entities. */
#include "proc/sysinfo.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <unistd.h>
#include <fcntl.h>
#include "proc/version.h"

#define BAD_OPEN_MESSAGE					\
"Error: /proc must be mounted\n"				\
"  To mount /proc at boot you need an /etc/fstab line like:\n"	\
"      /proc   /proc   proc    defaults\n"			\
"  In the meantime, mount /proc /proc -t proc\n"

#define STAT_FILE    "/proc/stat"
static int stat_fd = -1;
#define UPTIME_FILE  "/proc/uptime"
static int uptime_fd = -1;
#define LOADAVG_FILE "/proc/loadavg"
static int loadavg_fd = -1;
#define MEMINFO_FILE "/proc/meminfo"
static int meminfo_fd = -1;

static char buf[1024];

/* This macro opens filename only if necessary and seeks to 0 so
 * that successive calls to the functions are more efficient.
 * It also reads the current contents of the file into the global buf.
 */
#define FILE_TO_BUF(filename, fd) do{				\
    static int n;						\
    if (fd == -1 && (fd = open(filename, O_RDONLY)) == -1) {	\
	fprintf(stderr, BAD_OPEN_MESSAGE);			\
	close(fd);						\
	_exit(1);						\
    }								\
    lseek(fd, 0L, SEEK_SET);					\
    if ((n = read(fd, buf, sizeof buf - 1)) < 0) {		\
	perror(filename);					\
	close(fd);						\
	fd = -1;						\
	return 0;						\
    }								\
    buf[n] = '\0';						\
}while(0)

#define SET_IF_DESIRED(x,y)  if(x) *(x) = (y)	/* evals 'x' twice */


/***********************************************************************/
int uptime(double *uptime_secs, double *idle_secs) {
    double up=0, idle=0;

    FILE_TO_BUF(UPTIME_FILE,uptime_fd);
    if (sscanf(buf, "%lf %lf", &up, &idle) < 2) {
	fprintf(stderr, "bad data in " UPTIME_FILE "\n");
	return 0;
    }
    SET_IF_DESIRED(uptime_secs, up);
    SET_IF_DESIRED(idle_secs, idle);
    return up;	/* assume never be zero seconds in practice */
}

/***********************************************************************
 * Some values in /proc are expressed in units of 1/HZ seconds, where HZ
 * is the kernel clock tick rate. One of these units is called a jiffy.
 * The HZ value used in the kernel may vary according to hacker desire.
 * According to Linus Torvalds, this is not true. He considers the values
 * in /proc as being in architecture-dependant units that have no relation
 * to the kernel clock tick rate. Examination of the kernel source code
 * reveals that opinion as wishful thinking.
 *
 * In any case, we need the HZ constant as used in /proc. (the real HZ value
 * may differ, but we don't care) There are several ways we could get HZ:
 *
 * 1. Include the kernel header file. If it changes, recompile this library.
 * 2. Use the sysconf() function. When HZ changes, recompile the C library!
 * 3. Ask the kernel. This is obviously correct...
 *
 * Linus Torvalds won't let us ask the kernel, because he thinks we should
 * not know the HZ value. Oh well, we don't have to listen to him.
 * Someone smuggled out the HZ value. :-)
 *
 * This code should work fine, even if Linus fixes the kernel to match his
 * stated behavior. The code only fails in case of a partial conversion.
 *
 * (Albert Cahalan, I think, wrote the rant above.)
 *
 * Unfortunately, this code does not always succeed.  Anyone who can do
 * better is welcome to do so...
 */
unsigned long Hertz;
static int init_Hertz_value(void) __attribute__((constructor));
static int init_Hertz_value(void){
  unsigned long user_j, nice_j, sys_j, other_j;  /* jiffies (clock ticks) */
  double up_1, up_2, seconds;
  unsigned long jiffies, h;
  int i = 0;
  do{
    FILE_TO_BUF(UPTIME_FILE,uptime_fd);  sscanf(buf, "%lf", &up_1);
    /* uptime(&up_1, NULL); */
    FILE_TO_BUF(STAT_FILE,stat_fd);
    /* If we are SMP, then the first line is the sum of jiffies by all CPUs */
    /* In that case, skip it and use the jiffies of the first CPU instead. */
    /* On a single-CPU machine, the 2nd sscanf should harmlessly fail. */
    sscanf(buf, "cpu %lu %lu %lu %lu\n%n",
	   &user_j, &nice_j, &sys_j, &other_j, &i);
    sscanf(buf+i, "cpu0 %lu %lu %lu %lu", &user_j, &nice_j, &sys_j, &other_j);
    FILE_TO_BUF(UPTIME_FILE,uptime_fd);  sscanf(buf, "%lf", &up_2);
    /* uptime(&up_2, NULL); */
  } while((long)( (up_2-up_1)*1000.0/up_1 )); /* want under 0.1% error */
  jiffies = user_j + nice_j + sys_j + other_j;
  seconds = (up_1 + up_2) / 2;
  h = (unsigned long)( (double)jiffies/seconds );
  switch(h){
  case   48 ...   52 :  Hertz =   50; break;
  case   58 ...   62 :  Hertz =   60; break;
  case   95 ...  105 :  Hertz =  100; break; /* normal Linux */
  case  124 ...  132 :  Hertz =  128; break;
  case  195 ...  204 :  Hertz =  200; break; /* normal << 1 */
  case  253 ...  260 :  Hertz =  256; break;
  case  393 ...  408 :  Hertz =  400; break; /* normal << 2 */
  case  790 ...  808 :  Hertz =  800; break; /* normal << 3 */
  case  990 ... 1010 :  Hertz = 1000; break;
  case 1015 ... 1035 :  Hertz = 1024; break; /* Alpha */
  default:
#ifdef HZ
    Hertz = (unsigned long)HZ;    /* <asm/param.h> */
#else
    Hertz = (sizeof(long)==sizeof(int)) ? 100UL : 1024UL;
#endif
#if 0 /* This ends up causing more harm than good.  :-( */
    fprintf(stderr, "Unknown HZ value! (%ld) Assume %ld.\n", h, Hertz);
#endif
  }
  return 0; /* useless, but FILE_TO_BUF has a return in it */
}

/***********************************************************************/
#define JT unsigned long
int four_cpu_numbers(JT *uret, JT *nret, JT *sret, JT *iret) {
    static JT u, n, s, i;
    JT user_j, nice_j, sys_j, idle_j;

    FILE_TO_BUF(STAT_FILE,stat_fd);
    sscanf(buf, "cpu %lu %lu %lu %lu", &user_j, &nice_j, &sys_j, &idle_j);
    SET_IF_DESIRED(uret, user_j-u);
    SET_IF_DESIRED(nret, nice_j-n);
    SET_IF_DESIRED(sret,  sys_j-s);
    SET_IF_DESIRED(iret, idle_j-i);
    u=user_j;
    n=nice_j;
    s=sys_j;
    i=idle_j;
    return 0;
}
#undef JT

/***********************************************************************/
int loadavg(double *av1, double *av5, double *av15) {
    double avg_1=0, avg_5=0, avg_15=0;
    
    FILE_TO_BUF(LOADAVG_FILE,loadavg_fd);
    if (sscanf(buf, "%lf %lf %lf", &avg_1, &avg_5, &avg_15) < 3) {
	fprintf(stderr, "bad data in " LOADAVG_FILE "\n");
	exit(1);
    }
    SET_IF_DESIRED(av1,  avg_1);
    SET_IF_DESIRED(av5,  avg_5);
    SET_IF_DESIRED(av15, avg_15);
    return 1;
}

/************************************************************************
 * The following /proc/meminfo parsing routine assumes the following format:
 * [ <label> ... ]				# header lines
 * [ <label> ] <num> [ <num> ... ]		# table rows
 * [ repeats of above line ]
 * 
 * Any lines with fewer <num>s than <label>s get trailing <num>s set to zero.
 * The return value is a NULL terminated unsigned** which is the table of
 * numbers without labels.  Convenient enumeration constants for the major and
 * minor dimensions are available in the header file.  Note that this version
 * requires that labels do not contain digits.  It is readily extensible to
 * labels which do not *begin* with digits, though.
 */
#define MAX_ROW 3	/* these are a little liberal for flexibility */
#define MAX_COL 7
unsigned long long **get_meminfo(void){
    static unsigned long long *row[MAX_ROW + 1];		/* row pointers */
    static unsigned long long num[MAX_ROW * MAX_COL];	/* number storage */
    char *p;
    char fieldbuf[12];		/* bigger than any field name or size in kb */
    int i, j, k, l;

    FILE_TO_BUF(MEMINFO_FILE,meminfo_fd);
    if (!row[0])				/* init ptrs 1st time through */
	for (i=0; i < MAX_ROW; i++)		/* std column major order: */
	    row[i] = num + MAX_COL*i;		/* A[i][j] = A + COLS*i + j */
    p = buf;
    for (i=0; i < MAX_ROW; i++)			/* zero unassigned fields */
	for (j=0; j < MAX_COL; j++)
	    row[i][j] = 0;
    if (linux_version_code < LINUX_VERSION(2,0,0)) {
    	for (i=0; i < MAX_ROW && *p; i++) {                /* loop over rows */
		while(*p && !isdigit(*p)) p++;          /* skip chars until a digit */
		for (j=0; j < MAX_COL && *p; j++) {     /* scanf column-by-column */
		    l = sscanf(p, "%Lu%n", row[i] + j, &k);
		    p += k;                             /* step over used buffer */
		    if (*p == '\n' || l < 1)            /* end of line/buffer */
			break;
		}
	}
    }
    else {
	    while(*p) {
	    	sscanf(p,"%11s%n",fieldbuf,&k);
	    	if(!strcmp(fieldbuf,"MemTotal:")) {
	    		p+=k;
	    		sscanf(p," %Ld",&(row[meminfo_main][meminfo_total]));
	    		row[meminfo_main][meminfo_total]<<=10;
	    		while(*p++ != '\n');
	    	}
	    	else if(!strcmp(fieldbuf,"MemFree:")) {
	    		p+=k;
	    		sscanf(p," %Ld",&(row[meminfo_main][meminfo_free]));
	    		row[meminfo_main][meminfo_free]<<=10;
	    		while(*p++ != '\n');
	    	}
	    	else if(!strcmp(fieldbuf,"MemShared:")) {
	    		p+=k;
	    		sscanf(p," %Ld",&(row[meminfo_main][meminfo_shared]));
	    		row[meminfo_main][meminfo_shared]<<=10;
	    		while(*p++ != '\n');
	    	}
	    	else if(!strcmp(fieldbuf,"Buffers:")) {
	    		p+=k;
	    		sscanf(p," %Ld",&(row[meminfo_main][meminfo_buffers]));
	    		row[meminfo_main][meminfo_buffers]<<=10;
	    		while(*p++ != '\n');
	    	}
	    	else if(!strcmp(fieldbuf,"Cached:")) {
	    		p+=k;
    			sscanf(p," %Ld",&(row[meminfo_main][meminfo_cached]));
    			row[meminfo_main][meminfo_cached]<<=10;
    			while(*p++ != '\n');
    		}
    		else if(!strcmp(fieldbuf,"SwapTotal:")) {
    			p+=k;
    			sscanf(p," %Ld",&(row[meminfo_swap][meminfo_total]));
    			row[meminfo_swap][meminfo_total]<<=10;
    			while(*p++ != '\n');
    		}
    		else if(!strcmp(fieldbuf,"SwapFree:")) {
    			p+=k;
    			sscanf(p," %Ld",&(row[meminfo_swap][meminfo_free]));
    			row[meminfo_swap][meminfo_free]<<=10;
    			while(*p++ != '\n');
    		}
    		else
    			while(*p++ != '\n'); /* ignore lines we don't understand */
    	}		
    	row[meminfo_swap][meminfo_used]=row[meminfo_swap][meminfo_total]-row[meminfo_swap][meminfo_free];
    	row[meminfo_main][meminfo_used]=row[meminfo_main][meminfo_total]-row[meminfo_main][meminfo_free];
    }

    return row;					/* NULL return ==> error */
}

/**************************************************************************
 * shorthand for read_table("/proc/meminfo")[meminfo_main][meminfo_total] */
unsigned read_total_main(void) {
    unsigned long long** mem;
    return (mem = get_meminfo()) ? mem[meminfo_main][meminfo_total] : -1;
}
