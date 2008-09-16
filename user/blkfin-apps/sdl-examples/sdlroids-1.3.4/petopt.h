/*
** petopt.h - Command line argument parser header file
**
** Copyright (c) 1999 Peter Eriksson <pen@lysator.liu.se>
**
** This program is free software; you can redistribute it and/or
** modify it as you wish - as long as you don't claim that you wrote
** it.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

#ifndef PETOPT_H
#define PETOPT_H

/* Option types and flags */
#define POF_TYPEMASK	0x00FF

#define POF_NONE 	0x0000
#define POF_INT  	0x0001	/* Argument is an 'int' number */
#define POF_STR  	0x0002	/* Argument is a  'char *' string */
#define POF_BOOL	0x0003  /* Argument is a  'int' boolean */

#define POF_OPT  	0x0100	/* Argument is optional */
#define POF_DUP		0x0200	/* strdup() the assigned var (if string) */

/* Global flags */
#define POF_SYSLOG	0x1000	/* Send errors to syslog */
#define POF_NOERRPRINT	0x2000  /* Do not print errors to stderr */
#define POF_PRDEFAULT   0x4000  /* Print default values in usage text */

/* Error returns */
#define POE_EOF     	-1

#define POE_OPTION  	-2 /* Invalid option */
#define POE_MULTI   	-3 /* Option is not unique */
#define POE_MISSING 	-4 /* Required argument to option is missing */
#define POE_INVALID 	-5 /* Invalid argument to option */
#define POE_INTERNAL 	-6 /* Internal error */


typedef struct petopt_option
{
    int s;      /* Short option character */
    int f;      /* Argument flags */
    char *l;    /* Long option name */
    void *v;	/* Variable pointer */
    char *h;	/* Help/usage string */
} PETOPTS;


typedef struct petopt
{
    int f;
    int ai;
    int ci;
    int saved_ai;
    int saved_ci;
    int argc;
    const char **argv;
    PETOPTS *pov;
    int (*parse)(struct petopt *pp, PETOPTS *pov, const char *arg);
    int (*errpr)(struct petopt *pp, PETOPTS *pov, int err, FILE *fp);
    int oac;
    char **oav;
} PETOPT;


extern int
petopt_setup(PETOPT **popp,
	     int f,
	     int argc,
	     char **argv,
	     PETOPTS *pov,
	     int (*parse)(PETOPT *pop, PETOPTS *pov, const char *arg),
	     int (*errpr)(PETOPT *pop, PETOPTS *pov, int err, FILE *fp));
	     

extern int
petopt_parse(PETOPT *pop,
	     int *o_argc,
	     char ***o_argv);

extern int
petopt_print_error(PETOPT *pop,
		   PETOPTS *pov,
		   int err,
		   FILE *fp);
     
extern int
petopt_print_usage(PETOPT *pop,
		   FILE *fp);

extern int
petopt_cleanup(PETOPT *pop);

#endif
