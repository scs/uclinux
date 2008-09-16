/*
** petopt.c - Command line argument parser
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

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif
#include "petopt.h"



/*
** Compare the user supplied long style command line option against
** the program defined. Handle abbreviations, truncation and ambiguous
** abbreviations.
*/
static int
compare_long(const char *user_option,
	     const char *aov_long,
	     int len)
{
    unsigned char *uc, *ac;
    int diff = 0;
    int saved_len = len;
    
    
    uc = (unsigned char *) user_option;
    ac = (unsigned char *) aov_long;
    
    while (len > 0 && diff == 0)
    {
	/* If we reach a word delimiter, skip to next word */
	if (*uc == '-')
	    while (*ac && *ac != '-')
		++ac;

	diff = (int) tolower(*uc) - (int) tolower(*ac);

	++uc;
	++ac;
	--len;
    }

    if (diff)
    {
	/* Check abbrev */
	int adiff = 0;
	
	
	uc = (unsigned char *) user_option;
	ac = (unsigned char *) aov_long;
	len = saved_len;

	while (len > 0 && adiff == 0)
	{
	    /* Locate abbrev characters (uppercase) */
	    while (*ac && (islower(*ac) || *ac == '-'))
		++ac;
	    
	    adiff = (int) tolower(*uc) - (int) tolower(*ac);

	    ++uc;
	    ++ac;
	    --len;
	}

	if (adiff == 0)
	    diff = 0;
    }
    return diff;
}



static int
petopt_parse_option(PETOPT *pop,
		    PETOPTS **pov,
		    const char **optarg)
{
    int i;


    *pov = NULL;
    *optarg = NULL;


  Again:
    /* Index out of bounds? */
    if (pop->ai >= pop->argc)
    {
	return POE_EOF;
    }

    if (pop->ci == 0)
    {
	/* Non option or "-" */
	if (pop->argv[pop->ai][0] != '-' ||
	    (pop->argv[pop->ai][0] == '-' &&
	     pop->argv[pop->ai][1] == '\0'))
	{
	    pop->oav[pop->oac++] = strdup(pop->argv[pop->ai++]);
	    goto Again;
	}

	/* "--", stop parsing and skip */
	if (strcmp(pop->argv[pop->ai], "--") == 0)
	{
	    pop->ai++;

	    while (pop->ai < pop->argc)
	    {
		pop->oav[pop->oac++] = strdup(pop->argv[pop->ai++]);
	    }

	    return POE_EOF;
	}

	if (pop->argv[pop->ai][1] == '-')
	{
	    /* Long option */
	    const char *opt, *arg;
	    int len, ix;
	    char *boolval = NULL;
	    int withval = 0;
	    
	    
	    pop->saved_ai = pop->ai;
	    pop->saved_ci = pop->ci;
	    
	    opt = pop->argv[pop->ai]+2;
	    if (strncasecmp(opt, "enable-", 7) == 0)
	    {
		boolval = "true";
		opt += 7;
	    }
	    else if (strncasecmp(opt, "disable-", 8) == 0)
	    {
		boolval = "false";
		opt += 8;
	    }
	    else if (strncasecmp(opt, "with-", 5) == 0)
	    {
		withval = 1;
		opt += 5;
	    }
	    else if (strncasecmp(opt, "without-", 8) == 0)
	    {
		withval = -1;
		opt += 8;
	    }

	    
	    arg = strchr(opt, '=');
	    if (arg)
		len = arg - opt;
	    else
		len = strlen(opt);


	    ix = -1;
	    for (i = 0; pop->pov[i].s != -1; i++)
	    {
		if (pop->pov[i].l != NULL &&
		    compare_long(opt, pop->pov[i].l, len) == 0)
		{
		    /* Match found */
		    if (ix < 0)
			ix = i;
		    else
			return POE_MULTI;
		}
	    }

	    
	    if (ix >= 0)
	    {
		/* Found a unique match */
		
		pop->ai++;
		
		*pov = &pop->pov[ix];
		
		if (pop->pov[ix].f)
		{
		    /* Check for (optional) argument */
		    
		    if (boolval)
		    {
			/* --enable-XXX or --disable-XXX */
			
			if (arg ||
			    (pop->pov[ix].f & POF_TYPEMASK) != POF_BOOL)
			{
			    return POE_INVALID;
			}

			*optarg = boolval;
			return 0;
		    }
		    
		    if (withval)
		    {
			if (withval == 1)
			{
			    if (arg)
				*optarg = arg+1;
			    else
				*optarg = "yes";
			}
			else
			{
			    if (arg)
				return POE_INVALID;
			    else
				*optarg = NULL;
			}
			return 0;
		    }
			
		    if (arg)
		    {
			/* Argument after "=" */
			*optarg = arg+1;
			return 0;
		    }
		    
		    if (pop->ai < pop->argc &&
			(pop->argv[pop->ai][0] != '-' ||
			 pop->argv[pop->ai][0] == '\0'))
		    {
			/* Have an argument, empty string or "-" */
			if (((pop->pov[ix].f & POF_TYPEMASK) == POF_STR) ||
			    isdigit((int) pop->argv[pop->ai][0]))
			{
			    *optarg = pop->argv[pop->ai];
			    pop->ai++;
			}
		    }

		    /* Argument missing, and not optional? */
		    if (*optarg == NULL &&
			!((pop->pov[ix].f & POF_OPT) ||
			  ((pop->pov[ix].f & POF_TYPEMASK) == POF_BOOL)))
		    {
			pop->ai--;
			return POE_MISSING;
		    }
		}
		
		return 0;
	    }

	    /* Unknown long command line switch */
	    return POE_OPTION;
	}
	else
	{
	    /* Short option */
	    
	    pop->ci = 1;
	}
    }

    /* Short option */

    pop->saved_ai = pop->ai;
    pop->saved_ci = pop->ci;
    
    i = 0;
    while (pop->pov[i].s != -1 && pop->pov[i].s != pop->argv[pop->ai][pop->ci])
	i++;

    if (pop->pov[i].s == -1)
    {
	/* Unknown short command line switch */
	return POE_OPTION;
    }
    
    /* Found a matching short option */
    
    *pov = &pop->pov[i];
    pop->ci++;
    
    if (pop->argv[pop->ai][pop->ci] == '\0')
    {
	pop->ai++;
	pop->ci = 0;
    }

    /* Have an (optional) argument? */
    if (pop->pov[i].f)
    {
	if (pop->ai < pop->argc &&
	    (pop->ci != 0 ||
	     ((pop->argv[pop->ai][0] != '-') ||
	      pop->argv[pop->ai][1] == '\0')))
	{
	    if (((pop->pov[i].f & POF_TYPEMASK) == POF_STR) ||
		(isdigit((int) pop->argv[pop->ai][pop->ci]) ||
		 pop->argv[pop->ai][pop->ci] == '-'))
	    {
		*optarg = pop->argv[pop->ai]+pop->ci;
	    
		pop->ai++;
		pop->ci = 0;
	    }
	}
    }

    /* Argument missing, and not optional? */
    if (pop->pov[i].f &&
	!((pop->pov[i].f & POF_OPT) ||
	  (pop->pov[i].f & POF_TYPEMASK) == POF_BOOL) &&
	*optarg == NULL)
    {
	if (pop->ci == 0)
	{
	    pop->ai--;
	    pop->ci = strlen(pop->argv[pop->ai])-1;
	}
	
	return POE_MISSING;
    }
		
    return 0;
}


int
petopt_print_error(PETOPT *pop,
		   PETOPTS *pov,
		   int err,
		   FILE *fp)
{
    char buf[3];
    const char *arg;


    if (pop->saved_ci > 0)
    {
	buf[0] = '-';
	buf[1] = pop->argv[pop->saved_ai][pop->saved_ci];
	buf[2] = '\0';
	arg = buf;
    }
    else
    {
	arg = pop->argv[pop->saved_ai];
	if (arg == NULL)
	    arg = "";
    }
    
    switch (err)
    {
      case POE_EOF:
	return 0;

      case POE_OPTION:
#ifdef HAVE_SYSLOG
	if (pop->f & POF_SYSLOG)
	    syslog(LOG_ERR, "Unrecognized option: %s", arg);
#endif
	fprintf(fp, "%s: Unrecognized option: %s\n",
		pop->argv[0], arg);
	break;

      case POE_MULTI:
#ifdef HAVE_SYSLOG
	if (pop->f & POF_SYSLOG)
	    syslog(LOG_ERR, "Ambiguous option: %s", arg);
#endif
	fprintf(fp, "%s: Ambiguous option: %s\n",
		pop->argv[0], arg);
	break;
	
      case POE_MISSING:
#ifdef HAVE_SYSLOG
	if (pop->f & POF_SYSLOG)
	    syslog(LOG_ERR, "Missing argument for option: %s", arg);
#endif

	fprintf(fp, "%s: Missing argument for option: %s\n",
		pop->argv[0], arg);
	break;

      case POE_INVALID:
#ifdef HAVE_SYSLOG
	if (pop->f & POF_SYSLOG)
	    syslog(LOG_ERR, "Invalid argument for option: %s", arg);
#endif
	
	fprintf(fp, "%s: Invalid argument for option: %s\n",
		    pop->argv[0], arg);
	break;

      case POE_INTERNAL:
#ifdef HAVE_SYSLOG
	if (pop->f & POF_SYSLOG)
	    syslog(LOG_ERR, "Internal error parsing option: %s", arg);
#endif
	
	fprintf(fp, "%s: Internal error parsing option: %s\n",
		    pop->argv[0], arg);
	break;

      default:
#ifdef HAVE_SYSLOG
	if (pop->f & POF_SYSLOG)
	    syslog(LOG_ERR, "Internal options parsing error: #%d", err);
#endif
	
	fprintf(fp, "%s: Internal options parsing error: #%d\n",
		pop->argv[0], err);
    }

    return -1;
}


int
petopt_parse(PETOPT *pop,
	     int *o_argc,
	     char ***o_argv)
{
    int err;
    const char *arg;
    PETOPTS *pov;
    

    while ((err = petopt_parse_option(pop, &pov, &arg)) == 0)
    {
	if (pop->parse &&
	    (err = pop->parse(pop, pov, arg)) < 0)
	{
	    goto Fail;
	}

	/* Parser assigned the values */
	if (err == 0)
	    continue;

	/* Option not handled, and no storage assigned? */
	if (pov->v == NULL)
	{
	    err = POE_INTERNAL;
	    goto Fail;
	}
	
	switch (pov->f & POF_TYPEMASK)
	{
	  case POF_NONE:
	    break;

	  case POF_BOOL:
	    if (arg && *arg != '\0')
	    {
		if (strcasecmp(arg, "true") == 0 ||
		    strcasecmp(arg, "yes") == 0 ||
		    strcasecmp(arg, "on") == 0)
		{
		    *(int *)(pov->v) = 1;
		}
		else if (strcasecmp(arg, "false") == 0 ||
		    strcasecmp(arg, "no") == 0 ||
		    strcasecmp(arg, "off") == 0)
		{
		    *(int *)(pov->v) = 0;
		}
		else
		{
		    err = POE_INVALID;
		    goto Fail;
		}
	    }
	    else
	    {
		*(int *)(pov->v) = 1;
	    }
	    break;

	  case POF_INT:
	    if (arg && *arg != '\0')
	    {
		/* XXX: Check for integer number */
		*(int *)(pov->v) = atoi(arg);
	    }
	    else
	    {
		/* XXX: Check for POF_INC flag?? */
		++*(int *)(pov->v);
	    }
	    break;
	    
	  case POF_STR:
	    if (pov->f & POF_DUP)
		*(char **)(pov->v) = strdup(arg);
	    else
		*(char **)(pov->v) = (char *) arg;
	    break;
	    
	  default:
	    err = POE_OPTION;
	    goto Fail;
	}
    }

    if (err == POE_EOF)
	err = 0;

  Fail:
    if (err)
	err = pop->errpr(pop, pov, err,
			 (pop->f & POF_NOERRPRINT) ? NULL : stderr);
	
    *o_argc = pop->oac;
    *o_argv = pop->oav;

    return err;
}



int
petopt_print_usage(PETOPT *pop,
		   FILE *fp)
{
    int i, len;
    struct petopt_option *pov;


    pov = pop->pov;
    for (i = 0; pov[i].s != -1; i++)
    {
	if (pov[i].s > ' ' && pov[i].s <='~')
	    fprintf(fp, "  -%c, ", pov[i].s);
	else
	    fprintf(fp, "      ");

	len = 0;
	if (pov[i].l)
	{
	    len = fprintf(fp, "--%s", pov[i].l);
	    if (pov[i].f)
	    {
		if (pov[i].f & POF_OPT)
		    len += fprintf(fp, " [ARG]");
		else
		    len += fprintf(fp, " ARG");
	    }
	}
	
	while (len++ < 30)
	    putchar(' ');
	    
	if (pov[i].h)
	    fputs(pov[i].h, fp);
	if (pop->f & POF_PRDEFAULT && pov[i].v != NULL)
	    switch (pov[i].f & POF_TYPEMASK)
	    {
	      case POF_INT:
		  {
		      int *iv = pov[i].v;
		      if (*iv != 0)
			  fprintf(fp, " (Default: %d)", *iv);
		  }
		break;

	      case POF_STR:
		  {
		      char **cv = pov[i].v;
		      if (*cv)
			  fprintf(fp, " (Default: \"%s\")", *cv);
		  }
		  break;
	    }
	putc('\n', fp);
    }

    return 0;
}


int
petopt_setup(PETOPT **popp,
	     int f,
	     int argc,
	     char **argv,
	     PETOPTS *pov,
	     int (*parse)(PETOPT *pop, PETOPTS *pov, const char *arg),
	     int (*errpr)(PETOPT *pop, PETOPTS *pov, int err, FILE *fp))
{
    PETOPT *pop = malloc(sizeof(PETOPT));
    if (pop == NULL)
	return errno;
    
    memset(pop, 0, sizeof(*pop));
    
    pop->f = f;
    
    pop->argc = argc;
    pop->argv = (const char **) argv;
    pop->pov = pov;
    pop->parse = parse;

    if (errpr)
	pop->errpr = errpr;
    else
	pop->errpr = petopt_print_error;

    pop->ai = 1;
    pop->ci = 0;

    pop->saved_ai = 0;
    pop->saved_ci = 0;
    
    pop->oac = 1;
    
    pop->oav = calloc(argc+1, sizeof(char *));
    pop->oav[0] = strdup(pop->argv[0]);
    pop->oav[1] = NULL;
    
    *popp = pop;
    return 0;
}


int
petopt_rewind(PETOPT *pop)
{
    pop->ai = 1;
    pop->ci = 0;

    pop->oac = 1;
    pop->oav[1] = NULL;
    
    return 0;
}


int
petopt_cleanup(PETOPT *pop)
{
    int i;
    
    if (pop->oav)
    {
	for (i = 0; i < pop->oac; i++)
	    if (pop->oav[i])
		free(pop->oav[i]);
	free(pop->oav);
    }
    
    free(pop);
    return 0;
}
