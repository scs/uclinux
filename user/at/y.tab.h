#ifndef BISON_Y_TAB_H
# define BISON_Y_TAB_H

#ifndef YYSTYPE
typedef union {
	char *	  	charval;
	int		intval;
} yystype;
# define YYSTYPE yystype
#endif
# define	INT	257
# define	NOW	258
# define	AM	259
# define	PM	260
# define	NOON	261
# define	MIDNIGHT	262
# define	TEATIME	263
# define	SUN	264
# define	MON	265
# define	TUE	266
# define	WED	267
# define	THU	268
# define	FRI	269
# define	SAT	270
# define	TODAY	271
# define	TOMORROW	272
# define	NEXT	273
# define	MINUTE	274
# define	HOUR	275
# define	DAY	276
# define	WEEK	277
# define	MONTH	278
# define	YEAR	279
# define	JAN	280
# define	FEB	281
# define	MAR	282
# define	APR	283
# define	MAY	284
# define	JUN	285
# define	JUL	286
# define	AUG	287
# define	SEP	288
# define	OCT	289
# define	NOV	290
# define	DEC	291
# define	WORD	292


extern YYSTYPE yylval;

#endif /* not BISON_Y_TAB_H */
