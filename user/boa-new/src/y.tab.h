#ifndef BISON_Y_TAB_H
# define BISON_Y_TAB_H

#ifndef YYSTYPE
typedef union {
    char *	sval;
    int		ival;
    struct ccommand * cval;
} yystype;
# define YYSTYPE yystype
# define YYSTYPE_IS_TRIVIAL 1
#endif
# define	STMT_NO_ARGS	257
# define	STMT_ONE_ARG	258
# define	STMT_TWO_ARGS	259
# define	MIMETYPE	260
# define	STRING	261
# define	INTEGER	262


extern YYSTYPE yylval;

#endif /* not BISON_Y_TAB_H */
