/* A Bison parser, made from parsetime.y
   by GNU bison 1.31.  */

#define YYBISON 1  /* Identify Bison output.  */

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

#line 1 "parsetime.y"

#include <time.h>
#include <stdlib.h>
#include <string.h>
#include "parsetime.h"

#define YYDEBUG 1

time_t currtime;
struct tm exectm;
static int isgmt;
static int time_only;

extern int yyerror(char *s);
extern int yylex();

int add_date(int number, int period);

#line 20 "parsetime.y"
#ifndef YYSTYPE
typedef union {
	char *	  	charval;
	int		intval;
} yystype;
# define YYSTYPE yystype
#endif
#ifndef YYDEBUG
# define YYDEBUG 0
#endif



#define	YYFINAL		104
#define	YYFLAG		-32768
#define	YYNTBASE	47

/* YYTRANSLATE(YYLEX) -- Bison token number corresponding to YYLEX. */
#define YYTRANSLATE(x) ((unsigned)(x) <= 292 ? yytranslate[x] : 69)

/* YYTRANSLATE[YYLEX] -- Bison token number corresponding to YYLEX. */
static const char yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,    45,
       2,     2,     2,    43,    39,    40,    41,    42,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,    44,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,    46,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     3,     4,     5,
       6,     7,     8,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    19,    20,    21,    22,    23,    24,    25,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    38
};

#if YYDEBUG
static const short yyprhs[] =
{
       0,     0,     2,     4,     7,    10,    14,    16,    18,    21,
      23,    25,    27,    28,    30,    33,    37,    42,    45,    49,
      54,    60,    62,    64,    66,    69,    73,    78,    80,    82,
      84,    90,    96,   100,   103,   107,   113,   115,   117,   121,
     124,   127,   131,   133,   135,   137,   139,   141,   143,   145,
     147,   149,   151,   153,   155,   157,   159,   161,   163,   165,
     167,   169,   171,   173,   175,   177,   179,   181,   183,   185,
     187,   189,   191,   193,   195,   197,   199,   201,   203,   205,
     207,   209
};
static const short yyrhs[] =
{
      52,     0,    51,     0,    51,    52,     0,    50,    53,     0,
      50,    52,    53,     0,    48,     0,    49,     0,    49,    53,
       0,     4,     0,    18,     0,    51,     0,     0,    57,     0,
      57,    58,     0,    59,    68,    60,     0,    59,    68,    60,
      58,     0,    59,    61,     0,    59,    61,    58,     0,    59,
      68,    60,    61,     0,    59,    68,    60,    61,    58,     0,
       7,     0,     8,     0,     9,     0,    62,    64,     0,    62,
      64,    65,     0,    62,    64,    39,    65,     0,    66,     0,
      17,     0,    18,     0,    65,    40,    63,    40,    64,     0,
      64,    41,    63,    41,    65,     0,    64,    41,    63,     0,
      64,    62,     0,    64,    62,    65,     0,    63,    42,    64,
      42,    65,     0,    54,     0,    55,     0,    43,    67,    56,
       0,    19,    56,     0,    19,    66,     0,    40,    67,    56,
       0,    20,     0,    21,     0,    22,     0,    23,     0,    24,
       0,    25,     0,     3,     0,    38,     0,    57,     0,     3,
       0,     5,     0,     6,     0,    26,     0,    27,     0,    28,
       0,    29,     0,    30,     0,    31,     0,    32,     0,    33,
       0,    34,     0,    35,     0,    36,     0,    37,     0,     3,
       0,     3,     0,     3,     0,    10,     0,    11,     0,    12,
       0,    13,     0,    14,     0,    15,     0,    16,     0,     3,
       0,    44,     0,    45,     0,    41,     0,    46,     0,    39,
       0
};

#endif

#if YYDEBUG
/* YYRLINE[YYN] -- source line where rule number YYN was defined. */
static const short yyrline[] =
{
       0,    42,    43,    47,    48,    49,    50,    53,    54,    57,
      58,    64,    65,    67,    68,    69,    70,    71,    72,    73,
      74,    75,    80,    86,    93,    94,    95,    96,   100,   101,
     105,   106,   107,   108,   109,   110,   113,   114,   116,   120,
     124,   130,   136,   137,   138,   139,   140,   141,   144,   213,
     226,   229,   239,   249,   262,   263,   264,   265,   266,   267,
     268,   269,   270,   271,   272,   273,   276,   290,   303,   326,
     327,   328,   329,   330,   331,   332,   335,   345,   346,   347,
     348,   349
};
#endif


#if (YYDEBUG) || defined YYERROR_VERBOSE

/* YYTNAME[TOKEN_NUM] -- String name of the token TOKEN_NUM. */
static const char *const yytname[] =
{
  "$", "error", "$undefined.", "INT", "NOW", "AM", "PM", "NOON", "MIDNIGHT", 
  "TEATIME", "SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT", "TODAY", 
  "TOMORROW", "NEXT", "MINUTE", "HOUR", "DAY", "WEEK", "MONTH", "YEAR", 
  "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", 
  "NOV", "DEC", "WORD", "','", "'-'", "'.'", "'/'", "'+'", "':'", "'\\''", 
  "'h'", "timespec", "nowspec", "now", "time_or_not", "time", "date", 
  "inc_or_dec", "increment", "decrement", "inc_period", 
  "hr24clock_hr_min", "timezone_name", "hr24clock_hour", "minute", 
  "am_pm", "month_name", "month_number", "day_number", "year_number", 
  "day_of_week", "inc_number", "time_sep", NULL
};
#endif

/* YYR1[YYN] -- Symbol number of symbol that rule YYN derives. */
static const short yyr1[] =
{
       0,    47,    47,    47,    47,    47,    47,    48,    48,    49,
      49,    50,    50,    51,    51,    51,    51,    51,    51,    51,
      51,    51,    51,    51,    52,    52,    52,    52,    52,    52,
      52,    52,    52,    52,    52,    52,    53,    53,    54,    54,
      54,    55,    56,    56,    56,    56,    56,    56,    57,    58,
      59,    60,    61,    61,    62,    62,    62,    62,    62,    62,
      62,    62,    62,    62,    62,    62,    63,    64,    65,    66,
      66,    66,    66,    66,    66,    66,    67,    68,    68,    68,
      68,    68
};

/* YYR2[YYN] -- Number of symbols composing right hand side of rule YYN. */
static const short yyr2[] =
{
       0,     1,     1,     2,     2,     3,     1,     1,     2,     1,
       1,     1,     0,     1,     2,     3,     4,     2,     3,     4,
       5,     1,     1,     1,     2,     3,     4,     1,     1,     1,
       5,     5,     3,     2,     3,     5,     1,     1,     3,     2,
       2,     3,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     1,     1,     1,     1,     1,     1,     1,
       1,     1
};

/* YYDEFACT[S] -- default rule to reduce with in state S when YYTABLE
   doesn't specify something else to do.  Zero means the default is an
   error. */
static const short yydefact[] =
{
      12,    48,     9,    21,    22,    23,    69,    70,    71,    72,
      73,    74,    75,    28,    10,    54,    55,    56,    57,    58,
      59,    60,    61,    62,    63,    64,    65,     6,     7,     0,
      11,     1,    13,     0,     0,     0,     0,     0,    27,     0,
       0,     0,     8,    36,    37,    67,    29,     0,     4,     3,
      49,    14,    52,    53,    81,    79,    77,    78,    80,    17,
       0,    67,    24,     0,     0,    33,     0,    42,    43,    44,
      45,    46,    47,    39,    40,    76,     0,     0,     5,    18,
      51,    15,    68,     0,    25,     0,    66,    32,    34,     0,
      41,    38,    16,    19,    26,     0,     0,     0,    20,    35,
      31,    30,     0,     0,     0
};

static const short yydefgoto[] =
{
     102,    27,    28,    29,    30,    31,    42,    43,    44,    73,
      32,    51,    33,    81,    59,    34,    35,    36,    37,    38,
      76,    60
};

static const short yypact[] =
{
     114,   -21,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
  -32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,
  -32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,   -13,    41,
      79,-32768,    -4,     4,    22,   -14,   142,    -8,-32768,   174,
      33,    33,-32768,-32768,-32768,   -18,-32768,   -13,-32768,-32768,
  -32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,-32768,     9,
      58,-32768,     0,    22,    59,    61,    59,-32768,-32768,-32768,
  -32768,-32768,-32768,-32768,-32768,-32768,    -5,    -5,-32768,-32768,
  -32768,     8,-32768,    61,-32768,    23,-32768,    25,-32768,    40,
  -32768,-32768,-32768,     9,-32768,    61,    61,    22,-32768,-32768,
  -32768,-32768,    83,    85,-32768
};

static const short yypgoto[] =
{
  -32768,-32768,-32768,-32768,-32768,   -22,   -24,-32768,-32768,   -65,
  -32768,   -55,-32768,-32768,     5,    51,   -33,   -34,    71,    49,
      57,-32768
};


#define	YYLAST		199


static const short yytable[] =
{
      62,   -50,   -50,    82,    79,    48,    39,    47,    49,    52,
      53,    90,    91,    52,    53,    67,    68,    69,    70,    71,
      72,   -66,   -68,    78,   -66,    61,    92,    40,    63,    85,
      41,    87,    66,    89,    50,   -50,    75,   -50,    98,    83,
     -50,   -50,   -50,    54,    45,    55,    50,    50,    56,    57,
      58,     6,     7,     8,     9,    10,    11,    12,    13,    46,
      39,    80,    86,   101,    82,    95,    96,    15,    16,    17,
      18,    19,    20,    21,    22,    23,    24,    25,    26,    -2,
      97,    40,    45,   103,    41,   104,    93,    65,    74,     6,
       7,     8,     9,    10,    11,    12,    13,    46,    77,     0,
       0,     0,     0,     0,     0,    15,    16,    17,    18,    19,
      20,    21,    22,    23,    24,    25,    26,     1,     2,     0,
       0,     3,     4,     5,     6,     7,     8,     9,    10,    11,
      12,    13,    14,    84,     0,     0,    88,     0,     0,     0,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,     0,     0,    94,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,    99,   100,    15,    16,
      17,    18,    19,    20,    21,    22,    23,    24,    25,    26,
       0,     0,     0,    64,     6,     7,     8,     9,    10,    11,
      12,     0,     0,     0,    67,    68,    69,    70,    71,    72
};

static const short yycheck[] =
{
      34,     5,     6,     3,    59,    29,    19,    29,    30,     5,
       6,    76,    77,     5,     6,    20,    21,    22,    23,    24,
      25,    42,    40,    47,    42,     3,    81,    40,    42,    63,
      43,    64,    40,    66,    38,    39,     3,    41,    93,    39,
      44,    45,    46,    39,     3,    41,    38,    38,    44,    45,
      46,    10,    11,    12,    13,    14,    15,    16,    17,    18,
      19,     3,     3,    97,     3,    42,    41,    26,    27,    28,
      29,    30,    31,    32,    33,    34,    35,    36,    37,     0,
      40,    40,     3,     0,    43,     0,    81,    36,    39,    10,
      11,    12,    13,    14,    15,    16,    17,    18,    41,    -1,
      -1,    -1,    -1,    -1,    -1,    26,    27,    28,    29,    30,
      31,    32,    33,    34,    35,    36,    37,     3,     4,    -1,
      -1,     7,     8,     9,    10,    11,    12,    13,    14,    15,
      16,    17,    18,    62,    -1,    -1,    65,    -1,    -1,    -1,
      26,    27,    28,    29,    30,    31,    32,    33,    34,    35,
      36,    37,    -1,    -1,    83,    -1,    -1,    -1,    -1,    -1,
      -1,    -1,    -1,    -1,    -1,    -1,    95,    96,    26,    27,
      28,    29,    30,    31,    32,    33,    34,    35,    36,    37,
      -1,    -1,    -1,    41,    10,    11,    12,    13,    14,    15,
      16,    -1,    -1,    -1,    20,    21,    22,    23,    24,    25
};
/* -*-C-*-  Note some compilers choke on comments on `#line' lines.  */
#line 3 "/usr/share/bison/bison.simple"

/* Skeleton output parser for bison,
   Copyright (C) 1984, 1989, 1990, 2000, 2001 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place - Suite 330,
   Boston, MA 02111-1307, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* This is the parser code that is written into each bison parser when
   the %semantic_parser declaration is not specified in the grammar.
   It was written by Richard Stallman by simplifying the hairy parser
   used when %semantic_parser is specified.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

#ifdef __cplusplus
# define YYSTD(x) std::x
#else
# define YYSTD(x) x
#endif

#if ! defined (yyoverflow) || defined (YYERROR_VERBOSE)

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# if YYSTACK_USE_ALLOCA
#  define YYSTACK_ALLOC alloca
#  define YYSIZE_T YYSTD (size_t)
# else
#  ifndef YYSTACK_USE_ALLOCA
#   if defined (alloca) || defined (_ALLOCA_H)
#    define YYSTACK_ALLOC alloca
#    define YYSIZE_T YYSTD (size_t)
#   else
#    ifdef __GNUC__
#     define YYSTACK_ALLOC __builtin_alloca
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's `empty if-body' warning. */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
# else
#  ifdef __cplusplus
#   include <cstdlib> /* INFRINGES ON USER NAME SPACE */
#   define YYSIZE_T std::size_t
#  else
#   ifdef __STDC__
#    include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#    define YYSIZE_T size_t
#   endif
#  endif
#  define YYSTACK_ALLOC YYSTD (malloc)
#  define YYSTACK_FREE YYSTD (free)
# endif

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  short yyss;
  YYSTYPE yyvs;
# if YYLSP_NEEDED
  YYLTYPE yyls;
# endif
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAX (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# if YYLSP_NEEDED
#  define YYSTACK_BYTES(N) \
     ((N) * (sizeof (short) + sizeof (YYSTYPE) + sizeof (YYLTYPE))	\
      + 2 * YYSTACK_GAP_MAX)
# else
#  define YYSTACK_BYTES(N) \
     ((N) * (sizeof (short) + sizeof (YYSTYPE))				\
      + YYSTACK_GAP_MAX)
# endif

/* Relocate the TYPE STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Type, Stack)					\
    do									\
      {									\
	YYSIZE_T yynewbytes;						\
	yymemcpy ((char *) yyptr, (char *) (Stack),			\
		  yysize * (YYSIZE_T) sizeof (Type));			\
	Stack = &yyptr->Stack;						\
	yynewbytes = yystacksize * sizeof (Type) + YYSTACK_GAP_MAX;	\
	yyptr += yynewbytes / sizeof (*yyptr);				\
      }									\
    while (0)

#endif /* ! defined (yyoverflow) || defined (YYERROR_VERBOSE) */


#if ! defined (YYSIZE_T) && defined (__SIZE_TYPE__)
# define YYSIZE_T __SIZE_TYPE__
#endif
#if ! defined (YYSIZE_T) && defined (size_t)
# define YYSIZE_T size_t
#endif
#if ! defined (YYSIZE_T)
# ifdef __cplusplus
#  include <cstddef> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T std::size_t
# else
#  ifdef __STDC__
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#   define YYSIZE_T size_t
#  endif
# endif
#endif
#if ! defined (YYSIZE_T)
# define YYSIZE_T unsigned int
#endif

#define yyerrok		(yyerrstatus = 0)
#define yyclearin	(yychar = YYEMPTY)
#define YYEMPTY		-2
#define YYEOF		0
#define YYACCEPT	goto yyacceptlab
#define YYABORT 	goto yyabortlab
#define YYERROR		goto yyerrlab1
/* Like YYERROR except do call yyerror.  This remains here temporarily
   to ease the transition to the new meaning of YYERROR, for GCC.
   Once GCC version 2 has supplanted version 1, this can go.  */
#define YYFAIL		goto yyerrlab
#define YYRECOVERING()  (!!yyerrstatus)
#define YYBACKUP(Token, Value)					\
do								\
  if (yychar == YYEMPTY && yylen == 1)				\
    {								\
      yychar = (Token);						\
      yylval = (Value);						\
      yychar1 = YYTRANSLATE (yychar);				\
      YYPOPSTACK;						\
      goto yybackup;						\
    }								\
  else								\
    { 								\
      yyerror ("syntax error: cannot back up");			\
      YYERROR;							\
    }								\
while (0)

#define YYTERROR	1
#define YYERRCODE	256


/* YYLLOC_DEFAULT -- Compute the default location (before the actions
   are run).

   When YYLLOC_DEFAULT is run, CURRENT is set the location of the
   first token.  By default, to implement support for ranges, extend
   its range to the last symbol.  */

#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)       	\
   Current.last_line   = Rhs[N].last_line;	\
   Current.last_column = Rhs[N].last_column;
#endif


/* YYLEX -- calling `yylex' with the right arguments.  */

#if YYPURE
# if YYLSP_NEEDED
#  ifdef YYLEX_PARAM
#   define YYLEX		yylex (&yylval, &yylloc, YYLEX_PARAM)
#  else
#   define YYLEX		yylex (&yylval, &yylloc)
#  endif
# else /* !YYLSP_NEEDED */
#  ifdef YYLEX_PARAM
#   define YYLEX		yylex (&yylval, YYLEX_PARAM)
#  else
#   define YYLEX		yylex (&yylval)
#  endif
# endif /* !YYLSP_NEEDED */
#else /* !YYPURE */
# define YYLEX			yylex ()
#endif /* !YYPURE */


/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  ifdef __cplusplus
#   include <cstdio>  /* INFRINGES ON USER NAME SPACE */
#  else
#   include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYFPRINTF YYSTD (fprintf)
# endif

# define YYDPRINTF(Args)			\
do {						\
  if (yydebug)					\
    YYFPRINTF Args;				\
} while (0)
/* Nonzero means print parse trace. [The following comment makes no
   sense to me.  Could someone clarify it?  --akim] Since this is
   uninitialized, it does not stop multiple parsers from coexisting.
   */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args)
#endif /* !YYDEBUG */

/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef	YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   SIZE_MAX < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#if YYMAXDEPTH == 0
# undef YYMAXDEPTH
#endif

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif

#if ! defined (yyoverflow) && ! defined (yymemcpy)
# if __GNUC__ > 1		/* GNU C and GNU C++ define this.  */
#  define yymemcpy __builtin_memcpy
# else				/* not GNU C or C++ */

/* This is the most reliable way to avoid incompatibilities
   in available built-in functions on various systems.  */
static void
#  if defined (__STDC__) || defined (__cplusplus)
yymemcpy (char *yyto, const char *yyfrom, YYSIZE_T yycount)
#  else
yymemcpy (yyto, yyfrom, yycount)
     char *yyto;
     const char *yyfrom;
     YYSIZE_T yycount;
#  endif
{
  register const char *yyf = yyfrom;
  register char *yyt = yyto;
  register YYSIZE_T yyi = yycount;

  while (yyi-- != 0)
    *yyt++ = *yyf++;
}
# endif
#endif

#ifdef YYERROR_VERBOSE

# ifndef yystrlen
#  if defined (__GLIBC__) && defined (_STRING_H)
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
#   if defined (__STDC__) || defined (__cplusplus)
yystrlen (const char *yystr)
#   else
yystrlen (yystr)
     const char *yystr;
#   endif
{
  register const char *yys = yystr;

  while (*yys++ != '\0')
    continue;

  return yys - yystr - 1;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined (__GLIBC__) && defined (_STRING_H) && defined (_GNU_SOURCE)
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
#   if defined (__STDC__) || defined (__cplusplus)
yystpcpy (char *yydest, const char *yysrc)
#   else
yystpcpy (yydest, yysrc)
     char *yydest;
     const char *yysrc;
#   endif
{
  register char *yyd = yydest;
  register const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif
#endif

#line 341 "/usr/share/bison/bison.simple"


/* The user can define YYPARSE_PARAM as the name of an argument to be passed
   into yyparse.  The argument should have type void *.
   It should actually point to an object.
   Grammar actions can access the variable by casting it
   to the proper pointer type.  */

#ifdef YYPARSE_PARAM
# ifdef __cplusplus
#  define YYPARSE_PARAM_ARG void *YYPARSE_PARAM
#  define YYPARSE_PARAM_DECL
# else /* !__cplusplus */
#  define YYPARSE_PARAM_ARG YYPARSE_PARAM
#  define YYPARSE_PARAM_DECL void *YYPARSE_PARAM;
# endif /* !__cplusplus */
#else /* !YYPARSE_PARAM */
# define YYPARSE_PARAM_ARG
# define YYPARSE_PARAM_DECL
#endif /* !YYPARSE_PARAM */

/* Prevent warning if -Wstrict-prototypes.  */
#ifdef __GNUC__
# ifdef YYPARSE_PARAM
int yyparse (void *);
# else
int yyparse (void);
# endif
#endif

/* YY_DECL_VARIABLES -- depending whether we use a pure parser,
   variables are global, or local to YYPARSE.  */

#define YY_DECL_NON_LSP_VARIABLES			\
/* The lookahead symbol.  */				\
int yychar;						\
							\
/* The semantic value of the lookahead symbol. */	\
YYSTYPE yylval;						\
							\
/* Number of parse errors so far.  */			\
int yynerrs;

#if YYLSP_NEEDED
# define YY_DECL_VARIABLES			\
YY_DECL_NON_LSP_VARIABLES			\
						\
/* Location data for the lookahead symbol.  */	\
YYLTYPE yylloc;
#else
# define YY_DECL_VARIABLES			\
YY_DECL_NON_LSP_VARIABLES
#endif


/* If nonreentrant, generate the variables here. */

#if !YYPURE
YY_DECL_VARIABLES
#endif  /* !YYPURE */

int
yyparse (YYPARSE_PARAM_ARG)
     YYPARSE_PARAM_DECL
{
  /* If reentrant, generate the variables here. */
#if YYPURE
  YY_DECL_VARIABLES
#endif  /* !YYPURE */

  register int yystate;
  register int yyn;
  int yyresult;
  /* Number of tokens to shift before error messages enabled.  */
  int yyerrstatus;
  /* Lookahead token as an internal (translated) token number.  */
  int yychar1 = 0;

  /* Three stacks and their tools:
     `yyss': related to states,
     `yyvs': related to semantic values,
     `yyls': related to locations.

     Refer to the stacks thru separate pointers, to allow yyoverflow
     to reallocate them elsewhere.  */

  /* The state stack. */
  short	yyssa[YYINITDEPTH];
  short *yyss = yyssa;
  register short *yyssp;

  /* The semantic value stack.  */
  YYSTYPE yyvsa[YYINITDEPTH];
  YYSTYPE *yyvs = yyvsa;
  register YYSTYPE *yyvsp;

#if YYLSP_NEEDED
  /* The location stack.  */
  YYLTYPE yylsa[YYINITDEPTH];
  YYLTYPE *yyls = yylsa;
  YYLTYPE *yylsp;
#endif

#if YYLSP_NEEDED
# define YYPOPSTACK   (yyvsp--, yyssp--, yylsp--)
#else
# define YYPOPSTACK   (yyvsp--, yyssp--)
#endif

  YYSIZE_T yystacksize = YYINITDEPTH;


  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;
#if YYLSP_NEEDED
  YYLTYPE yyloc;
#endif

  /* When reducing, the number of symbols on the RHS of the reduced
     rule. */
  int yylen;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY;		/* Cause a token to be read.  */

  /* Initialize stack pointers.
     Waste one element of value and location stack
     so that they stay on the same level as the state stack.
     The wasted elements are never initialized.  */

  yyssp = yyss;
  yyvsp = yyvs;
#if YYLSP_NEEDED
  yylsp = yyls;
#endif
  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed. so pushing a state here evens the stacks.
     */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyssp >= yyss + yystacksize - 1)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
	/* Give user a chance to reallocate the stack. Use copies of
	   these so that the &'s don't force the real ones into
	   memory.  */
	YYSTYPE *yyvs1 = yyvs;
	short *yyss1 = yyss;

	/* Each stack pointer address is followed by the size of the
	   data in use in that stack, in bytes.  */
# if YYLSP_NEEDED
	YYLTYPE *yyls1 = yyls;
	/* This used to be a conditional around just the two extra args,
	   but that might be undefined if yyoverflow is a macro.  */
	yyoverflow ("parser stack overflow",
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),
		    &yyls1, yysize * sizeof (*yylsp),
		    &yystacksize);
	yyls = yyls1;
# else
	yyoverflow ("parser stack overflow",
		    &yyss1, yysize * sizeof (*yyssp),
		    &yyvs1, yysize * sizeof (*yyvsp),
		    &yystacksize);
# endif
	yyss = yyss1;
	yyvs = yyvs1;
      }
#else /* no yyoverflow */
      /* Extend the stack our own way.  */
      if (yystacksize >= YYMAXDEPTH)
	goto yyoverflowlab;
      yystacksize *= 2;
      if (yystacksize > YYMAXDEPTH)
	yystacksize = YYMAXDEPTH;

      {
	short *yyss1 = yyss;
	union yyalloc *yyptr =
	  (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
	if (! yyptr)
	  goto yyoverflowlab;
	YYSTACK_RELOCATE (short, yyss);
	YYSTACK_RELOCATE (YYSTYPE, yyvs);
# if YYLSP_NEEDED
	YYSTACK_RELOCATE (YYLTYPE, yyls);
# endif
# undef YYSTACK_RELOCATE
	if (yyss1 != yyssa)
	  YYSTACK_FREE (yyss1);
      }
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;
#if YYLSP_NEEDED
      yylsp = yyls + yysize - 1;
#endif

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
		  (unsigned long int) yystacksize));

      if (yyssp >= yyss + yystacksize - 1)
	YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:

/* Do appropriate processing given the current state.  */
/* Read a lookahead token if we need one and don't already have one.  */
/* yyresume: */

  /* First try to decide what to do without reference to lookahead token.  */

  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* yychar is either YYEMPTY or YYEOF
     or a valid token in external form.  */

  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = YYLEX;
    }

  /* Convert token to internal form (in yychar1) for indexing tables with */

  if (yychar <= 0)		/* This means end of input. */
    {
      yychar1 = 0;
      yychar = YYEOF;		/* Don't call YYLEX any more */

      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yychar1 = YYTRANSLATE (yychar);

#if YYDEBUG
     /* We have to keep this `#if YYDEBUG', since we use variables
	which are defined only if `YYDEBUG' is set.  */
      if (yydebug)
	{
	  YYFPRINTF (stderr, "Next token is %d (%s",
		     yychar, yytname[yychar1]);
	  /* Give the individual parser a way to print the precise
	     meaning of a token, for further debugging info.  */
# ifdef YYPRINT
	  YYPRINT (stderr, yychar, yylval);
# endif
	  YYFPRINTF (stderr, ")\n");
	}
#endif
    }

  yyn += yychar1;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != yychar1)
    goto yydefault;

  yyn = yytable[yyn];

  /* yyn is what to do for this token type in this state.
     Negative => reduce, -yyn is rule number.
     Positive => shift, yyn is new state.
       New state is final state => don't bother to shift,
       just return success.
     0, or most negative number => error.  */

  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrlab;

  if (yyn == YYFINAL)
    YYACCEPT;

  /* Shift the lookahead token.  */
  YYDPRINTF ((stderr, "Shifting token %d (%s), ",
	      yychar, yytname[yychar1]));

  /* Discard the token being shifted unless it is eof.  */
  if (yychar != YYEOF)
    yychar = YYEMPTY;

  *++yyvsp = yylval;
#if YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  yystate = yyn;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     `$$ = $1'.

     Otherwise, the following line sets YYVAL to the semantic value of
     the lookahead token.  This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];

#if YYLSP_NEEDED
  /* Similarly for the default location.  Let the user run additional
     commands if for instance locations are ranges.  */
  yyloc = yylsp[1-yylen];
  YYLLOC_DEFAULT (yyloc, (yylsp - yylen), yylen);
#endif

#if YYDEBUG
  /* We have to keep this `#if YYDEBUG', since we use variables which
     are defined only if `YYDEBUG' is set.  */
  if (yydebug)
    {
      int yyi;

      YYFPRINTF (stderr, "Reducing via rule %d (line %d), ",
		 yyn, yyrline[yyn]);

      /* Print the symbols being reduced, and their result.  */
      for (yyi = yyprhs[yyn]; yyrhs[yyi] > 0; yyi++)
	YYFPRINTF (stderr, "%s ", yytname[yyrhs[yyi]]);
      YYFPRINTF (stderr, " -> %s\n", yytname[yyr1[yyn]]);
    }
#endif

  switch (yyn) {

case 2:
#line 44 "parsetime.y"
{
			time_only = 1;
		    }
    break;
case 10:
#line 59 "parsetime.y"
{
			add_date(1, DAY);
		   }
    break;
case 21:
#line 76 "parsetime.y"
{
			exectm.tm_hour = 12;
			exectm.tm_min = 0;
		    }
    break;
case 22:
#line 81 "parsetime.y"
{
			exectm.tm_hour = 0;
			exectm.tm_min = 0;
			add_date(1, DAY);
		    }
    break;
case 23:
#line 87 "parsetime.y"
{
			exectm.tm_hour = 16;
			exectm.tm_min = 0;
		    }
    break;
case 27:
#line 97 "parsetime.y"
{
		       add_date ((6 + yyvsp[0].intval - exectm.tm_wday) %7 + 1, DAY);
		   }
    break;
case 29:
#line 102 "parsetime.y"
{
			add_date(1, DAY);
		   }
    break;
case 38:
#line 117 "parsetime.y"
{
		        add_date(yyvsp[-1].intval, yyvsp[0].intval);
		    }
    break;
case 39:
#line 121 "parsetime.y"
{
			add_date(1, yyvsp[0].intval);
		    }
    break;
case 40:
#line 125 "parsetime.y"
{
			add_date ((6 + yyvsp[0].intval - exectm.tm_wday) %7 +1, DAY);
		    }
    break;
case 41:
#line 131 "parsetime.y"
{
			add_date(-yyvsp[-1].intval, yyvsp[0].intval);
		    }
    break;
case 42:
#line 136 "parsetime.y"
{ yyval.intval = MINUTE ; }
    break;
case 43:
#line 137 "parsetime.y"
{ yyval.intval = HOUR ; }
    break;
case 44:
#line 138 "parsetime.y"
{ yyval.intval = DAY ; }
    break;
case 45:
#line 139 "parsetime.y"
{ yyval.intval = WEEK ; }
    break;
case 46:
#line 140 "parsetime.y"
{ yyval.intval = MONTH ; }
    break;
case 47:
#line 141 "parsetime.y"
{ yyval.intval = YEAR ; }
    break;
case 48:
#line 145 "parsetime.y"
{
			if (strlen(yyvsp[0].charval) == 4) {
			    exectm.tm_min = -1;
			    exectm.tm_hour = -1;
			    sscanf(yyvsp[0].charval, "%2d %2d", &exectm.tm_hour,
				&exectm.tm_min);
			} else if (strlen(yyvsp[0].charval) >= 5 && strlen(yyvsp[0].charval) <= 8) {
				/* Ok, this is a kluge.  I hate design errors...  -Joey */
				char shallot[5];
				char *onion;

				onion=yyvsp[0].charval;
				memset (shallot, 0, sizeof (shallot));
				if (strlen(yyvsp[0].charval) == 5 || strlen(yyvsp[0].charval) == 7) {
				    strncpy (shallot,onion,1);
				    onion++;
				} else {
				    strncpy (shallot,onion,2);
				    onion+=2;
				}
				sscanf(shallot, "%d", &exectm.tm_mon);

				if (exectm.tm_mon < 1 || exectm.tm_mon > 12) {
				    yyerror("Error in month number");
				    YYERROR;
				}
				exectm.tm_mon--;

				memset (shallot, 0, sizeof (shallot));
				strncpy (shallot,onion,2);
			    	sscanf(shallot, "%d", &exectm.tm_mday);
				if (exectm.tm_mday < 0 || exectm.tm_mday > 31)
				{
				    yyerror("Error in day of month");
				    YYERROR;
				}

				onion+=2;
				memset (shallot, 0, sizeof (shallot));
				strncpy (shallot,onion,4);
				if ( sscanf(shallot, "%d", &exectm.tm_year) != 1) {
				    yyerror("Error in year");
				    YYERROR;
				}
				if (exectm.tm_year < 70) {
				    exectm.tm_year += 100;
				}
				else if (exectm.tm_year > 1900) {
				    exectm.tm_year -= 1900;
				}
			}
			else {
			    sscanf(yyvsp[0].charval, "%d", &exectm.tm_hour);
			    exectm.tm_min = 0;
			}
			free(yyvsp[0].charval);

			if (exectm.tm_min > 60 || exectm.tm_min < 0) {
			    yyerror("Problem in minutes specification");
			    YYERROR;
			}
			if (exectm.tm_hour > 24 || exectm.tm_hour < 0) {
			    yyerror("Problem in hours specification");
			    YYERROR;
		        }
		    }
    break;
case 49:
#line 214 "parsetime.y"
{
			if (strcasecmp(yyvsp[0].charval,"utc") == 0) {
			    isgmt = 1;
			}
			else {
			    yyerror("Only UTC timezone is supported");
			    YYERROR;
			}
			free(yyvsp[0].charval);
		    }
    break;
case 51:
#line 230 "parsetime.y"
{
			if (sscanf(yyvsp[0].charval, "%d", &exectm.tm_min) != 1) {
			    yyerror("Error in minute");
			    YYERROR;
		        }
			free(yyvsp[0].charval);
		    }
    break;
case 52:
#line 240 "parsetime.y"
{
			if (exectm.tm_hour > 12) {
			    yyerror("Hour too large for AM");
			    YYERROR;
			}
			else if (exectm.tm_hour == 12) {
			    exectm.tm_hour = 0;
			}
		    }
    break;
case 53:
#line 250 "parsetime.y"
{
			if (exectm.tm_hour > 12) {
			    yyerror("Hour too large for PM");
			    YYERROR;
			}
			else if (exectm.tm_hour < 12) {
			    exectm.tm_hour +=12;
			}
		    }
    break;
case 54:
#line 262 "parsetime.y"
{ exectm.tm_mon = 0; }
    break;
case 55:
#line 263 "parsetime.y"
{ exectm.tm_mon = 1; }
    break;
case 56:
#line 264 "parsetime.y"
{ exectm.tm_mon = 2; }
    break;
case 57:
#line 265 "parsetime.y"
{ exectm.tm_mon = 3; }
    break;
case 58:
#line 266 "parsetime.y"
{ exectm.tm_mon = 4; }
    break;
case 59:
#line 267 "parsetime.y"
{ exectm.tm_mon = 5; }
    break;
case 60:
#line 268 "parsetime.y"
{ exectm.tm_mon = 6; }
    break;
case 61:
#line 269 "parsetime.y"
{ exectm.tm_mon = 7; }
    break;
case 62:
#line 270 "parsetime.y"
{ exectm.tm_mon = 8; }
    break;
case 63:
#line 271 "parsetime.y"
{ exectm.tm_mon = 9; }
    break;
case 64:
#line 272 "parsetime.y"
{ exectm.tm_mon =10; }
    break;
case 65:
#line 273 "parsetime.y"
{ exectm.tm_mon =11; }
    break;
case 66:
#line 277 "parsetime.y"
{
			{
			    int mnum = -1;
			    sscanf(yyvsp[0].charval, "%d", &mnum);

			    if (mnum < 1 || mnum > 12) {
				yyerror("Error in month number");
				YYERROR;
			    }
			    exectm.tm_mon = mnum -1;
			    free(yyvsp[0].charval);
			}
		    }
    break;
case 67:
#line 291 "parsetime.y"
{
			exectm.tm_mday = -1;
			sscanf(yyvsp[0].charval, "%d", &exectm.tm_mday);
			if (exectm.tm_mday < 0 || exectm.tm_mday > 31)
			{
			    yyerror("Error in day of month");
			    YYERROR; 
			}
			free(yyvsp[0].charval);
		     }
    break;
case 68:
#line 304 "parsetime.y"
{ 
			{
			    int ynum;

			    if ( sscanf(yyvsp[0].charval, "%d", &ynum) != 1) {
				yyerror("Error in year");
				YYERROR;
			    }
			    if (ynum < 70) {
				ynum += 100;
			    }
			    else if (ynum > 1900) {
				ynum -= 1900;
			    }

			    exectm.tm_year = ynum ;
			    free(yyvsp[0].charval);
			}
		    }
    break;
case 69:
#line 326 "parsetime.y"
{ yyval.intval = 0; }
    break;
case 70:
#line 327 "parsetime.y"
{ yyval.intval = 1; }
    break;
case 71:
#line 328 "parsetime.y"
{ yyval.intval = 2; }
    break;
case 72:
#line 329 "parsetime.y"
{ yyval.intval = 3; }
    break;
case 73:
#line 330 "parsetime.y"
{ yyval.intval = 4; }
    break;
case 74:
#line 331 "parsetime.y"
{ yyval.intval = 5; }
    break;
case 75:
#line 332 "parsetime.y"
{ yyval.intval = 6; }
    break;
case 76:
#line 336 "parsetime.y"
{
			if (sscanf(yyvsp[0].charval, "%d", &yyval.intval) != 1) {
			    yyerror("Unknown increment");
			    YYERROR;
		        }
		        free(yyvsp[0].charval);
		    }
    break;
}

#line 727 "/usr/share/bison/bison.simple"


  yyvsp -= yylen;
  yyssp -= yylen;
#if YYLSP_NEEDED
  yylsp -= yylen;
#endif

#if YYDEBUG
  if (yydebug)
    {
      short *yyssp1 = yyss - 1;
      YYFPRINTF (stderr, "state stack now");
      while (yyssp1 != yyssp)
	YYFPRINTF (stderr, " %d", *++yyssp1);
      YYFPRINTF (stderr, "\n");
    }
#endif

  *++yyvsp = yyval;
#if YYLSP_NEEDED
  *++yylsp = yyloc;
#endif

  /* Now `shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTBASE] + *yyssp;
  if (yystate >= 0 && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTBASE];

  goto yynewstate;


/*------------------------------------.
| yyerrlab -- here on detecting error |
`------------------------------------*/
yyerrlab:
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;

#ifdef YYERROR_VERBOSE
      yyn = yypact[yystate];

      if (yyn > YYFLAG && yyn < YYLAST)
	{
	  YYSIZE_T yysize = 0;
	  char *yymsg;
	  int yyx, yycount;

	  yycount = 0;
	  /* Start YYX at -YYN if negative to avoid negative indexes in
	     YYCHECK.  */
	  for (yyx = yyn < 0 ? -yyn : 0;
	       yyx < (int) (sizeof (yytname) / sizeof (char *)); yyx++)
	    if (yycheck[yyx + yyn] == yyx)
	      yysize += yystrlen (yytname[yyx]) + 15, yycount++;
	  yysize += yystrlen ("parse error, unexpected ") + 1;
	  yysize += yystrlen (yytname[YYTRANSLATE (yychar)]);
	  yymsg = (char *) YYSTACK_ALLOC (yysize);
	  if (yymsg != 0)
	    {
	      char *yyp = yystpcpy (yymsg, "parse error, unexpected ");
	      yyp = yystpcpy (yyp, yytname[YYTRANSLATE (yychar)]);

	      if (yycount < 5)
		{
		  yycount = 0;
		  for (yyx = yyn < 0 ? -yyn : 0;
		       yyx < (int) (sizeof (yytname) / sizeof (char *));
		       yyx++)
		    if (yycheck[yyx + yyn] == yyx)
		      {
			const char *yyq = ! yycount ? ", expecting " : " or ";
			yyp = yystpcpy (yyp, yyq);
			yyp = yystpcpy (yyp, yytname[yyx]);
			yycount++;
		      }
		}
	      yyerror (yymsg);
	      YYSTACK_FREE (yymsg);
	    }
	  else
	    yyerror ("parse error; also virtual memory exhausted");
	}
      else
#endif /* defined (YYERROR_VERBOSE) */
	yyerror ("parse error");
    }
  goto yyerrlab1;


/*--------------------------------------------------.
| yyerrlab1 -- error raised explicitly by an action |
`--------------------------------------------------*/
yyerrlab1:
  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
	 error, discard it.  */

      /* return failure if at end of input */
      if (yychar == YYEOF)
	YYABORT;
      YYDPRINTF ((stderr, "Discarding token %d (%s).\n",
		  yychar, yytname[yychar1]));
      yychar = YYEMPTY;
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */

  yyerrstatus = 3;		/* Each real token shifted decrements this */

  goto yyerrhandle;


/*-------------------------------------------------------------------.
| yyerrdefault -- current state does not do anything special for the |
| error token.                                                       |
`-------------------------------------------------------------------*/
yyerrdefault:
#if 0
  /* This is wrong; only states that explicitly want error tokens
     should shift them.  */

  /* If its default is to accept any token, ok.  Otherwise pop it.  */
  yyn = yydefact[yystate];
  if (yyn)
    goto yydefault;
#endif


/*---------------------------------------------------------------.
| yyerrpop -- pop the current state because it cannot handle the |
| error token                                                    |
`---------------------------------------------------------------*/
yyerrpop:
  if (yyssp == yyss)
    YYABORT;
  yyvsp--;
  yystate = *--yyssp;
#if YYLSP_NEEDED
  yylsp--;
#endif

#if YYDEBUG
  if (yydebug)
    {
      short *yyssp1 = yyss - 1;
      YYFPRINTF (stderr, "Error: state stack now");
      while (yyssp1 != yyssp)
	YYFPRINTF (stderr, " %d", *++yyssp1);
      YYFPRINTF (stderr, "\n");
    }
#endif

/*--------------.
| yyerrhandle.  |
`--------------*/
yyerrhandle:
  yyn = yypact[yystate];
  if (yyn == YYFLAG)
    goto yyerrdefault;

  yyn += YYTERROR;
  if (yyn < 0 || yyn > YYLAST || yycheck[yyn] != YYTERROR)
    goto yyerrdefault;

  yyn = yytable[yyn];
  if (yyn < 0)
    {
      if (yyn == YYFLAG)
	goto yyerrpop;
      yyn = -yyn;
      goto yyreduce;
    }
  else if (yyn == 0)
    goto yyerrpop;

  if (yyn == YYFINAL)
    YYACCEPT;

  YYDPRINTF ((stderr, "Shifting error token, "));

  *++yyvsp = yylval;
#if YYLSP_NEEDED
  *++yylsp = yylloc;
#endif

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

/*---------------------------------------------.
| yyoverflowab -- parser overflow comes here.  |
`---------------------------------------------*/
yyoverflowlab:
  yyerror ("parser stack overflow");
  yyresult = 2;
  /* Fall through.  */

yyreturn:
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
  return yyresult;
}
#line 352 "parsetime.y"



time_t parsetime(int, char **);

time_t
parsetime(int argc, char **argv)
{
    time_t exectime;

    my_argv = argv;
    currtime = time(NULL);
    exectm = *localtime(&currtime);
    exectm.tm_sec = 0;
    exectm.tm_isdst = -1;
    time_only = 0;
    if (yyparse() == 0) {
	exectime = mktime(&exectm);
	if (exectime == (time_t)-1)
	    return 0;
	if (isgmt) {
	    exectime += timezone;
	    if (daylight) {
		exectime -= 3600;
	    }
	}
	if (time_only && (currtime > exectime)) {
	    exectime += 24*3600;
	}
        return exectime;
    }
    else {
	return 0;    
    }
}

#ifdef TEST_PARSER
/*

Here are some lines to test:

./parsetest 7AM Mar 24 2000
./parsetest 7AM Mar 24 00
./parsetest 7AM 032400
./parsetest 7AM 03/24/00
./parsetest 7AM 24.03.00
./parsetest 7AM Mar 24

./parsetest 03242000
./parsetest noon 03242000
./parsetest 5:30
./parsetest 4pm + 3 days
./parsetest 10am Jul 31

 */
int
main(int argc, char **argv)
{
    time_t res;
    res = parsetime(argc-1, &argv[1]);
    if (res > 0) {
	printf("%s",ctime(&res));
    }
    else {
	printf("Ooops...\n");
    }
    return 0;
}

#endif
int yyerror(char *s)
{
    if (last_token == NULL)
	last_token = "(empty)";
    fprintf(stderr,"%s. Last token seen: %s\n",s, last_token);
    return 0;
}

void
add_seconds(struct tm *tm, long numsec)
{
    time_t timeval;
    timeval = mktime(tm);
    if (timeval == (time_t)-1)
        timeval = (time_t)0;
    timeval += numsec;
    *tm = *localtime(&timeval);
}

int
add_date(int number, int period)
{
    switch(period) {
    case MINUTE:
	add_seconds(&exectm , 60l*number);
	break;

    case HOUR:
	add_seconds(&exectm, 3600l * number);
	break;

    case DAY:
	add_seconds(&exectm, 24*3600l * number);
	break;

    case WEEK:
	add_seconds(&exectm, 7*24*3600l*number);
	break;

    case MONTH:
	{
	    int newmonth = exectm.tm_mon + number;
	    number = 0;
	    while (newmonth < 0) {
		newmonth += 12;
		number --;
	    }
	    exectm.tm_mon = newmonth % 12;
	    number += newmonth / 12 ;
	}
	if (number == 0) {
	    break;
	}
	/* fall through */

    case YEAR:
	exectm.tm_year += number;
	break;

    default:
	yyerror("Internal parser error");
	fprintf(stderr,"Unexpected case %d\n", period);
	abort();
    }
    return 0;
}
