#ifndef lint
static char const 
yyrcsid[] = "$FreeBSD: src/usr.bin/yacc/skeleton.c,v 1.28 2000/01/17 02:04:06 bde Exp $";
#endif
#include <stdlib.h>
#define YYBYACC 1
#define YYMAJOR 1
#define YYMINOR 9
#define YYLEX yylex()
#define YYEMPTY -1
#define yyclearin (yychar=(YYEMPTY))
#define yyerrok (yyerrflag=0)
#define YYRECOVERING() (yyerrflag!=0)
static int yygrowstack();
#define YYPREFIX "yy"
#line 38 "ftpcmd.y"

#ifndef lint
static char sccsid[] = "@(#)ftpcmd.y	8.3 (Berkeley) 4/6/94";
#endif /* not lint */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/ftp.h>

#include <ctype.h>
#include <errno.h>
#include <pwd.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#include <unistd.h>
#include <limits.h>
#ifdef HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif
/* Include glob.h last, because it may define "const" which breaks
   system headers on some platforms. */
#include <glob.h>

#include "extern.h"

#if ! defined (NBBY) && defined (CHAR_BIT)
#define NBBY CHAR_BIT
#endif

jmp_buf errcatch;
off_t restart_point;

static char cbuf[512];           /* Command Buffer.  */
static char *fromname;
static int cmd_type;
static int cmd_form;
static int cmd_bytesz;

struct tab
{
  const char	*name;
  short	token;
  short	state;
  short	implemented;	/* 1 if command is implemented */
  const char	*help;
};

extern struct tab cmdtab[];
extern struct tab sitetab[];
static char *copy         __P ((char *));
static void help          __P ((struct tab *, char *));
static struct tab *lookup __P ((struct tab *, char *));
static void sizecmd       __P ((char *));
static int yylex          __P ((void));
static void yyerror       __P ((const char *s));

#line 118 "ftpcmd.y"
typedef union {
	int	i;
	char   *s;
} YYSTYPE;
#line 101 "y.tab.c"
#define YYERRCODE 256
#define A 257
#define B 258
#define C 259
#define E 260
#define F 261
#define I 262
#define L 263
#define N 264
#define P 265
#define R 266
#define S 267
#define T 268
#define SP 269
#define CRLF 270
#define COMMA 271
#define USER 272
#define PASS 273
#define ACCT 274
#define REIN 275
#define QUIT 276
#define PORT 277
#define PASV 278
#define TYPE 279
#define STRU 280
#define MODE 281
#define RETR 282
#define STOR 283
#define APPE 284
#define MLFL 285
#define MAIL 286
#define MSND 287
#define MSOM 288
#define MSAM 289
#define MRSQ 290
#define MRCP 291
#define ALLO 292
#define REST 293
#define RNFR 294
#define RNTO 295
#define ABOR 296
#define DELE 297
#define CWD 298
#define LIST 299
#define NLST 300
#define SITE 301
#define STAT 302
#define HELP 303
#define NOOP 304
#define MKD 305
#define RMD 306
#define PWD 307
#define CDUP 308
#define STOU 309
#define SMNT 310
#define SYST 311
#define SIZE 312
#define MDTM 313
#define UMASK 314
#define IDLE 315
#define CHMOD 316
#define LEXERR 317
#define STRING 318
#define NUMBER 319
const short yylhs[] = {                                        -1,
    0,    0,    0,   12,   12,   12,   12,   12,   12,   12,
   12,   12,   12,   12,   12,   12,   12,   12,   12,   12,
   12,   12,   12,   12,   12,   12,   12,   12,   12,   12,
   12,   12,   12,   12,   12,   12,   12,   12,   12,   12,
   12,   12,   12,   12,   12,   12,   13,   13,   11,   10,
   10,    3,   14,    7,    7,    7,    6,    6,    6,    6,
    6,    6,    6,    6,    4,    4,    4,    5,    5,    5,
    9,    8,    2,    1,
};
const short yylen[] = {                                         2,
    0,    2,    2,    4,    4,    5,    3,    4,    4,    4,
    4,    8,    5,    5,    5,    3,    5,    3,    5,    5,
    2,    5,    5,    2,    3,    5,    2,    4,    2,    5,
    5,    3,    3,    4,    6,    5,    7,    9,    4,    7,
    5,    2,    5,    5,    2,    2,    5,    4,    1,    0,
    1,    1,   11,    1,    1,    1,    1,    3,    1,    3,
    1,    1,    3,    2,    1,    1,    1,    1,    1,    1,
    1,    1,    1,    0,
};
const short yydefred[] = {                                      1,
    0,    0,    0,    0,    0,   74,   74,    0,    0,    0,
   74,   74,   74,    0,    0,   74,   74,    0,   74,   74,
   74,   74,    0,    0,    0,    0,   74,   74,   74,   74,
   74,    0,   74,   74,    2,    3,   46,    0,    0,   45,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,   24,    0,    0,    0,    0,    0,   21,    0,
    0,   27,   29,    0,    0,    0,    0,    0,   42,    0,
    0,   49,    0,   51,    0,    0,    7,    0,    0,   61,
    0,    0,   65,   67,   66,    0,   69,   70,   68,    0,
    0,    0,    0,    0,   52,    0,    0,    0,    0,    0,
   25,    0,   18,    0,   16,    0,   74,    0,   74,    0,
    0,    0,    0,    0,   32,   33,    0,    0,    0,    4,
    5,    0,    0,    0,    0,    0,   64,    8,    9,   10,
   72,   71,    0,    0,    0,    0,   11,   48,    0,    0,
    0,    0,    0,    0,    0,   34,    0,   39,    0,    0,
    0,   28,    0,    0,    0,    0,    0,    0,    6,   56,
   54,   55,   58,   60,   63,   13,   14,   15,    0,   47,
   23,   22,   26,   19,   17,    0,    0,   36,    0,    0,
   20,   30,   31,   41,   43,   44,    0,    0,   35,   73,
    0,    0,    0,    0,    0,   37,    0,   40,    0,   12,
    0,    0,   38,    0,    0,    0,    0,   53,
};
const short yydgoto[] = {                                       1,
   41,  191,   96,   86,   90,   82,  163,  132,  133,   75,
   73,   35,   36,  123,
};
const short yysindex[] = {                                      0,
 -216, -261, -246, -234, -217,    0,    0, -171, -169, -167,
    0,    0,    0, -161, -160,    0,    0, -159,    0,    0,
    0,    0, -157, -155, -238, -154,    0,    0,    0,    0,
    0, -153,    0,    0,    0,    0,    0, -208, -205,    0,
 -151, -150, -156, -248, -247, -148, -147, -146, -194, -192,
 -141, -140,    0, -139, -227, -215, -211, -300,    0, -138,
 -204,    0,    0, -137, -136, -135, -134, -132,    0, -131,
 -130,    0, -129,    0, -128, -185,    0, -126, -125,    0,
 -267, -124,    0,    0,    0, -123,    0,    0,    0, -122,
 -199, -199, -199, -200,    0, -121, -199, -199, -199, -199,
    0, -199,    0, -178,    0, -198,    0, -120,    0, -170,
 -199, -119, -199, -199,    0,    0, -199, -199, -199,    0,
    0, -118, -116, -165, -165, -192,    0,    0,    0,    0,
    0,    0, -115, -114, -113, -108,    0,    0, -111, -110,
 -109, -107, -106, -105, -166,    0, -196,    0, -103, -102,
 -101,    0, -100,  -99,  -98,  -97,  -96, -144,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  -93,    0,
    0,    0,    0,    0,    0,  -91, -142,    0, -142, -133,
    0,    0,    0,    0,    0,    0,  -90, -127,    0,    0,
  -88,  -89,  -87, -117,  -86,    0, -199,    0,  -84,    0,
  -85, -112,    0,  -83, -104,  -82,  -95,    0,
};
const short yyrindex[] = {                                      0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,  -79,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,  -76,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,  -75, -155,    0,
  -74,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,    0,    0,
    0,    0,    0,    0,    0,    0,    0,    0,
};
const short yygindex[] = {                                      0,
   17,  -17,  -77,    0,    0,    0,   43,    0,  -92,    0,
    0,    0,    0,    0,
};
#define YYTABLESIZE 224
const short yytable[] = {                                     134,
  135,  126,  106,  127,  139,  140,  141,  142,   37,  143,
   87,   88,   83,  107,  108,  109,   84,   85,  151,   89,
  153,  154,   38,   42,  155,  156,  157,   46,   47,   48,
   61,   62,   51,   52,   39,   54,   55,   56,   57,    2,
   60,  100,  101,   64,   65,   66,   67,   68,  165,   70,
   71,   95,   40,  102,  103,    3,    4,  104,  105,    5,
    6,    7,    8,    9,   10,   11,   12,   13,  136,  137,
  145,  146,  177,  178,  110,   14,   15,   16,   17,   18,
   19,   20,   21,   22,   23,   24,   25,   26,   27,   28,
   29,   30,   31,  160,   32,   33,   34,   43,  161,   44,
   78,   45,  162,   79,  201,   80,   81,   49,   50,   72,
   53,   58,   74,  112,   59,   63,   69,   76,  131,   77,
   91,   92,   93,  147,   94,  149,   95,   97,   98,   99,
  111,  113,  114,  122,  115,  116,  117,  118,  119,  144,
  120,  121,  124,  125,  150,  128,  129,  130,  138,  148,
  152,  176,  158,  159,  166,  167,  168,  169,  170,  171,
  172,  192,  173,  174,  175,  179,  180,  164,  181,  182,
  183,  184,  185,  186,  187,  188,  190,    0,  189,  197,
  194,  196,  198,  200,  203,  193,  202,  205,  207,   74,
    0,  195,    0,   50,   57,   62,    0,    0,    0,    0,
    0,  199,    0,    0,    0,    0,  204,    0,    0,    0,
    0,    0,    0,    0,  206,    0,    0,    0,    0,    0,
    0,    0,    0,  208,
};
const short yycheck[] = {                                      92,
   93,  269,  303,   81,   97,   98,   99,  100,  270,  102,
  258,  259,  261,  314,  315,  316,  265,  266,  111,  267,
  113,  114,  269,    7,  117,  118,  119,   11,   12,   13,
  269,  270,   16,   17,  269,   19,   20,   21,   22,  256,
   24,  269,  270,   27,   28,   29,   30,   31,  126,   33,
   34,  319,  270,  269,  270,  272,  273,  269,  270,  276,
  277,  278,  279,  280,  281,  282,  283,  284,  269,  270,
  269,  270,  269,  270,   58,  292,  293,  294,  295,  296,
  297,  298,  299,  300,  301,  302,  303,  304,  305,  306,
  307,  308,  309,  259,  311,  312,  313,  269,  264,  269,
  257,  269,  268,  260,  197,  262,  263,  269,  269,  318,
  270,  269,  318,  318,  270,  270,  270,  269,  318,  270,
  269,  269,  269,  107,  319,  109,  319,  269,  269,  269,
  269,  269,  269,  319,  270,  270,  269,  269,  269,  318,
  270,  270,  269,  269,  315,  270,  270,  270,  270,  270,
  270,  318,  271,  270,  270,  270,  270,  266,  270,  270,
  270,  179,  270,  270,  270,  269,  269,  125,  270,  270,
  270,  270,  270,  270,  319,  269,  319,   -1,  270,  269,
  271,  270,  270,  270,  270,  319,  271,  271,  271,  269,
   -1,  319,   -1,  270,  270,  270,   -1,   -1,   -1,   -1,
   -1,  319,   -1,   -1,   -1,   -1,  319,   -1,   -1,   -1,
   -1,   -1,   -1,   -1,  319,   -1,   -1,   -1,   -1,   -1,
   -1,   -1,   -1,  319,
};
#define YYFINAL 1
#ifndef YYDEBUG
#define YYDEBUG 0
#endif
#define YYMAXTOKEN 319
#if YYDEBUG
const char * const yyname[] = {
"end-of-file",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,"A","B","C","E","F","I","L","N",
"P","R","S","T","SP","CRLF","COMMA","USER","PASS","ACCT","REIN","QUIT","PORT",
"PASV","TYPE","STRU","MODE","RETR","STOR","APPE","MLFL","MAIL","MSND","MSOM",
"MSAM","MRSQ","MRCP","ALLO","REST","RNFR","RNTO","ABOR","DELE","CWD","LIST",
"NLST","SITE","STAT","HELP","NOOP","MKD","RMD","PWD","CDUP","STOU","SMNT",
"SYST","SIZE","MDTM","UMASK","IDLE","CHMOD","LEXERR","STRING","NUMBER",
};
const char * const yyrule[] = {
"$accept : cmd_list",
"cmd_list :",
"cmd_list : cmd_list cmd",
"cmd_list : cmd_list rcmd",
"cmd : USER SP username CRLF",
"cmd : PASS SP password CRLF",
"cmd : PORT check_login SP host_port CRLF",
"cmd : PASV check_login CRLF",
"cmd : TYPE SP type_code CRLF",
"cmd : STRU SP struct_code CRLF",
"cmd : MODE SP mode_code CRLF",
"cmd : ALLO SP NUMBER CRLF",
"cmd : ALLO SP NUMBER SP R SP NUMBER CRLF",
"cmd : RETR check_login SP pathname CRLF",
"cmd : STOR check_login SP pathname CRLF",
"cmd : APPE check_login SP pathname CRLF",
"cmd : NLST check_login CRLF",
"cmd : NLST check_login SP STRING CRLF",
"cmd : LIST check_login CRLF",
"cmd : LIST check_login SP pathname CRLF",
"cmd : STAT check_login SP pathname CRLF",
"cmd : STAT CRLF",
"cmd : DELE check_login SP pathname CRLF",
"cmd : RNTO check_login SP pathname CRLF",
"cmd : ABOR CRLF",
"cmd : CWD check_login CRLF",
"cmd : CWD check_login SP pathname CRLF",
"cmd : HELP CRLF",
"cmd : HELP SP STRING CRLF",
"cmd : NOOP CRLF",
"cmd : MKD check_login SP pathname CRLF",
"cmd : RMD check_login SP pathname CRLF",
"cmd : PWD check_login CRLF",
"cmd : CDUP check_login CRLF",
"cmd : SITE SP HELP CRLF",
"cmd : SITE SP HELP SP STRING CRLF",
"cmd : SITE SP UMASK check_login CRLF",
"cmd : SITE SP UMASK check_login SP octal_number CRLF",
"cmd : SITE SP CHMOD check_login SP octal_number SP pathname CRLF",
"cmd : SITE SP IDLE CRLF",
"cmd : SITE SP check_login IDLE SP NUMBER CRLF",
"cmd : STOU check_login SP pathname CRLF",
"cmd : SYST CRLF",
"cmd : SIZE check_login SP pathname CRLF",
"cmd : MDTM check_login SP pathname CRLF",
"cmd : QUIT CRLF",
"cmd : error CRLF",
"rcmd : RNFR check_login SP pathname CRLF",
"rcmd : REST SP byte_size CRLF",
"username : STRING",
"password :",
"password : STRING",
"byte_size : NUMBER",
"host_port : NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER COMMA NUMBER",
"form_code : N",
"form_code : T",
"form_code : C",
"type_code : A",
"type_code : A SP form_code",
"type_code : E",
"type_code : E SP form_code",
"type_code : I",
"type_code : L",
"type_code : L SP byte_size",
"type_code : L byte_size",
"struct_code : F",
"struct_code : R",
"struct_code : P",
"mode_code : S",
"mode_code : B",
"mode_code : C",
"pathname : pathstring",
"pathstring : STRING",
"octal_number : NUMBER",
"check_login :",
};
#endif
#if YYDEBUG
#include <stdio.h>
#endif
#ifdef YYSTACKSIZE
#undef YYMAXDEPTH
#define YYMAXDEPTH YYSTACKSIZE
#else
#ifdef YYMAXDEPTH
#define YYSTACKSIZE YYMAXDEPTH
#else
#define YYSTACKSIZE 10000
#define YYMAXDEPTH 10000
#endif
#endif
#define YYINITSTACKSIZE 200
int yydebug;
int yynerrs;
int yyerrflag;
int yychar;
short *yyssp;
YYSTYPE *yyvsp;
YYSTYPE yyval;
YYSTYPE yylval;
short *yyss;
short *yysslim;
YYSTYPE *yyvs;
int yystacksize;
#line 809 "ftpcmd.y"

#define	CMD	0	/* beginning of command */
#define	ARGS	1	/* expect miscellaneous arguments */
#define	STR1	2	/* expect SP followed by STRING */
#define	STR2	3	/* expect STRING */
#define	OSTR	4	/* optional SP then STRING */
#define	ZSTR1	5	/* SP then optional STRING */
#define	ZSTR2	6	/* optional STRING after SP */
#define	SITECMD	7	/* SITE command */
#define	NSTR	8	/* Number followed by a string */

struct tab cmdtab[] = {		/* In order defined in RFC 765 */
	{ "USER", USER, STR1, 1,	"<sp> username" },
	{ "PASS", PASS, ZSTR1, 1,	"<sp> password" },
	{ "ACCT", ACCT, STR1, 0,	"(specify account)" },
	{ "SMNT", SMNT, ARGS, 0,	"(structure mount)" },
	{ "REIN", REIN, ARGS, 0,	"(reinitialize server state)" },
	{ "QUIT", QUIT, ARGS, 1,	"(terminate service)", },
	{ "PORT", PORT, ARGS, 1,	"<sp> b0, b1, b2, b3, b4" },
	{ "PASV", PASV, ARGS, 1,	"(set server in passive mode)" },
	{ "TYPE", TYPE, ARGS, 1,	"<sp> [ A | E | I | L ]" },
	{ "STRU", STRU, ARGS, 1,	"(specify file structure)" },
	{ "MODE", MODE, ARGS, 1,	"(specify transfer mode)" },
	{ "RETR", RETR, STR1, 1,	"<sp> file-name" },
	{ "STOR", STOR, STR1, 1,	"<sp> file-name" },
	{ "APPE", APPE, STR1, 1,	"<sp> file-name" },
	{ "MLFL", MLFL, OSTR, 0,	"(mail file)" },
	{ "MAIL", MAIL, OSTR, 0,	"(mail to user)" },
	{ "MSND", MSND, OSTR, 0,	"(mail send to terminal)" },
	{ "MSOM", MSOM, OSTR, 0,	"(mail send to terminal or mailbox)" },
	{ "MSAM", MSAM, OSTR, 0,	"(mail send to terminal and mailbox)" },
	{ "MRSQ", MRSQ, OSTR, 0,	"(mail recipient scheme question)" },
	{ "MRCP", MRCP, STR1, 0,	"(mail recipient)" },
	{ "ALLO", ALLO, ARGS, 1,	"allocate storage (vacuously)" },
	{ "REST", REST, ARGS, 1,	"<sp> offset (restart command)" },
	{ "RNFR", RNFR, STR1, 1,	"<sp> file-name" },
	{ "RNTO", RNTO, STR1, 1,	"<sp> file-name" },
	{ "ABOR", ABOR, ARGS, 1,	"(abort operation)" },
	{ "DELE", DELE, STR1, 1,	"<sp> file-name" },
	{ "CWD",  CWD,  OSTR, 1,	"[ <sp> directory-name ]" },
	{ "XCWD", CWD,	OSTR, 1,	"[ <sp> directory-name ]" },
	{ "LIST", LIST, OSTR, 1,	"[ <sp> path-name ]" },
	{ "NLST", NLST, OSTR, 1,	"[ <sp> path-name ]" },
	{ "SITE", SITE, SITECMD, 1,	"site-cmd [ <sp> arguments ]" },
	{ "SYST", SYST, ARGS, 1,	"(get type of operating system)" },
	{ "STAT", STAT, OSTR, 1,	"[ <sp> path-name ]" },
	{ "HELP", HELP, OSTR, 1,	"[ <sp> <string> ]" },
	{ "NOOP", NOOP, ARGS, 1,	"" },
	{ "MKD",  MKD,  STR1, 1,	"<sp> path-name" },
	{ "XMKD", MKD,  STR1, 1,	"<sp> path-name" },
	{ "RMD",  RMD,  STR1, 1,	"<sp> path-name" },
	{ "XRMD", RMD,  STR1, 1,	"<sp> path-name" },
	{ "PWD",  PWD,  ARGS, 1,	"(return current directory)" },
	{ "XPWD", PWD,  ARGS, 1,	"(return current directory)" },
	{ "CDUP", CDUP, ARGS, 1,	"(change to parent directory)" },
	{ "XCUP", CDUP, ARGS, 1,	"(change to parent directory)" },
	{ "STOU", STOU, STR1, 1,	"<sp> file-name" },
	{ "SIZE", SIZE, OSTR, 1,	"<sp> path-name" },
	{ "MDTM", MDTM, OSTR, 1,	"<sp> path-name" },
	{ NULL,   0,    0,    0,	0 }
};

struct tab sitetab[] = {
	{ "UMASK", UMASK, ARGS, 1,	"[ <sp> umask ]" },
	{ "IDLE", IDLE, ARGS, 1,	"[ <sp> maximum-idle-time ]" },
	{ "CHMOD", CHMOD, NSTR, 1,	"<sp> mode <sp> file-name" },
	{ "HELP", HELP, OSTR, 1,	"[ <sp> <string> ]" },
	{ NULL,   0,    0,    0,	0 }
};

static struct tab *
lookup(p, cmd)
	struct tab *p;
	char *cmd;
{

	for (; p->name != NULL; p++)
		if (strcmp(cmd, p->name) == 0)
			return (p);
	return (0);
}

#include <arpa/telnet.h>

/*
 * getline - a hacked up version of fgets to ignore TELNET escape codes.
 */
char *
telnet_fgets(char *s, int n, FILE *iop)
{
	int c;
	register char *cs;

	cs = s;
/* tmpline may contain saved command from urgent mode interruption */
	for (c = 0; tmpline[c] != '\0' && --n > 0; ++c) {
		*cs++ = tmpline[c];
		if (tmpline[c] == '\n') {
			*cs++ = '\0';
			if (debug)
				syslog(LOG_DEBUG, "command: %s", s);
			tmpline[0] = '\0';
			return(s);
		}
		if (c == 0)
			tmpline[0] = '\0';
	}
	while ((c = getc(iop)) != EOF) {
		c &= 0377;
		if (c == IAC) {
		    if ((c = getc(iop)) != EOF) {
			c &= 0377;
			switch (c) {
			case WILL:
			case WONT:
				c = getc(iop);
				printf("%c%c%c", IAC, DONT, 0377&c);
				(void) fflush(stdout);
				continue;
			case DO:
			case DONT:
				c = getc(iop);
				printf("%c%c%c", IAC, WONT, 0377&c);
				(void) fflush(stdout);
				continue;
			case IAC:
				break;
			default:
				continue;	/* ignore command */
			}
		    }
		}
		*cs++ = c;
		if (--n <= 0 || c == '\n')
			break;
	}
	if (c == EOF && cs == s)
	    return (NULL);
	*cs++ = '\0';
	if (debug) {
		if (!cred.guest && strncasecmp("pass ", s, 5) == 0) {
			/* Don't syslog passwords */
			syslog(LOG_DEBUG, "command: %.5s ???", s);
		} else {
			register char *cp;
			register int len;

			/* Don't syslog trailing CR-LF */
			len = strlen(s);
			cp = s + len - 1;
			while (cp >= s && (*cp == '\n' || *cp == '\r')) {
				--cp;
				--len;
			}
			syslog(LOG_DEBUG, "command: %.*s", len, s);
		}
	}
	return (s);
}

void
toolong(int signo)
{
  (void)signo;
	reply(421,
	    "Timeout (%d seconds): closing control connection.", timeout);
	if (logging)
		syslog(LOG_INFO, "User %s timed out after %d seconds",
		    (cred.name ? cred.name : "unknown"), timeout);
	dologout(1);
}

static int
yylex()
{
	static int cpos, state;
	char *cp, *cp2;
	struct tab *p;
	int n;
	char c;

	for (;;) {
		switch (state) {

		case CMD:
			(void) signal(SIGALRM, toolong);
			(void) alarm((unsigned) timeout);
			if (telnet_fgets(cbuf, sizeof(cbuf)-1, stdin) == NULL) {
				reply(221, "You could at least say goodbye.");
				dologout(0);
			}
			(void) alarm(0);
#ifdef HAVE_SETPROCTITLE
			if (strncasecmp(cbuf, "PASS", 4) != NULL)
				setproctitle("%s: %s", proctitle, cbuf);
#endif /* HAVE_SETPROCTITLE */
			if ((cp = strchr(cbuf, '\r'))) {
				*cp++ = '\n';
				*cp = '\0';
			}
			if ((cp = strpbrk(cbuf, " \n")))
				cpos = cp - cbuf;
			if (cpos == 0)
				cpos = 4;
			c = cbuf[cpos];
			cbuf[cpos] = '\0';
			upper(cbuf);
			p = lookup(cmdtab, cbuf);
			cbuf[cpos] = c;
			if (p != 0) {
				if (p->implemented == 0) {
					nack(p->name);
					longjmp(errcatch,0);
					/* NOTREACHED */
				}
				state = p->state;
				yylval.s = p->name;
				return (p->token);
			}
			break;

		case SITECMD:
			if (cbuf[cpos] == ' ') {
				cpos++;
				return (SP);
			}
			cp = &cbuf[cpos];
			if ((cp2 = strpbrk(cp, " \n")))
				cpos = cp2 - cbuf;
			c = cbuf[cpos];
			cbuf[cpos] = '\0';
			upper(cp);
			p = lookup(sitetab, cp);
			cbuf[cpos] = c;
			if (p != 0) {
				if (p->implemented == 0) {
					state = CMD;
					nack(p->name);
					longjmp(errcatch,0);
					/* NOTREACHED */
				}
				state = p->state;
				yylval.s = p->name;
				return (p->token);
			}
			state = CMD;
			break;

		case OSTR:
			if (cbuf[cpos] == '\n') {
				state = CMD;
				return (CRLF);
			}
			/* FALLTHROUGH */

		case STR1:
		case ZSTR1:
		dostr1:
			if (cbuf[cpos] == ' ') {
				cpos++;
				state = state == OSTR ? STR2 : ++state;
				return (SP);
			}
			break;

		case ZSTR2:
			if (cbuf[cpos] == '\n') {
				state = CMD;
				return (CRLF);
			}
			/* FALLTHROUGH */

		case STR2:
			cp = &cbuf[cpos];
			n = strlen(cp);
			cpos += n - 1;
			/*
			 * Make sure the string is nonempty and \n terminated.
			 */
			if (n > 1 && cbuf[cpos] == '\n') {
				cbuf[cpos] = '\0';
				yylval.s = copy(cp);
				cbuf[cpos] = '\n';
				state = ARGS;
				return (STRING);
			}
			break;

		case NSTR:
			if (cbuf[cpos] == ' ') {
				cpos++;
				return (SP);
			}
			if (isdigit(cbuf[cpos])) {
				cp = &cbuf[cpos];
				while (isdigit(cbuf[++cpos]))
					;
				c = cbuf[cpos];
				cbuf[cpos] = '\0';
				yylval.i = atoi(cp);
				cbuf[cpos] = c;
				state = STR1;
				return (NUMBER);
			}
			state = STR1;
			goto dostr1;

		case ARGS:
			if (isdigit(cbuf[cpos])) {
				cp = &cbuf[cpos];
				while (isdigit(cbuf[++cpos]))
					;
				c = cbuf[cpos];
				cbuf[cpos] = '\0';
				yylval.i = atoi(cp);
				cbuf[cpos] = c;
				return (NUMBER);
			}
			switch (cbuf[cpos++]) {

			case '\n':
				state = CMD;
				return (CRLF);

			case ' ':
				return (SP);

			case ',':
				return (COMMA);

			case 'A':
			case 'a':
				return (A);

			case 'B':
			case 'b':
				return (B);

			case 'C':
			case 'c':
				return (C);

			case 'E':
			case 'e':
				return (E);

			case 'F':
			case 'f':
				return (F);

			case 'I':
			case 'i':
				return (I);

			case 'L':
			case 'l':
				return (L);

			case 'N':
			case 'n':
				return (N);

			case 'P':
			case 'p':
				return (P);

			case 'R':
			case 'r':
				return (R);

			case 'S':
			case 's':
				return (S);

			case 'T':
			case 't':
				return (T);

			}
			break;

		default:
			fatal("Unknown state in scanner.");
		}
		yyerror((char *) 0);
		state = CMD;
		longjmp(errcatch,0);
	}
}

void
upper(char *s)
{
	while (*s != '\0') {
		if (islower(*s))
			*s = toupper(*s);
		s++;
	}
}

static char *
copy(char *s)
{
	char *p;

	p = malloc((unsigned) strlen(s) + 1);
	if (p == NULL)
		fatal("Ran out of memory.");
	(void) strcpy(p, s);
	return (p);
}

static void
help(struct tab *ctab, char *s)
{
	struct tab *c;
	int width, NCMDS;
	const char *help_type;

	if (ctab == sitetab)
		help_type = "SITE ";
	else
		help_type = "";
	width = 0, NCMDS = 0;
	for (c = ctab; c->name != NULL; c++) {
		int len = strlen(c->name);

		if (len > width)
			width = len;
		NCMDS++;
	}
	width = (width + 8) &~ 7;
	if (s == 0) {
		int i, j, w;
		int columns, lines;

		lreply(214, "The following %scommands are recognized %s.",
		    help_type, "(* =>'s unimplemented)");
		columns = 76 / width;
		if (columns == 0)
			columns = 1;
		lines = (NCMDS + columns - 1) / columns;
		for (i = 0; i < lines; i++) {
			printf("   ");
			for (j = 0; j < columns; j++) {
				c = ctab + j * lines + i;
				printf("%s%c", c->name,
					c->implemented ? ' ' : '*');
				if (c + lines >= &ctab[NCMDS])
					break;
				w = strlen(c->name) + 1;
				while (w < width) {
					putchar(' ');
					w++;
				}
			}
			printf("\r\n");
		}
		(void) fflush(stdout);
		reply(214, "Direct comments to ftp-bugs@%s.", hostname);
		return;
	}
	upper(s);
	c = lookup(ctab, s);
	if (c == (struct tab *)0) {
		reply(502, "Unknown command %s.", s);
		return;
	}
	if (c->implemented)
		reply(214, "Syntax: %s%s %s", help_type, c->name, c->help);
	else
		reply(214, "%s%-*s\t%s; unimplemented.", help_type, width,
		    c->name, c->help);
}

static void
sizecmd(char *filename)
{
	switch (type) {
	case TYPE_L:
	case TYPE_I: {
		struct stat stbuf;
		if (stat(filename, &stbuf) < 0 || !S_ISREG(stbuf.st_mode))
			reply(550, "%s: not a plain file.", filename);
		else
			reply(213,
			      (sizeof (stbuf.st_size) > sizeof(long)
			       ? "%qu" : "%lu"), stbuf.st_size);
		break; }
	case TYPE_A: {
		FILE *fin;
		int c;
		off_t count;
		struct stat stbuf;
		fin = fopen(filename, "r");
		if (fin == NULL) {
			perror_reply(550, filename);
			return;
		}
		if (fstat(fileno(fin), &stbuf) < 0 || !S_ISREG(stbuf.st_mode)) {
			reply(550, "%s: not a plain file.", filename);
			(void) fclose(fin);
			return;
		}

		count = 0;
		while((c=getc(fin)) != EOF) {
			if (c == '\n')	/* will get expanded to \r\n */
				count++;
			count++;
		}
		(void) fclose(fin);

		reply(213, sizeof(count) > sizeof(long) ? "%qd" : "%ld",
		      count);
		break; }
	default:
		reply(504, "SIZE not implemented for Type %c.", "?AEIL"[type]);
	}
}

/* ARGSUSED */
static void
yyerror(const char *s)
{
  char *cp;

  (void)s;
  cp = strchr(cbuf,'\n');
  if (cp != NULL)
    *cp = '\0';
  reply(500, "'%s': command not understood.", cbuf);
}
#line 973 "y.tab.c"
/* allocate initial stack or double stack size, up to YYMAXDEPTH */
static int yygrowstack()
{
    int newsize, i;
    short *newss;
    YYSTYPE *newvs;

    if ((newsize = yystacksize) == 0)
        newsize = YYINITSTACKSIZE;
    else if (newsize >= YYMAXDEPTH)
        return -1;
    else if ((newsize *= 2) > YYMAXDEPTH)
        newsize = YYMAXDEPTH;
    i = yyssp - yyss;
    newss = yyss ? (short *)realloc(yyss, newsize * sizeof *newss) :
      (short *)malloc(newsize * sizeof *newss);
    if (newss == NULL)
        return -1;
    yyss = newss;
    yyssp = newss + i;
    newvs = yyvs ? (YYSTYPE *)realloc(yyvs, newsize * sizeof *newvs) :
      (YYSTYPE *)malloc(newsize * sizeof *newvs);
    if (newvs == NULL)
        return -1;
    yyvs = newvs;
    yyvsp = newvs + i;
    yystacksize = newsize;
    yysslim = yyss + newsize - 1;
    return 0;
}

#define YYABORT goto yyabort
#define YYREJECT goto yyabort
#define YYACCEPT goto yyaccept
#define YYERROR goto yyerrlab

#ifndef YYPARSE_PARAM
#if defined(__cplusplus) || __STDC__
#define YYPARSE_PARAM_ARG void
#define YYPARSE_PARAM_DECL
#else	/* ! ANSI-C/C++ */
#define YYPARSE_PARAM_ARG
#define YYPARSE_PARAM_DECL
#endif	/* ANSI-C/C++ */
#else	/* YYPARSE_PARAM */
#ifndef YYPARSE_PARAM_TYPE
#define YYPARSE_PARAM_TYPE void *
#endif
#if defined(__cplusplus) || __STDC__
#define YYPARSE_PARAM_ARG YYPARSE_PARAM_TYPE YYPARSE_PARAM
#define YYPARSE_PARAM_DECL
#else	/* ! ANSI-C/C++ */
#define YYPARSE_PARAM_ARG YYPARSE_PARAM
#define YYPARSE_PARAM_DECL YYPARSE_PARAM_TYPE YYPARSE_PARAM;
#endif	/* ANSI-C/C++ */
#endif	/* ! YYPARSE_PARAM */

int
yyparse (YYPARSE_PARAM_ARG)
    YYPARSE_PARAM_DECL
{
    register int yym, yyn, yystate;
#if YYDEBUG
    register const char *yys;

    if ((yys = getenv("YYDEBUG")))
    {
        yyn = *yys;
        if (yyn >= '0' && yyn <= '9')
            yydebug = yyn - '0';
    }
#endif

    yynerrs = 0;
    yyerrflag = 0;
    yychar = (-1);

    if (yyss == NULL && yygrowstack()) goto yyoverflow;
    yyssp = yyss;
    yyvsp = yyvs;
    *yyssp = yystate = 0;

yyloop:
    if ((yyn = yydefred[yystate])) goto yyreduce;
    if (yychar < 0)
    {
        if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, reading %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
    }
    if ((yyn = yysindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: state %d, shifting to state %d\n",
                    YYPREFIX, yystate, yytable[yyn]);
#endif
        if (yyssp >= yysslim && yygrowstack())
        {
            goto yyoverflow;
        }
        *++yyssp = yystate = yytable[yyn];
        *++yyvsp = yylval;
        yychar = (-1);
        if (yyerrflag > 0)  --yyerrflag;
        goto yyloop;
    }
    if ((yyn = yyrindex[yystate]) && (yyn += yychar) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yychar)
    {
        yyn = yytable[yyn];
        goto yyreduce;
    }
    if (yyerrflag) goto yyinrecovery;
#if defined(lint) || defined(__GNUC__)
    goto yynewerror;
#endif
yynewerror:
    yyerror("syntax error");
#if defined(lint) || defined(__GNUC__)
    goto yyerrlab;
#endif
yyerrlab:
    ++yynerrs;
yyinrecovery:
    if (yyerrflag < 3)
    {
        yyerrflag = 3;
        for (;;)
        {
            if ((yyn = yysindex[*yyssp]) && (yyn += YYERRCODE) >= 0 &&
                    yyn <= YYTABLESIZE && yycheck[yyn] == YYERRCODE)
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: state %d, error recovery shifting\
 to state %d\n", YYPREFIX, *yyssp, yytable[yyn]);
#endif
                if (yyssp >= yysslim && yygrowstack())
                {
                    goto yyoverflow;
                }
                *++yyssp = yystate = yytable[yyn];
                *++yyvsp = yylval;
                goto yyloop;
            }
            else
            {
#if YYDEBUG
                if (yydebug)
                    printf("%sdebug: error recovery discarding state %d\n",
                            YYPREFIX, *yyssp);
#endif
                if (yyssp <= yyss) goto yyabort;
                --yyssp;
                --yyvsp;
            }
        }
    }
    else
    {
        if (yychar == 0) goto yyabort;
#if YYDEBUG
        if (yydebug)
        {
            yys = 0;
            if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
            if (!yys) yys = "illegal-symbol";
            printf("%sdebug: state %d, error recovery discards token %d (%s)\n",
                    YYPREFIX, yystate, yychar, yys);
        }
#endif
        yychar = (-1);
        goto yyloop;
    }
yyreduce:
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: state %d, reducing by rule %d (%s)\n",
                YYPREFIX, yystate, yyn, yyrule[yyn]);
#endif
    yym = yylen[yyn];
    yyval = yyvsp[1-yym];
    switch (yyn)
    {
case 2:
#line 155 "ftpcmd.y"
{
			if (fromname != NULL)
				free (fromname);
			fromname = (char *) 0;
			restart_point = (off_t) 0;
		}
break;
case 4:
#line 166 "ftpcmd.y"
{
			user(yyvsp[-1].s);
			free(yyvsp[-1].s);
		}
break;
case 5:
#line 171 "ftpcmd.y"
{
			pass(yyvsp[-1].s);
			memset (yyvsp[-1].s, 0, strlen (yyvsp[-1].s));
			free(yyvsp[-1].s);
		}
break;
case 6:
#line 177 "ftpcmd.y"
{
			usedefault = 0;
			if (pdata >= 0) {
				(void) close(pdata);
				pdata = -1;
			}
			if (yyvsp[-3].i) {
				if (memcmp (&his_addr.sin_addr,
					&data_dest.sin_addr,
					sizeof (data_dest.sin_addr)) == 0 &&
					ntohs (data_dest.sin_port) >
					IPPORT_RESERVED) {
					reply (200, "PORT command sucessful.");
				}
				else {
					memset (&data_dest, 0,
						sizeof (data_dest));
					reply(500, "Illegal PORT Command");
				}
			}
		}
break;
case 7:
#line 199 "ftpcmd.y"
{
			if (yyvsp[-1].i)
				passive();
		}
break;
case 8:
#line 204 "ftpcmd.y"
{
			switch (cmd_type) {

			case TYPE_A:
				if (cmd_form == FORM_N) {
					reply(200, "Type set to A.");
					type = cmd_type;
					form = cmd_form;
				} else
					reply(504, "Form must be N.");
				break;

			case TYPE_E:
				reply(504, "Type E not implemented.");
				break;

			case TYPE_I:
				reply(200, "Type set to I.");
				type = cmd_type;
				break;

			case TYPE_L:
#if defined (NBBY) && NBBY == 8
				if (cmd_bytesz == 8) {
					reply(200,
					    "Type set to L (byte size 8).");
					type = cmd_type;
				} else
					reply(504, "Byte size must be 8.");
#else /* NBBY == 8 */
				UNIMPLEMENTED for NBBY != 8
#endif /* NBBY == 8 */
			}
		}
break;
case 9:
#line 239 "ftpcmd.y"
{
			switch (yyvsp[-1].i) {

			case STRU_F:
				reply(200, "STRU F ok.");
				break;

			default:
				reply(504, "Unimplemented STRU type.");
			}
		}
break;
case 10:
#line 251 "ftpcmd.y"
{
			switch (yyvsp[-1].i) {

			case MODE_S:
				reply(200, "MODE S ok.");
				break;

			default:
				reply(502, "Unimplemented MODE type.");
			}
		}
break;
case 11:
#line 263 "ftpcmd.y"
{
			reply(202, "ALLO command ignored.");
		}
break;
case 12:
#line 267 "ftpcmd.y"
{
			reply(202, "ALLO command ignored.");
		}
break;
case 13:
#line 271 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				retrieve((char *) 0, yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
break;
case 14:
#line 278 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				store(yyvsp[-1].s, "w", 0);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
break;
case 15:
#line 285 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				store(yyvsp[-1].s, "a", 0);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
break;
case 16:
#line 292 "ftpcmd.y"
{
			if (yyvsp[-1].i)
				send_file_list(".");
		}
break;
case 17:
#line 297 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				send_file_list(yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
break;
case 18:
#line 304 "ftpcmd.y"
{
			if (yyvsp[-1].i)
				retrieve("/bin/ls -lgA", "");
		}
break;
case 19:
#line 309 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				retrieve("/bin/ls -lgA %s", yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
break;
case 20:
#line 316 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				statfilecmd(yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
break;
case 21:
#line 323 "ftpcmd.y"
{
			statcmd();
		}
break;
case 22:
#line 327 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				delete(yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
break;
case 23:
#line 334 "ftpcmd.y"
{
		    if (yyvsp[-3].i) {
			if (fromname) {
				renamecmd(fromname, yyvsp[-1].s);
				free(fromname);
				fromname = (char *) 0;
			} else {
				reply(503, "Bad sequence of commands.");
			}
		    }
		    free (yyvsp[-1].s);
		}
break;
case 24:
#line 347 "ftpcmd.y"
{
			reply(225, "ABOR command successful.");
		}
break;
case 25:
#line 351 "ftpcmd.y"
{
			if (yyvsp[-1].i)
				cwd(cred.homedir);
		}
break;
case 26:
#line 356 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				cwd(yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
break;
case 27:
#line 363 "ftpcmd.y"
{
			help(cmdtab, (char *) 0);
		}
break;
case 28:
#line 367 "ftpcmd.y"
{
			char *cp = yyvsp[-1].s;

			if (strncasecmp(cp, "SITE", 4) == 0) {
				cp = yyvsp[-1].s + 4;
				if (*cp == ' ')
					cp++;
				if (*cp)
					help(sitetab, cp);
				else
					help(sitetab, (char *) 0);
			} else
				help(cmdtab, yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
			    free (yyvsp[-1].s);
		}
break;
case 29:
#line 384 "ftpcmd.y"
{
			reply(200, "NOOP command successful.");
		}
break;
case 30:
#line 388 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				makedir(yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
break;
case 31:
#line 395 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				removedir(yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
break;
case 32:
#line 402 "ftpcmd.y"
{
			if (yyvsp[-1].i)
				pwd();
		}
break;
case 33:
#line 407 "ftpcmd.y"
{
			if (yyvsp[-1].i)
				cwd("..");
		}
break;
case 34:
#line 412 "ftpcmd.y"
{
			help(sitetab, (char *) 0);
		}
break;
case 35:
#line 416 "ftpcmd.y"
{
			help(sitetab, yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
			    free (yyvsp[-1].s);
		}
break;
case 36:
#line 422 "ftpcmd.y"
{
			int oldmask;

			if (yyvsp[-1].i) {
				oldmask = umask(0);
				(void) umask(oldmask);
				reply(200, "Current UMASK is %03o", oldmask);
			}
		}
break;
case 37:
#line 432 "ftpcmd.y"
{
			int oldmask;

			if (yyvsp[-3].i) {
				if ((yyvsp[-1].i == -1) || (yyvsp[-1].i > 0777)) {
					reply(501, "Bad UMASK value");
				} else {
					oldmask = umask(yyvsp[-1].i);
					reply(200,
					    "UMASK set to %03o (was %03o)",
					    yyvsp[-1].i, oldmask);
				}
			}
		}
break;
case 38:
#line 447 "ftpcmd.y"
{
			if (yyvsp[-5].i && (yyvsp[-1].s != NULL)) {
				if (yyvsp[-3].i > 0777)
					reply(501,
				"CHMOD: Mode value must be between 0 and 0777");
				else if (chmod(yyvsp[-1].s, yyvsp[-3].i) < 0)
					perror_reply(550, yyvsp[-1].s);
				else
					reply(200, "CHMOD command successful.");
			}
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
break;
case 39:
#line 461 "ftpcmd.y"
{
			reply(200,
			    "Current IDLE time limit is %d seconds; max %d",
				timeout, maxtimeout);
		}
break;
case 40:
#line 467 "ftpcmd.y"
{
		    	if (yyvsp[-4].i) {
			    if (yyvsp[-1].i < 30 || yyvsp[-1].i > maxtimeout) {
				reply (501,
			"Maximum IDLE time must be between 30 and %d seconds",
					maxtimeout);
			    } else {
				timeout = yyvsp[-1].i;
				(void) alarm((unsigned) timeout);
				reply(200,
					"Maximum IDLE time set to %d seconds",
					timeout);
			    }
			}
		}
break;
case 41:
#line 483 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				store(yyvsp[-1].s, "w", 1);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
break;
case 42:
#line 490 "ftpcmd.y"
{
		        const char *sys_type; /* Official rfc-defined os type.  */
			char *version = 0; /* A more specific type. */

#ifdef HAVE_UNAME
			struct utsname u;
			if (uname (&u) == 0) {
				version =
				  malloc (strlen (u.sysname)
					  + 1 + strlen (u.release) + 1);
				if (version)
					sprintf (version, "%s %s",
						 u.sysname, u.release);
		        }
#else
#ifdef BSD
			version = "BSD";
#endif
#endif

#ifdef unix
			sys_type = "UNIX";
#else
			sys_type = "UNKNOWN";
#endif

			if (version)
				reply(215, "%s Type: L%d Version: %s",
				      sys_type, NBBY, version);
			else
				reply(215, "%s Type: L%d", sys_type, NBBY);

#ifdef HAVE_UNAME
			if (version)
				free (version);
#endif
		}
break;
case 43:
#line 536 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL)
				sizecmd(yyvsp[-1].s);
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
break;
case 44:
#line 553 "ftpcmd.y"
{
			if (yyvsp[-3].i && yyvsp[-1].s != NULL) {
				struct stat stbuf;
				if (stat(yyvsp[-1].s, &stbuf) < 0)
					reply(550, "%s: %s",
					    yyvsp[-1].s, strerror(errno));
				else if (!S_ISREG(stbuf.st_mode)) {
					reply(550, "%s: not a plain file.", yyvsp[-1].s);
				} else {
					struct tm *t;
					t = gmtime(&stbuf.st_mtime);
					reply(213,
					    "%04d%02d%02d%02d%02d%02d",
					    1900 + t->tm_year, t->tm_mon+1,
					    t->tm_mday, t->tm_hour, t->tm_min,
					    t->tm_sec);
				}
			}
			if (yyvsp[-1].s != NULL)
				free(yyvsp[-1].s);
		}
break;
case 45:
#line 575 "ftpcmd.y"
{
			reply(221, "Goodbye.");
			dologout(0);
		}
break;
case 46:
#line 580 "ftpcmd.y"
{
			yyerrok;
		}
break;
case 47:
#line 586 "ftpcmd.y"
{
			restart_point = (off_t) 0;
			if (yyvsp[-3].i && yyvsp[-1].s) {
			    if (fromname != NULL)
				free (fromname);
			    fromname = renamefrom(yyvsp[-1].s);
			}
			if (fromname == (char *) 0 && yyvsp[-1].s)
			    free(yyvsp[-1].s);
		}
break;
case 48:
#line 597 "ftpcmd.y"
{
		    	if (fromname != NULL)
				free (fromname);
			fromname = (char *) 0;
			restart_point = yyvsp[-1].i;	/* XXX $3 is only "int" */
			reply(350,
			      (sizeof(restart_point) > sizeof(long)
			       ? "Restarting at %qd. %s"
			       : "Restarting at %ld. %s"), restart_point,
			    "Send STORE or RETRIEVE to initiate transfer.");
		}
break;
case 50:
#line 616 "ftpcmd.y"
{
			yyval.s = (char *)calloc(1, sizeof(char));
		}
break;
case 53:
#line 629 "ftpcmd.y"
{
			char *a, *p;

			a = (char *)&data_dest.sin_addr;
			a[0] = yyvsp[-10].i; a[1] = yyvsp[-8].i; a[2] = yyvsp[-6].i; a[3] = yyvsp[-4].i;
			p = (char *)&data_dest.sin_port;
			p[0] = yyvsp[-2].i; p[1] = yyvsp[0].i;
			data_dest.sin_family = AF_INET;
		}
break;
case 54:
#line 642 "ftpcmd.y"
{
			yyval.i = FORM_N;
		}
break;
case 55:
#line 646 "ftpcmd.y"
{
			yyval.i = FORM_T;
		}
break;
case 56:
#line 650 "ftpcmd.y"
{
			yyval.i = FORM_C;
		}
break;
case 57:
#line 657 "ftpcmd.y"
{
			cmd_type = TYPE_A;
			cmd_form = FORM_N;
		}
break;
case 58:
#line 662 "ftpcmd.y"
{
			cmd_type = TYPE_A;
			cmd_form = yyvsp[0].i;
		}
break;
case 59:
#line 667 "ftpcmd.y"
{
			cmd_type = TYPE_E;
			cmd_form = FORM_N;
		}
break;
case 60:
#line 672 "ftpcmd.y"
{
			cmd_type = TYPE_E;
			cmd_form = yyvsp[0].i;
		}
break;
case 61:
#line 677 "ftpcmd.y"
{
			cmd_type = TYPE_I;
		}
break;
case 62:
#line 681 "ftpcmd.y"
{
			cmd_type = TYPE_L;
			cmd_bytesz = NBBY;
		}
break;
case 63:
#line 686 "ftpcmd.y"
{
			cmd_type = TYPE_L;
			cmd_bytesz = yyvsp[0].i;
		}
break;
case 64:
#line 692 "ftpcmd.y"
{
			cmd_type = TYPE_L;
			cmd_bytesz = yyvsp[0].i;
		}
break;
case 65:
#line 700 "ftpcmd.y"
{
			yyval.i = STRU_F;
		}
break;
case 66:
#line 704 "ftpcmd.y"
{
			yyval.i = STRU_R;
		}
break;
case 67:
#line 708 "ftpcmd.y"
{
			yyval.i = STRU_P;
		}
break;
case 68:
#line 715 "ftpcmd.y"
{
			yyval.i = MODE_S;
		}
break;
case 69:
#line 719 "ftpcmd.y"
{
			yyval.i = MODE_B;
		}
break;
case 70:
#line 723 "ftpcmd.y"
{
			yyval.i = MODE_C;
		}
break;
case 71:
#line 730 "ftpcmd.y"
{
			/*
			 * Problem: this production is used for all pathname
			 * processing, but only gives a 550 error reply.
			 * This is a valid reply in some cases but not in others.
			 */
			if (cred.logged_in && yyvsp[0].s && *yyvsp[0].s == '~') {
				glob_t gl;
				int flags = GLOB_NOCHECK;

#ifdef GLOB_BRACE
				flags |= GLOB_BRACE;
#endif
#ifdef GLOB_QUOTE
				flags |= GLOB_QUOTE;
#endif
#ifdef GLOB_TILDE
				flags |= GLOB_TILDE;
#endif

				memset(&gl, 0, sizeof(gl));
				if (glob(yyvsp[0].s, flags, NULL, &gl) ||
				    gl.gl_pathc == 0) {
					reply(550, "not found");
					yyval.s = NULL;
				} else {
					yyval.s = strdup(gl.gl_pathv[0]);
				}
				globfree(&gl);
				free(yyvsp[0].s);
			} else
				yyval.s = yyvsp[0].s;
		}
break;
case 73:
#line 771 "ftpcmd.y"
{
			int ret, dec, multby, digit;

			/*
			 * Convert a number that was read as decimal number
			 * to what it would be if it had been read as octal.
			 */
			dec = yyvsp[0].i;
			multby = 1;
			ret = 0;
			while (dec) {
				digit = dec%10;
				if (digit > 7) {
					ret = -1;
					break;
				}
				ret += digit * multby;
				multby *= 8;
				dec /= 10;
			}
			yyval.i = ret;
		}
break;
case 74:
#line 798 "ftpcmd.y"
{
			if (cred.logged_in)
				yyval.i = 1;
			else {
				reply(530, "Please login with USER and PASS.");
				yyval.i = 0;
			}
		}
break;
#line 1889 "y.tab.c"
    }
    yyssp -= yym;
    yystate = *yyssp;
    yyvsp -= yym;
    yym = yylhs[yyn];
    if (yystate == 0 && yym == 0)
    {
#if YYDEBUG
        if (yydebug)
            printf("%sdebug: after reduction, shifting from state 0 to\
 state %d\n", YYPREFIX, YYFINAL);
#endif
        yystate = YYFINAL;
        *++yyssp = YYFINAL;
        *++yyvsp = yyval;
        if (yychar < 0)
        {
            if ((yychar = yylex()) < 0) yychar = 0;
#if YYDEBUG
            if (yydebug)
            {
                yys = 0;
                if (yychar <= YYMAXTOKEN) yys = yyname[yychar];
                if (!yys) yys = "illegal-symbol";
                printf("%sdebug: state %d, reading %d (%s)\n",
                        YYPREFIX, YYFINAL, yychar, yys);
            }
#endif
        }
        if (yychar == 0) goto yyaccept;
        goto yyloop;
    }
    if ((yyn = yygindex[yym]) && (yyn += yystate) >= 0 &&
            yyn <= YYTABLESIZE && yycheck[yyn] == yystate)
        yystate = yytable[yyn];
    else
        yystate = yydgoto[yym];
#if YYDEBUG
    if (yydebug)
        printf("%sdebug: after reduction, shifting from state %d \
to state %d\n", YYPREFIX, *yyssp, yystate);
#endif
    if (yyssp >= yysslim && yygrowstack())
    {
        goto yyoverflow;
    }
    *++yyssp = yystate;
    *++yyvsp = yyval;
    goto yyloop;
yyoverflow:
    yyerror("yacc stack overflow");
yyabort:
    return (1);
yyaccept:
    return (0);
}
