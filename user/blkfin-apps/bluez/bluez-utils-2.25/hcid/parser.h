/* A Bison parser, made by GNU Bison 2.1.  */

/* Skeleton parser for Yacc-like parsing with Bison,
   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005 Free Software Foundation, Inc.

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
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* As a special exception, when this file is copied by Bison into a
   Bison output file, you may use that output file without restriction.
   This special exception was added by the Free Software Foundation
   in version 1.24 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     K_OPTIONS = 258,
     K_DEVICE = 259,
     K_AUTOINIT = 260,
     K_SECURITY = 261,
     K_PAIRING = 262,
     K_PTYPE = 263,
     K_NAME = 264,
     K_CLASS = 265,
     K_VOICE = 266,
     K_INQMODE = 267,
     K_PAGETO = 268,
     K_LM = 269,
     K_LP = 270,
     K_AUTH = 271,
     K_ENCRYPT = 272,
     K_ISCAN = 273,
     K_PSCAN = 274,
     K_PINHELP = 275,
     K_DBUSPINHELP = 276,
     K_YES = 277,
     K_NO = 278,
     WORD = 279,
     PATH = 280,
     STRING = 281,
     LIST = 282,
     HCI = 283,
     BDADDR = 284,
     NUM = 285
   };
#endif
/* Tokens.  */
#define K_OPTIONS 258
#define K_DEVICE 259
#define K_AUTOINIT 260
#define K_SECURITY 261
#define K_PAIRING 262
#define K_PTYPE 263
#define K_NAME 264
#define K_CLASS 265
#define K_VOICE 266
#define K_INQMODE 267
#define K_PAGETO 268
#define K_LM 269
#define K_LP 270
#define K_AUTH 271
#define K_ENCRYPT 272
#define K_ISCAN 273
#define K_PSCAN 274
#define K_PINHELP 275
#define K_DBUSPINHELP 276
#define K_YES 277
#define K_NO 278
#define WORD 279
#define PATH 280
#define STRING 281
#define LIST 282
#define HCI 283
#define BDADDR 284
#define NUM 285




#if ! defined (YYSTYPE) && ! defined (YYSTYPE_IS_DECLARED)
#line 56 "parser.y"
typedef union YYSTYPE {
	char *str;
	long  num;
} YYSTYPE;
/* Line 1447 of yacc.c.  */
#line 103 "y.tab.h"
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;



