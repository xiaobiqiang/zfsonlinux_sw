
# line 2 "../../../eversholt/common/escparse.y"
/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * escparse.y -- parser for esc
 *
 * this is the yacc-based parser for Eversholt.  the syntax is simple
 * and is defined by the LALR(1) grammar described by this file.  there
 * should be no shift/reduce or reduce/reduce messages when building this
 * file.
 *
 * as the input is parsed, a parse tree is built by calling the
 * tree_X() functions defined in tree.c.  any syntax errors cause
 * us to skip to the next semicolon, achieved via the "error" clause
 * in the stmt rule below.  the yacc state machine code will call
 * yyerror() in esclex.c and that will keep count of the errors and
 * display the filename, line number, and current input stream of tokens
 * to help the user figure out the problem.  the -Y flag to this program
 * turns on the yacc debugging output which is quite large.  you probably
 * only need to do that if you're debugging the grammar below.
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include "out.h"
#include "stable.h"
#include "literals.h"
#include "lut.h"
#include "esclex.h"
#include "tree.h"


# line 61 "../../../eversholt/common/escparse.y"
typedef union
#ifdef __cplusplus
	YYSTYPE
#endif
 {
	struct tokstr tok;
	struct node *np;
} YYSTYPE;
# define OR 257
# define AND 258
# define EQ 259
# define NE 260
# define LE 261
# define GE 262
# define LSHIFT 263
# define RSHIFT 264
# define DIV 265
# define PROP 266
# define MASK 267
# define ARROW 268
# define EVENT 269
# define ENGINE 270
# define ASRU 271
# define FRU 272
# define COUNT 273
# define CONFIG 274
# define ID 275
# define QUOTE 276
# define NUMBER 277
# define IF 278
# define PATHFUNC 279

#include <inttypes.h>

#ifdef __STDC__
#include <stdlib.h>
#include <string.h>
#define	YYCONST	const
#else
#include <malloc.h>
#include <memory.h>
#define	YYCONST
#endif

#include <values.h>

#if defined(__cplusplus) || defined(__STDC__)

#if defined(__cplusplus) && defined(__EXTERN_C__)
extern "C" {
#endif
#ifndef yyerror
#if defined(__cplusplus)
	void yyerror(YYCONST char *);
#endif
#endif
#ifndef yylex
	int yylex(void);
#endif
	int yyparse(void);
#if defined(__cplusplus) && defined(__EXTERN_C__)
}
#endif

#endif

#define yyclearin yychar = -1
#define yyerrok yyerrflag = 0
extern int yychar;
extern int yyerrflag;
YYSTYPE yylval;
YYSTYPE yyval;
typedef int yytabelem;
#ifndef YYMAXDEPTH
#define YYMAXDEPTH 150
#endif
#if YYMAXDEPTH > 0
int yy_yys[YYMAXDEPTH], *yys = yy_yys;
YYSTYPE yy_yyv[YYMAXDEPTH], *yyv = yy_yyv;
#else	/* user does initial allocation */
int *yys;
YYSTYPE *yyv;
#endif
static int yymaxdepth = YYMAXDEPTH;
# define YYERRCODE 256

# line 464 "../../../eversholt/common/escparse.y"

static YYCONST yytabelem yyexca[] ={
-1, 1,
	0, -1,
	-2, 0,
-1, 2,
	0, 1,
	-2, 0,
-1, 150,
	58, 0,
	-2, 63,
	};
# define YYNPROD 127
# define YYLAST 692
static YYCONST yytabelem yyact[]={

    34,    13,    18,    43,   223,   140,   193,    36,   171,    34,
    26,    30,    43,   191,    50,   103,    36,    51,    34,    52,
    96,    43,    13,   134,   129,    36,   203,    34,     2,   114,
    43,   201,   117,   118,    36,   119,   120,   121,   122,    53,
   123,   116,    39,     3,   124,   209,   175,    44,    45,    46,
    43,    26,   178,    69,   191,   172,    95,    81,   207,    42,
   133,    92,    91,    29,    90,    48,    94,   235,    68,   138,
   203,   112,   111,    72,   233,   201,   200,    76,   199,    84,
    74,    86,    75,    25,    95,    81,   147,   183,   170,    92,
    91,    66,    90,    35,    94,    14,    21,   214,    66,    67,
    55,    54,    35,    66,    57,    76,   173,    84,    74,    86,
    75,    35,   206,    80,    37,   213,    13,   146,   110,    56,
    35,    66,    31,    95,    81,   221,   226,    63,    92,    91,
   218,    90,    95,    94,   109,   220,   145,    92,    91,   215,
    90,    80,    94,    79,    76,   108,    84,    74,    86,    75,
   137,    73,   187,   142,   187,   187,    61,    61,    95,    81,
   144,    63,   176,    92,    91,   106,    90,   221,    94,   105,
   196,    79,   218,   217,   182,   216,   208,   220,   104,    76,
    80,    84,   102,    86,    75,   221,    61,    95,   108,   244,
   218,   217,    92,   216,   101,   220,    95,    94,     4,   194,
   195,    92,    91,   143,    90,    64,    94,   108,     8,     9,
    79,     6,     7,    10,    11,    80,    12,   174,   141,     4,
     5,   108,   136,    15,   188,   222,   188,   188,   211,     8,
     9,   212,     6,     7,    10,    11,   128,    12,    44,    45,
    46,     5,    38,    40,    33,    79,    41,    44,    45,    46,
   225,    38,    40,    98,   202,    41,    44,    45,    46,   237,
    38,    40,    33,    28,    41,    44,    45,    46,   113,    38,
    40,    98,   176,    41,    49,     1,    77,    78,    82,    83,
    85,    87,    88,    89,    93,    44,    45,    46,   184,   192,
   190,   189,     0,    41,   227,   132,    50,   131,   202,    51,
     0,    52,   234,   108,    77,    78,    82,    83,    85,    87,
    88,    89,    93,     4,    50,   130,   236,    51,   107,    52,
    61,     0,   210,     8,     9,   209,     6,     7,    10,    11,
     0,    12,    95,    81,    17,     5,     0,    92,    91,    59,
    90,     0,    94,    77,    78,    82,    83,    85,    87,    88,
    89,    93,    60,   219,    20,    84,     0,    86,    88,    89,
    93,     0,   115,     0,    23,    95,    81,     0,     0,     0,
    92,    91,     0,    90,    62,    94,     0,     0,    77,    78,
    82,    83,    85,    87,    88,    89,    93,     0,    84,    80,
    86,    95,    81,   186,     0,   219,    92,    91,     0,    90,
     0,    94,    95,    81,    24,    27,     0,    92,    91,     0,
    90,     0,    94,   219,    84,    93,    86,     0,   125,    79,
   127,     0,    80,     0,    93,    84,     0,    86,    95,    81,
     0,     0,     0,    92,    91,    95,    90,     0,    94,     0,
    92,    91,     0,    90,   185,    94,   185,   185,    80,   204,
   126,    84,    79,    86,    32,     0,    95,     0,    84,    80,
    86,    92,    91,   203,    90,     0,    94,   198,   201,   200,
     0,   199,    47,     0,     0,     0,     0,     0,    79,    84,
   224,    86,   197,     0,     0,     0,     0,   205,     0,    97,
    99,   100,    58,     0,     0,     0,   177,    65,   179,   180,
    70,    71,     0,     0,    22,   238,   239,   240,   241,   242,
   243,    16,    19,     0,     0,   228,   229,   230,   231,   232,
     0,     0,   139,     0,     0,     0,     0,     0,     0,   148,
   149,   150,   151,   152,   153,   154,   155,   156,   157,   158,
   159,   160,   161,   162,   163,   164,   165,   166,   167,   168,
   169,     0,    77,    78,    82,    83,    85,    87,    88,    89,
    93,   101,     0,     0,     0,     0,    69,    57,   135,     0,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     0,    68,     0,     0,     0,     0,    78,    82,    83,    85,
    87,    88,    89,    93,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,   177,     0,     0,     0,
     0,   181,    67,    82,    83,    85,    87,    88,    89,    93,
     0,     0,     0,     0,    82,    83,    85,    87,    88,    89,
    93,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    82,    83,    85,    87,    88,    89,    93,    82,    83,    85,
    87,    88,    89,    93,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
    85,    87,    88,    89,    93,     0,     0,     0,     0,     0,
     0,   202 };
static YYCONST yytabelem yypact[]={

-10000000,-10000000,    57,-10000000,    36,   183,  -273,  -273,  -273,  -273,
  -265,  -265,  -264,-10000000,-10000000,   -15,  -256,    55,    58,  -256,
   280,   117,-10000000,   146,    44,-10000000,     8,    44,    26,-10000000,
-10000000,   110,    86,  -255,    -6,    -6,    -6,-10000000,   154,-10000000,
-10000000,   142,-10000000,  -260,   138,   129,   125,   259,-10000000,    73,
    11,    10,-10000000,   -94,  -234,  -234,  -265,  -234,   177,-10000000,
  -244,    20,  -245,  -273,-10000000,   163,  -265,   -24,   -57,  -265,
   144,   101,  -264,   -37,    -6,    -6,    -6,    -6,    -6,    -6,
    -6,    -6,    -6,    -6,    -6,    -6,    -6,    -6,    -6,    -6,
    -6,    -6,    -6,    -6,    -6,    -6,-10000000,-10000000,-10000000,-10000000,
    47,   -33,  -224,-10000000,  -265,  -265,  -273,-10000000,  -256,    14,
  -269,    14,    14,-10000000,   -15,-10000000,-10000000,-10000000,-10000000,-10000000,
-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,    51,-10000000,-10000000,   116,
   426,-10000000,-10000000,    20,   116,-10000000,-10000000,-10000000,-10000000,    19,
-10000000,    -4,-10000000,-10000000,-10000000,-10000000,-10000000,-10000000,    86,   121,
   295,   328,   354,   365,   391,   398,   419,   419,    95,    95,
    95,    95,   159,   159,   150,   150,-10000000,-10000000,-10000000,-10000000,
-10000000,-10000000,   281,-10000000,   187,-10000000,-10000000,    51,-10000000,    74,
    56,    98,-10000000,-10000000,   130,    55,    51,-10000000,-10000000,  -271,
-10000000,   -27,   521,-10000000,-10000000,-10000000,     1,  -273,-10000000,    20,
    20,    20,    20,    20,    33,  -273,-10000000,-10000000,   -58,   -15,
-10000000,-10000000,  -224,-10000000,-10000000,-10000000,   -27,   -27,   -27,   -27,
   -27,   -27,-10000000,-10000000,   148,-10000000,-10000000,    83,   -11,   -11,
-10000000,-10000000,-10000000,-10000000,    83,-10000000,-10000000,-10000000,    88,    88,
-10000000,-10000000,-10000000,-10000000,-10000000 };
static YYCONST yytabelem yypgo[]={

     0,   362,   275,    28,    43,   472,    65,   274,    87,    55,
   106,    83,   334,   393,    39,   268,   263,    63,   288,   454,
   114,    59,   217,    46,    96,   504,   352,   315,    42,   354 };
static YYCONST yytabelem yyr1[]={

     0,     2,     3,     3,     4,     4,     4,     4,     4,     4,
     4,     4,     4,     4,     4,    29,    29,    26,    26,    27,
    27,    27,    27,    27,    27,    27,    27,     5,     5,     5,
     6,     6,     6,     7,     7,     8,     8,     8,     8,     8,
     8,     8,    18,    18,    18,    18,    18,    18,    18,    18,
    24,    24,    25,    14,    14,    15,    15,     9,     9,    10,
    10,    19,    19,    19,    19,    19,    19,    19,    19,    19,
    19,    19,    19,    19,    19,    19,    19,    19,    19,    19,
    19,    19,    19,    19,    19,    19,    19,    19,    19,    19,
    19,    20,    20,    20,    20,    22,    22,    23,    23,    23,
    21,    21,    21,    28,    11,    11,    11,    11,    11,    11,
    17,    12,    12,    12,     1,     1,     1,     1,     1,     1,
     1,     1,     1,    13,    13,    16,    16 };
static YYCONST yytabelem yyr2[]={

     0,     3,     1,     5,     5,    11,    15,     9,     9,     7,
     7,     9,     9,     9,     3,    11,    11,     1,     7,     3,
     3,     7,     7,     7,     7,     7,     7,     1,     2,     7,
     7,     7,     7,     3,     7,     2,     5,     2,     2,     2,
     5,     3,     7,     7,     7,     7,     7,     7,     7,     3,
     2,     7,     7,     1,     5,     1,     7,     2,     7,     2,
     5,     7,     7,     7,     7,     7,     7,     7,     7,     7,
     7,     7,     7,     7,     7,     7,     7,     7,     7,     7,
     7,     7,     7,     5,     5,     7,     2,     3,     3,     2,
     3,     7,     9,     9,     2,     2,     7,     2,     3,     3,
     9,     9,     9,     5,     3,     7,     9,     7,     9,     7,
     3,     7,     7,     7,     2,     2,     2,     2,     2,     2,
     2,     2,     2,     2,     7,     2,     7 };
static YYCONST yytabelem yychk[]={

-10000000,    -2,    -3,    -4,   256,   278,   269,   270,   266,   267,
   271,   272,   274,    59,    59,    40,   -25,   -12,   275,   -25,
   -29,   -24,   -25,   -29,   -13,   -11,   275,   -13,   -16,   -17,
   275,   -10,   -19,   277,    33,   126,    40,   -20,   275,   -28,
   276,   279,   -21,    36,   271,   272,   273,    -5,    -6,    -7,
   270,   273,   275,   -14,    46,    45,    64,    46,    -5,    59,
   -26,    40,   -26,    44,    59,    -5,    47,    91,    60,    45,
    -5,    -5,    47,    41,    61,    63,    58,   257,   258,   124,
    94,    38,   259,   260,    60,   261,    62,   262,   263,   264,
    45,    43,    42,   265,    47,    37,   275,   -19,   277,   -19,
   -19,    40,    40,   275,    40,    40,    40,    59,    44,    61,
    45,    61,    61,   -15,   123,    -1,   275,   266,   267,   269,
   270,   271,   272,   274,   278,    -1,   -13,    -1,    59,   268,
   -27,   277,   275,    40,   268,   -25,    59,   -11,    93,   -19,
    62,   275,   -11,    59,    59,   -17,    -4,   123,   -19,   -19,
   -19,   -19,   -19,   -19,   -19,   -19,   -19,   -19,   -19,   -19,
   -19,   -19,   -19,   -19,   -19,   -19,   -19,   -19,   -19,   -19,
    41,    41,    -9,   -10,   -22,   -23,   -21,   -13,   276,   -13,
   -13,   -25,    -6,    -8,   -18,   -12,   -13,   -28,   -20,   277,
   276,    40,   275,   275,    -8,    -8,    -9,   -26,    41,    45,
    43,    42,   265,    37,   -27,   -26,    93,    62,    -3,    44,
    41,    41,    44,    41,    41,    41,    45,    43,    42,   265,
    47,    37,   -14,   275,   -18,   277,   125,   -24,   -27,   -27,
   -27,   -27,   -27,    41,   -24,   125,   -10,   -23,   -18,   -18,
   -18,   -18,   -18,   -18,    41 };
static YYCONST yytabelem yydef[]={

     2,    -2,    -2,     3,     0,     0,     0,     0,     0,     0,
     0,     0,     0,    14,     4,     0,    27,    53,     0,    27,
    17,    17,    50,    17,    27,   123,   104,    27,    27,   125,
   110,     0,    59,    87,     0,     0,     0,    86,    88,    89,
    90,     0,    94,     0,     0,     0,     0,     0,    28,     0,
     0,     0,    33,    55,     0,     0,     0,     0,     0,     9,
     0,     0,     0,     0,    10,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,     0,     0,     0,     0,
     0,     0,     0,     0,     0,     0,    60,    83,    87,    84,
     0,     0,     0,   103,     0,     0,     0,     7,     0,     0,
     0,     0,     0,    52,     0,   112,   114,   115,   116,   117,
   118,   119,   120,   121,   122,   113,    54,   111,     8,    17,
     0,    19,    20,     0,    17,    51,    11,   124,   105,     0,
   107,     0,   109,    12,    13,   126,     5,     2,    61,    62,
    -2,    64,    65,    66,    67,    68,    69,    70,    71,    72,
    73,    74,    75,    76,    77,    78,    79,    80,    81,    82,
    85,    91,     0,    57,     0,    95,    97,    98,    99,     0,
     0,     0,    29,    30,    35,    53,    37,    38,    39,    49,
    41,     0,   104,    34,    31,    32,     0,     0,    18,     0,
     0,     0,     0,     0,     0,     0,   106,   108,     0,     0,
    92,    93,     0,   100,   101,   102,     0,     0,     0,     0,
     0,     0,    36,    40,     0,    49,    56,    16,    22,    23,
    24,    25,    26,    21,    15,     6,    58,    96,    42,    43,
    44,    45,    46,    47,    48 };
typedef struct
#ifdef __cplusplus
	yytoktype
#endif
{
#ifdef __cplusplus
const
#endif
char *t_name; int t_val; } yytoktype;
#ifndef YYDEBUG
#	define YYDEBUG	1	/* allow debugging */
#endif

#if YYDEBUG

yytoktype yytoks[] =
{
	"=",	61,
	"?",	63,
	":",	58,
	"OR",	257,
	"AND",	258,
	"|",	124,
	"^",	94,
	"&",	38,
	"EQ",	259,
	"NE",	260,
	"LE",	261,
	"GE",	262,
	"<",	60,
	">",	62,
	"LSHIFT",	263,
	"RSHIFT",	264,
	"-",	45,
	"+",	43,
	"*",	42,
	"%",	37,
	"DIV",	265,
	"/",	47,
	"!",	33,
	"~",	126,
	".",	46,
	"PROP",	266,
	"MASK",	267,
	"ARROW",	268,
	"EVENT",	269,
	"ENGINE",	270,
	"ASRU",	271,
	"FRU",	272,
	"COUNT",	273,
	"CONFIG",	274,
	"ID",	275,
	"QUOTE",	276,
	"NUMBER",	277,
	"IF",	278,
	"PATHFUNC",	279,
	"-unknown-",	-1	/* ends search */
};

#ifdef __cplusplus
const
#endif
char * yyreds[] =
{
	"-no such reduction-",
	"root : stmtlist",
	"stmtlist : /* empty */",
	"stmtlist : stmtlist stmt",
	"stmt : error ';'",
	"stmt : IF '(' expr ')' stmt",
	"stmt : IF '(' expr ')' '{' stmtlist '}'",
	"stmt : EVENT event nvpairlist ';'",
	"stmt : ENGINE event nvpairlist ';'",
	"stmt : PROP propbody ';'",
	"stmt : MASK propbody ';'",
	"stmt : ASRU pname nvpairlist ';'",
	"stmt : FRU pname nvpairlist ';'",
	"stmt : CONFIG ipname nvpairlist ';'",
	"stmt : ';'",
	"propbody : eventlist nork ARROW nork eventlist",
	"propbody : propbody nork ARROW nork eventlist",
	"nork : /* empty */",
	"nork : '(' norkexpr ')'",
	"norkexpr : NUMBER",
	"norkexpr : ID",
	"norkexpr : '(' norkexpr ')'",
	"norkexpr : norkexpr '-' norkexpr",
	"norkexpr : norkexpr '+' norkexpr",
	"norkexpr : norkexpr '*' norkexpr",
	"norkexpr : norkexpr DIV norkexpr",
	"norkexpr : norkexpr '%' norkexpr",
	"nvpairlist : /* empty */",
	"nvpairlist : nvpair",
	"nvpairlist : nvpairlist ',' nvpair",
	"nvpair : nvname '=' nvexpr",
	"nvpair : ENGINE '=' nvexpr",
	"nvpair : COUNT '=' nvexpr",
	"nvname : ID",
	"nvname : nvname '-' ID",
	"nvexpr : numexpr",
	"nvexpr : ename epname",
	"nvexpr : pname",
	"nvexpr : globid",
	"nvexpr : func",
	"nvexpr : NUMBER ID",
	"nvexpr : QUOTE",
	"numexpr : numexpr '-' numexpr",
	"numexpr : numexpr '+' numexpr",
	"numexpr : numexpr '*' numexpr",
	"numexpr : numexpr DIV numexpr",
	"numexpr : numexpr '/' numexpr",
	"numexpr : numexpr '%' numexpr",
	"numexpr : '(' numexpr ')'",
	"numexpr : NUMBER",
	"eventlist : event",
	"eventlist : eventlist ',' event",
	"event : ename epname eexprlist",
	"epname : /* empty */",
	"epname : '@' pname",
	"eexprlist : /* empty */",
	"eexprlist : '{' exprlist '}'",
	"exprlist : expr",
	"exprlist : exprlist ',' expr",
	"expr : cexpr",
	"expr : NUMBER ID",
	"cexpr : cexpr '=' cexpr",
	"cexpr : cexpr '?' cexpr",
	"cexpr : cexpr ':' cexpr",
	"cexpr : cexpr OR cexpr",
	"cexpr : cexpr AND cexpr",
	"cexpr : cexpr '|' cexpr",
	"cexpr : cexpr '^' cexpr",
	"cexpr : cexpr '&' cexpr",
	"cexpr : cexpr EQ cexpr",
	"cexpr : cexpr NE cexpr",
	"cexpr : cexpr '<' cexpr",
	"cexpr : cexpr LE cexpr",
	"cexpr : cexpr '>' cexpr",
	"cexpr : cexpr GE cexpr",
	"cexpr : cexpr LSHIFT cexpr",
	"cexpr : cexpr RSHIFT cexpr",
	"cexpr : cexpr '-' cexpr",
	"cexpr : cexpr '+' cexpr",
	"cexpr : cexpr '*' cexpr",
	"cexpr : cexpr DIV cexpr",
	"cexpr : cexpr '/' cexpr",
	"cexpr : cexpr '%' cexpr",
	"cexpr : '!' cexpr",
	"cexpr : '~' cexpr",
	"cexpr : '(' cexpr ')'",
	"cexpr : func",
	"cexpr : NUMBER",
	"cexpr : ID",
	"cexpr : globid",
	"cexpr : QUOTE",
	"func : ID '(' ')'",
	"func : ID '(' exprlist ')'",
	"func : PATHFUNC '(' parglist ')'",
	"func : pfunc",
	"parglist : parg",
	"parglist : parglist ',' parg",
	"parg : pfunc",
	"parg : pname",
	"parg : QUOTE",
	"pfunc : ASRU '(' pname ')'",
	"pfunc : FRU '(' pname ')'",
	"pfunc : COUNT '(' event ')'",
	"globid : '$' ID",
	"iterid : ID",
	"iterid : ID '[' ']'",
	"iterid : ID '[' cexpr ']'",
	"iterid : ID '<' '>'",
	"iterid : ID '<' ID '>'",
	"iterid : ID '-' iterid",
	"iname : ID",
	"ename : ID '.' enameid",
	"ename : ename '.' enameid",
	"ename : ename '-' enameid",
	"enameid : ID",
	"enameid : PROP",
	"enameid : MASK",
	"enameid : EVENT",
	"enameid : ENGINE",
	"enameid : ASRU",
	"enameid : FRU",
	"enameid : CONFIG",
	"enameid : IF",
	"pname : iterid",
	"pname : pname '/' iterid",
	"ipname : iname",
	"ipname : ipname '/' iname",
};
#endif /* YYDEBUG */
# line	1 "/usr/share/lib/ccs/yaccpar"
/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 1993 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1988 AT&T */
/* All Rights Reserved */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
** Skeleton parser driver for yacc output
*/

/*
** yacc user known macros and defines
*/
#define YYERROR		goto yyerrlab
#define YYACCEPT	return(0)
#define YYABORT		return(1)
#define YYBACKUP( newtoken, newvalue )\
{\
	if ( yychar >= 0 || ( yyr2[ yytmp ] >> 1 ) != 1 )\
	{\
		yyerror( "syntax error - cannot backup" );\
		goto yyerrlab;\
	}\
	yychar = newtoken;\
	yystate = *yyps;\
	yylval = newvalue;\
	goto yynewstate;\
}
#define YYRECOVERING()	(!!yyerrflag)
#define YYNEW(type)	malloc(sizeof(type) * yynewmax)
#define YYCOPY(to, from, type) \
	(type *) memcpy(to, (char *) from, yymaxdepth * sizeof (type))
#define YYENLARGE( from, type) \
	(type *) realloc((char *) from, yynewmax * sizeof(type))
#ifndef YYDEBUG
#	define YYDEBUG	1	/* make debugging available */
#endif

/*
** user known globals
*/
int yydebug;			/* set to 1 to get debugging */

/*
** driver internal defines
*/
#define YYFLAG		(-10000000)

/*
** global variables used by the parser
*/
YYSTYPE *yypv;			/* top of value stack */
int *yyps;			/* top of state stack */

int yystate;			/* current state */
int yytmp;			/* extra var (lasts between blocks) */

int yynerrs;			/* number of errors */
int yyerrflag;			/* error recovery flag */
int yychar;			/* current input token number */



#ifdef YYNMBCHARS
#define YYLEX()		yycvtok(yylex())
/*
** yycvtok - return a token if i is a wchar_t value that exceeds 255.
**	If i<255, i itself is the token.  If i>255 but the neither 
**	of the 30th or 31st bit is on, i is already a token.
*/
#if defined(__STDC__) || defined(__cplusplus)
int yycvtok(int i)
#else
int yycvtok(i) int i;
#endif
{
	int first = 0;
	int last = YYNMBCHARS - 1;
	int mid;
	wchar_t j;

	if(i&0x60000000){/*Must convert to a token. */
		if( yymbchars[last].character < i ){
			return i;/*Giving up*/
		}
		while ((last>=first)&&(first>=0)) {/*Binary search loop*/
			mid = (first+last)/2;
			j = yymbchars[mid].character;
			if( j==i ){/*Found*/ 
				return yymbchars[mid].tvalue;
			}else if( j<i ){
				first = mid + 1;
			}else{
				last = mid -1;
			}
		}
		/*No entry in the table.*/
		return i;/* Giving up.*/
	}else{/* i is already a token. */
		return i;
	}
}
#else/*!YYNMBCHARS*/
#define YYLEX()		yylex()
#endif/*!YYNMBCHARS*/

/*
** yyparse - return 0 if worked, 1 if syntax error not recovered from
*/
#if defined(__STDC__) || defined(__cplusplus)
int yyparse(void)
#else
int yyparse()
#endif
{
	register YYSTYPE *yypvt = 0;	/* top of value stack for $vars */

#if defined(__cplusplus) || defined(lint)
/*
	hacks to please C++ and lint - goto's inside
	switch should never be executed
*/
	static int __yaccpar_lint_hack__ = 0;
	switch (__yaccpar_lint_hack__)
	{
		case 1: goto yyerrlab;
		case 2: goto yynewstate;
	}
#endif

	/*
	** Initialize externals - yyparse may be called more than once
	*/
	yypv = &yyv[-1];
	yyps = &yys[-1];
	yystate = 0;
	yytmp = 0;
	yynerrs = 0;
	yyerrflag = 0;
	yychar = -1;

#if YYMAXDEPTH <= 0
	if (yymaxdepth <= 0)
	{
		if ((yymaxdepth = YYEXPAND(0)) <= 0)
		{
			yyerror("yacc initialization error");
			YYABORT;
		}
	}
#endif

	{
		register YYSTYPE *yy_pv;	/* top of value stack */
		register int *yy_ps;		/* top of state stack */
		register int yy_state;		/* current state */
		register int  yy_n;		/* internal state number info */
	goto yystack;	/* moved from 6 lines above to here to please C++ */

		/*
		** get globals into registers.
		** branch to here only if YYBACKUP was called.
		*/
	yynewstate:
		yy_pv = yypv;
		yy_ps = yyps;
		yy_state = yystate;
		goto yy_newstate;

		/*
		** get globals into registers.
		** either we just started, or we just finished a reduction
		*/
	yystack:
		yy_pv = yypv;
		yy_ps = yyps;
		yy_state = yystate;

		/*
		** top of for (;;) loop while no reductions done
		*/
	yy_stack:
		/*
		** put a state and value onto the stacks
		*/
#if YYDEBUG
		/*
		** if debugging, look up token value in list of value vs.
		** name pairs.  0 and negative (-1) are special values.
		** Note: linear search is used since time is not a real
		** consideration while debugging.
		*/
		if ( yydebug )
		{
			register int yy_i;

			printf( "State %d, token ", yy_state );
			if ( yychar == 0 )
				printf( "end-of-file\n" );
			else if ( yychar < 0 )
				printf( "-none-\n" );
			else
			{
				for ( yy_i = 0; yytoks[yy_i].t_val >= 0;
					yy_i++ )
				{
					if ( yytoks[yy_i].t_val == yychar )
						break;
				}
				printf( "%s\n", yytoks[yy_i].t_name );
			}
		}
#endif /* YYDEBUG */
		if ( ++yy_ps >= &yys[ yymaxdepth ] )	/* room on stack? */
		{
			/*
			** reallocate and recover.  Note that pointers
			** have to be reset, or bad things will happen
			*/
			long yyps_index = (yy_ps - yys);
			long yypv_index = (yy_pv - yyv);
			long yypvt_index = (yypvt - yyv);
			int yynewmax;
#ifdef YYEXPAND
			yynewmax = YYEXPAND(yymaxdepth);
#else
			yynewmax = 2 * yymaxdepth;	/* double table size */
			if (yymaxdepth == YYMAXDEPTH)	/* first time growth */
			{
				char *newyys = (char *)YYNEW(int);
				char *newyyv = (char *)YYNEW(YYSTYPE);
				if (newyys != 0 && newyyv != 0)
				{
					yys = YYCOPY(newyys, yys, int);
					yyv = YYCOPY(newyyv, yyv, YYSTYPE);
				}
				else
					yynewmax = 0;	/* failed */
			}
			else				/* not first time */
			{
				yys = YYENLARGE(yys, int);
				yyv = YYENLARGE(yyv, YYSTYPE);
				if (yys == 0 || yyv == 0)
					yynewmax = 0;	/* failed */
			}
#endif
			if (yynewmax <= yymaxdepth)	/* tables not expanded */
			{
				yyerror( "yacc stack overflow" );
				YYABORT;
			}
			yymaxdepth = yynewmax;

			yy_ps = yys + yyps_index;
			yy_pv = yyv + yypv_index;
			yypvt = yyv + yypvt_index;
		}
		*yy_ps = yy_state;
		*++yy_pv = yyval;

		/*
		** we have a new state - find out what to do
		*/
	yy_newstate:
		if ( ( yy_n = yypact[ yy_state ] ) <= YYFLAG )
			goto yydefault;		/* simple state */
#if YYDEBUG
		/*
		** if debugging, need to mark whether new token grabbed
		*/
		yytmp = yychar < 0;
#endif
		if ( ( yychar < 0 ) && ( ( yychar = YYLEX() ) < 0 ) )
			yychar = 0;		/* reached EOF */
#if YYDEBUG
		if ( yydebug && yytmp )
		{
			register int yy_i;

			printf( "Received token " );
			if ( yychar == 0 )
				printf( "end-of-file\n" );
			else if ( yychar < 0 )
				printf( "-none-\n" );
			else
			{
				for ( yy_i = 0; yytoks[yy_i].t_val >= 0;
					yy_i++ )
				{
					if ( yytoks[yy_i].t_val == yychar )
						break;
				}
				printf( "%s\n", yytoks[yy_i].t_name );
			}
		}
#endif /* YYDEBUG */
		if ( ( ( yy_n += yychar ) < 0 ) || ( yy_n >= YYLAST ) )
			goto yydefault;
		if ( yychk[ yy_n = yyact[ yy_n ] ] == yychar )	/*valid shift*/
		{
			yychar = -1;
			yyval = yylval;
			yy_state = yy_n;
			if ( yyerrflag > 0 )
				yyerrflag--;
			goto yy_stack;
		}

	yydefault:
		if ( ( yy_n = yydef[ yy_state ] ) == -2 )
		{
#if YYDEBUG
			yytmp = yychar < 0;
#endif
			if ( ( yychar < 0 ) && ( ( yychar = YYLEX() ) < 0 ) )
				yychar = 0;		/* reached EOF */
#if YYDEBUG
			if ( yydebug && yytmp )
			{
				register int yy_i;

				printf( "Received token " );
				if ( yychar == 0 )
					printf( "end-of-file\n" );
				else if ( yychar < 0 )
					printf( "-none-\n" );
				else
				{
					for ( yy_i = 0;
						yytoks[yy_i].t_val >= 0;
						yy_i++ )
					{
						if ( yytoks[yy_i].t_val
							== yychar )
						{
							break;
						}
					}
					printf( "%s\n", yytoks[yy_i].t_name );
				}
			}
#endif /* YYDEBUG */
			/*
			** look through exception table
			*/
			{
				register YYCONST int *yyxi = yyexca;

				while ( ( *yyxi != -1 ) ||
					( yyxi[1] != yy_state ) )
				{
					yyxi += 2;
				}
				while ( ( *(yyxi += 2) >= 0 ) &&
					( *yyxi != yychar ) )
					;
				if ( ( yy_n = yyxi[1] ) < 0 )
					YYACCEPT;
			}
		}

		/*
		** check for syntax error
		*/
		if ( yy_n == 0 )	/* have an error */
		{
			/* no worry about speed here! */
			switch ( yyerrflag )
			{
			case 0:		/* new error */
				yyerror( "syntax error" );
				goto skip_init;
			yyerrlab:
				/*
				** get globals into registers.
				** we have a user generated syntax type error
				*/
				yy_pv = yypv;
				yy_ps = yyps;
				yy_state = yystate;
			skip_init:
				yynerrs++;
				/* FALLTHRU */
			case 1:
			case 2:		/* incompletely recovered error */
					/* try again... */
				yyerrflag = 3;
				/*
				** find state where "error" is a legal
				** shift action
				*/
				while ( yy_ps >= yys )
				{
					yy_n = yypact[ *yy_ps ] + YYERRCODE;
					if ( yy_n >= 0 && yy_n < YYLAST &&
						yychk[yyact[yy_n]] == YYERRCODE)					{
						/*
						** simulate shift of "error"
						*/
						yy_state = yyact[ yy_n ];
						goto yy_stack;
					}
					/*
					** current state has no shift on
					** "error", pop stack
					*/
#if YYDEBUG
#	define _POP_ "Error recovery pops state %d, uncovers state %d\n"
					if ( yydebug )
						printf( _POP_, *yy_ps,
							yy_ps[-1] );
#	undef _POP_
#endif
					yy_ps--;
					yy_pv--;
				}
				/*
				** there is no state on stack with "error" as
				** a valid shift.  give up.
				*/
				YYABORT;
			case 3:		/* no shift yet; eat a token */
#if YYDEBUG
				/*
				** if debugging, look up token in list of
				** pairs.  0 and negative shouldn't occur,
				** but since timing doesn't matter when
				** debugging, it doesn't hurt to leave the
				** tests here.
				*/
				if ( yydebug )
				{
					register int yy_i;

					printf( "Error recovery discards " );
					if ( yychar == 0 )
						printf( "token end-of-file\n" );
					else if ( yychar < 0 )
						printf( "token -none-\n" );
					else
					{
						for ( yy_i = 0;
							yytoks[yy_i].t_val >= 0;
							yy_i++ )
						{
							if ( yytoks[yy_i].t_val
								== yychar )
							{
								break;
							}
						}
						printf( "token %s\n",
							yytoks[yy_i].t_name );
					}
				}
#endif /* YYDEBUG */
				if ( yychar == 0 )	/* reached EOF. quit */
					YYABORT;
				yychar = -1;
				goto yy_newstate;
			}
		}/* end if ( yy_n == 0 ) */
		/*
		** reduction by production yy_n
		** put stack tops, etc. so things right after switch
		*/
#if YYDEBUG
		/*
		** if debugging, print the string that is the user's
		** specification of the reduction which is just about
		** to be done.
		*/
		if ( yydebug )
			printf( "Reduce by (%d) \"%s\"\n",
				yy_n, yyreds[ yy_n ] );
#endif
		yytmp = yy_n;			/* value to switch over */
		yypvt = yy_pv;			/* $vars top of value stack */
		/*
		** Look in goto table for next state
		** Sorry about using yy_state here as temporary
		** register variable, but why not, if it works...
		** If yyr2[ yy_n ] doesn't have the low order bit
		** set, then there is no action to be done for
		** this reduction.  So, no saving & unsaving of
		** registers done.  The only difference between the
		** code just after the if and the body of the if is
		** the goto yy_stack in the body.  This way the test
		** can be made before the choice of what to do is needed.
		*/
		{
			/* length of production doubled with extra bit */
			register int yy_len = yyr2[ yy_n ];

			if ( !( yy_len & 01 ) )
			{
				yy_len >>= 1;
				yyval = ( yy_pv -= yy_len )[1];	/* $$ = $1 */
				yy_state = yypgo[ yy_n = yyr1[ yy_n ] ] +
					*( yy_ps -= yy_len ) + 1;
				if ( yy_state >= YYLAST ||
					yychk[ yy_state =
					yyact[ yy_state ] ] != -yy_n )
				{
					yy_state = yyact[ yypgo[ yy_n ] ];
				}
				goto yy_stack;
			}
			yy_len >>= 1;
			yyval = ( yy_pv -= yy_len )[1];	/* $$ = $1 */
			yy_state = yypgo[ yy_n = yyr1[ yy_n ] ] +
				*( yy_ps -= yy_len ) + 1;
			if ( yy_state >= YYLAST ||
				yychk[ yy_state = yyact[ yy_state ] ] != -yy_n )
			{
				yy_state = yyact[ yypgo[ yy_n ] ];
			}
		}
					/* save until reenter driver code */
		yystate = yy_state;
		yyps = yy_ps;
		yypv = yy_pv;
	}
	/*
	** code supplied by user is placed in this switch
	*/
	switch( yytmp )
	{
		
case 1:
# line 98 "../../../eversholt/common/escparse.y"
{ (void)tree_root(yypvt[-0].np); } break;
case 2:
# line 102 "../../../eversholt/common/escparse.y"
{ yyval.np = NULL; } break;
case 3:
# line 104 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_LIST, yypvt[-1].np, yypvt[-0].np); } break;
case 4:
# line 108 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_nothing(); } break;
case 5:
# line 110 "../../../eversholt/common/escparse.y"
{ yyval.np = yypvt[-0].np; } break;
case 6:
# line 112 "../../../eversholt/common/escparse.y"
{ yyval.np = yypvt[-1].np; } break;
case 7:
# line 114 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_decl(T_EVENT, yypvt[-2].np, yypvt[-1].np, yypvt[-3].tok.file, yypvt[-3].tok.line); } break;
case 8:
# line 116 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_decl(T_ENGINE, yypvt[-2].np, yypvt[-1].np, yypvt[-3].tok.file, yypvt[-3].tok.line); } break;
case 9:
# line 118 "../../../eversholt/common/escparse.y"
{
			yyval.np = tree_stmt(T_PROP, yypvt[-1].np, yypvt[-2].tok.file, yypvt[-2].tok.line);
		} break;
case 10:
# line 122 "../../../eversholt/common/escparse.y"
{
			yyval.np = tree_stmt(T_MASK, yypvt[-1].np, yypvt[-2].tok.file, yypvt[-2].tok.line);
		} break;
case 11:
# line 126 "../../../eversholt/common/escparse.y"
{
			yyval.np = tree_decl(T_ASRU, yypvt[-2].np, yypvt[-1].np, yypvt[-3].tok.file, yypvt[-3].tok.line);
		} break;
case 12:
# line 130 "../../../eversholt/common/escparse.y"
{
			yyval.np = tree_decl(T_FRU, yypvt[-2].np, yypvt[-1].np, yypvt[-3].tok.file, yypvt[-3].tok.line);
		} break;
case 13:
# line 134 "../../../eversholt/common/escparse.y"
{
			yyval.np = tree_decl(T_CONFIG, yypvt[-2].np, yypvt[-1].np, yypvt[-3].tok.file, yypvt[-3].tok.line);
		} break;
case 14:
# line 138 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_nothing(); } break;
case 15:
# line 142 "../../../eversholt/common/escparse.y"
{
			yyval.np = tree_arrow(yypvt[-4].np, yypvt[-3].np, yypvt[-1].np, yypvt[-0].np);
		} break;
case 16:
# line 146 "../../../eversholt/common/escparse.y"
{
			yyval.np = tree_arrow(yypvt[-4].np, yypvt[-3].np, yypvt[-1].np, yypvt[-0].np);
		} break;
case 17:
# line 152 "../../../eversholt/common/escparse.y"
{ yyval.np = NULL; } break;
case 18:
# line 154 "../../../eversholt/common/escparse.y"
{ yyval.np = yypvt[-1].np; } break;
case 19:
# line 158 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_num(yypvt[-0].tok.s, yypvt[-0].tok.file, yypvt[-0].tok.line); } break;
case 20:
# line 161 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_name(yypvt[-0].tok.s, IT_NONE, yypvt[-0].tok.file, yypvt[-0].tok.line); } break;
case 21:
# line 163 "../../../eversholt/common/escparse.y"
{ yyval.np = yypvt[-1].np; } break;
case 22:
# line 165 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_SUB, yypvt[-2].np, yypvt[-0].np); } break;
case 23:
# line 167 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_ADD, yypvt[-2].np, yypvt[-0].np); } break;
case 24:
# line 169 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_MUL, yypvt[-2].np, yypvt[-0].np); } break;
case 25:
# line 171 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_DIV, yypvt[-2].np, yypvt[-0].np); } break;
case 26:
# line 173 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_MOD, yypvt[-2].np, yypvt[-0].np); } break;
case 27:
# line 177 "../../../eversholt/common/escparse.y"
{ yyval.np = NULL; } break;
case 29:
# line 180 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_LIST, yypvt[-2].np, yypvt[-0].np); } break;
case 30:
# line 184 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_NVPAIR, yypvt[-2].np, yypvt[-0].np); } break;
case 31:
# line 187 "../../../eversholt/common/escparse.y"
{
			yyval.np = tree_expr(T_NVPAIR,
				tree_name(yypvt[-2].tok.s, IT_NONE, yypvt[-2].tok.file, yypvt[-2].tok.line), yypvt[-0].np);
		} break;
case 32:
# line 193 "../../../eversholt/common/escparse.y"
{
			yyval.np = tree_expr(T_NVPAIR,
				tree_name(yypvt[-2].tok.s, IT_NONE, yypvt[-2].tok.file, yypvt[-2].tok.line), yypvt[-0].np);
		} break;
case 33:
# line 200 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_name(yypvt[-0].tok.s, IT_NONE, yypvt[-0].tok.file, yypvt[-0].tok.line); } break;
case 34:
# line 202 "../../../eversholt/common/escparse.y"
{
			/* hack to allow dashes in property names */
			yyval.np = tree_name_repairdash(yypvt[-2].np, yypvt[-0].tok.s);
		} break;
case 36:
# line 211 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_event(yypvt[-1].np, yypvt[-0].np, NULL); } break;
case 40:
# line 220 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_timeval(yypvt[-1].tok.s, yypvt[-0].tok.s, yypvt[-1].tok.file, yypvt[-1].tok.line); } break;
case 41:
# line 222 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_quote(yypvt[-0].tok.s, yypvt[-0].tok.file, yypvt[-0].tok.line); } break;
case 42:
# line 227 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_SUB, yypvt[-2].np, yypvt[-0].np); } break;
case 43:
# line 229 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_ADD, yypvt[-2].np, yypvt[-0].np); } break;
case 44:
# line 231 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_MUL, yypvt[-2].np, yypvt[-0].np); } break;
case 45:
# line 233 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_DIV, yypvt[-2].np, yypvt[-0].np); } break;
case 46:
# line 235 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_DIV, yypvt[-2].np, yypvt[-0].np); } break;
case 47:
# line 237 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_MOD, yypvt[-2].np, yypvt[-0].np); } break;
case 48:
# line 239 "../../../eversholt/common/escparse.y"
{ yyval.np = yypvt[-1].np; } break;
case 49:
# line 241 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_num(yypvt[-0].tok.s, yypvt[-0].tok.file, yypvt[-0].tok.line); } break;
case 51:
# line 246 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_LIST, yypvt[-2].np, yypvt[-0].np); } break;
case 52:
# line 250 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_event(yypvt[-2].np, yypvt[-1].np, yypvt[-0].np); } break;
case 53:
# line 254 "../../../eversholt/common/escparse.y"
{ yyval.np = NULL; } break;
case 54:
# line 256 "../../../eversholt/common/escparse.y"
{ yyval.np = yypvt[-0].np; } break;
case 55:
# line 260 "../../../eversholt/common/escparse.y"
{ yyval.np = NULL; } break;
case 56:
# line 262 "../../../eversholt/common/escparse.y"
{ yyval.np = yypvt[-1].np; } break;
case 58:
# line 267 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_LIST, yypvt[-2].np, yypvt[-0].np); } break;
case 60:
# line 280 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_timeval(yypvt[-1].tok.s, yypvt[-0].tok.s, yypvt[-1].tok.file, yypvt[-1].tok.line); } break;
case 61:
# line 284 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_ASSIGN, yypvt[-2].np, yypvt[-0].np); } break;
case 62:
# line 286 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_CONDIF, yypvt[-2].np, yypvt[-0].np); } break;
case 63:
# line 288 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_CONDELSE, yypvt[-2].np, yypvt[-0].np); } break;
case 64:
# line 290 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_OR, yypvt[-2].np, yypvt[-0].np); } break;
case 65:
# line 292 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_AND, yypvt[-2].np, yypvt[-0].np); } break;
case 66:
# line 294 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_BITOR, yypvt[-2].np, yypvt[-0].np); } break;
case 67:
# line 296 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_BITXOR, yypvt[-2].np, yypvt[-0].np); } break;
case 68:
# line 298 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_BITAND, yypvt[-2].np, yypvt[-0].np); } break;
case 69:
# line 300 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_EQ, yypvt[-2].np, yypvt[-0].np); } break;
case 70:
# line 302 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_NE, yypvt[-2].np, yypvt[-0].np); } break;
case 71:
# line 304 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_LT, yypvt[-2].np, yypvt[-0].np); } break;
case 72:
# line 306 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_LE, yypvt[-2].np, yypvt[-0].np); } break;
case 73:
# line 308 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_GT, yypvt[-2].np, yypvt[-0].np); } break;
case 74:
# line 310 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_GE, yypvt[-2].np, yypvt[-0].np); } break;
case 75:
# line 312 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_LSHIFT, yypvt[-2].np, yypvt[-0].np); } break;
case 76:
# line 314 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_RSHIFT, yypvt[-2].np, yypvt[-0].np); } break;
case 77:
# line 316 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_SUB, yypvt[-2].np, yypvt[-0].np); } break;
case 78:
# line 318 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_ADD, yypvt[-2].np, yypvt[-0].np); } break;
case 79:
# line 320 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_MUL, yypvt[-2].np, yypvt[-0].np); } break;
case 80:
# line 322 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_DIV, yypvt[-2].np, yypvt[-0].np); } break;
case 81:
# line 324 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_DIV, yypvt[-2].np, yypvt[-0].np); } break;
case 82:
# line 326 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_MOD, yypvt[-2].np, yypvt[-0].np); } break;
case 83:
# line 328 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_NOT, yypvt[-0].np, NULL); } break;
case 84:
# line 330 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_BITNOT, yypvt[-0].np, NULL); } break;
case 85:
# line 332 "../../../eversholt/common/escparse.y"
{ yyval.np = yypvt[-1].np; } break;
case 87:
# line 335 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_num(yypvt[-0].tok.s, yypvt[-0].tok.file, yypvt[-0].tok.line); } break;
case 88:
# line 337 "../../../eversholt/common/escparse.y"
{
			/* iteration variable */
			yyval.np = tree_name(yypvt[-0].tok.s, IT_NONE, yypvt[-0].tok.file, yypvt[-0].tok.line);
		} break;
case 90:
# line 343 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_quote(yypvt[-0].tok.s, yypvt[-0].tok.file, yypvt[-0].tok.line); } break;
case 91:
# line 347 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_func(yypvt[-2].tok.s, NULL, yypvt[-2].tok.file, yypvt[-2].tok.line); } break;
case 92:
# line 349 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_func(yypvt[-3].tok.s, yypvt[-1].np, yypvt[-3].tok.file, yypvt[-3].tok.line); } break;
case 93:
# line 351 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_func(yypvt[-3].tok.s, yypvt[-1].np, yypvt[-3].tok.file, yypvt[-3].tok.line); } break;
case 96:
# line 357 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_expr(T_LIST, yypvt[-2].np, yypvt[-0].np); } break;
case 98:
# line 362 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_pname(yypvt[-0].np); } break;
case 99:
# line 364 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_quote(yypvt[-0].tok.s, yypvt[-0].tok.file, yypvt[-0].tok.line); } break;
case 100:
# line 372 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_func(yypvt[-3].tok.s, tree_pname(yypvt[-1].np), yypvt[-3].tok.file, yypvt[-3].tok.line); } break;
case 101:
# line 374 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_func(yypvt[-3].tok.s, tree_pname(yypvt[-1].np), yypvt[-3].tok.file, yypvt[-3].tok.line); } break;
case 102:
# line 376 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_func(yypvt[-3].tok.s, yypvt[-1].np, yypvt[-3].tok.file, yypvt[-3].tok.line); } break;
case 103:
# line 380 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_globid(yypvt[-0].tok.s, yypvt[-0].tok.file, yypvt[-0].tok.line); } break;
case 104:
# line 384 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_name(yypvt[-0].tok.s, IT_VERTICAL, yypvt[-0].tok.file, yypvt[-0].tok.line); } break;
case 105:
# line 386 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_name(yypvt[-2].tok.s, IT_VERTICAL, yypvt[-2].tok.file, yypvt[-2].tok.line); } break;
case 106:
# line 388 "../../../eversholt/common/escparse.y"
{
			yyval.np = tree_name_iterator(
			   tree_name(yypvt[-3].tok.s, IT_VERTICAL, yypvt[-3].tok.file, yypvt[-3].tok.line), yypvt[-1].np);
		} break;
case 107:
# line 393 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_name(yypvt[-2].tok.s, IT_HORIZONTAL, yypvt[-2].tok.file, yypvt[-2].tok.line); } break;
case 108:
# line 395 "../../../eversholt/common/escparse.y"
{
			yyval.np = tree_name_iterator(
			    tree_name(yypvt[-3].tok.s, IT_HORIZONTAL, yypvt[-3].tok.file, yypvt[-3].tok.line),
			    tree_name(yypvt[-1].tok.s, IT_NONE, yypvt[-1].tok.file, yypvt[-1].tok.line));
		} break;
case 109:
# line 401 "../../../eversholt/common/escparse.y"
{
			/* hack to allow dashes in path name components */
			yyval.np = tree_name_repairdash2(yypvt[-2].tok.s, yypvt[-0].np);
		} break;
case 110:
# line 409 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_iname(yypvt[-0].tok.s, yypvt[-0].tok.file, yypvt[-0].tok.line); } break;
case 111:
# line 414 "../../../eversholt/common/escparse.y"
{
			yyval.np = tree_name_append(
			    tree_name(yypvt[-2].tok.s, IT_ENAME, yypvt[-2].tok.file, yypvt[-2].tok.line),
			    tree_name(yypvt[-0].tok.s, IT_NONE, yypvt[-0].tok.file, yypvt[-0].tok.line));
		} break;
case 112:
# line 420 "../../../eversholt/common/escparse.y"
{
			yyval.np = tree_name_append(yypvt[-2].np,
			    tree_name(yypvt[-0].tok.s, IT_NONE, yypvt[-0].tok.file, yypvt[-0].tok.line));
		} break;
case 113:
# line 425 "../../../eversholt/common/escparse.y"
{
			/*
			 * hack to allow dashes in class names.  when we
			 * detect the dash here, we know we're in a class
			 * name because the left recursion of this rule
			 * means we've already matched at least:
			 * 	ID '.' ID
			 * so the ename here has an incomplete final
			 * component (because the lexer stopped at the
			 * dash).  so we repair that final component here.
			 */
			yyval.np = tree_name_repairdash(yypvt[-2].np, yypvt[-0].tok.s);
		} break;
case 124:
# line 455 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_name_append(yypvt[-2].np, yypvt[-0].np); } break;
case 126:
# line 461 "../../../eversholt/common/escparse.y"
{ yyval.np = tree_name_append(yypvt[-2].np, yypvt[-0].np); } break;
# line	556 "/usr/share/lib/ccs/yaccpar"
	}
	goto yystack;		/* reset registers in driver code */
}

