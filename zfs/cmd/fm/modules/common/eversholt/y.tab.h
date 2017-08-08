
typedef union
#ifdef __cplusplus
	YYSTYPE
#endif
 {
	struct tokstr tok;
	struct node *np;
} YYSTYPE;
extern YYSTYPE yylval;
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
