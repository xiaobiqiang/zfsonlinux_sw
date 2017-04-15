#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include "deflt.h"

#define	BUFFERSIZE	1024

struct thr_data {
	FILE *fp;
	char *buf;
};

struct thr_data *thr_data = NULL;

/*
 *	defopen() - declare defopen filename
 *
 *	defopen(fn)
 *		char *fn
 *
 *	If 'fn' is non-null; it is a full pathname of a file
 *	which becomes the one read by subsequent defread() calls.
 *	If 'fn' is null the defopen file is closed.
 *
 *	see defread() for more details.
 *
 *	EXIT    returns 0 if ok
 *		returns -1 if error
 */
int
defopen(char *fn)
{
	if (thr_data == NULL)
		thr_data = malloc(sizeof(struct thr_data));
	if (thr_data == NULL)
		return (-1);

	if (thr_data->fp != NULL) {
		(void) fclose(thr_data->fp);
		thr_data->fp = NULL;
	}

	if (fn == NULL) {
		free(thr_data);
		thr_data = NULL;
		return (0);
	}

	if ((thr_data->fp = fopen(fn, "rF")) == NULL)
		return (-1);

	if (thr_data->buf == NULL &&
	    (thr_data->buf = malloc(BUFFERSIZE)) == NULL) {
		(void) fclose(thr_data->fp);
		thr_data->fp = NULL;
		return (-1);
	}

	return (0);
}

/*
 *	strip_quotes -- strip double (") or single (') quotes from a buffer
 *
 *	ENTRY
 *	  ptr		initial string
 *
 *	EXIT
 *	  ptr		string with quotes (if any) removed
 */
static void
strip_quotes(char *ptr)
{
	char *strip_ptr = NULL;

	while (*ptr != '\0') {
		if ((*ptr == '"') || (*ptr == '\'')) {
			if (strip_ptr == NULL)
				strip_ptr = ptr;	/* skip over quote */
		} else {
			if (strip_ptr != NULL) {
				*strip_ptr = *ptr;
				strip_ptr++;
			}
		}
		ptr++;
	}
	if (strip_ptr != NULL) {
		*strip_ptr = '\0';
	}
}

/*
 *	defread() - read an entry from the defopen file
 *
 *	defread(cp)
 *		char *cp
 *
 *	The defopen data file must have been previously opened by
 *	defopen().  defread scans the data file looking for a line
 *	which begins with the string '*cp'.  If such a line is found,
 *	defread returns a pointer to the first character following
 *	the matched string (*cp).  If no line is found or no file
 *	is open, defread() returns NULL.
 *
 *	Note that there is no way to simultaneously peruse multiple
 *	defopen files; since there is no way of indicating 'which one'
 *	to defread().  If you want to peruse a secondary file you must
 *	recall defopen().  If you need to go back to the first file,
 *	you must call defopen() again.
 */
char *
defread(char *cp)
{
	int (*compare)(const char *, const char *, size_t);
	char *buf_tmp;
	char *ret_ptr = NULL;
	size_t off, patlen;

	if (thr_data == NULL || thr_data->fp == NULL)
		return (NULL);

	compare = strncasecmp;
	patlen = strlen(cp);

	rewind(thr_data->fp);

	while (fgets(thr_data->buf, BUFFERSIZE, thr_data->fp)) {
		for (buf_tmp = thr_data->buf; *buf_tmp == ' '; buf_tmp++)
			;
		off = strlen(buf_tmp) - 1;
		if (buf_tmp[off] == '\n')
			buf_tmp[off] = 0;
		else
			break;	/* line too long */
		if ((*compare)(cp, buf_tmp, patlen) == 0) {
			/* found it */
			/* strip quotes if requested */
			strip_quotes(buf_tmp);
			ret_ptr = &buf_tmp[patlen];
			break;
		}
	}

	return (ret_ptr);
}
