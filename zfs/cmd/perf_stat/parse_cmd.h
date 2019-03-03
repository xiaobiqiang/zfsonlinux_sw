#ifndef	_PARSE_CMD_H
#define	_PARSE_CMD_H

#define	LINEBUFSIZ	1024
#define	MAXBUFC	32

struct line_buf {
	int bufc;
	char *bufv[MAXBUFC];
	char buffer[LINEBUFSIZ];
	struct line_buf *next;
};

struct parse_result {
	struct line_buf *head, *tail;
};

void free_parse_result(struct parse_result *result);
struct parse_result * parse_cmd(const char *cmd);
struct parse_result * parse_file(const char *path);

#endif
