#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <syslog.h>
#include "parse_cmd.h"

void
free_parse_result(struct parse_result *result)
{
	struct line_buf *p = result->head, *q;

	while (p) {
		q = p;
		p = p->next;
		free(q);
	}
	free(result);
}

struct parse_result *
parse_cmd(const char *cmd)
{
	FILE *fp;
	struct parse_result *result = NULL;
	struct line_buf *buf;
	char *p;
	int error;

	fp = popen(cmd, "r");
	if (fp == NULL) {
		syslog(LOG_ERR, "popen error %d", errno);
		return (NULL);
	}

	result = malloc(sizeof(struct parse_result));
	if (result == NULL) {
		syslog(LOG_ERR, "alloc parse_result failed");
		pclose(fp);
		return (NULL);
	}
	result->head = result->tail = NULL;

	while (1) {
		buf = malloc(sizeof(struct line_buf));
		if (buf == NULL) {
			syslog(LOG_ERR, "alloc line_buf failed");
			free_parse_result(result);
			pclose(fp);
			return (NULL);
		}

		if (fgets(buf->buffer, LINEBUFSIZ, fp) == NULL) {
			free(buf);
			break;
		}

		for (buf->bufc = 0, p = buf->buffer; buf->bufc < MAXBUFC; buf->bufc++) {
			while (*p == ' ' || *p == '\t' || *p == '\n')
				p++;
			if (*p == '\0')
				break;
			buf->bufv[buf->bufc] = p;
			while (*p != ' ' && *p != '\t' && *p != '\n' && *p != '\0')
				p++;
			if (*p != '\0') {
				*p = '\0';
				p++;
			}
		}

		buf->next = NULL;
		if (result->head == NULL)
			result->head = buf;
		if (result->tail)
			result->tail->next = buf;
		result->tail = buf;
	}

	error = pclose(fp);
	if (error) {
		syslog(LOG_ERR, "pclose error %d, errno = %d", error, errno);
		free_parse_result(result);
		return (NULL);
	}

	return (result);
}

struct parse_result *
parse_file(const char *path)
{
	FILE *fp;
	struct parse_result *result = NULL;
	struct line_buf *buf;
	char *p;

	fp = fopen(path, "r");
	if (fp == NULL) {
		syslog(LOG_ERR, "fopen error %d", errno);
		return (NULL);
	}

	result = malloc(sizeof(struct parse_result));
	if (result == NULL) {
		syslog(LOG_ERR, "alloc parse_result failed");
		fclose(fp);
		return (NULL);
	}
	result->head = result->tail = NULL;

	while (1) {
		buf = malloc(sizeof(struct line_buf));
		if (buf == NULL) {
			syslog(LOG_ERR, "alloc line_buf failed");
			free_parse_result(result);
			fclose(fp);
			return (NULL);
		}

		if (fgets(buf->buffer, LINEBUFSIZ, fp) == NULL) {
			free(buf);
			break;
		}

		for (buf->bufc = 0, p = buf->buffer; buf->bufc < MAXBUFC; buf->bufc++) {
			while (*p == ' ' || *p == '\t' || *p == '\n')
				p++;
			if (*p == '\0')
				break;
			buf->bufv[buf->bufc] = p;
			while (*p != ' ' && *p != '\t' && *p != '\n' && *p != '\0')
				p++;
			if (*p != '\0') {
				*p = '\0';
				p++;
			}
		}

		buf->next = NULL;
		if (result->head == NULL)
			result->head = buf;
		if (result->tail)
			result->tail->next = buf;
		result->tail = buf;
	}

	fclose(fp);

	return (result);
}
