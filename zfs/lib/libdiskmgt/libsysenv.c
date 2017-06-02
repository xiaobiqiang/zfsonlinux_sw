#include <stdarg.h>
#include <synch.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <malloc.h>
#include <errno.h>
#include <unistd.h>
#include <libsysenv.h>


#define	ENV_NAMEVAL_LEN			 1024
#define	MAX_VALUE_BUFLEN		 	 600
#define	MAX_VALUES_PATHLEN		 64
#define 	ENV_STORE_LEN				 256

static char env_path[ENV_STORE_LEN] = {"\0"};			/* path of store path */

struct env_entry {
    struct env_entry *next;
    char tmp;
    char nameval[ENV_NAMEVAL_LEN];
};

static struct {
	struct env_entry *head;
} getenv_info;

/* every time when we save env, we need to free the list */
int df_savefree()
{
	struct env_entry *ee = NULL, *eetmp = NULL;
	
	ee =  getenv_info.head; 
	while(ee) {
		eetmp = ee;
		ee = ee->next;
		free(eetmp);
	}

	getenv_info.head = NULL;

	return 0;
}

int 
df_get_envs(sysenv_t **envs,int tol_envs)
{
        int i = 0;
	sysenv_t *env;
	struct env_entry *ee;
	ee = getenv_info.head;

	env = *envs = (sysenv_t *)malloc(sizeof (sysenv_t)*tol_envs);
	memset(*envs, 0, sizeof (sysenv_t)*tol_envs);
	for(i = 0; i < tol_envs;i++)
		{
		df_getone_sysenv(env,ee);
		env++;
		ee = ee->next;
	}
	return 0;
}

int
df_getone_sysenv(sysenv_t *env,struct env_entry *eee)
{
	int ii= 0;
	char *name_buf;
	char *nv_buf;

	nv_buf = eee->nameval;
	while(*nv_buf != '=')
		{
		nv_buf++;
		ii ++;
	}
	env->name = (char*)malloc(sizeof(eee->nameval));
	strlcpy (env->name,eee->nameval,(ii+1));	
	env->value = (char *)(nv_buf+1);
	
	return 0;
}
int
df_listenv()
{
	int ret=0;
	struct env_entry *ee;
	ee = getenv_info.head;
	for (; ee; ee = ee->next){
		ret ++;
	}
	return ret;
}
char *
df_getsysenv(
	const char *name)
{
	struct env_entry *ee;
	ee = getenv_info.head;
	for (; ee; ee = ee->next) {
		const char *p = name;
		char *q = ee->nameval;

		while (*p == *q && *q != '=')
			p++, q++;
		if (*p == 0 && *q == '=') {
			return (char *)(q+1);
		}
		if (*q != '=' && *p < *q)
			break;
	}
	return (0);
}

static void
sysenv_doit(
	const char *name,
	const char *value,
	int   tmp)
{
	struct env_entry **eep = &getenv_info.head;
	struct env_entry *ee;
	int			found = 0;
	int			nl = strlen(name);
	int			vl = strlen(value);

	for (; (ee = *eep); eep = &ee->next) {
		const char *p = name;
		char *q = ee->nameval;
		
		while (*p == *q && *q != '=')
			p++, q++;
		if (*p == 0 && *q == '=') {
			found = 1;
			break;
		}
		if (*q != '=' && *p < *q)
			break;
	}
	if (found) {
		*eep = ee->next;
		ee = (struct env_entry *)realloc(ee, nl+vl+sizeof (*ee));
	} else {
		ee = (struct env_entry *)malloc(nl+vl+sizeof (*ee));
	}

	if (ee == NULL) {
		syslog(LOG_ERR, "setenv: unable to alloc");
	}

	ee->next = *eep;
	strcpy(ee->nameval, name);
	ee->nameval[nl] = '=';
	strcpy(ee->nameval+nl+1, value);
	ee->tmp = tmp;
	*eep = ee;
}

int
df_loadsysenv(char *path)
{
	char *nameval;
	char *p, *p_end;
	int buflen;	
	int	c;
	int ret;
	FILE *fd = NULL;
	char file_path[ENV_STORE_LEN] = {"\0"};	


	if(path == NULL) {		/* default file path */
		strcpy(file_path, SYSENV_FILE);
	} else {
		strcpy(file_path, path);
	}
	
	if ((fd = fopen(file_path, "r")) == 0) {
		syslog(LOG_ERR, "loadenv: unable to open %s, errno= %d",file_path, errno);
		return (-1);
	}

	/* setting global variable */
	strcpy(env_path, file_path);

	nameval = (char *)malloc(ENV_NAMEVAL_LEN);
	if (nameval == NULL) {
		syslog(LOG_ERR, "loadenv: unable to malloc");
		fclose(fd);
		return (-1);
	}

	buflen = ENV_NAMEVAL_LEN;
	p = nameval;
	p_end = nameval + buflen;
	while ((c = getc(fd)) != EOF) {
		if (c == '\r')
			continue;
		if (c != '\n') {
			/* move into buffer */
			*p++ = c;

			/* is buffer full? */
			if (p == p_end) {
				/* yes, make it bigger */
				p = realloc(nameval, buflen+ENV_NAMEVAL_LEN);
				if (p != NULL) {
					nameval = p;
					p = nameval + buflen;
					buflen += ENV_NAMEVAL_LEN;
					p_end = nameval + buflen;
				} else {
					do
					{
						c = getc(fd);
					} while (c != '\n' && c != EOF);

					p = nameval;
					continue;
				}
			}
			continue;
		}
		*p = '\0';
		if (nameval[0] != '\0' &&
			nameval[0] != '=') {
			p = strchr(nameval, '=');
			if (p == NULL)
				p = ""; /* no =, set to empty string */
			else
				*p++ = '\0';
			sysenv_doit(nameval, p, 0);
		}
		p = nameval;
	}
	free(nameval);
	fclose(fd);
	return (0);
}

