#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "clumgt_impl.h"
#include "clumgt.h"

#include <nanomsg/nn.h>
#include <nanomsg/reqrep.h>

#include <readline/readline.h>
#include <readline/history.h>

#define DEBUG 0

#define BUFSIZE 1024

#define CLU_CMD_LIST_CONF		"/etc/clumgt_cmdlist.config"
#define CLU_STAT_PATH			"/tmp/clumgt_stat.xml"
#define CLU_FCINFO_PATH			"/tmp/clumgt_fcinfo.xml"
#define CLU_DF_PATH				"/tmp/clumgt_df.xml"
#define	POOL_XML_PATH 			"/tmp/pool.xml"

xmlDocPtr g_doc;
xmlNodePtr g_root_node;

static int clu_cmd_read_char(char *str);
static int clu_cmd_parse_args(char *arg, char **argv, int number);
static boolean_t isquit(char *args);
static int clu_cmd_handle_arg(int argc, char *argv[]);
static int clu_cmd_shell_cd(char *args[]);
static int clu_cmd_shell_fork(char *args[]);
static int clu_cmd_get_cmdnum(char *cmd);
static int clu_cmd_get_reqtype(char *cmd);
static int clu_cmd_mutifork(char *args[]);
static int clu_cmd_process(char *args[]);
static void signal_hanlde(int signo);
static boolean_t clu_cmd_is_allowed(char *cmd);
static int clu_get_custom_cmd(char **clu_allowedcmd);
static int clu_resp_xml_process(const char *xml_str, int str_len, int *is_first);
static int clumgt_deal_zpool_stauts_x_out(clumgt_request_t *req, clumgt_response_t **resp, int node_num);
static int clumgt_deal_common_out(clumgt_request_t *req, clumgt_response_t **resp, int node_num);
static int clumgt_deal_stmfmgt_out(clumgt_request_t *req, clumgt_response_t **resp, int node_num);
static int clumgt_deal_fmadm_genxml_out(clumgt_request_t *req, clumgt_response_t **resp, int node_num);
static int clu_cmd_init_info(void);
static boolean_t clu_cmd_is_hostname(char *name);
static void create_poolxml_file(void);
static char *stripwhite (char *string);
static boolean_t clu_cmd_is_localcmd(char **argv);
static int clu_get_master(char *master);

#define ALLOWED_CMD_MAX		1024
static char *clu_allowed_cmd[ALLOWED_CMD_MAX] = 
{
	"pwd",
	"ls",
	"status",
	"fcinfo",
	"df",
	"show",
	"stmfadm",
	"cd",
	"disk",
	"cat",
	"fmadm",
	"zfs",
	"zpool",
	"chmod",
	"useradd",
	"userdel",
	"echo",
	"auto_passwd",
	"pwconv",
	"/gui/smbpasswd",
	"poweroff",
	"reboot",
	"fmadm genxml;cat /tmp/topo.xml",
	NULL
};

static clumgt_host_t host[MAXWORKERS];
static int hostnum = 0;
static const char * const cmdprompt = "Clumgt-root#";

static int
clu_cmd_get_allowed_cnt(char **clu_allowed_cmd)
{
	int len = 0;

	while(clu_allowed_cmd[len]){
		len++;
	}
	return (len);
}
static char*
clu_cmd_generator(const char *text_p, int state)
{
	static int list_idx = 0, text_len = 0;
	char *name_p = NULL;

	if(!state){
		list_idx = 0;
		text_len = strlen(text_p);
	}

	/*match part*/
	while((name_p = clu_allowed_cmd[list_idx])){
		list_idx++;

		if(!strncmp (name_p, text_p, text_len))
			return (strdup(name_p));
	}

	return (NULL);
}

static char**
clu_cmd_completion(const char *text_p, int start, int end)
{
	char **matches_p = NULL;
	if(0 == start)
		matches_p = rl_completion_matches(text_p, clu_cmd_generator);

	return (matches_p);
}

static void
clu_cmd_init_readline(void)
{
	rl_attempted_completion_function = clu_cmd_completion;
}

int
clu_cmd_handle(int argc, char *argv[])
{
	char *arg;
	struct sigaction act;
	int argc_local;
	char **argv_local;
	char *argv_buf[CMDNUMBER];
	int ret = 0;
	
	act.sa_handler = signal_hanlde;
	sigaddset(&act.sa_mask, SIGINT);
	act.sa_flags = SA_ONSTACK;

	/*Define a new environment variable to tell excuted cmds that we enter from clumgt.*/
	putenv("CLUMGT=1");

	if (clu_cmd_init_info() != 0)
		return (-1);

	if (argc > 1){ 
	/*excute cmd.*/
		argc_local = --argc;
		argv_local = ++argv;

		if(clu_cmd_is_allowed(argv_local[0]) != B_TRUE) {
			return (-1);
		}
		ret = clu_cmd_handle_arg(argc_local, argv_local);
	}else{
	/*start a liked shell.*/
		sigaction(SIGINT, &act, 0);
		clu_cmd_init_readline();
		
		while((arg = readline(cmdprompt)) != NULL){
			rl_bind_key('\t',rl_complete);
			arg = stripwhite(arg);
			if(strcmp(arg, ""))
				add_history(arg);

			if(isquit(arg) == B_TRUE){
				free(arg);
				break;
			}
			argc_local = clu_cmd_parse_args(arg, argv_buf, CMDNUMBER);
			if (argc_local>0) {
				/*just exec*/
				if (clu_cmd_is_allowed(argv_buf[0]) == B_TRUE) 
					clu_cmd_handle_arg(argc_local, argv_buf);
			}
			free(arg);
		}
	}
	return (ret);
}

/*
* parse args
* note that: args[n] and arg shared memory!
*/
static int
clu_cmd_parse_args(char *arg, char **argv, int number)
{
	char *q;
	int ch;
	int count;

	q = arg;

	
	count = 0;
	while(*q != '\0'){
		/* skip space */
		while((ch = clu_cmd_read_char(q)) == ' '){
			q++;
		}
		
		argv[count++] = q++;
		if(count>=number)
			break;

		ch = clu_cmd_read_char(q);
		/* find first space after word */
		while(ch != ' ' && ch != '\0'){
			q++;
			ch = clu_cmd_read_char(q);
		}

		if(ch != '\0'){	
			*q++ = '\0';
			ch = clu_cmd_read_char(q);
		}
	}
	argv[count] = NULL;
	return (count);
}

/*
 * filter string
 */
static int
clu_cmd_read_char(char *str)
{
	char filter[] = " \t\n";
	char *p;
	/* flag 1 return ' ', 0 return *str */
	int flag;
	
	flag = 0;
	p = filter;
	while(*p != '\0'){
		if(*str == *p){
			flag = 1;
			break;
		}
		p++;
	}
	
	if(flag == 1){
		return (' ');
	}else{
		return (*str);
	}
}

static boolean_t
isquit(char *arg)
{
	if(strcmp(arg, "quit") == 0||strcmp(arg, "exit") == 0){
		return (B_TRUE);
	}else{
		return (B_FALSE);
	}
}
static void 
create_xml_file(xmlDocPtr *clu_doc, xmlNodePtr *clu_root_node)
{
	
	xmlDocPtr doc = xmlNewDoc((xmlChar *)"1.0");
	xmlNodePtr root_node = xmlNewNode(NULL, (xmlChar *)"Clumgt");

	xmlDocSetRootElement(doc, root_node);
	*clu_doc = doc;
	*clu_root_node = root_node;
}

static void
close_xml_file(xmlDocPtr *clu_doc,const char *filepath)
{
	xmlChar *xmlbuff;
	int buffersize;
	xmlDocDumpFormatMemory(*clu_doc, &xmlbuff, &buffersize, 1);

	xmlSaveFormatFileEnc(filepath, *clu_doc, "UTF-8", 1);
	xmlFree(xmlbuff);
	xmlFreeDoc(*clu_doc);
}
static int
clu_cmd_handle_status_req(boolean_t need_xml)
{
	int i;
	int host_num, ret = 0;
	clumgt_response_t **resp= NULL;
	clumgt_request_t *reqp;
	clu_status_t *clu_stat_p = NULL;
	xmlNodePtr node, name_node, sbb_node, child_node;
	xmlNodePtr stat_root = NULL;
	xmlDocPtr stat_doc = NULL;
	char cmd[10] = "status";

	reqp = nn_allocmsg(sizeof(clumgt_request_t) + strlen(cmd), 0);
	if (NULL == reqp) {
		clumgt_errprint("nn_allocmsg failed.\n");
		return (-1);
	}
	reqp->req_type = SHELL_STATUS;
	reqp->req_timeout = REP_STATUS_TIMEOUT;
	reqp->req_len = sizeof(clumgt_request_t) + strlen(cmd);
	strcpy(reqp->req, cmd);

	if((ret = clumgt_send_request(reqp, (void *)&resp, NULL, &host_num)) != 0){
		nn_freemsg(reqp);
		if(resp)
			free(resp);
		return ret;
	}

	for(i=0; i<host_num; i++){
		fprintf(stdout, "------------------------\n");
		if(resp[i] != NULL && strncmp(resp[i]->resp, "cmd execute", 11)){
			clu_stat_p = (clu_status_t *)(resp[i]->resp);
			fprintf(stdout, "name:%s\n", clu_stat_p->name);
			fprintf(stdout, "stat:online\n");
			fprintf(stdout, "ip:%s\n", clu_stat_p->ip);
			fprintf(stdout, "version:%s\n", clu_stat_p->version);
			fprintf(stdout, "uptime:%s\n", clu_stat_p->uptime);
			//fprintf(stdout, "stat:%s\n", clu_stat_p->stat);
			fprintf(stdout, "hostid:%s\n", clu_stat_p->hostid);
			fprintf(stdout, "systime:%s\n", clu_stat_p->systime);
			fprintf(stdout, "mem:%s\n", clu_stat_p->mem);
			fprintf(stdout, "gui_ver:%s\n", clu_stat_p->gui_ver);
			if(need_xml != B_TRUE)
				nn_freemsg(resp[i]);
		} else if(resp[i] != NULL && (strncmp(resp[i]->resp, "cmd execute", 11) == 0)){
			fprintf(stdout, "name:%s\n", host[i].hostname);
			fprintf(stdout, "stat:timeout\n");
			if(need_xml != B_TRUE)
				nn_freemsg(resp[i]);
		}else {
			fprintf(stdout, "name:%s\n", host[i].hostname);
			fprintf(stdout, "stat:offline\n");
		}
	}

	if (need_xml == B_TRUE) {
		remove(CLU_STAT_PATH);
		create_xml_file(&stat_doc, &stat_root);
		for(i=0; i<host_num; i++){
			if( i%2 == 0 )
				sbb_node = xmlNewChild( stat_root, NULL, (xmlChar *) "sbb", NULL ) ;

			node = xmlNewChild(sbb_node, NULL, (xmlChar *)"node", NULL);
			name_node = xmlNewChild(node, NULL, (xmlChar *)"name", NULL);
			if(resp[i] != NULL && strncmp(resp[i]->resp, "cmd execute", 11)){
				clu_stat_p = (clu_status_t *)(resp[i]->resp);
				xmlNodeSetContent(name_node, (xmlChar *)clu_stat_p->name);
				child_node = xmlNewChild(node, NULL, (xmlChar *)"node_stat", NULL);
				xmlNodeSetContent(child_node, (xmlChar *)"online");
				child_node = xmlNewChild(node, NULL, (xmlChar *)"ip", NULL);
				xmlNodeSetContent(child_node, (xmlChar *)clu_stat_p->ip);
				child_node = xmlNewChild(node, NULL, (xmlChar *)"version", NULL);
				xmlNodeSetContent(child_node, (xmlChar *)clu_stat_p->version);
				child_node = xmlNewChild(node, NULL, (xmlChar *)"uptime", NULL);
				xmlNodeSetContent(child_node, (xmlChar *)clu_stat_p->uptime);
				//child_node = xmlNewChild(node, NULL, (xmlChar *)"stat", NULL);
				//xmlNodeSetContent(child_node, (xmlChar *)clu_stat_p->stat);
				child_node = xmlNewChild(node, NULL, (xmlChar *)"hostid", NULL);
				xmlNodeSetContent(child_node, (xmlChar *)clu_stat_p->hostid);
				child_node = xmlNewChild(node, NULL, (xmlChar *)"systime", NULL);
				xmlNodeSetContent(child_node, (xmlChar *)clu_stat_p->systime);
				child_node = xmlNewChild(node, NULL, (xmlChar *)"mem", NULL);
				xmlNodeSetContent(child_node, (xmlChar *)clu_stat_p->mem);
				child_node = xmlNewChild(node, NULL, (xmlChar *)"gui_ver", NULL);
				xmlNodeSetContent(child_node, (xmlChar *)clu_stat_p->gui_ver);

				nn_freemsg(resp[i]);
			}else if (resp[i] != NULL && (strncmp(resp[i]->resp, "cmd execute", 11) == 0)){
				xmlNodeSetContent(name_node, (xmlChar *)host[i].hostname);
				child_node = xmlNewChild(node, NULL, (xmlChar *)"node_stat", NULL);
				xmlNodeSetContent(child_node, (xmlChar *)"timeout");
				nn_freemsg(resp[i]);
			}else {
				xmlNodeSetContent(name_node, (xmlChar *)host[i].hostname);
				child_node = xmlNewChild(node, NULL, (xmlChar *)"node_stat", NULL);
				xmlNodeSetContent(child_node, (xmlChar *)"offline");
			}
		
		}
		close_xml_file(&stat_doc, CLU_STAT_PATH);
	}

	nn_freemsg(reqp);
	if(resp)
		free(resp);
	return (ret);
}

static int
clu_cmd_handle_fcinfo_req(boolean_t need_xml)
{
	int i,j;
	int	host_num, ret = 0;
	clumgt_response_t **resp= NULL;
	clumgt_request_t *reqp;
	clu_fc_status_t *clu_fc_status_p = NULL;
	clu_fc_stat_t *clu_fc_stat_p = NULL;
	xmlNodePtr node, name_node, child_node, fc_node;
	xmlNodePtr stat_root = NULL;
	xmlDocPtr stat_doc = NULL;
	char cmd[10] = "fcinfo";


	reqp = nn_allocmsg(sizeof(clumgt_request_t) + strlen(cmd), 0);
	if (NULL == reqp) {
		clumgt_errprint("nn_allocmsg failed.\n");
		return (-1);
	}
	reqp->req_type = SHELL_FCINFO;
	reqp->req_timeout = REP_FCINFO_TIMEOUT;
	reqp->req_len = sizeof(clumgt_request_t) + strlen(cmd);
	strcpy(reqp->req, cmd);

	if((ret = clumgt_send_request(reqp, (void *)&resp, NULL, &host_num)) != 0){
		nn_freemsg(reqp);
		if(resp)
			free(resp);
		return ret;
	}

	for(i=0; i<hostnum; i++){
		if(resp[i] != NULL && strncmp(resp[i]->resp, "cmd execute", 11)){
			fprintf(stdout, "------------------------\n");
			clu_fc_status_p = (clu_fc_status_t *)(resp[i]->resp);
			fprintf(stdout, "node:%s\n", clu_fc_status_p->name);
			clu_fc_stat_p = (clu_fc_stat_t *)(clu_fc_status_p->fc_stat);
			for(j=0; j<clu_fc_status_p->fc_num; j++){

				fprintf(stdout, "fc status:\n");
				fprintf(stdout, "port_wwn:%s\n", clu_fc_stat_p->wwn);
				fprintf(stdout, "port_mode:%s\n", clu_fc_stat_p->mode);
				fprintf(stdout, "driver_name:%s\n", clu_fc_stat_p->driver);
				fprintf(stdout, "state:%s\n", clu_fc_stat_p->stat);
				fprintf(stdout, "speed:%s\n", clu_fc_stat_p->speed);
				fprintf(stdout, "cur_speed:%s\n", clu_fc_stat_p->current);
				clu_fc_stat_p ++;
			}
			if(need_xml != B_TRUE)
				nn_freemsg(resp[i]);
		}else if(resp[i] != NULL && (strncmp(resp[i]->resp, "cmd execute", 11) == 0)){
			fprintf(stdout, "%s\n", resp[i]->resp);		
			nn_freemsg(resp[i]);
		}
	}
	if (need_xml == B_TRUE) {
		remove(CLU_FCINFO_PATH);
		create_xml_file(&stat_doc, &stat_root);
		for(i=0; i<hostnum; i++){
			if(resp[i] != NULL){
				node = xmlNewChild(stat_root, NULL, (xmlChar *)"node", NULL);
				name_node = xmlNewChild(node, NULL, (xmlChar *)"name", NULL);
				clu_fc_status_p = (clu_fc_status_t *)(resp[i]->resp);
				xmlNodeSetContent(name_node, (xmlChar *)clu_fc_status_p->name);
				clu_fc_stat_p = (clu_fc_stat_t *)clu_fc_status_p->fc_stat;
				for(j=0; j<clu_fc_status_p->fc_num; j++){
					fc_node = xmlNewChild(node, NULL, (xmlChar *)"fc_stat", NULL);
					child_node = xmlNewChild(fc_node, NULL, (xmlChar *)"port_wwn", NULL);
					xmlNodeSetContent(child_node, (xmlChar *)clu_fc_stat_p->wwn);
					child_node = xmlNewChild(fc_node, NULL, (xmlChar *)"port_mode", NULL);
					xmlNodeSetContent(child_node, (xmlChar *)clu_fc_stat_p->mode);
					child_node = xmlNewChild(fc_node, NULL, (xmlChar *)"driver_name", NULL);
					xmlNodeSetContent(child_node, (xmlChar *)clu_fc_stat_p->driver);
					child_node = xmlNewChild(fc_node, NULL, (xmlChar *)"state", NULL);
					xmlNodeSetContent(child_node, (xmlChar *)clu_fc_stat_p->stat);
					child_node = xmlNewChild(fc_node, NULL, (xmlChar *)"speed", NULL);
					xmlNodeSetContent(child_node, (xmlChar *)clu_fc_stat_p->speed);
					child_node = xmlNewChild(fc_node, NULL, (xmlChar *)"cur_speed", NULL);
					xmlNodeSetContent(child_node, (xmlChar *)clu_fc_stat_p->current);
					clu_fc_stat_p ++;
				}
				nn_freemsg(resp[i]);
			} 
		
		}
		close_xml_file(&stat_doc, CLU_FCINFO_PATH);
	}
	nn_freemsg(reqp);
	if(resp)
		free(resp);
	return (ret);
}
static int
clu_cmd_handle_df_req(boolean_t need_xml)
{
	int i,j;
	int host_num, ret = 0;
	clumgt_response_t **resp= NULL;
	clumgt_request_t *reqp;
	clu_df_status_t *clu_df_status_p = NULL;
	clu_df_stat_t *clu_df_stat_p = NULL;
	xmlNodePtr node, name_node, child_node, df_node;
	xmlNodePtr stat_root = NULL;
	xmlDocPtr stat_doc = NULL;
	char cmd[10] = "df";
	int just_once = 0;

	reqp = nn_allocmsg(sizeof(clumgt_request_t) + strlen(cmd), 0);
	if (NULL == reqp) {
		clumgt_errprint("nn_allocmsg failed.\n");
		return (-1);
	}
	reqp->req_type = SHELL_DF;
	reqp->req_timeout = REP_STATUS_TIMEOUT;
	reqp->req_len = sizeof(clumgt_request_t) + strlen(cmd);
	strcpy(reqp->req, cmd);

	if((ret = clumgt_send_request(reqp, (void *)&resp, NULL, &host_num)) != 0){
		nn_freemsg(reqp);
		if(resp)
			free(resp);
		return ret;
	}

	for(i=0; i<hostnum; i++){
		if(resp[i] != NULL && strncmp(resp[i]->resp, "cmd execute", 11)){
			if (just_once == 0){
				fprintf(stdout, "node filesystem   avail capacity max\n");
				just_once = 1;
			}
			clu_df_status_p = (clu_df_status_t *)(resp[i]->resp);
			clu_df_stat_p = (clu_df_stat_t *)(clu_df_status_p->df_stat);
			for(j=0; j<clu_df_status_p->df_num; j++){
				fprintf(stdout, "%s  %-10s %6s %6s    %-10s\n", clu_df_status_p->name, clu_df_stat_p->name,
					clu_df_stat_p->avail, clu_df_stat_p->capacity, clu_df_stat_p->max);
				clu_df_stat_p ++;
			}
			if(need_xml != B_TRUE)
				nn_freemsg(resp[i]);
		}else if(resp[i] != NULL && (strncmp(resp[i]->resp, "cmd execute", 11) == 0)){
			fprintf(stdout, "%s\n", resp[i]->resp);		
			nn_freemsg(resp[i]);
		}
	}
	if (need_xml == B_TRUE) {
		remove(CLU_DF_PATH);
		create_xml_file(&stat_doc, &stat_root);
		for(i=0; i<hostnum; i++){
			if(resp[i] != NULL){
				node = xmlNewChild(stat_root, NULL, (xmlChar *)"node", NULL);
				name_node = xmlNewChild(node, NULL, (xmlChar *)"name", NULL);
				clu_df_status_p = (clu_df_status_t *)(resp[i]->resp);
				xmlNodeSetContent(name_node, (xmlChar *)clu_df_status_p->name);
				clu_df_stat_p = (clu_df_stat_t *)clu_df_status_p->df_stat;
				for(j=0; j<clu_df_status_p->df_num; j++){
					df_node = xmlNewChild(node, NULL, (xmlChar *)"df_node", NULL);
					child_node = xmlNewChild(df_node, NULL, (xmlChar *)"Filesystem", NULL);
					xmlNodeSetContent(child_node, (xmlChar *)clu_df_stat_p->name);
					child_node = xmlNewChild(df_node, NULL, (xmlChar *)"avail", NULL);
					xmlNodeSetContent(child_node, (xmlChar *)clu_df_stat_p->avail);
					child_node = xmlNewChild(df_node, NULL, (xmlChar *)"capacity", NULL);
					xmlNodeSetContent(child_node, (xmlChar *)clu_df_stat_p->capacity);
					child_node = xmlNewChild(df_node, NULL, (xmlChar *)"max", NULL);
					xmlNodeSetContent(child_node, (xmlChar *)clu_df_stat_p->max);
					clu_df_stat_p ++;
				}
				nn_freemsg(resp[i]);
			} 
		
		}
		close_xml_file(&stat_doc, CLU_DF_PATH);
	}
	nn_freemsg(reqp);
	if(resp)
		free(resp);
	return (ret);
}

static int
clu_cmd_handle_show_req(int argc, char *argv[])
{
	int i;
	FILE *fp;
	char cmd_buf[1024] = {0};
	char *tmp = cmd_buf;

	for(i=0; (tmp-cmd_buf<1023)&& (i<argc); i++){
		sprintf(tmp, "%s ", argv[i]);
		tmp += strlen(argv[i])+1;
	}

	if ((fp = popen(cmd_buf, "r")) == NULL) {
		syslog(LOG_ERR, "exec cmd_clumgt show fail\n");
		return (EXIT_FAILURE);
	}
	while(fgets(cmd_buf, 1024, fp) != NULL){
		fprintf(stdout, "%s", cmd_buf);
	}
	return (WEXITSTATUS(pclose(fp)));
}
static int
clumgt_deal_common_out(clumgt_request_t *req, clumgt_response_t **resp, int node_num)
{
	int i;
	int failed_cnt = 0;
	int locate = -1;
	int flag = 1;
	
	for (i = 0; i < node_num; i++) {
		if (NULL == resp[i] || 0 != resp[i]->ret_val) {
			failed_cnt++;
			if (NULL != resp[i] &&
				0 != resp[i]->ret_val &&
				strstr(resp[i]->resp, "cannot open") == NULL) {
				locate = i;
			}
		}
	}

	for (i = 0; i < node_num; i++) { 
		if (NULL != resp[i] && resp[i]->ret_val == 0) { 
			fprintf(stdout, "%s", (char *)resp[i]->resp);
		} else if (NULL != resp[i] &&
			resp[i]->ret_val != 0 &&
			failed_cnt == node_num &&
			flag == 1) {
			if (locate != -1) 
				fprintf(stderr, "%s", (char *)resp[locate]->resp);
			else
				fprintf(stderr, "%s", (char *)resp[i]->resp);
			flag = 0;
		}
		if (NULL != resp[i])
			nn_freemsg(resp[i]);
	}
	if (failed_cnt == node_num && flag == 1)
		fprintf(stderr, "No host node normal.\n");

	return ((node_num == failed_cnt)?-1:0);
}

static void
create_poolxml_file(void)
{
	xmlDocPtr doc = xmlNewDoc((xmlChar *)"1.0");
	xmlNodePtr root_node = xmlNewNode(NULL, (xmlChar *)"Clumgt");
	xmlDocSetRootElement(doc, root_node);

	xmlSaveFormatFileEnc(POOL_XML_PATH, doc, "UTF-8", 1);
	xmlFreeDoc(doc);
}

static int
clumgt_deal_zpool_stauts_x_out(clumgt_request_t *req, clumgt_response_t **resp, int node_num)
{
	int i;
	int is_first_xml = B_TRUE;
	int is_success = B_FALSE;

	for (i = 0; i < node_num; i++) {
		if (NULL != resp[i]) {
			if (0 == resp[i]->ret_val) {
				clu_resp_xml_process(resp[i]->resp, strlen(resp[i]->resp), &is_first_xml);
				is_success = B_TRUE;
			}
			nn_freemsg(resp[i]);
		}
	}
	
	if (is_success == B_TRUE) {
		xmlSaveFormatFileEnc(POOL_XML_PATH, g_doc, "UTF-8", 1);
		xmlFreeDoc(g_doc); 
	} else {
		create_poolxml_file();
	}

	return (0);
}


static int
clumgt_deal_stmfmgt_out(clumgt_request_t *req, clumgt_response_t **resp, int node_num)
{
	int i;
	
	for (i = 0; i < node_num; i++) {
		if (NULL != resp[i]) {
			if (0 != strlen(resp[i]->resp)) {
				fprintf(stdout, "node: %s\n", resp[i]->hostname);
			}
			fprintf(stdout, "%s", resp[i]->resp);
			nn_freemsg(resp[i]);
		}
	}

	return (0);
}

static int
clumgt_deal_fmadm_genxml_out(clumgt_request_t *req, clumgt_response_t **resp, int node_num)
{
	int i=0;
	int num;
	char topo_name[HOSTNAMELEN];
	FILE *fd;
	int ret = -1;
	
	for (i = 0; i < node_num; i++) {
		if (NULL != resp[i] && resp[i]->ret_val == 0) {
			memset(topo_name, 0, HOSTNAMELEN);
			snprintf(topo_name, HOSTNAMELEN, "/tmp/%s_topo.xml", resp[i]->hostname);
			
			if ((fd = fopen(topo_name, "w")) == NULL)
				continue;

			num = resp[i]->resp_len - sizeof(clumgt_response_t) - 1;
			if (fwrite(resp[i]->resp, 1, num, fd) < num)
				clumgt_errprint("write error.\n");
			fclose(fd);
			ret = 0;
		}

		if (NULL != resp[i]) {
			nn_freemsg(resp[i]);
		}
	}
	return (ret);
}


/*
 * Receive message and deal something
 */
static int
clu_cmd_handle_arg(int argc, char *argv[])
{
	cmd_type_t cmd_type;
	int ret = 0;

	cmd_type = clu_cmd_get_cmdnum(argv[0]);
	
	switch(cmd_type){
	case SHELL_EMPTY:
		break;
	case SHELL_CD:
		 ret = clu_cmd_shell_cd(argv);
		break;
	case SHELL_FORK:
		ret = clu_cmd_shell_fork(argv);
		break;
	case SHELL_STATUS:
		ret = clu_cmd_handle_status_req(B_TRUE);
		break;
	case SHELL_FCINFO:
		ret = clu_cmd_handle_fcinfo_req(B_TRUE);
		break;
	case SHELL_DF:
		ret = clu_cmd_handle_df_req(B_TRUE);
		break;
	case SHELL_SHOW:
		ret = clu_cmd_handle_show_req(argc, argv);
		break;
	default:
		fprintf(stderr, "%s:%d: getcmd failed\n", __FILE__, __LINE__);
		break;
	}

	return (ret);
}

static int
clu_resp_xml_process(const char *xml_str, int str_len, int *is_first)
{
	xmlDocPtr doc;
	xmlNodePtr cur_node;
	xmlNodePtr copy_node;
	
	doc = xmlParseMemory(xml_str, str_len);
	if (NULL == doc) {
		clumgt_errprint("pares xml string failed.\n");
		return (-1);
	}
	
	cur_node = xmlDocGetRootElement(doc);
	if (NULL == cur_node) {
		clumgt_errprint("get xml root node failed.\n");
		return (-1);
	}

	if (*is_first == B_TRUE) {
		g_doc = doc;
		g_root_node = cur_node;
		*is_first = B_FALSE;
		return (0);
	}

	cur_node = cur_node->xmlChildrenNode;
	
	while (NULL != cur_node) {
		copy_node = xmlCopyNode(cur_node, 1);
		xmlAddChild(g_root_node, cur_node);
		
		cur_node = cur_node->next;
	}

	xmlFreeDoc(doc);
	
	return (0);	
}

static int
clu_cmd_get_reqtype(char *cmd)
{
	char *tmp;
	if(cmd == NULL) return (SHELL_COMMON);

	tmp = cmd;
	
	if (strncmp(tmp, "/usr/sbin/", strlen("/usr/sbin/")) == 0) {
		tmp += strlen("/usr/sbin/");
	}
	if(strncmp(tmp, "fmadm genxml", strlen("fmadm genxml")) == 0)
		return (REQ_FMADMGENXML);
	
	if (strncmp(tmp, "useradd", strlen("useradd")) == 0
		|| strncmp(tmp, "auto_passwd", strlen("auto_passwd")) == 0
		|| strncmp(tmp, "userdel", strlen("userdel")) == 0) 
		return (SYNC_REQ);

	if (strncmp(tmp, "zpool status -x", strlen("zpool status -x")) == 0)
		return (REQ_ZPOOLSTATUS_X);

	if (strncmp(tmp, "stmfadm", strlen("stmfadm")) == 0)
		return (REQ_STMFMGT);
		
	
	return (SHELL_COMMON);
}

static int
clu_cmd_process(char *args[])
{
	clumgt_request_t *req = NULL;	
	clumgt_response_t **resp= NULL;

	char **pargs = NULL;
	char cmd[CMDNUMBER];
	int cmd_offset = 0;
	int ret = 0;
	int node_num;
	boolean_t to_single_node = B_FALSE;
	char master[HOSTNAMELEN];

	pargs = args;
	if(clu_cmd_is_hostname(pargs[0])){
		if(pargs[1]){
			if(clu_cmd_is_hostname(pargs[1])){
				clumgt_errprint("\"%s\" is a hostname, not command. \n", pargs[1]);
				return (-1);
			}
			if(clu_cmd_is_allowed(pargs[1])){
				to_single_node = B_TRUE;
				pargs++;
			}
		}else{
			clumgt_errprint("\"%s\" is a hostname, but no command. \n", pargs[0]);
			return (-1);
		}
	} else {
		if (pargs[0] != NULL && 
			strcmp(pargs[0], "zpool") == 0 &&
			pargs[1] != NULL &&
			(strcmp(pargs[1], "create") == 0 ||
			strcmp(pargs[1], "destroy") == 0 ||
			strcmp(pargs[1], "import") == 0 ||
			strcmp(pargs[1], "export") == 0 ||
			strcmp(pargs[1], "release") == 0)) {
			clumgt_errprint("you must specify a host node.\n");
			return (-1);
		}
	}

	memset(cmd, 0, sizeof(cmd));
	while (NULL != *pargs) {
		strcpy(cmd + cmd_offset, *pargs);
		cmd_offset += strlen(*pargs);
		cmd[cmd_offset++] = ' '; 
		++pargs;
	}

	req = nn_allocmsg(sizeof(clumgt_request_t) + strlen(cmd), 0);
	if (NULL == req) {
		clumgt_errprint("nn_allocmsg failed.\n");
		return (-1);
	}
	req->req_type = clu_cmd_get_reqtype(cmd);
	req->req_timeout = WAIT_RESP_TIMEOUT;
	req->req_len = sizeof(clumgt_request_t) + strlen(cmd);
	strcpy(req->req, cmd);
	clumgt_print(VERBOSE_MID, "cmd:%s\n", cmd);

	if (req->req_type == SYNC_REQ) {
		clu_get_master(master);
		/*send request to master node*/
		if ((ret = clumgt_send_request(req, (void *)&resp, master, &node_num)) != 0) {
			clumgt_errprint("send msg to master node %s failed.\n", master);
		}
	} else if(to_single_node){
		ret = clumgt_send_request(req, (void *)&resp, args[0], &node_num);
	}else{
		ret = clumgt_send_request(req, (void *)&resp, NULL, &node_num);
	}
	if (ret != 0){
		if(resp)
			free(resp);
		nn_freemsg(req);
		return (ret);
	}
	switch (req->req_type) {
		case SHELL_COMMON:
			ret = clumgt_deal_common_out(req, resp, node_num);
			break;
		case REQ_ZPOOLSTATUS_X:
			ret = clumgt_deal_zpool_stauts_x_out(req, resp, node_num);
			break;
		case REQ_STMFMGT:
			ret = clumgt_deal_stmfmgt_out(req, resp, node_num);
			break;
		case REQ_FMADMGENXML:
			ret = clumgt_deal_fmadm_genxml_out(req, resp, node_num);
			break;
		case SYNC_REQ:
			if (resp == NULL || resp[0] == NULL) {
				clumgt_errprint("send msg to master node (%s) failed.\n", master);
			} else {
				free(resp[0]);
				printf("send msg to master node (%s) success.\n", master);
			}
			break;
		default:
			break;
	}
	if(resp)
		free(resp);
	nn_freemsg(req);
	
	return (ret);
}


/*
 * fork and called exec
 */
static int
clu_cmd_shell_fork(char *args[])
{
	pid_t pid[CMDNUMBER];
	int status;
	int fork_num;
	char **p;		/* point args */
	char *q;		/* point *args */

	/* get numbers of child process*/
	fork_num = 1;
	p = args;
	while(*p != NULL){
		q = *p;
		while(*q != '\0'){
			if(*q == '|'){
				fork_num++;
			}
			q++;
		}
		p++;
	}

	/* case: child process number is one */
	if(fork_num < 2){
		if((pid[0] = fork()) < 0){
			/* error */
			perror("fork");
			exit(1);
		}else if(pid[0] == 0){
			/* child process */
			if(clu_cmd_is_localcmd(args)){
				if(execvp(args[0], args) < 0){
					exit(1);
				}
			}else if (clu_cmd_process(args) < 0) {
				exit(1);
			}

			exit(0);
		}
	}

	/* parent process */
	if(fork_num < 2){
		if((waitpid(pid[0], &status, 0) < 0) ||
			WIFEXITED(status) == 0) {
			return (-1);
		}
		return WEXITSTATUS(status);
	}else{
		status = clu_cmd_mutifork(args);
			
	}
	return (status);
}

/*
 * likes shell's cd
 */
static int
clu_cmd_shell_cd(char *args[])
{
	char buf[BUFSIZE + 1];

	memset(buf, 0, BUFSIZE + 1);
	
	if(0 == strcmp(args[1], "~")){
		strcpy(args[1], getenv("HOME"));
	}

	if(args[1][0] != '/' && args[1][0] != '.'){
		if(getcwd(buf, BUFSIZE) == NULL){
			clumgt_errprint("getcwd failed.\n");
			return (-1);
		}

		strncat(buf, "/", BUFSIZE - strlen(buf));
	}

	strncat(buf, args[1], BUFSIZE - strlen(buf));

#if DEBUG
	fprintf(stdout, "%s\n", buf);

#endif
	if(chdir(buf) == -1){
		clumgt_errprint("chdir failed.\n");
	}

	return (0);
}

/*
 * Change cmd to int, according to shell.h
 */
static int
clu_cmd_get_cmdnum(char *cmd)
{
	if(cmd == NULL) return SHELL_EMPTY;
	if(strcmp(cmd, "cd") == 0) return SHELL_CD;
	if(strcmp(cmd, "status") == 0) return SHELL_STATUS;
	if(strcmp(cmd, "fcinfo") == 0) return SHELL_FCINFO;
	if(strcmp(cmd, "df") == 0) return SHELL_DF;
	if(strcmp(cmd, "show") == 0) return SHELL_SHOW;


	return (SHELL_FORK);
}

static int
clu_cmd_mutifork(char *args[])
{
	int pipefd[CMDNUMBER][2];
	pid_t pid[CMDNUMBER];
	int i, j;
	int count;
	int status;
	int ret;
	char **arg_child[CMDNUMBER];
	char **p;
	char ***q;


	/* parse and split args to child arg */
	count = 0;
	p = args;
	q = arg_child;
	while(*p != NULL && p != NULL){
		*q++ = p;
		count++;
		while(*p != NULL && strcmp(*p, "|") != 0){
			p++;
		}
						
		if(*p != NULL){
			*p++ = NULL;
		}	
	}
	*q = NULL;

#if DEBUG			/* check child args */

	fprintf(stdout, "----------------------------------------\n");
	fprintf(stdout, "count = %d\n", count);
	q = arg_child; i = 0;
	while(*q != NULL){
		p = *q++;
		while(*p != NULL){
			fprintf(stdout, "[%d]%s\n", i, *p++);
		}
		i++;
	}
#endif
	
	/* fork count child process */
	for(i = 0; i < count; i++){
		/* init pipe file descriptor */
		if(pipe(pipefd[i]) < 0){ /* FIXME: excess one */
			perror("pipe");
			return -1;
		}
		
		/* fork child i */
		if((pid[i] = fork()) < 0){
			fprintf(stderr, "%s:%d: fork() failed: %s\n", __FILE__,
				__LINE__, strerror(errno));
			return (-1);
		}else if(pid[i] == 0){
			/* child i */
			
			if(i == 0){ /* the first child */
				close(pipefd[i][0]); /* close curr process read */

				if(dup2(pipefd[i][1], STDOUT_FILENO) < 0){
					perror("dup2 failed");
					return (-1);
				}
			}else if(i == count - 1){ /* the last child */
				for(j = 0; j < i - 1; j++){ /* close unuse pipefd */
					close(pipefd[j][1]);
					close(pipefd[j][0]);
				}
				close(pipefd[j][1]); /* close prev process end of write */
				close(pipefd[i][0]); /* close curr process end of read */

				if(dup2(pipefd[j][0], STDIN_FILENO) < 0){
					perror("dup2 failed");
					return (-1);
				}
			}else{
				for(j = 0; j < i - 1; j++){ /* close unuse pipefd */
					close(pipefd[j][1]);
					close(pipefd[j][0]);
				}
				close(pipefd[j][1]); /* close prev process end of write */
				close(pipefd[i][0]); /* close curr process end of read */

				if(dup2(pipefd[j][0], STDIN_FILENO) < 0){
					perror("dup2 failed");
					return (-1);
				}
				if(dup2(pipefd[i][1], STDOUT_FILENO) < 0){
					perror("dup2 failed");
					return (-1);
				}
			}
			if(execvp(arg_child[i][0], arg_child[i]) < 0){
				clumgt_errprint("fork() failed.\n");

				exit(1);
			}
			
			exit(0);
		
			/* child process exit */
		}
	}

	/* parent process */

	for(i = 0; i < count; i++){
		/* close all pipe file descriptor */
		close(pipefd[i][0]);
		close(pipefd[i][1]);	
	}

	for(i = 0; i < count; i++){
		if((waitpid(pid[i], &status, 0) < 0) ||
			WIFEXITED(status) == 0) {
			return (-1);
		}
		if((ret = WEXITSTATUS(status)) != 0)
			return ret;
	}
	return 0;
}

static void
signal_hanlde(int signo)
{
	switch(signo){
		case SIGINT:
		fprintf(stdout,"\n%s", cmdprompt);
			break;

		default:
			break;
	}
}

static boolean_t
clu_cmd_is_hostname(char *name)
{
	int i = 0;

	while(i < hostnum){
		if(0 == strcmp(host[i].hostname, name)){
			return (B_TRUE);
		}
		i++;
	}

	return (B_FALSE);
}
static char*
rfind_slash(char* str, int len)
{
	int i;
	for(i=len; i>=0; i--){
		if(str[i] == '/')
			return (str+i);
	}
	return (NULL);
}
static boolean_t
clu_cmd_is_allowed(char *cmd)
{
	int i = 0;
	char *cmd_p, *tmp_p;
	char cmd_buf[BUFSIZE] = {0};
	
	if(0 == strcmp("", cmd))
		return (B_TRUE);

	if(!strncmp(cmd, "/gui", 4)){
		strcpy(cmd_buf, cmd);
	}else if (cmd[0] == '/') {
		tmp_p = cmd + strlen(cmd);
		cmd_p = rfind_slash(cmd, strlen(cmd));
		cmd_p++;
		strncpy(cmd_buf, cmd_p, tmp_p - cmd_p);
	}

	if (strlen(cmd_buf) != 0) {
		cmd_p = cmd_buf;
	} else {
		cmd_p = cmd;
	}

	while(clu_allowed_cmd[i]){
		if(0 == strcmp(clu_allowed_cmd[i], cmd_p)){
			return (B_TRUE);
		}

		i++;
	}

	clumgt_errprint("\"%s\" is not a clumgt command.\n", cmd_p);
	return (B_FALSE);
}

static int
clu_get_custom_cmd(char **clu_allowed_cmd)
{
	char buf[BUFSIZE];
	int len = 0, ret = 0;
	int eachlen = 0;
	FILE *fd;

	len = clu_cmd_get_allowed_cnt(clu_allowed_cmd);
#if DEBUG
	printf("len:%d\n",len);
#endif
	fd = fopen(CLU_CMD_LIST_CONF, "r");
	if (NULL == fd){
		clumgt_errprint("open clumgt_cmdlist.config failed.\n");
		return (-1);
	}
	/* null for end*/
	while((len<ALLOWED_CMD_MAX-1) && fgets(buf, BUFSIZE, fd)){
		if (buf[0] == '#' || !strcmp(buf, "\n"))
			continue;

		eachlen = strlen(buf);
		clu_allowed_cmd[len] = malloc(eachlen + 1);
		strcpy(clu_allowed_cmd[len], buf);
		if(clu_allowed_cmd[len][eachlen-1] == '\n')
			clu_allowed_cmd[len][eachlen-1] = '\0';
#if DEBUG
		printf("%s\n", clu_allowed_cmd[len]);
#endif
		len++;
	}

	clu_allowed_cmd[len] = NULL;
	if((len == ALLOWED_CMD_MAX-1) && fgets(buf, BUFSIZE, fd)) {
		if((eachlen = strlen(buf)) !=0)
			ret = -1;
	}
	fclose(fd);

	return (ret);
}
static int
clu_cmd_init_hostinfo(void)
{
	int len = 0, num = 0;
	int eachlen;

	len = clu_cmd_get_allowed_cnt(clu_allowed_cmd);
	if (clumgt_get_hostnode(host, &hostnum, NULL) != 0) {
		clumgt_errprint("get host node failed, please check config.\n");
		return (-1);
	}

	while((len<ALLOWED_CMD_MAX-1) && (num<hostnum)) {
		eachlen = strlen(host[num].hostname);
		clu_allowed_cmd[len] = malloc(eachlen + 1);
		strcpy(clu_allowed_cmd[len], host[num].hostname);
		if(clu_allowed_cmd[len][eachlen-1] == '\n')
			clu_allowed_cmd[len][eachlen-1] = '\0';

		len++;
		num++;
	}
	clu_allowed_cmd[len] = NULL;

	if(num != hostnum) {
		return (-1);
	} else {
		return (0);
	}
	
}
/*Get host info of all nodes.*/
static int
clu_cmd_init_info(void)
{
	int ret = 0;

	if ((ret = clu_cmd_init_hostinfo()) != 0)
		return (ret);
	
	ret = clu_get_custom_cmd(clu_allowed_cmd);

	return (ret);
}

static char *
stripwhite(char *string)
{
  register char *s, *t;

  for (s = string; isspace(*s); s++)
    ;
    
  if (*s == 0)
    return (s);

  t = s + strlen (s) - 1;
  while (t > s && isspace (*t))
    t--;
  *++t = '\0';

  return (s);
}

static boolean_t
clu_cmd_is_localcmd(char **argv){
	if((0 == strcmp("disk", argv[0]) && 0 == strcmp("list", argv[1]))
	|| 0 == strcmp("ls", argv[0])
	|| 0 == strcmp("cd", argv[0])
	|| 0 == strcmp("pwd", argv[0])){
		return B_TRUE;
	}
	return B_FALSE;
}

static int 
clu_get_master(char *master)
{
	clumgt_request_t *req = NULL;	
	clumgt_response_t **resp= NULL;
	int node_num;
	char host[HOSTNAMELEN];
	int ret = 0;
	
	req = nn_allocmsg(sizeof(clumgt_request_t), 0);
	if (NULL == req) {
		clumgt_errprint("nn_allocmsg failed.\n");
		return (-1);
	}
	req->req_type = REQ_GETMASTER;
	req->req_timeout = WAIT_RESP_TIMEOUT;
	req->req_len = sizeof(clumgt_request_t);

	memset(host, 0x0, sizeof(host));
	gethostname(host, sizeof(host));
	
	ret = clumgt_send_request(req, (void *)&resp, host, &node_num);
	if (0 != ret) {
		if(resp)
			free(resp);
		nn_freemsg(req);
		return (ret);
	}

	if (NULL != resp[0] && 0 == resp[0]->ret_val)
		strncpy(master, resp[0]->resp, HOSTNAMELEN);

	if(resp)
		free(resp);
	nn_freemsg(req);
	
	return 0;
}

