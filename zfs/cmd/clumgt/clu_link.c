#include <string.h>
#include <stdio.h>
#include <nanomsg/nn.h>
#include <nanomsg/reqrep.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <pthread.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "clumgt_impl.h"

typedef enum status_cmd_type {
	CLU_NAME_CMD = 0,
	CLU_IP_CMD,
	CLU_VER_CMD,
	CLU_UPTIME_CMD,
	CLU_HOSTID_CMD,
	//CLU_STAT_CMD,
	CLU_SYSTIME_CMD,
	CLU_MEM_CMD,
	CLU_GUI_VER_CMD
}status_cmd_type_t;

typedef struct status_cmd {
	status_cmd_type_t type;
	char cmd_string[BUF_MAX];
}status_cmd_t;

static status_cmd_t command_table[] = {
	{CLU_NAME_CMD, "zfs clustersan list-host | head -n 2 | grep hostname | cut -d: -f2 | sed 's/^ *//'"},
	{CLU_IP_CMD, "head -n 1 /etc/hostname.igb0"},
	{CLU_VER_CMD, "echo zfsonlinux_v0.2"},
	{CLU_UPTIME_CMD, "uptime"},
	//{CLU_STAT_CMD, "clusterinfo|awk '{print $3 }'|sed -n '$p'"},
	{CLU_HOSTID_CMD, "hostid"},
	{CLU_SYSTIME_CMD, "date '+%Y-%m-%d %H:%M'"},
	{CLU_MEM_CMD, " echo $( expr $(head /proc/meminfo | grep MemTotal | grep -o [0-9]* ) / 1024 ) Megabytes"},
	{CLU_GUI_VER_CMD, "head -n 1 /gui/lib/release"}
};

#define	NCOMMAND	(sizeof (command_table) / sizeof (command_table[0]))

#define CLU_FC_INFO_CMD "ls /sys/class/fc_host | wc -l"
#define FC_INFO_HEAD	"HBA Port WWN"
#define FC_INFO_MODE	"Port Mode"
#define FC_INFO_ID		"Port ID"
#define FC_INFO_DRIVER	"Driver Name"
#define FC_INFO_VER		"Driver Version"
#define FC_INFO_STATE	"State"
#define FC_INFO_SPEED	"Supported Speeds"
#define FC_INFO_CURRENT	"Current Speed"
#define FC_INFO_NODE	"Node WWN"

typedef enum dir_type {
	VAR = 0,
	ROOT,
	ETC,
	GUI
}dir_type_t;

typedef struct dir {
	dir_type_t type;
	char dir[BUF_SHORT];
}dir_t;

static dir_t dir_table[] = {
	{VAR, "/var"},
	{ROOT, "/root"},
	{ETC, "/etc"},
	{GUI, "/gui"}
};

#define	NDIR	(sizeof (dir_table) / sizeof (dir_table[0]))

static char*
rfind_comma(char* str, int len)
{
	int i;
	for(i=len; i>=0; i--){
		if(str[i] == ',')
			return (str+i);
	}
	return NULL;
}
static char*
rfind_colon(char* str, int len)
{
	int i;
	for(i=len; i>=0; i--){
		if(str[i] == ':')
			return (str+i);
	}
	return NULL;
}
static void
clumgt_uptime_get(char *uptime)
{
	char buf[BUF_MAX] = {0};
	char *start_p, *end_p;

	memcpy(buf, uptime, strlen(uptime));
	start_p = strstr(buf, "up");
	start_p += 3;
	end_p = strstr(buf, "user");
	end_p = rfind_comma(start_p, end_p-start_p);
	memset(uptime, 0, BUF_MAX);
	memcpy(uptime, start_p, end_p-start_p);
}
static void
clumgt_ip_get(char *url)
{
	char buf[BUF_MAX] = {0};
	char *start_p, *end_p;

	memcpy(buf, url, strlen(url));
	start_p = strstr(buf, "//");
	start_p += 2;
	end_p = buf + strlen(buf);
	end_p = rfind_colon(start_p, end_p-start_p);
	memset(url, 0, BUF_MAX);
	memcpy(url, start_p, end_p-start_p);
}
static void
clumgt_status_get(clu_status_t *clu_status)
{
	int i;
	FILE * fp;
	char *tmp = (char*)clu_status;

	for (i=0; i<NCOMMAND; i++){
		if(command_table[i].type == CLU_IP_CMD){

			if (clumgt_get_hosturl(tmp) < 0) {
				syslog(LOG_ERR, "get hostip fail\n");
			}
			clumgt_ip_get(tmp);
			tmp += BUF_MAX;
			continue;
		}
		fp = popen(command_table[i].cmd_string, "r");
		if (fp) {
			if(fgets(tmp, BUF_MAX, fp) == NULL) {
		 		syslog(LOG_ERR, "get %d fail\n", command_table[i].type);
				if (command_table[i].type == CLU_GUI_VER_CMD){
					memset(tmp, 0, BUF_MAX);
					snprintf(tmp, 6, "%s", "1.0.0");
				}
			} else {
			 	if (tmp[strlen(tmp)-1] == '\n')
					tmp[strlen(tmp)-1] = '\0';
				if (command_table[i].type == CLU_UPTIME_CMD){
					clumgt_uptime_get(tmp);
				}
			}
			pclose(fp);
		} else {
			syslog(LOG_ERR, "exec cmd fail\n");
		}
		tmp += BUF_MAX;
	}
}

static void
clumgt_hostname_get(char *hostname)
{
	FILE * fp;
	char *tmp = (char*)hostname;

	fp = popen("cat /etc/cluster_hostname", "r");
	if (fp) {
		if(fgets(tmp, BUF_MAX, fp) == NULL) {
		 	syslog(LOG_ERR, "get hostname fail\n");
		}
		if (tmp[strlen(tmp)-1] == '\n')
			tmp[strlen(tmp)-1] = '\0';
			pclose(fp);
	} else {
			syslog(LOG_ERR, "exec cmd fail\n");
	}
}
static int
clumgt_get_fc_num(char *fc_info_p)
{
	FILE * fp;
	int i=0;
	char tmp[10] = {0};

	fp = popen(CLU_FC_INFO_CMD, "r");
	if (fp) {
		if (fgets(tmp, BUF_MAX, fp) != NULL){
			i = atoi(tmp);
		}
	} else {
		syslog(LOG_ERR, "exec cmd fail\n");
		pclose(fp);
		return 0;
	}
	pclose(fp);
	
	return (i);
}
static void
clumgt_fc_status_get(char *fc_info_p, clu_fc_stat_t *clu_fc_stat)
{
	FILE * fp;
	char path[100];
	char *tmp_p = fc_info_p;
	char *next_p;
	int len;
	
	/*wwn*/
	memset(path, 0, 100);
	sprintf(path, "cat %s/%s",tmp_p, "port_name");
	fp = popen(path, "r");
	if (fp) {
		fgets(clu_fc_stat->wwn, BUF_SHORT, fp);
		*(clu_fc_stat->wwn + strlen(clu_fc_stat->wwn) -1) = 0;
	} else {
		memset(clu_fc_stat->wwn, 0, BUF_SHORT);
	}
	pclose(fp);
	
	/*mode*/
	memset(path, 0, 100);
	sprintf(path, "cat %s/%s",tmp_p, "port_type");
	fp = popen(path, "r");
	if (fp) {
		fgets(clu_fc_stat->mode, BUF_SHORT, fp);
		*(clu_fc_stat->mode + strlen(clu_fc_stat->mode) -1) = 0;
	} else {
		memset(clu_fc_stat->mode, 0, BUF_SHORT);
	}
	pclose(fp);
	
	/*driver*/
	/*tmp_p = strstr(tmp_p, FC_INFO_DRIVER);
	tmp_p += strlen(FC_INFO_DRIVER) + 2;
	next_p = strstr(tmp_p, FC_INFO_VER);
	len = next_p - tmp_p -1;
	snprintf(clu_fc_stat->driver, len, "%s", tmp_p);*/
	
	/*state*/
	memset(path, 0, 100);
	sprintf(path, "cat %s/%s",tmp_p, "port_state");
	fp = popen(path, "r");
	if (fp) {
		fgets(clu_fc_stat->stat, BUF_SHORT, fp);
		*(clu_fc_stat->stat + strlen(clu_fc_stat->stat) -1) = 0;
	} else {
		memset(clu_fc_stat->stat, 0, BUF_SHORT);
	}
	pclose(fp);
	
	/*speed*/
	memset(path, 0, 100);
	sprintf(path, "cat %s/%s",tmp_p, "supported_speeds");
	fp = popen(path, "r");
	if (fp) {
		fgets(clu_fc_stat->speed, BUF_SHORT, fp);
		*(clu_fc_stat->speed + strlen(clu_fc_stat->speed) -1) = 0;
	} else {
		memset(clu_fc_stat->speed, 0, BUF_SHORT);
	}
	pclose(fp);
	
	/*current speed*/
	memset(path, 0, 100);
	sprintf(path, "cat %s/%s",tmp_p, "speed");
	fp = popen(path, "r");
	if (fp) {
		fgets(clu_fc_stat->current, BUF_SHORT, fp);
		*(clu_fc_stat->current + strlen(clu_fc_stat->current) -1) = 0;
	} else {
		memset(clu_fc_stat->current, 0, BUF_SHORT);
	}
	pclose(fp);
}

static int
clumgt_handle_status_req(clumgt_response_t **respp)
{
	clu_status_t *clu_status_p = NULL;
	clumgt_response_t *resp = NULL;
	uint32_t resp_len;

	resp_len = sizeof(clumgt_response_t) + sizeof (clu_status_t);
	resp = nn_allocmsg(resp_len, 0);
	memset(resp, 0, resp_len);
	resp->resp_len = resp_len;
	clu_status_p = (clu_status_t *)(resp->resp);
	clumgt_status_get(clu_status_p);
	*respp = resp;
	return 0;
}
static int
clumgt_handle_fcinfo_req(clumgt_response_t **respp)
{
	clu_fc_status_t *clu_fc_status_p = NULL;
	clu_fc_stat_t *clu_fc_stat_p = NULL;
	clumgt_response_t *resp = NULL;
	int fc_num = 0;
	uint32_t resp_len;
	char fc_info_p[4096] = {0};
	char *tmp_p = fc_info_p;
	char path[100]={0};
	FILE *fp;

	fc_num = clumgt_get_fc_num(fc_info_p);
	resp_len = sizeof(clumgt_response_t) + sizeof (clu_fc_status_t) + sizeof (clu_fc_stat_t)* fc_num;
	resp = nn_allocmsg(resp_len, 0);
	memset(resp, 0, resp_len);
	resp->resp_len = resp_len;
	clu_fc_status_p = (clu_fc_status_t *)(resp->resp);
	clumgt_hostname_get(clu_fc_status_p->name);
	clu_fc_status_p->fc_num = (uint32_t)fc_num;
	clu_fc_stat_p = (clu_fc_stat_t *)(clu_fc_status_p->fc_stat);

	fp = popen("ls /sys/class/fc_host/ | cut -d' ' -f 1", "r");
	while(fgets(path, 100, fp)) {
		sprintf(fc_info_p, "/sys/class/fc_host/%s", path);
		*(fc_info_p + strlen(fc_info_p) - 1) = 0;
		clumgt_fc_status_get(fc_info_p, clu_fc_stat_p);
		clu_fc_stat_p++;
	}
	pclose(fp);
	
	*respp = resp;
	return 0;
}
static void
clumgt_df_status_get(char *fs, clu_df_stat_t *clu_df_stat_p)
{
	FILE * fp;
	char buf[BUF_MAX] = {0};
	char *ptr = NULL;
	char *stat_p = (char *)clu_df_stat_p;

	sprintf(buf, "df -h %s|sed -n '2p'|awk '{print $6\",\"$4\",\"$5}'", fs);
	fp = popen(buf, "r");
	if (fp) {
		memset(buf, 0, BUF_MAX);
		if(fgets(buf, BUF_MAX, fp) != NULL){
			if (buf[strlen(buf)-1] == '\n')
			buf[strlen(buf)-1] = '\0';
			ptr = strtok(buf, ",");
			while(ptr != NULL){
				strncpy(stat_p, ptr, strlen(ptr));
				ptr = strtok(NULL, ",");
				stat_p += BUF_MAX;
			}
		}
		pclose(fp);
	} else {
		syslog(LOG_ERR, "exec cmd fail\n");
	}
}
static void
clumgt_df_max_get(char *fs, clu_df_stat_t *clu_df_stat_p)
{
	FILE * fp;
	char buf[BUF_MAX] = {0};
	char *tmp = clu_df_stat_p->max;

	sprintf(buf, "du -s %s/* |sort -nr|sed -n '1p'|awk '{print $2 }'", fs);
	fp = popen(buf, "r");
	if (fp) {
		if(fgets(tmp, BUF_MAX, fp) != NULL){
		if (tmp[strlen(tmp)-1] == '\n')
			tmp[strlen(tmp)-1] = '\0';
		}
		pclose(fp);
	} else {
		syslog(LOG_ERR, "exec cmd fail\n");
	}
}
static int
clumgt_handle_df_req(clumgt_response_t **respp)
{
	clu_df_status_t *clu_df_status_p = NULL;
	clu_df_stat_t *clu_df_stat_p = NULL;
	clumgt_response_t *resp = NULL;
	int i = 0;
	uint32_t resp_len;

	resp_len = sizeof(clumgt_response_t) + sizeof (clu_df_status_t) + sizeof (clu_df_stat_t)* NDIR;
	resp = nn_allocmsg(resp_len, 0);
	memset(resp, 0, resp_len);
	resp->resp_len = resp_len;
	clu_df_status_p = (clu_df_status_t *)(resp->resp);
	clumgt_hostname_get(clu_df_status_p->name);
	clu_df_status_p->df_num = NDIR;
	clu_df_stat_p = (clu_df_stat_t *)(clu_df_status_p->df_stat);
	for (i=0; i<NDIR; i++){
		clumgt_df_status_get(dir_table[i].dir, &clu_df_stat_p[dir_table[i].type]);
		clumgt_df_max_get(dir_table[i].dir, &clu_df_stat_p[dir_table[i].type]);
	}

	*respp = resp;
	return 0;
}

static int
clumgt_handle_common_req(char *cmd, clumgt_response_t **presp, uint32_t req_type)
{
	clumgt_response_t *resp;

	FILE *pp;
	char tmp_buf[512];
	char *out_buf;
	char *switch_buf;
	int out_buf_offset = 0;
	int out_buf_size = 2048; 
	int ret;
	char cmd_buf[CMDNUMBER];
	char *pxml_str = NULL;

	memset(cmd_buf, 0, sizeof(cmd_buf));
	strncpy(cmd_buf, cmd, sizeof(cmd_buf));
	strcat(cmd_buf, " 2>&1");
	
	if ((pp = popen(cmd_buf, "r")) == NULL) {
		syslog(LOG_ERR, "exec cmd fail\n");
		return -1;
	}

	out_buf = malloc(out_buf_size);
	memset(out_buf, 0, out_buf_size);
	
	memset(tmp_buf, 0, sizeof(tmp_buf));
	while (fgets(tmp_buf, sizeof(tmp_buf), pp) != NULL) {
		if (strlen(tmp_buf) + out_buf_offset >= out_buf_size) {
			switch_buf = out_buf;
			
			out_buf = malloc(out_buf_size*2);
			out_buf_size = out_buf_size*2;
			
			strcpy(out_buf, switch_buf);
			
			free(switch_buf);
			switch_buf = NULL;
		}
		
		strcpy(out_buf + out_buf_offset, tmp_buf);
		out_buf_offset += strlen(tmp_buf);
	}

	ret = WEXITSTATUS(pclose(pp));
	syslog(LOG_INFO, "Exit code: %i\n", ret);

	if (req_type == REQ_ZPOOLSTATUS_X) {
		pxml_str = strstr(out_buf, "<?xml version=\"1.0\"?>");
		if (NULL != pxml_str) {
			out_buf_offset -= (pxml_str - out_buf);
		}
	}
	
	if (strncmp(out_buf, "no pools available",	
		strlen("no pools available")) == 0 || 
		strncmp(out_buf, "no datasets available", 
		strlen("no datasets available")) == 0) { 
		ret = -1; 
	}
	
	resp = nn_allocmsg(sizeof(clumgt_response_t) + out_buf_offset+1, 0);
	resp->resp_len = sizeof(clumgt_response_t) + out_buf_offset+1;
	resp->ret_val = ret;
	memset(resp->resp, 0, out_buf_offset+1);
	if (pxml_str != NULL)
		strcpy(resp->resp, pxml_str);
	else
		strcpy(resp->resp, out_buf);
	gethostname(resp->hostname, sizeof(resp->hostname));

	free(out_buf);
	
	*presp = resp;
	return 0;
}

int
clumgt_parse_revcdata(void *request, clumgt_response_t **response)
{
	clumgt_request_t *req;
	clumgt_response_t *resp = NULL;

	req = (clumgt_request_t *)request;

	if (strncmp("ABCXYZ", (char *)req, 6) == 0) {
		return (-1);
	}

	syslog(LOG_DEBUG, "type = 0x%x, len = %x, timeout = %d, req = %s\n",
		req->req_type, req->req_len, req->req_timeout, (char *)req->req);
	
	switch(req->req_type){
	case SHELL_STATUS:
		(void)clumgt_handle_status_req(&resp);
		break;
	case SHELL_FCINFO:
		(void)clumgt_handle_fcinfo_req(&resp);
		break;
	case SHELL_DF:
		(void)clumgt_handle_df_req(&resp);
		break;
	case SYNC_REQ:
		(void)sync_receive_msg_form_agent((char*)req->req, &resp);
		break;
	case SYNC_MSG:
		(void)sync_deal_msg_from_master_node((char*)req->req, &resp);
		break;
	case REQ_GETMASTER:
		(void)sync_probe_mster_node((char*)req->req, &resp);
		break;
	case REQ_CHECK_SYNC_LOCATE:
		(void)sync_send_current_locate_to_master(&resp);
		break;
	case REQ_FULL_SCALE_SYNC_REQ:
		(void)sync_agent_fullscale_process((char*)req->req, &resp);
		break;
	default:
		(void)clumgt_handle_common_req((char*)req->req, &resp, req->req_type);
		break;
	}

	*response = resp;
	return (0);
}



