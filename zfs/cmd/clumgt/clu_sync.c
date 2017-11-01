#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <pthread.h>
#include <time.h>
#include <nanomsg/nn.h>
#include <nanomsg/reqrep.h>



#include "clumgt.h"
#include "clu_sync.h"

static sync_msg_queue_t sync_msg_queue;

static sync_master_info_t sync_master_info;


static uint64_t
sync_generate_guid(void)
{
	//hrtime_t hrt = gethrtime();
	hrtime_t hrt=0;
	struct timespec time = {0, 0};
	clock_gettime(CLOCK_REALTIME, &time);
	hrt = time.tv_sec + time.tv_nsec*1000*1000;

	return ((uint64_t)((1 & 3) |
		((pthread_self() << 10) & 0x00000000000FFC00ull) |
		((hrt << 20) & 0xFFFFFFFFFFF00000ull)));
}

void
sync_initqueue(void)
{
	sync_msg_queue_t *q = &sync_msg_queue;
	
	memset(q, 0, sizeof(sync_msg_queue_t));
	q->queuesize = CLU_SYNC_MSG_QUEUE_LEN;
	q->tail = 0;
	q->head = 0;
	q->msg_num = 0;
	q->cur_sync_locate = 0;
	gethostname(q->hostname, sizeof(q->hostname));
	(void)pthread_mutex_init(&q->sync_lock, NULL);
	(void)pthread_cond_init(&q->sync_cv, NULL); 
}

void
update_sync_queue(void) 
{
	sync_msg_queue_t *q = &sync_msg_queue;

	q->msg_seq = q->cur_sync_locate;
	q->tail = q->msg_seq % q->queuesize;
	q->head  = q->msg_seq % q->queuesize;
}

static int
sync_enqueue(sync_msg_t *msg)
{
	int tail;
	sync_msg_queue_t *q = &sync_msg_queue;
	
	tail = (q->tail + 1) % q->queuesize;
	if (tail == q->head) {
		clumgt_errprint("the msg queue has been filled full.\n");
		return (-1);
	} else {
		if (q->sync_msg[q->tail] != NULL)
			free(q->sync_msg[q->tail]);
		msg->seq_num = q->msg_seq;
		msg->guid = sync_generate_guid();
		q->msg_seq++;
		q->sync_msg[q->tail] = msg;
		q->tail = tail;
		q->msg_num++;
	}
	clumgt_print(VERBOSE_MID, "sync_enqueue key=%d\n", msg->key);
	return (0);
}


static sync_msg_t *
sync_dequeue(void)
{
	sync_msg_t *msg;
	sync_msg_queue_t *q = &sync_msg_queue;

	if (q->tail == q->head) {
		clumgt_errprint("the msg queue is NULL.\n");
		return (NULL);
	} else {
		msg = q->sync_msg[q->head];
		q->head = (q->head+1) % q->queuesize;
		q->msg_num--;
	}
	return (msg);
}

static int
sync_rollbackqueue(int locate, uint64_t guid)
{
	int step;
	sync_msg_queue_t *q = &sync_msg_queue;
	uint64_t lguid;
	int l;

	clumgt_print(VERBOSE_MID, "rollback locate %d, g %llu.\n", locate, guid);

	pthread_mutex_lock(&q->sync_lock);
	l = (locate + q->queuesize - 1) % q->queuesize;
	lguid = (q->sync_msg[l] == NULL) ? -1 : q->sync_msg[l]->guid;
	if (lguid != guid || q->sync_msg[locate] == NULL) {
		/* node need all sync */
		update_sync_queue();
		pthread_mutex_unlock(&q->sync_lock);
		clumgt_print(VERBOSE_MID, "rollback g %llu, g %llu.\n", lguid, guid);

		return (-1);
	} else {
		
		step = q->head - locate;
		q->head = locate;
		step = (step < 0) ? step + q->queuesize : step;
		q->msg_num = q->msg_num + step;
		clumgt_print(VERBOSE_MID, "step: %d.\n", step);
	}
	pthread_mutex_unlock(&q->sync_lock);
	return (0);
}

/*static int
sync_isqueue_empty()
{
	sync_msg_queue_t *q = &sync_msg_queue;
	
	if (q->head == q->tail) {
		return (1);
	} else {
		return (0);
	};
}

static int
sync_isqueue_full()
{
	sync_msg_queue_t *q = &sync_msg_queue;
	
	if ((q->tail + 1) % q->queuesize == q->head) {
		return (1);
	} else {
		return (0);
	}
}*/

static int 
sync_send_fullscale_to_agent(char *hostname)
{
	clumgt_request_t *req = NULL;	
	clumgt_response_t **resp= NULL;
	clu_sync_req_t sreq;
	int node_num;
	sync_msg_queue_t *smq = &sync_msg_queue;
	char *files[] = {"/etc/passwd", "/etc/shadow", "/etc/group"};
	char buf[8192];
	char *p;
	int fd;
	int ret = 0;
	int i, n;
	int l;

	memset(buf, 0x0, sizeof(buf));
	p = buf;
	pthread_mutex_lock(&smq->sync_lock);
	for (i = 0; i < 3; i++) {	
		if ((fd = open(files[i], O_RDONLY)) < 0) {
			syslog(LOG_ERR, "open %s failed\n", files[i]);
			return -1;
		}
		while ((n = read(fd, p, 8192)) > 0) {
			p = p + n;
		}
		close(fd);
		strncpy(p, "[end]", 5);
		p = p + 5;
	}
	l = (smq->cur_sync_locate + smq->queuesize - 1) % smq->queuesize;
	sreq.msg_head.guid = smq->node_guid[l];
	sreq.msg_head.seq_start = smq->cur_sync_locate;
	pthread_mutex_unlock(&smq->sync_lock);
	
	req = nn_allocmsg(sizeof(clumgt_request_t) + sizeof(clu_sync_req_t) + strlen(buf), 0);
	if (NULL == req) {
		clumgt_errprint("nn_allocmsg failed.\n");
		return (-1);
	}
	req->req_type = REQ_FULL_SCALE_SYNC_REQ;
	req->req_timeout = CHECK_SYNC_TIMEOUT;
	req->req_len = sizeof(clumgt_request_t) + sizeof(clu_sync_req_t) + strlen(buf);
	bcopy((char *)&sreq, req->req, sizeof(clu_sync_req_t));
	strncpy(req->req + sizeof(clu_sync_req_t) - 4, buf, strlen(buf) + 1);
	
	ret = clumgt_send_request(req, (void *)&resp, hostname, &node_num);

	if(resp) {
		if(resp[0] != NULL)
			nn_freemsg(resp[0]);
		free(resp);
	}
	nn_freemsg(req);
	
	return ret;
}

static void
sync_check_someone_need_rollback(clumgt_response_t **resp, int node_num)
{
	int i;
	int find = 0;
	int min_seq;
	int locate;
	clu_sync_resp_t *p, *p1;

	for (i = 0; i < node_num; i++) {
		if (NULL != resp[i] && resp[i]->ret_val != 0) {
			p = (clu_sync_resp_t *)resp[i]->resp;
			if (find == 0) {
				min_seq = p->msg_head.seq_start;
				p1 = p;
				locate = i;
			} else if (min_seq > p->msg_head.seq_start) {
				min_seq = p->msg_head.seq_start;
				p1 = p;
				locate = i;
			}
			find = 1;
		}
	}

	if (find && sync_rollbackqueue(p1->msg_head.seq_start,
				p1->msg_head.guid) != 0) {
				clumgt_errprint("queue rollback failed, it need all sync.\n");
				sync_send_fullscale_to_agent(resp[locate]->hostname);
	}

	for (i = 0; i < node_num; i++) {
		if (NULL != resp[i])
			nn_freemsg(resp[i]);
	}
}

/*

function of client 

*/
int
sync_send_current_locate_to_master(clumgt_response_t **presp)
{
	int resp_len;
	int l;
	clumgt_response_t *resp;
	clu_sync_resp_t *sq;
	sync_msg_queue_t *q = &sync_msg_queue;
	
	resp_len = sizeof(clumgt_response_t) + sizeof(clu_sync_resp_t);
	resp = nn_allocmsg(resp_len, 0); 
	if (NULL == resp) { 
		clumgt_errprint("nn_allocmsg failed.\n"); 
		return (-1); 
	}
	
	memset(resp, 0, resp_len);
	resp->resp_len = resp_len;
	resp->ret_val = 0;
	strcpy(resp->hostname, q->hostname);
	sq = (clu_sync_resp_t *)resp->resp;
	pthread_mutex_lock(&q->sync_lock);
	sq->msg_head.seq_start = q->cur_sync_locate;
	l = (q->cur_sync_locate + q->queuesize - 1) % q->queuesize;
	sq->msg_head.guid = q->node_guid[l];
	sq->err = 0;
	pthread_mutex_unlock(&q->sync_lock);

	*presp = resp;

	return 0;	
}


int
sync_deal_msg_from_master_node(char *msg, clumgt_response_t **presp)
{
	int status;
	int seq_start;
	uint64_t guid;
	int ret = -1;
	int l;
	clumgt_response_t *resp;
	clu_sync_resp_t *sq;
	sync_msg_t *sync_msg = (sync_msg_t *)msg;
	sync_msg_queue_t *q = &sync_msg_queue;

	clumgt_print(VERBOSE_MID, "re msg: %d, seq: %d, guid: %llu.\n",
		sync_msg->key, sync_msg->seq_num, sync_msg->guid);

	pthread_mutex_lock(&q->sync_lock);
	seq_start = q->cur_sync_locate;
	l = (q->cur_sync_locate + q->queuesize - 1) % q->queuesize;
	guid = q->node_guid[l];
	clumgt_print(VERBOSE_MID, "need seq: %d, guid: %llu.\n", seq_start, guid);
	if (q->cur_sync_locate < sync_msg->seq_num) {
		pthread_mutex_unlock(&q->sync_lock);
		goto out;
	} else if (q->cur_sync_locate > sync_msg->seq_num &&
		sync_msg->guid == q->node_guid[sync_msg->seq_num%CLU_SYNC_MSG_QUEUE_LEN]) {
		ret = 0;
		pthread_mutex_unlock(&q->sync_lock);
		goto out;
	} else if (q->cur_sync_locate > sync_msg->seq_num &&
		sync_msg->guid != q->node_guid[sync_msg->seq_num%CLU_SYNC_MSG_QUEUE_LEN]) {
		q->node_guid[sync_msg->seq_num%CLU_SYNC_MSG_QUEUE_LEN] = sync_msg->guid;
		q->cur_sync_locate = sync_msg->seq_num + 1;
	} else {
		q->node_guid[q->cur_sync_locate%CLU_SYNC_MSG_QUEUE_LEN] = sync_msg->guid;
		q->cur_sync_locate++;
	}
	pthread_mutex_unlock(&q->sync_lock);

	clumgt_print(VERBOSE_MID, "system %s.\n", sync_msg->cmd);
	if ((status = system(sync_msg->cmd)) < 0 ||
		WIFEXITED(status) == 0) {
		clumgt_errprint("sync system error.\n");
		goto out;
	} else {
		if ((ret = WEXITSTATUS(status)) != 0) {
			clumgt_errprint("configuration sync failed.\n");
		}
	}
	
out:
	resp = nn_allocmsg(sizeof(clumgt_response_t) + sizeof(clu_sync_resp_t), 0);
	resp->resp_len = sizeof(clumgt_response_t) + sizeof(clu_sync_resp_t);
	resp->ret_val = ret;
	sq = (clu_sync_resp_t *)resp->resp;
	sq->err = ret;
	sq->msg_head.seq_start = seq_start;
	sq->msg_head.guid = guid;
	
	gethostname(resp->hostname, sizeof(resp->hostname));
	
	*presp = resp;	

	return (0);
}



/*
 * function of server
 */
int
sync_receive_msg_form_agent(char *msg, clumgt_response_t **presp)
{
	int ret = 0;
	clumgt_response_t *resp;
	sync_msg_t *node;
	sync_msg_queue_t *q = &sync_msg_queue;
	
	if ((node = malloc(sizeof(sync_msg_t))) == NULL)
		goto out;
	memset(node, 0, sizeof(sync_msg_t));
	strncpy(node->cmd, msg, CLU_SYNC_CMD_LEN);
	pthread_mutex_lock(&q->sync_lock);
	sync_enqueue(node);
	pthread_cond_broadcast(&q->sync_cv);
	pthread_mutex_unlock(&q->sync_lock);

out:
	clumgt_print(VERBOSE_MID, "cmd:%s\n", msg);
	resp = nn_allocmsg(sizeof(clumgt_response_t), 0);
	resp->resp_len = sizeof(clumgt_response_t);
	resp->ret_val = ret;
	gethostname(resp->hostname, sizeof(resp->hostname));
	
	*presp = resp;
	return 0;
}

int
sync_check_someone_need_syncfrom_master(void)
{
	clumgt_request_t *req = NULL;	
	clumgt_response_t **resp= NULL;
	int node_num;
	int ret = 0;
	int locate = 0;
	int i, min_seq;
	sync_msg_queue_t *smq = &sync_msg_queue;
	clu_sync_resp_t *p, *p1=NULL;
	
	req = nn_allocmsg(sizeof(clumgt_request_t), 0);
	if (NULL == req) {
		clumgt_errprint("nn_allocmsg failed.\n");
		return (-1);
	}
	req->req_type = REQ_CHECK_SYNC_LOCATE;
	req->req_timeout = CHECK_SYNC_TIMEOUT;
	req->req_len = sizeof(clumgt_request_t);

	ret = clumgt_send_request(req, (void *)&resp, NULL, &node_num);
	if (0 != ret) {
		if(resp)
			free(resp);
		nn_freemsg(req);
		return (ret);
	}

	min_seq = smq->cur_sync_locate;
	for (i = 0; i < node_num; i++) {
		if (NULL != resp[i] && resp[i]->ret_val == 0) {
			p = (clu_sync_resp_t *)resp[i]->resp;
			if (min_seq > p->msg_head.seq_start) {
				min_seq = p->msg_head.seq_start;
				p1 = p;
				locate = i;
			}			
		}
	}

	if (min_seq < smq->cur_sync_locate &&
		sync_rollbackqueue(p1->msg_head.seq_start,
		p1->msg_head.guid) != 0) {
		clumgt_errprint("queue rollback1 failed, it need all sync.\n");
		sync_send_fullscale_to_agent(resp[locate]->hostname);
	}
	
	for (i = 0; i < node_num; i++) {
		if (NULL != resp[i])
			nn_freemsg(resp[i]);
	}

	if(resp)
		free(resp);
	nn_freemsg(req);
	
	return 0;
}


void *
sync_send_msg_to_agent (void *arg)
{

	clumgt_request_t *req = NULL; 
	clumgt_response_t **resp= NULL;
	sync_msg_t *node;
	int node_num;
	int err;
	timestruc_t to;
	sync_msg_queue_t *q = &sync_msg_queue;
	sync_master_info_t *smi = &sync_master_info;
	
	/*  Main processing loop. */
	clumgt_errprint("thread start.\n");

	for (;;) {
		pthread_mutex_lock(&smi->sync_master_node_lock);
		while (B_FALSE == smi->sync_master_node_flag) {
			pthread_cond_wait(&smi->sync_master_node_cv, &smi->sync_master_node_lock);
		}
		pthread_mutex_unlock(&smi->sync_master_node_lock);
			
		node = NULL;
		req = NULL;
		resp = NULL;
		clumgt_print(VERBOSE_MID, "q->msg_num %d.\n",q->msg_num);
		pthread_mutex_lock(&q->sync_lock);
		to.tv_sec = time(NULL) + 10;
		to.tv_nsec = 0;
		while (q->msg_num == 0) {
			err = pthread_cond_timedwait(&q->sync_cv, &q->sync_lock, &to);
			if (err == ETIMEDOUT) {
				pthread_mutex_unlock(&q->sync_lock);
				/* check some one need sync */
				sync_check_someone_need_syncfrom_master();
				pthread_mutex_lock(&q->sync_lock);
				to.tv_sec = time(NULL) + 10;
				to.tv_nsec = 0;
			}
		}
		node = sync_dequeue();
		pthread_mutex_unlock(&q->sync_lock);

		req = nn_allocmsg(sizeof(clumgt_request_t) + sizeof(sync_msg_t), 0);
		if (NULL == req) {
			clumgt_errprint("nn_allocmsg failed.\n");
			return NULL;
		}
		req->req_type = SYNC_MSG;
        req->req_timeout = WAIT_RESP_TIMEOUT;
        req->req_len = sizeof(clumgt_request_t) + sizeof(sync_msg_t);
        bcopy((char *)node, req->req, sizeof(sync_msg_t));

		if (clumgt_send_request(req, (void *)&resp, NULL, &node_num) != 0) {
			if (resp)
				free(resp);
			nn_freemsg(req);
			return NULL;
		}
		/* update Synchronous number by return info */
		sync_check_someone_need_rollback(resp, node_num);

		if (resp)
			free(resp);
		nn_freemsg(req);
		
	}

	return (NULL);
}


/*
 * probe master node
 */

int
sync_probe_mster_node(char *msg, clumgt_response_t **presp)
{
	sync_master_info_t *smi = &sync_master_info;
	clumgt_response_t *resp;

	resp = nn_allocmsg(sizeof(clumgt_response_t) + HOSTNAMELEN, 0);
	resp->resp_len = sizeof(clumgt_response_t) + HOSTNAMELEN;
	resp->ret_val = 0;
	
	pthread_mutex_lock(&smi->sync_master_node_lock);
	strncpy(resp->resp, smi->master_node, HOSTNAMELEN);
	pthread_mutex_unlock(&smi->sync_master_node_lock);
	
	*presp = resp;	

	return (0);
}

void
sync_init_master()
{
	sync_master_info_t *smi = &sync_master_info;
	
	memset(smi->master_node, 0x0, HOSTNAMELEN);
	smi->sync_master_node_flag = B_FALSE;
	(void)pthread_mutex_init(&smi->sync_master_node_lock, NULL);
	(void)pthread_cond_init(&smi->sync_master_node_cv, NULL); 
}

static int
get_master_form_xml(char *master_id)
{
	xmlDocPtr doc;
	xmlNodePtr cur_node;
	xmlChar *mhostid;
	
	xmlKeepBlanksDefault(0);
	doc = xmlReadFile("/tmp/multiclus.xml", "UTF-8", XML_PARSE_RECOVER);
	if (NULL == doc) {
		fprintf(stderr, "open /tmp/multiclus.xml failed");
		return -1;
	}
		
	cur_node = xmlDocGetRootElement(doc);
	if (NULL == cur_node) {
		fprintf(stderr, "get root node failed");
		xmlFreeDoc(doc);
		return -1;
	}
		
	if (0 != xmlStrcmp(cur_node->name, (const xmlChar*)"multiclus")) {
		fprintf(stderr, "xml is not matched");
		xmlFreeDoc(doc);
		return -1;
	}
		
	cur_node = cur_node->xmlChildrenNode;
	while (NULL != cur_node) {
		if (0 == (xmlStrcmp(cur_node->name, (const xmlChar*)"group"))) {
			mhostid = xmlGetProp(cur_node, (const xmlChar*)"mhostid");
			if (NULL == mhostid || xmlStrcmp((const xmlChar*)"0", mhostid) == 0) {
				fprintf(stderr, "get mhostid failed");
				if (NULL != mhostid) {
					xmlFree(mhostid);
				}
				xmlFreeDoc(doc);
				return -1;
			}

			strncpy(master_id, (char*)mhostid, HOSTNAMELEN);
			xmlFree(mhostid);
		}
		cur_node = cur_node->next;
	}
		
	xmlFreeDoc(doc);
		
	return 0;
}


int 
find_master(int *self_change_to_master) 
{	
	FILE *pp;
	int ret;
	char master_curr[HOSTNAMELEN];
	char master_node_id[64];
	char tmp_buf[256];
	sync_master_info_t *smi = &sync_master_info;
	sync_msg_queue_t *smq = &sync_msg_queue;

	*self_change_to_master = B_FALSE;

	/* do zfs multiclus -xv */
	if ((pp = popen("zfs multiclus -vx", "r")) == NULL) {
		syslog(LOG_ERR, "exec cmd fail\n");
		return (EXIT_FAILURE);
	}
	
	fgets(tmp_buf, 256, pp);

	ret = WEXITSTATUS(pclose(pp));
	if (0 != ret) {
		syslog(LOG_ERR, "Exit code: %i\n", ret);
		return (EXIT_FAILURE);
	}

	/* parse result xml file */
	if (0 != get_master_form_xml(master_node_id)) {
		return (EXIT_FAILURE);
	}

	memset(master_curr, 0x0, HOSTNAMELEN);
	/* get the master node name */
	snprintf(master_curr, HOSTNAMELEN, "%s%c", "df", 'a'+atoi(master_node_id)-1);
	
	if (0 != strncmp(master_curr, smi->master_node, HOSTNAMELEN)){
		pthread_mutex_lock(&smi->sync_master_node_lock);
		strncpy(smi->master_node, master_curr, HOSTNAMELEN);
		smi->sync_master_node_flag = B_FALSE;
		pthread_mutex_unlock(&smi->sync_master_node_lock);

		if (0 == strncmp(master_curr, smq->hostname, HOSTNAMELEN)) {
			*self_change_to_master = B_TRUE;
		}
	}
	
	return (EXIT_SUCCESS);
}

int
sync_agent_fullscale_process(char* buf, clumgt_response_t **presp)
{
	char *files[3] = {
		"/etc/passwd.tmp", 
		"/etc/shadow.tmp", 
		"/etc/group.tmp"
	};
	int i;
	int ret = 0;
	int fd;
	char *p_begin;
	char *p_end;
	int write_len;
	sync_msg_queue_t *smq = &sync_msg_queue;
	clumgt_response_t *resp;
	clu_sync_req_t *srq = (clu_sync_req_t *)buf;
	int l;
	
	if (NULL == buf) {
		ret = -1;
		goto out;
	}
	
	p_begin = srq->msg_body;
	for (i = 0; i < 3; ++i) {
		if (0 == (fd = open(files[i], O_RDWR|O_CREAT, 0644))) {
			ret = -1;
			goto out;
		}

		if (NULL == (p_end = strstr(p_begin, "[end]"))) {
			close(fd);
			ret = -1;
			goto out;
		}
		
		write_len = p_end - p_begin;
		if (write_len != write(fd, p_begin, write_len)) {
			close(fd);
			ret = -1;
			goto out;
		}
		
		close(fd);
		p_begin = p_end + strlen("[end]");
	}
	pthread_mutex_lock(&smq->sync_lock);
	rename("/etc/passwd", "/etc/passwd.bak");
	rename("/etc/shadow", "/etc/shadow.bak");
	rename("/etc/group", "/etc/group.bak");
	rename("/etc/passwd.tmp", "/etc/passwd");
	rename("/etc/shadow.tmp", "/etc/shadow");
	rename("/etc/group.tmp", "/etc/group");
	smq->cur_sync_locate = srq->msg_head.seq_start;
	l = (smq->cur_sync_locate + smq->queuesize - 1) % smq->queuesize;
	smq->node_guid[l] = srq->msg_head.guid;
	pthread_mutex_unlock(&smq->sync_lock);

out:
	resp = nn_allocmsg(sizeof(clumgt_response_t), 0);
	resp->resp_len = sizeof(clumgt_response_t);
	resp->ret_val = ret;
	*presp = resp;

	return 0;
}

void*
sync_choose_master(void *args)
{
	time_t interval = 30;
	time_t last_search_time = 0;
	time_t curr_time;
	int self_change_to_master;

	sync_master_info_t *smi = &sync_master_info;
	sync_msg_queue_t *q = &sync_msg_queue;

	
	for (;;) {
		curr_time = time(NULL);
		if (curr_time - last_search_time < interval) {
			sleep(5);
			continue;
		}
		
		if (0 != find_master(&self_change_to_master)){
			last_search_time += 5;
			continue;
		}
		last_search_time = curr_time;

		if (self_change_to_master) {
			/* update the master node */
			pthread_mutex_lock(&smi->sync_master_node_lock);
			pthread_mutex_lock(&q->sync_lock);
			smi->sync_master_node_flag = B_TRUE;
			update_sync_queue();
			pthread_mutex_unlock(&q->sync_lock);
			pthread_cond_broadcast(&smi->sync_master_node_cv);
			pthread_mutex_unlock(&smi->sync_master_node_lock);
		} 
	}

	return NULL;
}




