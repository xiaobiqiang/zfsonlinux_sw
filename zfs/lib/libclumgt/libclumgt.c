#include <stdarg.h>
#include <strings.h>
#include <stdio.h>
#include <syslog.h>
#include <fcntl.h>
#include <malloc.h>
#include <string.h>
#include <libnvpair.h>
#include <pthread.h>
#include <nanomsg/nn.h>
#include <nanomsg/reqrep.h>
#include "libclumgt.h"


#define test_connect(s, a) test_connect_impl (__FILE__, __LINE__, (s), (a))
#define test_send(s, d) test_send_impl (__FILE__, __LINE__, (s), (d))
#define test_recv(s) test_recv_impl (__FILE__, __LINE__, (s))


static int test_connect_impl (char *file, int line,
    int sock, char *address)
{
    int rc;

    rc = nn_connect (sock, address);
    if(rc < 0) {
        fprintf (stderr, "Failed connect to \"%s\": %s [%d] (%s:%d)\n",
            address,
            nn_strerror(nn_errno()),
            nn_errno(), file, line);
        abort ();
    }
    return rc;
}

static int test_send_impl (char *file, int line, int sock, char *data)
{
    size_t data_len;
    int rc;

    data_len = strlen (data);

    rc = nn_send (sock, data, data_len, 0);
    if (rc < 0) {
        fprintf (stderr, "Failed to send: %s [%d] (%s:%d)\n",
            nn_strerror (nn_errno()),
            (int) nn_errno(), file, line);
        return (-1);
    }
	return (0);
}

static int test_recv_impl (char *file, int line, int sock)
{
    int rc;
	void *recv = NULL;
	int timeout = 3000;

	if (nn_setsockopt(sock, NN_SOL_SOCKET, NN_RCVTIMEO,
		&timeout, sizeof(timeout)) < 0) {
		fprintf (stderr, "Failed to setsockopt: %s [%d] (%s:%d)\n",
            nn_strerror (nn_errno()),
            (int) nn_errno(), file, line);
		return (-1);  
	}

    rc = nn_recv (sock, &recv, NN_MSG, 0);
    if (rc < 0) {
        return (-1);
    }
	nn_freemsg(recv);
	return (0);
}

int
clumgt_get_hostnode(clumgt_host_t *c_host, int *host_num, char *hostname)
{
	FILE	*cfg = NULL;
	char	ip[HOSTURLLEN];
	char	buf[TMPBUFLEN];
	int		i = 0;

	if ((cfg = fopen(CLUMGT_CONFIG_FILE, "r")) == NULL) {
		return (-1);
	}

	memset(buf, 0, TMPBUFLEN);
	memset(c_host[i].hostname, 0, HOSTNAMELEN);
	memset(ip, 0, HOSTURLLEN);
	while (fgets(buf, TMPBUFLEN, cfg)){
		if (buf[0] == '#')
			continue;
		sscanf(buf, "%31s%31s", c_host[i].hostname, ip);
		if (c_host[i].hostname[0] == 0||
			ip[0] == 0||
			(hostname != NULL && strcmp(hostname, c_host[i].hostname) != 0)) {
			memset(c_host[i].hostname, 0, HOSTNAMELEN);
			memset(ip, 0, HOSTURLLEN);
			continue;
		}
		snprintf(c_host[i].hosturl, HOSTURLLEN, "tcp://%s:%d", ip, TCPPORT);
		/*printf("name:%s, url:%s\n", c_host[i].hostname, c_host[i].hosturl);*/
		i++;
		if (i == MAXWORKERS || 
			(hostname != NULL &&
			strcmp(hostname, c_host[i].hostname) == 0))
			break;
		memset(buf, 0, TMPBUFLEN);
		memset(c_host[i].hostname, 0, HOSTNAMELEN);
		memset(ip, 0, HOSTURLLEN);
	}
	*host_num = i;
	fclose(cfg);
	
	return (0);
}

void *
thread_send_request(void *arg)
{
	int		sockid;
	int		rc;
	int		timeout = WAIT_RESP_TIMEOUT;
	clumgt_host_t		*c_host;
	clumgt_thread_arg_t *t_arg;
	clumgt_response_t *resp = NULL;

	t_arg = (clumgt_thread_arg_t *)arg;
	c_host = t_arg->c_host;

	if ((sockid = nn_socket(AF_SP, NN_REQ)) < 0) {
		fprintf(stderr, "[libclumgt] nn_socket: %s\n", 
			nn_strerror(nn_errno ()));
		return (NULL);
	}
	
	if (test_connect(sockid, c_host->hosturl) < 0) {
		nn_close(sockid);
		return (NULL);
	}
	
    if ((rc = test_send (sockid, "ABCXYZ")) < 0 || 
		(rc = test_recv (sockid)) < 0) {
		nn_close(sockid);
		return (NULL);
	}

	if (t_arg->req->req_timeout != 0) {
		timeout = t_arg->req->req_timeout;
	}

	if (nn_setsockopt(sockid, NN_SOL_SOCKET, NN_RCVTIMEO,
		&timeout, sizeof(timeout)) < 0) {
		fprintf(stderr, "[libclumgt] nn_setsockopt: %s\n",
			nn_strerror(nn_errno()));
		nn_close(sockid);
		return (NULL);  
	}

	if (nn_send(sockid, t_arg->req, t_arg->req->req_len, 0) < 0) {
		fprintf(stderr, "[libclumgt] nn_send: %s\n", nn_strerror(nn_errno()));
		nn_close(sockid);
		return (NULL);
	}

	rc = nn_recv(sockid, t_arg->resp, NN_MSG, 0);
	/*printf("rc=%d\n", rc);*/
	if (rc < 0) {
		resp = nn_allocmsg(sizeof(clumgt_response_t) + TMPBUFLEN, 0);
		resp->resp_len = sizeof(clumgt_response_t) + TMPBUFLEN;
		resp->ret_val = 0;
		memset(resp->resp, 0, TMPBUFLEN);
		strcpy(resp->hostname, t_arg->c_host->hostname);
		snprintf(resp->resp, TMPBUFLEN, "cmd execute on %s timed out, please check %s status.\n",
			c_host->hostname, c_host->hostname);
		*(t_arg->resp) = resp;
		syslog(LOG_ERR, "[libclumgt] nn_recv from %s: %s\n", c_host->hostname, 
			nn_strerror(nn_errno()));
		nn_close(sockid);
		return (NULL);
	}

	nn_close(sockid);
	return (NULL);
}


int
clumgt_send_request(clumgt_request_t *req, void *resp, char *hostname, int *num)
{
	int			i;
	int			rc;
	int			host_num;
	pthread_t	tids [MAXWORKERS];
	clumgt_host_t c_host[MAXWORKERS];
	clumgt_thread_arg_t t_arg[MAXWORKERS];
	void **respp;

	if (clumgt_get_hostnode(c_host, &host_num, hostname) != 0) {
		fprintf(stderr, "[libclumgt] get host node failed, "
			"please check config.\n");
		return (-1);
	}

	if (host_num <= 0) {
		*num = 0;
		return (-1);
	}
	
	if ((respp = (void **)malloc((host_num + 1) * sizeof(void *))) == NULL) {
		fprintf(stderr, "[libclumgt] malloc error\n");
		return (-1);
	}

	memset(respp, 0, (host_num + 1) * sizeof(void *));
	
	/*  Start up the threads for each host node. */
	for (i = 0; i < host_num; i++) {
		t_arg[i].req = req;
		t_arg[i].resp = &respp[i];
		t_arg[i].c_host = &c_host[i];
		rc = pthread_create(&tids[i], NULL, thread_send_request, &t_arg[i]);
		if (rc < 0) {
			fprintf(stderr, "[libclumgt] pthread_create: %s\n", strerror(rc));
			break;
		}
	}

	/*  Now wait on them to finish. */
	for (i = 0; i < host_num; i++) {
		if (tids[i] != 0) {
			pthread_join(tids[i], NULL);
		}
	}
	*(void ***)resp = respp;
	*num = host_num;
	return (0);
}



