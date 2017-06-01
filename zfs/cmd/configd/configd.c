#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <wctype.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wchar.h>
#include <libintl.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <getopt.h>
#include <libstmf.h>
#include <signal.h>
#include <pthread.h>
#include <locale.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <syslog.h>
#include <libcomm.h>
#include "store.h"

#define	CONFIGD_CMD_OPTS	"n"
#define	CONFIGD_MSG_QUEUE	"/configd_msgq"

extern cfg_store_t db_store;
extern msg_handler_t stmf_msg_handler_table[];

volatile sig_atomic_t running = 1;

void sigterm_handler(int arg)  
{  
    running = 0;  
}

/*
 * Processing for daemonization
 */
static void
daemonize_start(void)
{
   	pid_t pid;
	
    pid = fork();  
    if(pid < 0)  
    {  
        perror("fork error!");  
        exit(1);  
    }  
    else if(pid > 0)  
    {  
        exit(0);  
    }  
  
    setsid();	
	(void) chdir("/");
	umask(0);

	/*
	 * Close stdin, stdout, and stderr.
	 * Open again to redirect input+output
	 */
	(void) close(0);
	(void) close(1);
	(void) close(2);
	(void) open("/dev/null", O_RDONLY);
	(void) open("/dev/null", O_WRONLY);
	(void) dup(1);
}

int
main(int argc, char *argv[])
{
	int c;
	int ret = 0;
	int daemonize = 1;		/* default to daemonizing */

	while ((c = getopt(argc, argv, CONFIGD_CMD_OPTS)) != EOF) {
		switch (c) {
		case 'n':
			daemonize = 0;
			break;
		default:
			break;
		}
	}

	if (daemonize)
		daemonize_start();

	/* init comm service */
	comm_register_msg_handler(stmf_msg_handler_table);
	ret = comm_init(COMM_TYPE_SERVER, CONFIGD_MSG_QUEUE);
	if (ret != 0) {
		syslog(LOG_ERR, "configd comm init failed");
		return (ret);
	}

	/* init database */
	ret = psInit(&db_store);
	if (ret != 0) {
		syslog(LOG_ERR, "configd db init failed");
		return (ret);
	}
	
	signal(SIGTERM, sigterm_handler);

	while (running)
		(void) pause();

	comm_fini();
	return (ret);
} /* end main */
