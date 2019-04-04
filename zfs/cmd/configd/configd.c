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
#include "systemd_util.h"
#include "store.h"

#define	CONFIGD_CMD_OPTS	"n"
#define	CONFIGD_MSG_QUEUE	"/configd_msgq"
#define	PID_FILE	RUNSTATEDIR "/configd.pid"

extern cfg_store_t db_store;
extern msg_handler_t stmf_msg_handler_table[];

volatile sig_atomic_t running = 1;

void sigterm_handler(int arg)  
{  
    running = 0;  
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
		write_pid(PID_FILE);

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
