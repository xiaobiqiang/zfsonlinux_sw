#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/stat.h>
#include <linux/ioctl.h>
#include <sys/zfs_ioctl.h>
#include <libuutil.h>
#include <libnvpair.h>

#define COMMSOCK_IOC_SET_TCP 1
typedef int (*cs_subcmd_fn)(int, char **argv);
typedef struct cs_subcmd {
    char *name;
    int (*fn)(int, char **);
    void (*usage)(void);
} cs_subcmd_t;

typedef struct commsock_cmd {
    uint64_t	cc_nvlist_src;	
    uint64_t	cc_nvlist_src_size;
    uint64_t	cc_nvlist_dst;	
    uint64_t	cc_nvlist_dst_size;
} cs_cmd_t;

static int commsock_do_enable(int, char **);
static int commsock_do_listinfo(int, char **);
static void commsock_do_enable_usage(void);
static void commsock_do_listinfo_usage(void);
static void commsock_do_main_usage(void);
static cs_subcmd_fn commsock_get_subcmd(char *);

static cs_subcmd_t cs_subcmd_vec[] = {
    {"enable", commsock_do_enable, commsock_do_enable_usage},
    {"list-info", commsock_do_listinfo, commsock_do_listinfo_usage}
};

int main(int argc, char **argv)
{ 
    char *subcmd;
    cs_subcmd_fn fn;
    
    if(argc < 2) {
        commsock_do_main_usage();
        return 1;
    }

    subcmd = argv[1];
    fn = commsock_get_subcmd(subcmd);
    argc -= 1; // originally, optindex = 1 instead of 0
    argv += 1;
    return fn(argc, argv);
}

static cs_subcmd_fn commsock_get_subcmd(char *name)
{
    int i=0;
    int cnt = sizeof(cs_subcmd_vec)/sizeof(cs_subcmd_t);

    for( ; i<cnt; i++) {
        if(strcmp(cs_subcmd_vec[i].name, name) == 0)
            return cs_subcmd_vec[i].fn;
    }
}

static void commsock_do_enable_usage(void)
{
    printf("\nUsage:   commsock enable <OPTIONS> <attrs ...>"
           "\n         OPTIONS:"
           "\n                 -i,   <ipaddr>"
           "\n                 -p,   <port>"
           "\n");
}

static void commsock_do_listinfo_usage(void)
{
    printf("\nUsage:   commsock list-info <OPTIONS> <attrs ...>"
           "\n         OPTIONS:"
           "\n                 -i,   <ipaddr>"
           "\n                 -p,   <port>"
           "\n                 -a,   <all>"
           "\n");
}


static void commsock_do_main_usage(void)
{
    int i = 0;
    int cnt = sizeof(cs_subcmd_vec)/sizeof(cs_subcmd_t);
    for( ; i<cnt; i++) {
        printf("Usage:   commsock %s [-?]\n", cs_subcmd_vec[i].name);
    }
}

static int commsock_do_enable(int argc, char **argv)
{
    int c;
    int port = 0;
    char *ipaddr = NULL;
    cs_cmd_t cmd;
    int exit = 0;
    nvlist_t *nvl = NULL;
    int error;
    char *packed = NULL;
    size_t packlen = 0;
    int fd;
    
    if(argc <= 1) {
        commsock_do_enable_usage();
        return 1;
    }
    while((c = getopt(argc, argv, "i:p:")) != -1) {
		switch (c) {
		case 'i': ipaddr = optarg; break;
		case 'p': port = atoi(optarg); break; 
		case '?':
			commsock_do_enable_usage();
			exit = 1;
		    break;
		}
	}

    if(exit)
        return 1;
        
	if(!ipaddr || (port<=0) || (port>65535)) {
	    printf("invalid argument\n");
	    return EINVAL;
	}
    printf("ipaddr:%s, port:%d\n", ipaddr, port);
    memset(&cmd, 0, sizeof(cmd));
    if(nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP) != 0) {
        printf("nvlist_alloc failed,internal error: out of memory\n");
        error = 2;
        goto out;
    }
	if( (nvlist_add_string(nvl, "ipaddr", ipaddr) != 0) ||
	    (nvlist_add_int32(nvl, "port", port) != 0) ) {
        printf("nvlist add attrs failed,internal error: out of memory\n");
        error = 3;
        goto free_nvl;
	}
    printf("------------\n");
    nvlist_size(nvl, &packlen, NV_ENCODE_XDR);
    if((packed = malloc(packlen)) == NULL) {
        printf("malloc failed,internal error: out of memory\n");
        error = 4;
        goto free_nvl;
    }
    
	if(nvlist_pack(nvl, &packed, &packlen, NV_ENCODE_XDR, KM_SLEEP) != 0) {
        printf("nvlist_pack failed,internal error: out of memory\n");
        error = 5;
        goto free_pack;
	}

	cmd.cc_nvlist_src = packed;
	cmd.cc_nvlist_src_size = packlen;

	if((fd=open("/dev/commsock_dev", O_RDWR)) < 0) {
        printf("open /dev/commsock failed,strerror:%s\n", strerror(errno));
        goto free_pack;
	}

	if((error=ioctl(fd, COMMSOCK_IOC_SET_TCP, (unsigned long)&cmd)) != 0) {
        printf("ioctl failed,error:%d\n", error);
	}
	close(fd);
free_pack:
    free(packed);
free_nvl:
    nvlist_free(nvl);
out:
    return error;
}
static int commsock_do_listinfo(int argc, char **argv)
{
    return 0;
}

