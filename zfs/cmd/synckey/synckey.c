
#include <stdio.h>
#include <string.h>
#include <libzfs.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/systeminfo.h>

#define	DIR_PERMS	(S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH)
#define	UNKNOW_OPT	0
#define	SYNCFILE_OPT	1
#define	SYNCCMD_OPT	2

void
synckey_usage()
{
	printf("Usage:\n"
		  "	synckey <option> <key file name> \n"
		  "option:\n"
		  "	-f: sync file\n"
		  "	-c: sync commond\n");	
}

int synckey_update_filepath(char *filename)
{
	int ret = 0;
	int size = 0;
	char buffer[256];
	libzfs_handle_t *zfs_handle = NULL;
	bzero(buffer, 256);
	bcopy(filename, buffer, strlen(filename));
	buffer[strlen(filename)] = 0;
	size = strlen(buffer);

	if ((zfs_handle = libzfs_init()) == NULL) {
		printf("key file get zfs handle failed\n");
		return (-1);
	}

	zfs_do_hbx_process(zfs_handle, buffer, size, ZFS_HBX_KEYPATH_UPDATE);
	libzfs_fini(zfs_handle);
	return ret;
}

static int
synckey_update_keyfile(char *filename)
{
	int fd, ret= -1;
	off_t offset = 0, size;
	char *buffer = NULL;
	int current_id;

	current_id = getpid();
	
	fd = open(filename, O_RDONLY);
	
	if (fd < 0) {
		printf("key file open local failed\n");
		return (ret);
	}
	
	lseek(fd, 0, SEEK_END);
	offset = lseek(fd, 0, SEEK_CUR);
	if (offset <= 0) {
		printf("key file seek offset (%d) invalid\n", offset);
		close(fd);
		return (ret);
	}

	/* the process ID leave 8 byte */
	if ((offset + MAX_ID_BYTE)> 512*1024) {
		printf("key file too large :length > 512K\n");
		close(fd);
		return -1;
	}
		
	if ((buffer = malloc(offset + MAX_ID_BYTE)) == NULL) {
		printf("key file malloc failed\n");
		close(fd);
		return (ret);
	}
	sprintf(buffer, "%d", current_id);
	lseek(fd, 0, SEEK_SET);
	size = read(fd, buffer + MAX_ID_BYTE, offset);
	if (size != offset) {
		printf("key file read size not equal %d:%d\n", size, offset);
		free(buffer);
		close(fd);
		return (ret);
	}
	
	close(fd);

	size = size + MAX_ID_BYTE;
	zfs_add_guide_info(buffer, size, ZFS_HBX_KEYFILE_UPDATE);
	free(buffer);
	return (0);
}

static int
synckey_update_cmd(char *cmd_name)
{
	libzfs_handle_t *zfs_handle = NULL;
	long int current_id = 0;
	long int hostval;
	long int opposite_hostid;
	nvlist_t *result;
	nvpair_t *nvp_elem;
	char *hostnameid;
	int ret;
	int have_others = 0;
	
	current_id = getpid();

	if(cmd_name[0] == '\"') {
		cmd_name[0] = ' ';
	}
	if(cmd_name[strlen(cmd_name) - 1] == '\"') {
		cmd_name[strlen(cmd_name) - 1] = 0;
	}

	if ((unsigned int)(hostval = gethostid()) == HW_INVALID_HOSTID ||
		hostval > 100) {
		(void) fprintf(stderr, "bad hostid format\n");
		return (-1);
	}

	opposite_hostid = ((hostval % 2) == 0) ? (hostval - 1) : (hostval + 1);
	
	if ((zfs_handle = libzfs_init()) == NULL) {
		printf("get zfs handle failed\n");
		return (-1);
	}
	result = zfs_clustersan_sync_cmd(zfs_handle, current_id,
		cmd_name, 10, opposite_hostid);
	libzfs_fini(zfs_handle);

	if (result == NULL) {
		return (-1);
	}

	nvp_elem = NULL;
	printf("execution results from other hosts\n");
	while ((nvp_elem = nvlist_next_nvpair(result, nvp_elem)) != NULL) {
		have_others = 1;
		hostnameid = nvpair_name(nvp_elem);
		verify(0 == nvpair_value_int32(nvp_elem, &ret));
		printf("  %s: ", hostnameid);
		if (ret == 0) {
			printf("successs\n");
		} else {
			printf("fail\n");
		}
	}

	if (have_others == 0) {
		printf("  no other hosts\n");
	}
	nvlist_free(result);

	return (0);
}

static int 
synckey_getopt(char *cmd_opt) {
	int cmd_type ;

	cmd_type = UNKNOW_OPT;
	if (strcmp(cmd_opt, "-f") == 0)
		cmd_type = SYNCFILE_OPT;
	if(strcmp(cmd_opt, "-c") == 0)
		cmd_type = SYNCCMD_OPT;

	return cmd_type;
}

int main (int argc, char **argv)
{
	int i;
	int optchar;
	char rcmd[512];
	struct stat64 ls_buf;

	bzero(rcmd, 512);

	if (argc < 3) 
		synckey_usage();
	else {
		optchar = synckey_getopt(argv[1]);

		switch (optchar) {
			case SYNCFILE_OPT:
				if (argv[2][0] != '/'){
					printf("please input absolute path\n");
					return (-1);
				}

				/*  lack of the file name */
				i = strlen(argv[2]) - 1;
				if (argv[2][i] == '/'){
					printf("please input file name\n");
					return (-1);
				}

				/* Judge Whether or not file */
				if (lstat64(argv[2],&ls_buf) <0) {
					printf("please check the file\n");
					return (-1); 
				}
				if ((ls_buf.st_mode & S_IFMT)!= S_IFREG) {
					printf("please input general file\n");
					return (-1);
				}
				
				synckey_update_filepath(argv[2]);
				synckey_update_keyfile(argv[2]);
				break;
			case SYNCCMD_OPT:
				sprintf(rcmd, "%s", argv[2]);
				for(i = 3; i< argc;i++) {
					sprintf(rcmd, "%s %s", rcmd, argv[i]);
				}
				rcmd[strlen(rcmd)] = 0;
				synckey_update_cmd(rcmd);
				break;
			default:
				synckey_usage();
				break;
		}
	}
	return 0;
}
