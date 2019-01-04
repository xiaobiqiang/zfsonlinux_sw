#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/errno.h>
#include <sys/stat.h>
//#include <sys/param.h>
//#include <libdevinfo.h>
//#include <libzfs.h>
#include <fcntl.h>
//#include <sys/vtoc.h>
//#include <sys/efi_partition.h>
#include <ctype.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <dirent.h>
//#include "mpt3sas_ctl.h"

#define MPT3GETSASDEVINFO   _IOWR(MPT3_MAGIC_NUMBER, 32, \
	struct mpt3_sas_devinfo_buffer)


#define SCSIHOST_DIR "/sys/class/scsi_host"
#define MPT3CTL_DEV  "/dev/mpt3ctl"

typedef enum mpt_type {
    MPT2SAS,
    MPT3SAS
}mpt_type_e;


typedef struct mpt_ioc {
    int ioc_id;
    uint32_t ioc_dev_num;
    mpt_type_e ioc_type;
    int ioc_enabled;
}mpt_ioc_t;

/**
 * struct mpt3_ioctl_header - main header structure
 * @ioc_number -  IOC unit number
 * @port_number - IOC port number
 * @max_data_size - maximum number bytes to transfer on read
 */
struct mpt3_ioctl_header {
	unsigned int ioc_number;
	unsigned int port_number;
	unsigned int max_data_size;
};
#define MPT3_MAGIC_NUMBER	'L'

struct mpt3sas_dev_info {
    unsigned long long  sas_address;
    unsigned long long  wwid;
    unsigned long long  enclosure_id;
    unsigned long long  slot;
};

struct mpt3_sas_devinfo_buffer {
    struct mpt3_ioctl_header hdr;
    unsigned int sas_dev_cnt;
    struct mpt3sas_dev_info  buffer[0];
};

static int find_mpt_host(mpt_ioc_t **ioc_ids, int *ioc_ids_nr)
{
    DIR *dir;
    struct dirent *dirent;
    int fd = -1;
    ssize_t ret = -1;
    mpt_ioc_t *ids = NULL;
    int ids_idx = 0;
    int ids_sz = 10;

    ids = malloc(sizeof(*ids) * ids_sz);
    if (!ids)
        return -1;

    memset(ids, 0, sizeof(*ids) * ids_sz);

    dir = opendir(SCSIHOST_DIR);
    if (!dir) {
        free(ids);
        return -1;
    }

    while ( (dirent = readdir(dir)) != NULL ) {
        char filename[512];
        char procname[8];
        char dev_num[8];

        snprintf(filename, sizeof(filename), "%s/%s/proc_name", SCSIHOST_DIR, dirent->d_name);

        fd = open(filename, O_RDONLY);
        if (fd < 0)
            continue;

        ret = read(fd, procname, 8);
        if (ret < 0)
            continue;

        close(fd);

        procname[7] = '\0';

        if (strncmp("mpt3sas", procname, 7) == 0) {
            ids[ids_idx].ioc_type = MPT3SAS;
        } else if (strncmp("mpt2sas", procname, 7) == 0) {
            ids[ids_idx].ioc_type = MPT2SAS;
        } else {
            continue;
        }

        /* fetch scsi host uniqeu id. */
        snprintf(filename, sizeof(filename), "%s/%s/unique_id", SCSIHOST_DIR, dirent->d_name);

        fd = open(filename, O_RDONLY);
        if (fd < 0) {
            syslog(LOG_ERR, "open file :%s failed", filename);
            continue;
        }

        ret = read(fd, procname, 8);
        if (ret < 0) {
            syslog(LOG_ERR, "read failed, %s:%d", __FILE__, __LINE__);
            continue;
        }

        close(fd);

        /* fetch scsi host sas device number. */
        snprintf(filename, sizeof(filename), "%s/%s/host_sas_dev_cnt", SCSIHOST_DIR, dirent->d_name);

        fd = open(filename, O_RDONLY);
        if (fd < 0)
            continue;

        ret = read(fd, dev_num, 8);
        if (ret < 0)
            continue;

        close(fd);

        if (ids_idx == ids_sz)
        {
            ids_sz *= 2;
            ids = realloc(ids, sizeof(*ids) * ids_sz);
            if (!ids)
                break;

            ids[ids_idx].ioc_id = atoi(procname);
            ids[ids_idx].ioc_dev_num = atoi(dev_num);
            syslog(LOG_INFO, "Found MPT ioc %d type %d",
                    ids[ids_idx].ioc_id, ids[ids_idx].ioc_type);
            ids_idx += 1;
        }
        else
        {
            ids[ids_idx].ioc_id = atoi(procname);
            ids[ids_idx].ioc_dev_num = atoi(dev_num);
            syslog(LOG_INFO, "Found MPT ioc %d type %d",
                    ids[ids_idx].ioc_id, ids[ids_idx].ioc_type);
            ids_idx += 1;
        }
    }

    closedir(dir);

    *ioc_ids = ids;
    *ioc_ids_nr = ids_idx;

    return 0;
}




int main(int argc, char **argv) 
{
    int ret;
    mpt_ioc_t *ids = NULL;
    int ids_nr = 0;
    int idx = 0;

    int fd = open(MPT3CTL_DEV, O_RDWR);
	if (fd < 0) {
		syslog(LOG_ERR, "Failed to open mpt device %s: %d (%m)", MPT3CTL_DEV, errno);
		return -1;
	}
    
    ret = find_mpt_host(&ids, &ids_nr);
    if (ret < 0) {
		syslog(LOG_WARNING, "no mpt host found");
        return -1;
    }

    if (ids_nr == 0) {
        free(ids);
        syslog(LOG_WARNING, "Not found any supported MPT controller");
        return -1;
    }

    /* ids_nr usually equls 1.*/
	for (idx = 0; idx < ids_nr; idx++) 
    {
    	struct mpt3_sas_devinfo_buffer *cmd;
    	int i;
    	int ret;
        uint32_t append_len;

        append_len = ids[idx].ioc_dev_num * sizeof(struct mpt3sas_dev_info);

        cmd = malloc(sizeof(struct mpt3_sas_devinfo_buffer) + append_len);
        if(NULL == cmd) {
            syslog(LOG_ERR, "malloc failed for mpt device: %d, malloc size:%lu", 
                    ids[idx].ioc_id, sizeof(struct mpt3_sas_devinfo_buffer) + append_len);
            continue;
        }

    	memset(cmd, 0, sizeof(struct mpt3_sas_devinfo_buffer) + append_len);
    	cmd->hdr.ioc_number = ids[idx].ioc_id;
    	cmd->hdr.port_number = 0;
        cmd->sas_dev_cnt = ids[idx].ioc_dev_num;

        

    	ret = ioctl(fd, MPT3GETSASDEVINFO, cmd);
    	if (ret < 0) {
            syslog(LOG_ERR, "Failed to fetch info on mpt device:%d, this might not be a real mpt device: %d (%m)",
                    cmd->hdr.ioc_number,  errno);
    	} else {
            syslog(LOG_ERR, "Success to fetch info on mpt device %d", cmd->hdr.ioc_number);
            for(i = 0; i < cmd->sas_dev_cnt; i++)
            {
                printf("Enclosure:0x%llx, Slot:%llu, sas_address:0x%llx, wwid:0x%llx\n",
                    cmd->buffer[i].enclosure_id, 
                    cmd->buffer[i].slot, 
                    cmd->buffer[i].sas_address, 
                    cmd->buffer[i].wwid);
            }
        }

        free(cmd);
        cmd = NULL;
    }

    free(ids);
    return ret;
}

