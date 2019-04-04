#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

#define LIBC_PATH "/lib/libc.so.6.1"
#define HK_SHM_KEY  0x4af92c6d
#define HK_SHM_MODE 0600

#define HKT_TYPE_READ  0x01
#define HKT_TYPE_WRITE 0x02
#define HKT_PATH_MAX 128

#define HK_SHMLIST_BEG 0xffff0000
#define HK_SHMLIST_HEAD 0x00ffff00
#define HK_SHMLIST_EOF (~HK_SHMLIST_BEG)

static pthread_mutex_t hk_key_mutex = PTHREAD_MUTEX_INITIALIZER;
static int hk_keyoff = 1;
static int hk_last_freekey = 0;

/* prev<- self -> behind */
typedef int hk_shmlist_entry[3];

typedef struct hk_task {
    int hkt_type;
    key_t hkt_key;
    int hkt_index;
    size_t hkt_buflen;
    char hkt_path[HKT_PATH_MAX];
} hk_task_t;

typedef struct hk_info {
    int hki_iput;
    int hki_ntask;
    int hki_hdlen;
    hk_shmlist_entry hki_task_head; /* active task head  */
    hk_shmlist_entry hki_task_tail;
    sem_t hki_mutex;
    sem_t hki_nempty;
    sem_t hki_condvar;
    /* task array */
} hk_info_t;

/* should shmdt hk_info_t returned by hkipp */
int hki_init(int ntask, hk_info_t **hkipp)
{
    int shmid, ret;
    char *data = NULL;
    hk_task_t *hktp = NULL;
    hk_info_t *hkip = NULL;
    size_t sz = sizeof(hk_info_t) + 
                sizeof(hk_task_t) * ntask;
                
    if( ((shmid = shmget(HK_SHM_KEY, sz, HK_SHM_MODE)) < 0) || 
        ((hkip = shmat(shmid, NULL, 0)) == (void *)-1) )
        return -1;
        
    hkip->hki_hdlen = sizeof(hk_info_t);
    hkip->hki_ntask = ntask;
    hkip->hki_iput = 0;
    hkip->hki_task_head[0] = hkip->hki_task_tail[0] = HK_SHMLIST_BEG; 
    hkip->hki_task_head[1] = hkip->hki_task_tail[1] = HK_SHMLIST_HEAD; 
    hkip->hki_task_head[2] = hkip->hki_task_tail[2] = HK_SHMLIST_EOF;

    sem_init(&hkip->hki_mutex, 1, 1);
    sem_init(&hkip->hki_nempty, 1, ntask);
    sem_init(&hkip->hki_condvar, 1, 0);

    *hkipp = hkip;
    return shmid;
}

/* init hkt_entry */
void hkt_init(hk_info_t *hkip) 
{
    int i = 0;
    hk_task_t *hktp = ((char *)hkip) + hkip->hki_hdlen;
    for( ; i<hkip->hki_ntask; i++,hktp++) {
        hktp->hkt_index = i;
    }
}

int hk_get_next_shmkey(hk_info_t *hkip)
{
    int ret;
    pthread_mutex_lock(&hk_key_mutex);
    if(hk_last_freekey != 0) {
        ret = hk_last_freekey;
        hk_last_freekey = 0;
        goto done;
    }
    if(hk_keyoff <= hkip->hki_ntask) {
        ret = HK_SHM_KEY + hk_keyoff;
        hk_keyoff++;
        goto done;
    }
    ret = -1;
done:
    pthread_mutex_unlock(&hk_key_mutex);
    return ret;
}

/* assert have hold hki_mutex lock */
static int 
hk_post_task_impl(hk_info_t *hkip, hk_task_t *hktp)
{
    if(hkip->hki_task_head[2] == HK_SHMLIST_EOF)
        hkip->hki_task_head[2] = hktp->hkt_index;
    hkip->hki_task_tail[0] = hkip->hki_task_head[1];
    hkip->hki_task_tail[1] = hktp->hkt_index;
    if(++hkip->hki_iput >= hkip->hki_ntask)
        hkip->hki_iput = 0;
}

int hk_post_task(int type, key_t key, 
                char *data, size_t dlen, int fd)
{
    int shmid, ret;
    hk_task_t *hktp = NULL;
    hk_info_t *hkip = NULL;
    char tmppath[32];
    char tmppath2[32];
    
    if( (type < HKT_TYPE_READ) || (type > HKT_TYPE_WRITE) || 
        !data || (dlen <= 0) || (fd < 0) ||
        ((shmid = shmget(HK_SHM_KEY, 0, HK_SHM_MODE)) < 0) || 
        ((hkip = shmat(shmid, NULL, 0)) == (void *)-1) ) {
        return -1;
    }
    
    snprintf(tmppath, 32, "/proc/self/fd/%d", fd);
    if(readlink(tmppath, tmppath2, 31) < 0)
        return -1;

    if(sem_trywait(&hkip->hki_nempty) == -1) {
        ret = errno;
        goto done;
    }
    
    sem_wait(&hkip->hki_mutex);
    hktp = (char *)hkip + hkip->hki_hdlen + 
           sizeof(hk_task_t)*hkip->hki_iput;
    hktp->hkt_type = type;
    hktp->hkt_buflen = dlen;
    strncpy(hktp->hkt_path, tmppath2, strlen(tmppath2)+1);
    hktp->hkt_key = hk_get_next_shmkey(hkip);

    hk_post_task_impl(hkip, hktp);
    sem_post(&hkip->hki_mutex);
done:
    shmdt(hkip);
    return ret;
}

ssize_t write(int fd,const char* buf,size_t count)
{
    int shmid, ret;
    char *data = NULL;
    hk_task_t *hktp = NULL;
    hk_info_t *hkip = NULL;
    if( (fd < 0) || !buf || (count <= 0) || 
         )
        return -1;
    
    if(sem_trywait(&hkip->hki_nempty) == -1) {
        ret = errno;
        goto done;
    }

    if((data = malloc(count)) == NULL) {
        ret = ENOMEM;
        sem_post(&hkip->hki_nempty);
        goto done;
    }
        
    sem_wait(&hkip->hki_mutex);
    hktp = &hkip->hki_task[hkip->hki_iput];
    if(++hkip->hki_iput >= HK_MAX_TASK)
        hkip->hki_iput = 0;
    sem_post(&hkip->hki_mutex);
    hktp->hkt_fd = fd;
    hktp->hkt_type = HKT_TYPE_WRITE;
    hktp->hkt_buflen = count;
    hktp->hkt_buf = data;      
    sem_post(&hkip->hki_nstored);
done :
    shmdt(hkip);
    return ret;
}

ssize_t read(int fd,const char* buf,size_t count)
{
    void *hook_handle;

    return count;
}

int open(const char *pathname, int flags)
{
    void *hook_handle;
    int (*open)(const char*, int);
    int result = -1;
 
    if( ((hook_handle = dlopen(LIBC_PATH, RTLD_LAZY)) == NULL) ||
        ((open = dlsym(hook_handle, "open")) == NULL))
        return result;
        
    result = open(pathname, flags);
    dlclose(hook_handle);
    
    return result;
}

int close(int fd)
{
    void *hook_handle;
    int (*close)(int);
    int result = -1;

    if( ((hook_handle = dlopen(LIBC_PATH, RTLD_LAZY)) == NULL) ||
        ((close = dlsym(hook_handle, "close")) == NULL) )
        return result;

    result = close(fd);
    dlclose(hook_handle);
  
    return result;
}

