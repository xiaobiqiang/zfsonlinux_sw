/******************************************************************************
 *          Copyright (c) 2017 by Ceresdata. All rights reserved
 ******************************************************************************
 * filename   : cm_pmm.c
 * author     : wbn
 * create date: 2017年11月14日
 * description: TODO:
 *
 *****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <pthread.h>
#include <semaphore.h>
#include <memory.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>

/*
Device:         rrqm/s   wrqm/s     r/s     w/s    rMB/s    wMB/s avgrq-sz avgqu-sz   await r_await w_await  svctm  %util
sda               0.00     1.28   41.37   10.88     1.51     0.07    61.85     1.62   30.99   12.08  102.86   3.87  20.20

*/
/*============= 配置部分 ==============*/
/* 最大文件个数 */
#define CM_PMM_MAX_FILE_CNT 60
/* 从r/s列开始计算 */
#define CM_PMM_FILE_OFFSET 4

/* 秒级统计缺省周期 1-59*/
#define CM_PMM_STAT_PERIOD_SEC 5

/* 配置文件
格式:
period=<xx>
minute=<aa>
hour=<bb>
day=<cc>
month=<dd>
*/
#define CM_PMM_CFG_FILE "/etc/ceres_pmm.conf"

/* 临时文件 */
#define CM_PMM_IOSTAT_TMP "/tmp/iostat_xm_tmp"
/* 生成临时文件命令 */
#define CM_PMM_IOSTAT_CMD "iostat -xm |grep '^zd' >/tmp/iostat_xm_tmp"
/* 统计文件目录 */
#define CM_PMM_DIR_IOSTAT_S "/var/performance_stat/iostat/minute/"
#define CM_PMM_DIR_IOSTAT_M "/var/performance_stat/iostat/hour/"
#define CM_PMM_DIR_IOSTAT_H "/var/performance_stat/iostat/day/"
#define CM_PMM_DIR_IOSTAT_D "/var/performance_stat/iostat/month/"

const char* g_pmm_data_name[] = {"rs", "ws", "rMBs", "wMBs"};

#define CM_PMM_LOG_BUFF_SIZE 512
#define CM_PMM_DATA_NAME_LEN 128
#define CM_PMM_OK 0
#define CM_PMM_FAIL 1

typedef enum {
    CM_PMM_DATA_IOPS_READ = 0,
    CM_PMM_DATA_IOPS_WRITE,
    CM_PMM_DATA_IO_READ,
    CM_PMM_DATA_IO_WRITE,
    CM_PMM_DATA_BUTT
} cm_pmm_data_e;

typedef enum {
    CM_PMM_PERIOD_SECOND = 0,
    CM_PMM_PERIOD_SEC_EXT,
    CM_PMM_PERIOD_MINUTE,
    CM_PMM_PERIOD_HOUR,
    CM_PMM_PERIOD_DAY,
    CM_PMM_PERIOD_BUTT
} cm_pmm_period_e;

typedef struct {
    char name[CM_PMM_DATA_NAME_LEN];
    double data[CM_PMM_PERIOD_BUTT][CM_PMM_DATA_BUTT];
} cm_pmm_data_t;

typedef struct cm_pmm_node_tt {
    struct cm_pmm_node_tt *pnext;
    cm_pmm_data_t info;
    char zval[CM_PMM_DATA_NAME_LEN];
} cm_pmm_node_t;

const char* g_pmm_cfg_name[CM_PMM_PERIOD_BUTT] = {"second", "minute", "hour", "day", "month"};

typedef struct {
    /* 秒级统计频率 */
    int period;

    /* 每个统计级别文件个数 */
    int cnt[CM_PMM_PERIOD_BUTT];
} cm_pmm_config_t;

typedef struct {
    cm_pmm_config_t cfginfo;
    cm_pmm_data_t sum;
    cm_pmm_node_t *plist;
} cm_pmm_iostat_t;

static cm_pmm_iostat_t g_pmm_iostat;

static void* cm_pmm_thread(void* arg);
static int cm_pmm_exec(const char* cmd, char *buff, int size);
static int cm_pmm_exec_int(const char* cmdforamt, ...);
static double cm_pmm_exec_double_ext(const char* cmdforamt, ...);
static int cm_pmm_exec_ext(char *buff, int size, const char* cmdforamt, ...);
#define CM_PMM_LOG(...)

static void cm_pmm_cfg_init(cm_pmm_config_t *pcfg)
{
    const char** pcfgname = g_pmm_cfg_name;
    int iloop = 0;
    int val = cm_pmm_exec_int("grep '^period' %s 2>/dev/null |awk -F'=' '{print $2}'",
                              CM_PMM_CFG_FILE);

    if((0 >= val) || (60 <= val)) {
        val = CM_PMM_STAT_PERIOD_SEC;
    }

    pcfg->period = val;

    while(iloop < CM_PMM_PERIOD_BUTT) {
        val = cm_pmm_exec_int("grep '^%s' %s 2>/dev/null |awk -F'=' '{print $2}'",
                              pcfgname[iloop],CM_PMM_CFG_FILE);

        if((0 >= val) || (CM_PMM_MAX_FILE_CNT < val)) {
            val = CM_PMM_MAX_FILE_CNT;
        }

        pcfg->cnt[iloop] = val;
        iloop++;
    }

    return;
}

int cm_pmm_init(void)
{
    int iret = 0;
    pthread_t handle;
    cm_pmm_iostat_t* piostat = &g_pmm_iostat;

    memset(piostat, 0, sizeof(cm_pmm_iostat_t));

    cm_pmm_exec_ext(NULL, 0, "mkdir -p %s", CM_PMM_DIR_IOSTAT_S);
    cm_pmm_exec_ext(NULL, 0, "mkdir -p %s", CM_PMM_DIR_IOSTAT_M);
    cm_pmm_exec_ext(NULL, 0, "mkdir -p %s", CM_PMM_DIR_IOSTAT_H);
    cm_pmm_exec_ext(NULL, 0, "mkdir -p %s", CM_PMM_DIR_IOSTAT_D);

    cm_pmm_cfg_init(&piostat->cfginfo);

    iret = pthread_create(&handle, NULL, cm_pmm_thread, (void*)piostat);

    if(0 != iret) {
        return CM_PMM_FAIL;
    }

    pthread_detach(handle);
    return CM_PMM_OK;
}

int main(int argc, char **argv)
{
    /* 检查进程是已经存在 */
    int cnt = cm_pmm_exec_int("ps -ef|grep -w '%s' |wc -l", argv[0]);

    if(3 < cnt) {
        printf("already run!\n");
        exit(1);
    }

    if(CM_PMM_OK != cm_pmm_init()) {
        printf("cm_pmm_init fail!\n");
        exit(1);
    }

    while(1) {
        sleep(10);
    }

    return 0;
}

static void cm_pmm_node_delete(cm_pmm_iostat_t *piostat, cm_pmm_node_t *node)
{
    cm_pmm_node_t *tmp = piostat->plist;

    if(piostat->plist == node) {
        piostat->plist = node->pnext;
        free(node);
        return;
    }

    while(NULL != tmp->pnext) {
        if(tmp->pnext == node) {
            tmp->pnext = node->pnext;
            free(node);
            return;
        }

        tmp = tmp->pnext;
    }

    return;
}

static void cm_pmm_node_update(cm_pmm_data_t *info)
{
    double *data = info->data[CM_PMM_PERIOD_SECOND];
    double *sum = info->data[CM_PMM_PERIOD_SEC_EXT];
    int iloop = 0;

    while(iloop < CM_PMM_DATA_BUTT) {
        *data = cm_pmm_exec_double_ext(
                    "grep -w '%s' %s |awk '{printf $%d}'",
                    info->name, CM_PMM_IOSTAT_TMP, (iloop + CM_PMM_FILE_OFFSET));
        *sum += *data;
        sum++;
        iloop++;
        data++;
    }

    /* 更新之后就从临时文件中删除 */
    (void)cm_pmm_exec_ext(NULL, 0, "sed -i '/^%s /d' %s",
                          info->name, CM_PMM_IOSTAT_TMP);
    return;
}

static void cm_pmm_iostat_update_sum(cm_pmm_data_t *info)
{
    double *data = info->data[CM_PMM_PERIOD_SECOND];
    double *sum = info->data[CM_PMM_PERIOD_SEC_EXT];
    int iloop = 0;

    while(iloop < CM_PMM_DATA_BUTT) {
        *data = cm_pmm_exec_double_ext(
                    "awk '{sum += $%d};END {printf sum}' %s",
                    (iloop + CM_PMM_FILE_OFFSET),CM_PMM_IOSTAT_TMP);
        *sum += *data;
        sum++;
        iloop++;
        data++;
    }

    return;
}

static void cm_pmm_get_zval_name(const char* devname, char *zval, int size)
{
    (void)cm_pmm_exec_ext(zval, size - 1,
                          "ls -l `stmfadm list-lu -v 2>/dev/null "
                          "|grep 'Data File' |awk '{print $4}' |grep '^/dev'` "
                          "|grep -w '%s' |awk '{printf $9}'", devname);
    return;
}

static void cm_pmm_iostat_second(cm_pmm_iostat_t *piostat)
{
    cm_pmm_node_t *tmp  = piostat->plist;
    cm_pmm_node_t *next = NULL;
    int cnt = 0;

    /* 生成临时文件 */
    (void)system(CM_PMM_IOSTAT_CMD);
    /* 统计总数 */
    cm_pmm_iostat_update_sum(&piostat->sum);

    /* 先检查之前存在的 */
    while(NULL != tmp) {
        cnt = cm_pmm_exec_int("grep -w '%s' %s |wc -l",
                              tmp->info.name, CM_PMM_IOSTAT_TMP);

        if(0 == cnt) {
            next = tmp->pnext;
            cm_pmm_node_delete(piostat, tmp);
            tmp = next;
            continue;
        }

        cm_pmm_node_update(&tmp->info);
        tmp = tmp->pnext;
    }

    /* 接下来如果还有就是新的 */
    do {
        cnt = cm_pmm_exec_int("cat %s |wc -l", CM_PMM_IOSTAT_TMP);

        if(0 == cnt) {
            break;
        }

        tmp = malloc(sizeof(cm_pmm_node_t));

        if(NULL == tmp) {
            CM_PMM_LOG("malloc fail");
            break;
        }

        memset(tmp, 0, sizeof(cm_pmm_node_t));

        /*取第一行*/
        if(CM_PMM_OK != cm_pmm_exec_ext(tmp->info.name, sizeof(tmp->info.name),
                                        "cat %s |sed -n '1p' |awk '{printf $1}'", CM_PMM_IOSTAT_TMP)) {
            free(tmp);
            break;
        }

        if(strlen(tmp->info.name) == 0) {
            free(tmp);
            break;
        }

        /* 取卷名称 ,如果取不到后面刷新的时候继续取*/
        cm_pmm_get_zval_name(tmp->info.name, tmp->zval, sizeof(tmp->zval));
        cm_pmm_node_update(&tmp->info);
        tmp->pnext = piostat->plist;
        piostat->plist = tmp;
    } while(1);

    return;
}

static void cm_pmm_iostat_save_each(FILE *handle, cm_pmm_data_t *info, int period)
{
    double *curr = info->data[period];
    double *next = NULL;
    const char **dataname = g_pmm_data_name;
    int iloop = 0;

    if(period < CM_PMM_PERIOD_DAY) {
        next = info->data[period + 1];
    }

    while(iloop < CM_PMM_DATA_BUTT) {
        fprintf(handle, "<%s>%.02f</%s>\n", *dataname, *curr, *dataname);

        if(NULL != next) {
            *next += *curr;
            next++;
        }

        *curr = 0.0;
        dataname++;
        curr++;
        iloop++;
    }

    return;
}

static void cm_pmm_iostat_save(cm_pmm_iostat_t *piostat, int period, const char* filename)
{
    FILE *handle = NULL;
    struct timeval tv;
    long tmnow = 0;
    cm_pmm_node_t *node = piostat->plist;

    if(period > CM_PMM_PERIOD_DAY) {
        return;
    }

    (void)gettimeofday(&tv, NULL);
    tmnow = tv.tv_sec;

    handle = fopen(filename, "w");

    if(NULL == handle) {
        CM_PMM_LOG("fopen(%s) fail", filename);
        return;
    }

    fprintf(handle, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    fprintf(handle, "<p>\n");

    /* 时间 */
    fprintf(handle, "<t>%ld</t>\n", tmnow);
    /* 先输出总的 */
    fprintf(handle, "<s>\n<n>sum</n>\n");
    cm_pmm_iostat_save_each(handle, &piostat->sum, period);
    fprintf(handle, "</s>\n");

    /* 详细的 */
    /*fprintf(handle, "<l>\n");*/

    while(NULL != node) {
        fprintf(handle, "<e>\n");

        if(node->info.name[0] == '\0') {
            /* 重新获取一下 */
            cm_pmm_get_zval_name(node->info.name, node->zval, sizeof(node->zval));
        }

        fprintf(handle, "<n>%s</n>\n", node->info.name);
        fprintf(handle, "<v>%s</v>\n", node->zval);
        cm_pmm_iostat_save_each(handle, &node->info, period);
        fprintf(handle, "</e>\n");
        node = node->pnext;
    }

    /*fprintf(handle, "</l>\n");*/
    fprintf(handle, "</p>\n");
    fclose(handle);
    return;
}

static void cm_pmm_iostat_check(const char *dir, int max)
{
    int cnt = 0;

    cnt = cm_pmm_exec_int("ls -l %s |grep '^-' |wc -l", dir);

    if(cnt <= max) {
        return;
    }

    cnt -= max;
    cm_pmm_exec_ext(NULL, 0, "cd %s;"
                    "rm -f `ls -l |grep '^-' |sed -n '1,%dp' |awk '{print $9}'`;"
                    "cd -", dir, cnt);
    return;
}

static void cm_pmm_iostat(cm_pmm_iostat_t *piostat, struct tm *now, int period)
{
    char tmpfile[CM_PMM_DATA_NAME_LEN] = {0};
    const char *filedir = NULL;

    switch(period) {
        case CM_PMM_PERIOD_SEC_EXT:
            snprintf(tmpfile, sizeof(tmpfile), "/tmp/s%04d%02d%02d%02d%02d%02d",
                     now->tm_year, now->tm_mon, now->tm_mday,
                     now->tm_hour, now->tm_min, now->tm_sec);
            filedir = CM_PMM_DIR_IOSTAT_S;
            break;

        case CM_PMM_PERIOD_MINUTE:
            snprintf(tmpfile, sizeof(tmpfile), "/tmp/m%04d%02d%02d%02d%02d",
                     now->tm_year, now->tm_mon, now->tm_mday,
                     now->tm_hour, now->tm_min);
            filedir = CM_PMM_DIR_IOSTAT_M;
            break;

        case CM_PMM_PERIOD_HOUR:
            snprintf(tmpfile, sizeof(tmpfile), "/tmp/h%04d%02d%02d%02d",
                     now->tm_year, now->tm_mon, now->tm_mday,
                     now->tm_hour);
            filedir = CM_PMM_DIR_IOSTAT_H;
            break;

        case CM_PMM_PERIOD_DAY:
            snprintf(tmpfile, sizeof(tmpfile), "/tmp/d%04d%02d%02d",
                     now->tm_year, now->tm_mon, now->tm_mday);
            filedir = CM_PMM_DIR_IOSTAT_D;
            break;

        default:
            return;
    }

    cm_pmm_iostat_save(piostat, period, tmpfile);
    cm_pmm_exec_ext(NULL, 0, "mv %s %s", tmpfile, filedir);
    cm_pmm_iostat_check(filedir, piostat->cfginfo.cnt[period]);
    return;
}

static void cm_pmm_get_time(struct tm *tin)
{
    struct timeval tv;
    struct tm *t;

    (void)gettimeofday(&tv, NULL);
    t = localtime(&tv.tv_sec);

    memcpy(tin, t, sizeof(struct tm));
    tin->tm_year += 1900;
    tin->tm_mon += 1;
    return;
}

static void* cm_pmm_thread(void* arg)
{
    struct tm pre;
    struct tm now;
    cm_pmm_iostat_t* piostat = (cm_pmm_iostat_t*)arg;
    int sec_period = piostat->cfginfo.period;

    cm_pmm_get_time(&pre);

    while(1) {
        cm_pmm_iostat_second(piostat);
        cm_pmm_get_time(&now);

        if(0 == (now.tm_sec % sec_period)) {
            /* 秒级统计 */
            cm_pmm_iostat(piostat, &now, CM_PMM_PERIOD_SEC_EXT);
        }

        if(pre.tm_min != now.tm_min) {
            /* 分钟到期 */
            cm_pmm_iostat(piostat, &now, CM_PMM_PERIOD_MINUTE);
        }

        if(pre.tm_hour != now.tm_hour) {
            /* 小时到期 */
            cm_pmm_iostat(piostat, &now, CM_PMM_PERIOD_HOUR);
        }

        if(pre.tm_mday != now.tm_mday) {
            /* 天到期 */
            cm_pmm_iostat(piostat, &now, CM_PMM_PERIOD_DAY);
        }

        memcpy(&pre, &now, sizeof(struct tm));
        sleep(1);
    }

    return NULL;
}

static int cm_pmm_exec(const char* cmd, char *buff, int size)
{
    FILE *handle = popen(cmd, "r");

    if(NULL == handle) {
        CM_PMM_LOG("popen(%s),fail", cmd);
        return CM_PMM_FAIL;
    }

    if(NULL != buff && 0 != size) {
        size = fread(buff, 1, size - 1, handle);
        buff[size] = '\0';
    }

    return pclose(handle);
}

static int cm_pmm_exec_ext(char *buff, int size, const char* cmdforamt, ...)
{
    va_list args;
    char cmdbuf[CM_PMM_LOG_BUFF_SIZE] = {0};

    va_start(args, cmdforamt);
    (void)vsnprintf(cmdbuf, CM_PMM_LOG_BUFF_SIZE - 1, cmdforamt, args);
    va_end(args);
    return cm_pmm_exec(cmdbuf, buff, size);
}

static double cm_pmm_exec_double(const char* cmd)
{
    char buff[64] = {0};
    double val = 0;

    if(CM_PMM_OK != cm_pmm_exec(cmd, buff, sizeof(buff))) {
        return 0;
    }

    val = atof(buff);
    return val;
}

static double cm_pmm_exec_double_ext(const char* cmdforamt, ...)
{
    va_list args;
    char cmdbuf[CM_PMM_LOG_BUFF_SIZE] = {0};

    va_start(args, cmdforamt);
    (void)vsnprintf(cmdbuf, CM_PMM_LOG_BUFF_SIZE - 1, cmdforamt, args);
    va_end(args);
    return cm_pmm_exec_double(cmdbuf);
}

static int cm_pmm_exec_int(const char* cmdforamt, ...)
{
    va_list args;
    char cmdbuf[CM_PMM_LOG_BUFF_SIZE] = {0};

    va_start(args, cmdforamt);
    (void)vsnprintf(cmdbuf, CM_PMM_LOG_BUFF_SIZE - 1, cmdforamt, args);
    va_end(args);
    return (int)cm_pmm_exec_double(cmdbuf);
}

