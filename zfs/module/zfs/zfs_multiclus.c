#ifdef _KERNEL
#include <sys/ddi.h>
#include <sys/byteorder.h>
#include <sys/sysmacros.h>
#include <sys/atomic.h>
#include <sys/sysmacros.h>
#include <sys/cmn_err.h>
#include <sys/crc32.h>
#include <sys/dmu.h>
#include <sys/dmu_impl.h>
#include <sys/dmu_tx.h>
#include <sys/dbuf.h>
#include <sys/dnode.h>
#include <sys/zfs_context.h>
#include <sys/dmu_objset.h>
#include <sys/dmu_traverse.h>
#include <sys/dsl_dataset.h>
#include <sys/dsl_dir.h>
#include <sys/dsl_pool.h>
#include <sys/dsl_synctask.h>
#include <sys/dsl_prop.h>
#include <sys/dmu_zfetch.h>
#include <sys/zfs_ioctl.h>
#include <sys/dbuf.h>
#include <sys/zap.h>
#include <sys/zio_checksum.h>
#include <sys/sa.h>
#include <sys/arc.h>
#include <sys/zfs_multiclus.h>
//#include <sys/zfs_group.h>
#include <sys/dsl_dataset.h>
#include <sys/spa.h>
#include <sys/zfs_group_dtl.h>
#include <sys/zfs_dir.h>
#include <sys/cluster_san.h>
#include <sys/list.h>
#include <asm-generic/errno.h>



/* multiclus golable struct */
zfs_multiclus_workers_t	zfs_multiclus_global_workers;  // = {0};

/* wait variables */
uint32_t	zfs_multiclus_wait_io_time = 20;		/* s */
uint32_t	zfs_multiclus_wait_write_io_time = 20;		/* s */
uint32_t	zfs_multiclus_timeout = 10;		/* s */
uint32_t	zfs_multiclus_write_timeout = 60;		/* s */
uint64_t	zfs_multiclus_master_wait_time = ZFS_MULTICLUS_CVWAIT_TIME;
uint64_t	zfs_multiclus_master2_wait_count = 5;
uint64_t	zfs_multiclus_master3_wait_count = 9;
uint64_t	zfs_multiclus_master4_wait_count = 13;
uint64_t	zfs_multiclus_slave_wait_time = ZFS_MULTICLUS_CVWAIT_TIME;
uint64_t	zfs_multiclus_master_update_wait_time = ZFS_MULTICLUS_CVWAIT_TIME * 2;

/* task num */
uint32_t	zfs_multiclus_server_action_max_tasks = 256;
uint32_t	zfs_multiclus_mp_post_action_max_tasks = 256;

/* server rx process frames taskq variables */
volatile int	zfs_multiclus_server_nworkers = 512;
volatile int	zfs_multiclus_rx_mp_worker_nworkers = 32;
volatile int	zfs_multiclus_dispatch_nworkers = 32;

/* group table variables */
kmutex_t	multiclus_mtx;
kmutex_t	multiclus_mtx_update_record;
zfs_multiclus_group_t	*zfs_multiclus_table = NULL;

/* hash variables */
kmutex_t	zfs_multiclus_tx_hash_mtx;
zfs_multiclus_hash_header_t	*zfs_multiclus_tx_hash = NULL;
kmutex_t	zfs_multiclus_rx_hash_mtx;
zfs_multiclus_hash_header_t	*zfs_multiclus_rx_hash = NULL;

/* others */
boolean_t	zfs_multiclus_mac_initialized = B_FALSE;
char	rpc_port_name[MAXNAMELEN] = {0};
char	rpc_port_addr[MAXNAMELEN] = {0};
uint64_t	zfs_multiclus_node_id = 0;
int	DOUBLE_MASTER_PANIC = 0;
int timeout_chk_flag = 1;
int register_debug_flag = 0;

extern int ZFS_GROUP_DTL_ENABLE;

typedef struct zfs_multiclus_worker_para{
	list_node_t	worker_para_node;
	uint8_t	frame_type;
	zfs_multiclus_worker_t	*worker;
	zfs_group_header_t	*msg_header;
	zfs_msg_t	*msg_data;
	char	*omsg;
} zfs_multiclus_worker_para_t;

static mod_hash_t *zfs_multiclus_find_hash_header(uint64_t spa_id, uint64_t os_id, boolean_t tx);
static zfs_multiclus_hash_t *zfs_multiclus_find_hash_member(mod_hash_t *modhash, uint64_t hash_key);
static mod_hash_t *zfs_multiclus_fill_hash_table(uint64_t spa_id, uint64_t os_id, boolean_t tx);
static zfs_multiclus_hash_t *zfs_multiclus_create_hash_member(uint64_t hash_key, boolean_t rx_flag);
static void zfs_multiclus_destroy_hash_member(zfs_multiclus_hash_t *hash_member);
static void zfs_multiclus_insert_hash(mod_hash_t *modhash, zfs_multiclus_hash_t *blk_hash);
static int zfs_multiclus_remove_hash(mod_hash_t *modhash, zfs_multiclus_hash_t *blk_hash);
void zfs_multiclus_handle_frame(zfs_multiclus_worker_t *action_worker, zfs_group_header_t *msg_header, zfs_msg_t *msg_data);
int zfs_multiclus_get_group(char *group_name, zfs_multiclus_group_t **group);
static void zfs_multiclus_record_reg_and_update(zfs_group_header_t *msg_header, zfs_group_reg_t *reg_msg);
static void zfs_multiclus_update_group(zfs_group_header_t *msg_header, zfs_msg_t *msg_data);
static int zfs_multiclus_write_group_reply_msg(void *group_msg, zfs_group_header_t *msg_head, uint8_t reply_type);
static int zfs_multiclus_write_operate_reply_msg(zfs_group_header_t *msg_header, zfs_msg_t *msg_data);
// static int zfs_multiclus_get_rx_hash_header(uint64_t spa_id, uint64_t os_id, boolean_t tx);
static void zfs_multiclus_worker_wakeup(zfs_multiclus_worker_t *w, zfs_multiclus_worker_para_t *para);
static void zfs_multiclus_rx_operate_check(void *arg);
static void zfs_multiclus_load_config(void);
int zmc_set_node_type(char* group_name, char* fs_name, zfs_multiclus_node_type_t node_type);
int zmc_do_set_node_type(zfs_multiclus_group_record_t* record, char *fs_name, zfs_multiclus_node_type_t node_type);
zfs_multiclus_group_record_t* zmc_find_record(zfs_multiclus_group_t* group, zfs_multiclus_node_type_t node_type);
zfs_multiclus_node_type_t zmc_get_node_type(objset_t* os);
uint64_t zmc_node_type_to_os_type(zfs_multiclus_node_type_t node_type);
int zfs_multiclus_check_group_master_count(const char *group_name);
uint64_t zfs_multiclus_get_log_index(void);
int zfs_multiclus_set_node_type_to_os(char *group_name, char *fs_name, zfs_multiclus_node_type_t node_type,
 	uint64_t master_spa, uint64_t master_os, uint64_t master_root);
void zfs_multiclus_clear_group(char *group_name);
// void zfs_multiclus_set_node_status(char* group_name, uint64_t spa_id, uint64_t os_id, status_type_t status);
int zmc_change_objset_node_type(char* group_name, char *fsname, objset_t* os, zfs_multiclus_node_type_t new_type);





#define	ISDIGIT(_c) \
	((_c) >= '0' && (_c) <= '9')

#define	ISXDIGIT(_c) \
	(ISDIGIT(_c) || \
	((_c) >= 'a' && (_c) <= 'f') || \
	((_c) >= 'A' && (_c) <= 'F'))

#define	ISLOWER(_c) \
	((_c) >= 'a' && (_c) <= 'z')

#define	ISUPPER(_c) \
	((_c) >= 'A' && (_c) <= 'Z')

void 
zfs_multiclus_group_record_init(char *group_name, char *fs_name, uint64_t spa_id, uint64_t os_id, uint64_t root, 
		zfs_multiclus_node_type_t node_type, uint64_t avail_size, uint64_t used_size, uint64_t load_ios, uint64_t node_id)
{
	int name_len = 0;
	zfs_group_header_t msg_header = {0};

	zfs_group_reg_t *reg_msg = kmem_zalloc(sizeof(zfs_group_reg_t), KM_SLEEP);

	name_len = strlen(group_name);
	reg_msg->spa_id = spa_id;
	reg_msg->os_id = os_id;
	reg_msg->hostid= zfs_multiclus_node_id;
	reg_msg->node_type = node_type;
	reg_msg->root = root;
	reg_msg->avail_size = avail_size;
	reg_msg->used_size = used_size;
	reg_msg->load_ios = load_ios;
	reg_msg->node_id = node_id;
	reg_msg->node_status.status = ZFS_MULTICLUS_NODE_ONLINE;
	bcopy(fs_name, reg_msg->fsname, MAX_FSNAME_LEN);
	bcopy(group_name, reg_msg->group_name, name_len);
	reg_msg->group_name[strlen(group_name)] = '\0';
	reg_msg->group_name_len = name_len;
	bcopy(rpc_port_addr, reg_msg->rpc_addr, ZFS_MULTICLUS_RPC_ADDR_SIZE);

	bcopy(group_name, msg_header.group_name, name_len);
	msg_header.group_name[strlen(group_name)] = '\0';
	msg_header.group_name_len = name_len;
	zfs_multiclus_record_reg_and_update(&msg_header, reg_msg);
	kmem_free(reg_msg, sizeof(zfs_group_reg_t));
}

static void
zfs_multiclus_post_frame(zfs_multiclus_worker_para_t *work_para)
{
	zfs_multiclus_worker_t *action_worker = NULL;
	uint64_t key = 0;

	if (work_para->msg_header->msg_type == ZFS_MULTICLUS_OPERATE_MSG) {
		key = work_para->msg_header->data_index;
		action_worker = &zfs_multiclus_global_workers.zfs_multiclus_action_workers.zfs_multiclus_action_worker_nodes[(key) % \
			(zfs_multiclus_global_workers.zfs_multiclus_action_workers.zfs_multiclus_action_running_workers)];
	}
	zfs_multiclus_handle_frame(action_worker, work_para->msg_header, work_para->msg_data);

	return;
}


static void
zfs_multiclus_transfer_frame(zfs_multiclus_worker_para_t *para)
{
	zfs_multiclus_worker_t *rx_worker = NULL;
	uint64_t tx_data_index = 0;

	tx_data_index = para->msg_header->data_index;
	rx_worker = &zfs_multiclus_global_workers.zfs_multiclus_rx_workers.zfs_multiclus_rx_worker_nodes[(tx_data_index) % zfs_multiclus_rx_mp_worker_nworkers];
	zfs_multiclus_worker_wakeup(rx_worker, para);
}

volatile int ztq_test_deadbeef = 1;
static void
zfs_multiclus_test_data_error(void* header, void* data, uint64_t data_len)
{
	uint32_t test_tmp = 0;
	uint64_t *test_var = NULL;
	header = header;
	data = data;
	data_len = data_len;
	if(ztq_test_deadbeef==1){
		if(header==NULL || data==NULL){
			panic("[ztq]BAD POINTER:%p,%p",header,data);;
		}else{
			test_var = (uint64_t *)header;
			test_tmp += ((*test_var) == 0xdeadbeefdeadbeefULL);
			test_var = (uint64_t *)data;
			test_tmp += ((*test_var) == 0xdeadbeefdeadbeefULL)<<1;
			if(test_tmp)
				panic("[ztq]DEADBEEF:%d,%llx",test_tmp,(longlong_t)data_len);
		}
	}
}

static void
zfs_multiclus_rx(cs_rx_data_t *cs_data, void *arg)
{
	zfs_group_header_t *group_header = (zfs_group_header_t *)cs_data->ex_head;
	zfs_msg_t *group_data = (zfs_msg_t *)cs_data->data;
	zfs_multiclus_worker_para_t *work_para = NULL;

	if (B_FALSE == zfs_multiclus_global_workers.b_initialized) {
		csh_rx_data_free( cs_data, B_TRUE);
		return;
	}
	group_header = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
	group_data = vmem_zalloc(cs_data->data_len, KM_SLEEP);
	work_para = kmem_zalloc(sizeof(zfs_multiclus_worker_para_t), KM_SLEEP);
	bcopy(cs_data->ex_head, group_header, sizeof(zfs_group_header_t));
	bcopy(cs_data->data, group_data, cs_data->data_len);
	zfs_multiclus_test_data_error((void *)group_header,(void *)group_data, (uint64_t)cs_data->data_len);
	work_para->msg_header = group_header;
	work_para->msg_data = group_data;
	group_header->cs_data = cs_data;
	group_header->work_para = (void *)work_para;
	/*wake up zfs_multiclus_rx_mp_worker_frame*/
	zfs_multiclus_transfer_frame(work_para);
}

static void zfs_multiclus_server_operate(zfs_multiclus_worker_para_t *multiclus_para)
{
	uint64_t data_len = 0;
	uint64_t rx_length;
	void *data = NULL;
	zfs_group_server_para_t *server_para = NULL;
	zfs_multiclus_worker_para_t *work_para = NULL;
	zfs_msg_t *nmsg_data = NULL;
	zfs_group_header_t *nmsg_header = NULL;


	server_para = kmem_zalloc(sizeof(zfs_group_server_para_t), KM_SLEEP);
	nmsg_header = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
	nmsg_data = (zfs_msg_t *) zfs_group_alloc_data(multiclus_para->msg_header, 1, &rx_length);
	data_len = multiclus_para->msg_header->length;
	data = (void *)((char *)multiclus_para->msg_data);
	zfs_group_fill_data(multiclus_para->msg_header, 0, 0, data_len, data, nmsg_data, nmsg_header);
	server_para->msg_header = nmsg_header;
	server_para->msg_data = nmsg_data;

	zfs_group_server_rx(server_para);

	zfs_multiclus_write_operate_reply_msg(nmsg_header, nmsg_data);

	work_para = multiclus_para->msg_header->work_para;
	zfs_group_free_data(nmsg_header, (void *)nmsg_data, rx_length);
	csh_rx_data_free(multiclus_para->msg_header->cs_data, B_TRUE);
	kmem_free(multiclus_para->msg_header, sizeof(zfs_group_header_t));
	vmem_free(multiclus_para->msg_data, data_len);
	kmem_free(multiclus_para, sizeof(zfs_multiclus_worker_para_t));
	kmem_free(nmsg_header, sizeof(zfs_group_header_t));
	kmem_free(server_para, sizeof(zfs_group_server_para_t));
	kmem_free(work_para, sizeof(zfs_multiclus_worker_para_t));
}

static void
zfs_multiclus_worker_wakeup(zfs_multiclus_worker_t *w, zfs_multiclus_worker_para_t *para)
{
	mutex_enter(&w->worker_lock);
	w->worker_ntasks++;
	list_insert_tail(&w->worker_para_list, para);
	if ((w->worker_flags & ZFS_MULTICLUS_WORKER_ACTIVE) == 0) {
		cv_broadcast(&w->worker_cv);
	}
	mutex_exit(&w->worker_lock);
}

static void
zfs_multiclus_server_worker_frame(void *arg)
{
	zfs_multiclus_worker_t	*action_worker = (zfs_multiclus_worker_t *)arg;
	zfs_multiclus_worker_para_t *work_para;
	clock_t time = drv_usectohz(10);

	mutex_enter(&action_worker->worker_lock);
	atomic_add_32(&zfs_multiclus_global_workers.zfs_multiclus_action_workers.zfs_multiclus_action_running_workers, 1);
	action_worker->worker_flags |= ZFS_MULTICLUS_WORKER_STARTED | ZFS_MULTICLUS_WORKER_ACTIVE;
	while ((action_worker->worker_flags & ZFS_MULTICLUS_WORKER_TERMINATE) == 0) {
		while ((work_para = list_head(&action_worker->worker_para_list))) {
			list_remove(&action_worker->worker_para_list, work_para);
			mutex_exit(&action_worker->worker_lock);

			if (work_para->frame_type == ZFS_MULTICLUS_OPERATE_MSG) {
				work_para->worker = action_worker;
				if (taskq_dispatch(action_worker->worker_taskq,
				    (void (*)(void *))zfs_multiclus_server_operate,
				    work_para, TQ_NOSLEEP) == 0) {
					cmn_err(CE_WARN, "dispatch server operate fail,to do directly");
					zfs_multiclus_server_operate(work_para);
				}
			} else {
				cmn_err(CE_WARN, " work frame msg type unknown;%d",
				    work_para->frame_type);
			}
			mutex_enter(&action_worker->worker_lock);
			action_worker->worker_ntasks --;
		}
		action_worker->worker_flags &= ~ZFS_MULTICLUS_WORKER_ACTIVE;
		cv_timedwait(&action_worker->worker_cv, &action_worker->worker_lock, ddi_get_lbolt() + time);
		action_worker->worker_flags |= ZFS_MULTICLUS_WORKER_ACTIVE;
	}
	mutex_exit(&action_worker->worker_lock);
	
	action_worker->worker_flags &= ~(ZFS_MULTICLUS_WORKER_STARTED | ZFS_MULTICLUS_WORKER_ACTIVE);
	atomic_add_32(&zfs_multiclus_global_workers.zfs_multiclus_action_workers.zfs_multiclus_action_running_workers, -1);
	list_destroy(&action_worker->worker_para_list);
}

static void
zfs_multiclus_start_reg(char *groupname, uint64_t target_spa, uint64_t target_os, start_reg_types_t start_type)
{
	int i = 0;
	int j = 0;

	mutex_enter(&multiclus_mtx);
	for (; i < ZFS_MULTICLUS_GROUP_TABLE_SIZE; i++){
		if(zfs_multiclus_table[i].used && 
			(0 == strncmp(zfs_multiclus_table[i].group_name, groupname, strlen(groupname))))	{
			mutex_enter(&zfs_multiclus_table[i].multiclus_group_mutex);
			for (j = 0; j < ZFS_MULTICLUS_GROUP_NODE_NUM; j++){
				if (zfs_multiclus_table[i].multiclus_reg[j].used){
					mutex_enter(&zfs_multiclus_table[i].multiclus_reg[j].reg_timer_lock);
					if (start_type == EXCEPT_SOMEONE
						&& (zfs_multiclus_table[i].multiclus_reg[j].spa_id != target_spa
						|| zfs_multiclus_table[i].multiclus_reg[j].os_id != target_os)){
						cv_broadcast(&zfs_multiclus_table[i].multiclus_reg[j].reg_timer_cv);
						mutex_exit(&zfs_multiclus_table[i].multiclus_reg[j].reg_timer_lock);
						continue;
					} else if (start_type == WAKEUP_SOMEONE
								&& zfs_multiclus_table[i].multiclus_reg[j].spa_id == target_spa
								&& zfs_multiclus_table[i].multiclus_reg[j].os_id == target_os) {
						cv_broadcast(&zfs_multiclus_table[i].multiclus_reg[j].reg_timer_cv);
						mutex_exit(&zfs_multiclus_table[i].multiclus_reg[j].reg_timer_lock);
						break;
					}
					mutex_exit(&zfs_multiclus_table[i].multiclus_reg[j].reg_timer_lock);
				}
			}
			mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
			break;
		}
	}

	mutex_exit(&multiclus_mtx);
	
	return;
}

static void 
zfs_multiclus_change_master_to_record(char *groupname, char *new_master_fsname, 
	uint64_t new_master_spa, uint64_t new_master_os, uint64_t new_master_root, 
	uint64_t old_master_spa, uint64_t old_master_os, zfs_multiclus_node_type_t old_node_type)
{
	int i = 0;
	int j = 0;
	int err = 0;
	int count = 0;
	uint64_t local_spa = 0;
	uint64_t local_os = 0;
	objset_t *os = NULL;

	uint64_t os_is_master = 0;
	uint64_t os_node_type = 0; 
	spa_t * os_spa = NULL;
	
	count = zfs_multiclus_check_group_master_count((const char *)groupname);
	if (count >= 2) {
		if (DOUBLE_MASTER_PANIC) {
			zfs_panic_recover("[%s %d] %d, DOUBLE_MASTER A new_master_spa(0x%llx) == old_master_spa(0x%llx), new_master_os(0x%llx) == old_master_os(0x%llx)", 
				__func__, __LINE__, count, (unsigned long long)new_master_spa, (unsigned long long)old_master_spa,
				(unsigned long long)new_master_os, (unsigned long long)old_master_os);
		} else {
			cmn_err(CE_WARN, "[%s %d] %d, DOUBLE_MASTER A new_master_spa(0x%llx) == old_master_spa(0x%llx), new_master_os(0x%llx) == old_master_os(0x%llx)",
				__func__, __LINE__, count, (unsigned long long)new_master_spa, (unsigned long long)old_master_spa,
				(unsigned long long)new_master_os, (unsigned long long)old_master_os);
		}
	}

	mutex_enter(&multiclus_mtx);
	for (; i < ZFS_MULTICLUS_GROUP_TABLE_SIZE; i++) {
		if(zfs_multiclus_table[i].used && 
			(0 == strncmp(zfs_multiclus_table[i].group_name, groupname, strlen(groupname)))) {
			mutex_enter(&zfs_multiclus_table[i].multiclus_group_mutex);
			for (j = 0; j < ZFS_MULTICLUS_GROUP_NODE_NUM; j++){
				if (zfs_multiclus_table[i].multiclus_group[j].used){
					
					if (zfs_multiclus_table[i].multiclus_group[j].spa_id == new_master_spa &&
						zfs_multiclus_table[i].multiclus_group[j].os_id == new_master_os) {
						zfs_multiclus_table[i].multiclus_group[j].node_type = ZFS_MULTICLUS_MASTER;
					} else if (zfs_multiclus_table[i].multiclus_group[j].spa_id == old_master_spa &&
						zfs_multiclus_table[i].multiclus_group[j].os_id == old_master_os) {
						zfs_multiclus_table[i].multiclus_group[j].node_type = old_node_type;
					}
					err = dmu_objset_hold((const char*)zfs_multiclus_table[i].multiclus_group[j].fsname, FTAG, &os);
					if (err == 0) {
						local_spa = spa_guid(dmu_objset_spa(os));
						local_os = dmu_objset_id(os);
						if (local_spa == new_master_spa && local_os == new_master_os) {
							os_is_master = B_TRUE;
							os->os_is_master = os_is_master;
							os_node_type = OS_NODE_TYPE_SLAVE;
							os->os_node_type = os_node_type;
							if(zfs_multiclus_table[i].multiclus_group[j].node_status.status
								!= ZFS_MULTICLUS_NODE_ONLINE)
							{
								zfs_multiclus_table[i].multiclus_group[j].node_status.status
								= ZFS_MULTICLUS_NODE_ONLINE;
								zfs_multiclus_table[i].multiclus_group[j].node_status.last_update_time
								= gethrtime();
							}
							zfs_unlinked_drain(dmu_objset_get_user(os));
						} else if (local_spa == old_master_spa && local_os == old_master_os) {
							os_is_master = B_FALSE;
							os->os_is_master = os_is_master;
							os_node_type = zmc_node_type_to_os_type(old_node_type);
							os->os_node_type = os_node_type;
						}

						os->os_last_master_spa = os->os_master_spa;
						os->os_last_master_os = os->os_master_os;
						os->os_master_spa = new_master_spa;
						os->os_master_os = new_master_os;
						os->os_master_root = new_master_root;
						if(debug_nas_group_dtl == 2){
							cmn_err(CE_WARN, "%s %d (last) 0x%llx, 0x%llx, (current) x%llx, 0x%llx", __func__, __LINE__,
								(unsigned long long) os->os_last_master_spa,(unsigned long long)os->os_last_master_os,
								(unsigned long long) os->os_master_spa, (unsigned long long)os->os_master_os);
						}

						os_spa = dmu_objset_spa(os);
						dmu_objset_rele(os, FTAG);
						dsl_prop_set_int((const char*)(zfs_multiclus_table[i].multiclus_group[j].fsname), 
							zfs_prop_to_name(ZFS_PROP_MASTER), ZPROP_SRC_LOCAL, os_is_master);       /*os->os_is_master*/
						dsl_prop_set_int((const char*)(zfs_multiclus_table[i].multiclus_group[j].fsname), 
							zfs_prop_to_name(ZFS_PROP_NODE_TYPE),ZPROP_SRC_LOCAL, os_node_type);	 /*os->os_node_type*/
						dsl_prop_set_int((const char*)(zfs_multiclus_table[i].multiclus_group[j].fsname), 
							zfs_prop_to_name(ZFS_PROP_MASTER_SPA),ZPROP_SRC_LOCAL, new_master_spa);   /*os->os_master_spa*/
						dsl_prop_set_int((const char*)(zfs_multiclus_table[i].multiclus_group[j].fsname), 
							zfs_prop_to_name(ZFS_PROP_MASTER_OS), ZPROP_SRC_LOCAL, new_master_os);    /*os->os_master_os*/
						dsl_prop_set_int((const char*)(zfs_multiclus_table[i].multiclus_group[j].fsname), 
							zfs_prop_to_name(ZFS_PROP_MASTER_ROOT), ZPROP_SRC_LOCAL, new_master_root);  /*os->os_master_root*/
						if (os_spa != NULL)
							spa_async_request(os_spa, SPA_ASYNC_SYSTEM_SPACE);
					}
				}
			}
			mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
			break;
		}
	}

	mutex_exit(&multiclus_mtx);
	count = zfs_multiclus_check_group_master_count((const char *)groupname);
	if (count >= 2){
		if (DOUBLE_MASTER_PANIC) {
			zfs_panic_recover("[%s %d] %d, DOUBLE_MASTER B new_master_spa(0x%llx) == old_master_spa(0x%llx), new_master_os(0x%llx) == old_master_os(0x%llx)", 
				__func__, __LINE__, count, (unsigned long long)new_master_spa, (unsigned long long)old_master_spa,
				(unsigned long long)new_master_os, (unsigned long long)old_master_os);
		} else {
			cmn_err(CE_WARN, "[%s %d] %d, DOUBLE_MASTER B new_master_spa(0x%llx) == old_master_spa(0x%llx), new_master_os(0x%llx) == old_master_os(0x%llx)",
				__func__, __LINE__, count, (unsigned long long)new_master_spa, (unsigned long long)old_master_spa,
				(unsigned long long)new_master_os, (unsigned long long)old_master_os);
		}
	}

	return;
}

void zfs_multiclus_handle_frame(zfs_multiclus_worker_t *action_worker, zfs_group_header_t *msg_header, zfs_msg_t *msg_data)
{
	int	count = 0;
	int	record_num = 0;
	uint64_t	data_len = 0;
	cs_rx_data_t	*tmp_cs = NULL;
	zfs_group_reg_t	*reg_msg = NULL;
	zfs_group_header_t	*ohdr = NULL;
	zfs_multiclus_group_t	*group = NULL;
	zfs_multiclus_worker_para_t	*para = NULL;
	zfs_multiclus_worker_para_t *tmp_para = NULL;
	zfs_multiclus_group_record_t	*group_master = NULL;
	uint8_t	group_name[MAXNAMELEN];


	if (msg_header->msg_type == ZFS_MULTICLUS_OPERATE_MSG || msg_header->msg_type == ZFS_MULTICLUS_OPERATE_REPLY) {
			if (msg_header->msg_type == ZFS_MULTICLUS_OPERATE_MSG) {
				para = kmem_zalloc(sizeof(zfs_multiclus_worker_para_t), KM_SLEEP);
				para->frame_type = msg_header->msg_type;
				para->msg_header = msg_header;
				para->msg_data = msg_data;
				zfs_multiclus_worker_wakeup(action_worker, para);
			} else if (msg_header->msg_type == ZFS_MULTICLUS_OPERATE_REPLY){
				uint64_t	key = 0;
				mod_hash_t	*modhash_tmp = NULL;
				zfs_multiclus_hash_t	*hash_member = NULL;

				mutex_enter(&zfs_multiclus_tx_hash_mtx);
				modhash_tmp = zfs_multiclus_find_hash_header(msg_header->client_spa, msg_header->client_os, B_TRUE);
				key = msg_header->seqno;
				mutex_exit(&zfs_multiclus_tx_hash_mtx);
				tmp_cs = msg_header->cs_data;
				tmp_para = (zfs_multiclus_worker_para_t *)msg_header->work_para;
				if (modhash_tmp == NULL) {
					/*
					 *	client on localhost send operate to server, then localhost down.
					 *	after localhost up, client receive server's operation reply. 
					 *	in this scene, will be step to here.
					 */
					vmem_free(msg_data, msg_header->length);
					kmem_free(msg_header, sizeof(zfs_group_header_t));
					cmn_err(CE_WARN, "%s, %d, There is no hash header for this reply!", __func__, __LINE__);
				} else {
					hash_member = zfs_multiclus_find_hash_member(modhash_tmp, key);
					if (hash_member != NULL && hash_member->tx_no_rx == 0){
						ohdr = (zfs_group_header_t *)(hash_member->omsg_header);
						ohdr->nmsg_data = (uintptr_t)(msg_data);
						ohdr->nmsg_len = msg_header->length;
						ohdr->nmsg_header = (uintptr_t)(msg_header);

						hash_member->multiclus_segments = 0;
						cv_broadcast(&hash_member->multiclus_hash_cv);
						mutex_exit(&hash_member->multiclus_hash_mutex);		
					} else {
						if (hash_member != NULL) {
							mutex_exit(&hash_member->multiclus_hash_mutex);
						}
						/*can not find tx_hash_member, wo do nothing.*/
						vmem_free(msg_data, msg_header->length);
						kmem_free(msg_header, sizeof(zfs_group_header_t));
						//cmn_err(CE_WARN, "%s, %d, Can not find tx_hash_member, this msg mybe timeout already!", __func__, __LINE__);
					}
				}
				csh_rx_data_free(tmp_cs, B_TRUE);
				kmem_free(tmp_para, sizeof(zfs_multiclus_worker_para_t));
			}
	} else if (msg_header->msg_type == ZFS_MULTICLUS_GROUP_MSG) {
		reg_msg = &msg_data->call.regist;

		bcopy(msg_header->group_name, group_name, msg_header->group_name_len);
		group_name[msg_header->group_name_len] = '\0';
		group_master = zfs_multiclus_get_group_master((char *)group_name, ZFS_MULTICLUS_MASTER);
		if (msg_header->m_node_type != ZFS_MULTICLUS_MASTER){
			group = NULL;
			record_num = zfs_multiclus_get_group((char *)group_name, &group);
			
			if (group && (group_master != NULL && 
				group_master->node_status.status == ZFS_MULTICLUS_NODE_ONLINE && 
				group_master->hostid == zfs_multiclus_node_id)){
				zfs_multiclus_record_reg_and_update(msg_header, reg_msg);
				count = zfs_multiclus_check_group_master_count((const char *)group_name);
				if (count >= 2){
					if (DOUBLE_MASTER_PANIC) {
						zfs_panic_recover("[%s %d] %d, DOUBLE_MASTER There are two or more masters in group!", 
							__func__, __LINE__, count);
					} else {
						cmn_err(CE_WARN, "[%s %d] %d, DOUBLE_MASTER There are two or more masters in group!", 
							__func__, __LINE__, count);
					}
				}
				mutex_enter(&multiclus_mtx_update_record);
				mutex_enter(&multiclus_mtx);
				mutex_enter(&group->multiclus_group_mutex);
				zfs_multiclus_write_group_reply_msg(&(group->multiclus_group), msg_header, ZFS_MULTICLUS_GROUP_REPLY);
				mutex_exit(&group->multiclus_group_mutex);
				mutex_exit(&multiclus_mtx);
				mutex_exit(&multiclus_mtx_update_record);
			}
		} else {
			if (group_master != NULL && group_master->spa_id != reg_msg->spa_id && 
				group_master->os_id != reg_msg->os_id) {
				zfs_multiclus_change_master_to_record((char *)group_name, (char *)reg_msg->fsname, 
					reg_msg->spa_id, reg_msg->os_id, reg_msg->root, group_master->spa_id, 
					group_master->os_id, ZFS_MULTICLUS_SLAVE);
			}
			zfs_multiclus_start_reg((char *)group_name, 0, 0, EXCEPT_SOMEONE);
		}
		data_len = msg_header->cs_data->data_len;
		csh_rx_data_free(msg_header->cs_data, B_TRUE);
		tmp_para = (zfs_multiclus_worker_para_t *)msg_header->work_para;
		kmem_free(msg_header, sizeof(zfs_group_header_t));
		vmem_free(msg_data, data_len);
		kmem_free(tmp_para, sizeof(zfs_multiclus_worker_para_t));
	} else if (msg_header->msg_type == ZFS_MULTICLUS_GROUP_REPLY) {
		bcopy(msg_header->group_name, group_name, msg_header->group_name_len);
		group_name[msg_header->group_name_len] = '\0';
		group = NULL;
		record_num = zfs_multiclus_get_group((char *)group_name, &group);
		if (group) {
			count = zfs_multiclus_check_group_master_count((const char *)group_name);
			if (count >= 2){
				if (DOUBLE_MASTER_PANIC) {
					zfs_panic_recover("%s, %d, %d, DOUBLE_MASTER A There are two or more masters in group!", __func__, __LINE__, count);
				} else {
					cmn_err(CE_WARN, "%s, %d, %d, DOUBLE_MASTER A There are two or more masters in group!", __func__, __LINE__, count);
				}
			}
			zfs_multiclus_update_group(msg_header, msg_data);
			count = zfs_multiclus_check_group_master_count((const char *)group_name);
			if (count >= 2){
				if (DOUBLE_MASTER_PANIC) {
					zfs_panic_recover("%s, %d, %d, DOUBLE_MASTER B There are two or more masters in group!", __func__, __LINE__, count);
				} else {
					cmn_err(CE_WARN, "%s, %d, %d, DOUBLE_MASTER B There are two or more masters in group!", __func__, __LINE__, count);
				}
			}
		}
		
		data_len = msg_header->cs_data->data_len;
		csh_rx_data_free(msg_header->cs_data, B_TRUE);
		tmp_para = (zfs_multiclus_worker_para_t *)msg_header->work_para;
		kmem_free(msg_header, sizeof(zfs_group_header_t));
		vmem_free(msg_data, data_len);
		kmem_free(tmp_para, sizeof(zfs_multiclus_worker_para_t));
	}  else if (msg_header->msg_type == ZFS_MULTICLUS_GROUP_CHANGE) {
		uint64_t master_hid = 0;
		cmn_err(CE_WARN, "%s, %d, Receive master change msg, group table will be clear!", __func__, __LINE__);
		mutex_enter(&multiclus_mtx_update_record);
		reg_msg = &msg_data->call.regist;
		group_master = zfs_multiclus_get_group_master((char *)reg_msg->group_name, ZFS_MULTICLUS_MASTER);
		if (group_master)
			master_hid = group_master->hostid;
		zfs_multiclus_set_node_type_to_os((char*)reg_msg->group_name, (char*)reg_msg->fsname, 
			reg_msg->node_type, reg_msg->spa_id, reg_msg->os_id, reg_msg->root);
		zfs_multiclus_clear_group((char*)reg_msg->group_name);
		if (master_hid == zfs_multiclus_node_id)
			zfs_group_wait(ZFS_MULTICLUS_SECOND * 10);
		mutex_exit(&multiclus_mtx_update_record);
		zfs_multiclus_start_reg((char *)reg_msg->group_name, 0, 0, EXCEPT_SOMEONE);
		data_len = msg_header->cs_data->data_len;
		csh_rx_data_free(msg_header->cs_data, B_TRUE);
		tmp_para = (zfs_multiclus_worker_para_t *)msg_header->work_para;
		kmem_free(msg_header, sizeof(zfs_group_header_t));
		vmem_free(msg_data, data_len);
		kmem_free(tmp_para, sizeof(zfs_multiclus_worker_para_t));
	} 
}

static void
zfs_multiclus_rx_mp_worker_frame(void *arg)
{
	zfs_multiclus_worker_t	*rx_worker = (zfs_multiclus_worker_t *)arg;
	zfs_multiclus_worker_para_t *work_para;
	clock_t time = drv_usectohz(10);

	mutex_enter(&rx_worker->worker_lock);
	atomic_add_32(&zfs_multiclus_global_workers.zfs_multiclus_rx_workers.zfs_multiclus_rx_running_workers, 1);
	rx_worker->worker_flags |= ZFS_MULTICLUS_WORKER_STARTED | ZFS_MULTICLUS_WORKER_ACTIVE;
	while ((rx_worker->worker_flags & ZFS_MULTICLUS_WORKER_TERMINATE) == 0) {
		/* loop through the frames */
		while ((work_para = list_head(&rx_worker->worker_para_list))) {
			list_remove(&rx_worker->worker_para_list, work_para);
			mutex_exit(&rx_worker->worker_lock);

			work_para->worker = rx_worker;
			if (taskq_dispatch(rx_worker->worker_taskq,
			    (void (*)(void *))zfs_multiclus_post_frame,
			    work_para, TQ_NOSLEEP) == 0) {
				cmn_err(CE_WARN, "dispatch mp post fail,to do directly");
				zfs_multiclus_post_frame(work_para);
			}
			
			mutex_enter(&rx_worker->worker_lock);
			rx_worker->worker_ntasks --;
		}

		rx_worker->worker_flags &= ~ZFS_MULTICLUS_WORKER_ACTIVE;
		cv_timedwait(&rx_worker->worker_cv, &rx_worker->worker_lock, ddi_get_lbolt() + time);
		rx_worker->worker_flags |= ZFS_MULTICLUS_WORKER_ACTIVE;
	}

	mutex_exit(&rx_worker->worker_lock);
	rx_worker->worker_flags &= ~(ZFS_MULTICLUS_WORKER_STARTED | ZFS_MULTICLUS_WORKER_ACTIVE);
	atomic_add_32(&zfs_multiclus_global_workers.zfs_multiclus_rx_workers.zfs_multiclus_rx_running_workers, -1);
	list_destroy(&rx_worker->worker_para_list);
}

static void
zfs_multiclus_workers_init(void)
{
	uint32_t i;
	char name[MAXNAMELEN];

	/*initialize post taskq*/
/*	zfs_multiclus_global_workers.zfs_multiclus_action_post_tq = 
		taskq_create("multiclus_server_action", zfs_multiclus_dispatch_nworkers,
		    minclsyspri, 256, zfs_multiclus_server_action_max_tasks, TASKQ_PREPOPULATE);

	zfs_multiclus_global_workers.zfs_multiclus_rx_post_tq = 
		taskq_create("multiclus_mp_post_action", zfs_multiclus_dispatch_nworkers,
		    minclsyspri, 128, zfs_multiclus_mp_post_action_max_tasks, TASKQ_PREPOPULATE);*/

	/*initialize rx workers*/
	zfs_multiclus_global_workers.zfs_multiclus_rx_workers.zfs_multiclus_rx_worker_nodes = 
		kmem_zalloc(sizeof(zfs_multiclus_worker_t) * zfs_multiclus_rx_mp_worker_nworkers, KM_SLEEP);
	zfs_multiclus_global_workers.zfs_multiclus_rx_workers.zfs_multiclus_rx_worker_taskq = 
		taskq_create("ZFS_MULTICLUS_RX_MP_WORKER_TASKQ", zfs_multiclus_rx_mp_worker_nworkers,TASKQ_DEFAULTPRI,
		1, zfs_multiclus_rx_mp_worker_nworkers, 0);
	zfs_multiclus_global_workers.zfs_multiclus_rx_workers.zfs_multiclus_rx_running_workers = 0;

	for (i = 0; i < zfs_multiclus_rx_mp_worker_nworkers; i++) {
		zfs_multiclus_worker_t *rx_worker = &zfs_multiclus_global_workers.zfs_multiclus_rx_workers.zfs_multiclus_rx_worker_nodes[i];
		mutex_init(&rx_worker->worker_lock, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&rx_worker->worker_avl_lock, NULL, MUTEX_DRIVER, NULL);
		cv_init(&rx_worker->worker_cv, NULL, CV_DRIVER, NULL);
		rx_worker->worker_flags &= ~ZFS_MULTICLUS_WORKER_TERMINATE;
		sprintf(name,"mulcls_mp_post_%d", i);
		rx_worker->worker_taskq = taskq_create(name, zfs_multiclus_dispatch_nworkers,
		    minclsyspri, 1, zfs_multiclus_mp_post_action_max_tasks, TASKQ_PREPOPULATE);
		list_create(&rx_worker->worker_para_list, sizeof (zfs_multiclus_worker_para_t),
		    offsetof(zfs_multiclus_worker_para_t, worker_para_node));
		(void)taskq_dispatch(zfs_multiclus_global_workers.zfs_multiclus_rx_workers.zfs_multiclus_rx_worker_taskq,
			zfs_multiclus_rx_mp_worker_frame, rx_worker, TQ_SLEEP);
	}

	while (zfs_multiclus_global_workers.zfs_multiclus_rx_workers.zfs_multiclus_rx_running_workers != 
		zfs_multiclus_rx_mp_worker_nworkers) {
		delay(100);
	}	

	/*initialize action workers*/
	zfs_multiclus_global_workers.zfs_multiclus_action_workers.zfs_multiclus_action_worker_nodes = 
		vmem_zalloc(sizeof(zfs_multiclus_worker_t) * zfs_multiclus_server_nworkers, KM_SLEEP);
	zfs_multiclus_global_workers.zfs_multiclus_action_workers.zfs_multiclus_action_worker_taskq =
		taskq_create("ZFS_MULTICLUS_SERVER_WORKER_TASKQ", zfs_multiclus_server_nworkers,TASKQ_DEFAULTPRI,
		1, zfs_multiclus_server_nworkers, 0);
	zfs_multiclus_global_workers.zfs_multiclus_action_workers.zfs_multiclus_action_running_workers = 0;

	for (i = 0; i < zfs_multiclus_server_nworkers; i++) {
		zfs_multiclus_worker_t *action_worker = &zfs_multiclus_global_workers.zfs_multiclus_action_workers.zfs_multiclus_action_worker_nodes[i];
		mutex_init(&action_worker->worker_lock, NULL, MUTEX_DRIVER, NULL);
		mutex_init(&action_worker->worker_avl_lock, NULL, MUTEX_DRIVER, NULL);
		cv_init(&action_worker->worker_cv, NULL, CV_DRIVER, NULL);
		action_worker->worker_flags &= ~ZFS_MULTICLUS_WORKER_TERMINATE;
		sprintf(name,"mulcls_srv_%d", i);
		action_worker->worker_taskq = taskq_create(name, zfs_multiclus_dispatch_nworkers,
		    minclsyspri, 1, zfs_multiclus_server_action_max_tasks, TASKQ_PREPOPULATE);
		list_create(&action_worker->worker_para_list, sizeof (zfs_multiclus_worker_para_t),
		    offsetof(zfs_multiclus_worker_para_t, worker_para_node));
		(void)taskq_dispatch(zfs_multiclus_global_workers.zfs_multiclus_action_workers.zfs_multiclus_action_worker_taskq,
			zfs_multiclus_server_worker_frame, action_worker, TQ_SLEEP);
	}
	
	while (zfs_multiclus_global_workers.zfs_multiclus_action_workers.zfs_multiclus_action_running_workers != 
		zfs_multiclus_server_nworkers) {
		delay(100);
	}

	zfs_multiclus_global_workers.mm_log_index = 0;
	mutex_init(&zfs_multiclus_global_workers.mm_mutex, NULL, MUTEX_DRIVER, NULL);

	zfs_multiclus_global_workers.b_initialized = B_TRUE;
}

static void
zfs_multiclus_workers_finit(void)
{
	uint32_t i;

	zfs_multiclus_global_workers.b_initialized = B_FALSE;
	mutex_destroy(&zfs_multiclus_global_workers.mm_mutex);

	/*finit action workers*/
	for (i = 0; i < zfs_multiclus_server_nworkers; i++) {
		zfs_multiclus_worker_t *action_worker = &zfs_multiclus_global_workers.zfs_multiclus_action_workers.zfs_multiclus_action_worker_nodes[i];
		mutex_enter(&action_worker->worker_lock);
		if (action_worker->worker_flags & ZFS_MULTICLUS_WORKER_STARTED) {
			action_worker->worker_flags |= ZFS_MULTICLUS_WORKER_TERMINATE;
			cv_signal(&action_worker->worker_cv);
		}
		mutex_exit(&action_worker->worker_lock);
	}

	while (zfs_multiclus_global_workers.zfs_multiclus_action_workers.zfs_multiclus_action_running_workers != 0) {
		delay(drv_usectohz(10000));
	}
	/*finit action cv mutex*/
	for (i = 0; i < zfs_multiclus_server_nworkers; i++) {
		zfs_multiclus_worker_t *action_worker = &zfs_multiclus_global_workers.zfs_multiclus_action_workers.zfs_multiclus_action_worker_nodes[i];

		taskq_destroy(action_worker->worker_taskq);
		mutex_destroy(&action_worker->worker_lock);
		mutex_destroy(&action_worker->worker_avl_lock);
		cv_destroy(&action_worker->worker_cv);
	}
	/*finit action taskq*/
	taskq_destroy(zfs_multiclus_global_workers.zfs_multiclus_action_workers.zfs_multiclus_action_worker_taskq);
	vmem_free(zfs_multiclus_global_workers.zfs_multiclus_action_workers.zfs_multiclus_action_worker_nodes,
	    sizeof (zfs_multiclus_worker_t) * zfs_multiclus_server_nworkers);
	zfs_multiclus_global_workers.zfs_multiclus_action_workers.zfs_multiclus_action_worker_nodes = NULL;

	/*finit rx workers*/
	for (i = 0; i < zfs_multiclus_rx_mp_worker_nworkers; i++) {
		zfs_multiclus_worker_t *rx_worker = &zfs_multiclus_global_workers.zfs_multiclus_rx_workers.zfs_multiclus_rx_worker_nodes[i];
		mutex_enter(&rx_worker->worker_lock);
		if (rx_worker->worker_flags & ZFS_MULTICLUS_WORKER_STARTED) {
			rx_worker->worker_flags |= ZFS_MULTICLUS_WORKER_TERMINATE;
			cv_signal(&rx_worker->worker_cv);
		}
		mutex_exit(&rx_worker->worker_lock);
	}

	while (zfs_multiclus_global_workers.zfs_multiclus_rx_workers.zfs_multiclus_rx_running_workers != 0) {
		delay(drv_usectohz(10000));
	}
	/*finit rx cv mutex*/
	for (i = 0; i < zfs_multiclus_rx_mp_worker_nworkers; i++) {
		zfs_multiclus_worker_t *rx_worker = &zfs_multiclus_global_workers.zfs_multiclus_rx_workers.zfs_multiclus_rx_worker_nodes[i];
		taskq_destroy(rx_worker->worker_taskq);
		mutex_destroy(&rx_worker->worker_lock);
		mutex_destroy(&rx_worker->worker_avl_lock);
		cv_destroy(&rx_worker->worker_cv);
	}
	/*finit rx taskq*/
	taskq_destroy(zfs_multiclus_global_workers.zfs_multiclus_rx_workers.zfs_multiclus_rx_worker_taskq);
	kmem_free(zfs_multiclus_global_workers.zfs_multiclus_rx_workers.zfs_multiclus_rx_worker_nodes,
	    sizeof (zfs_multiclus_worker_t) * zfs_multiclus_rx_mp_worker_nworkers);
	zfs_multiclus_global_workers.zfs_multiclus_rx_workers.zfs_multiclus_rx_worker_nodes = NULL;

	/*finit action post tq*/
/*	taskq_destroy(zfs_multiclus_global_workers.zfs_multiclus_action_post_tq);*/
	
	/*finit rx post tq*/
/*	taskq_destroy(zfs_multiclus_global_workers.zfs_multiclus_rx_post_tq);*/
}

static void
zfs_multiclus_hash_tmchk_thr_wait(callb_cpr_t *cpr, kcondvar_t *cv,
    uint64_t time, kmutex_t *tmchk_lock)
{
	CALLB_CPR_SAFE_BEGIN(cpr);
	if (time)
		(void) cv_timedwait(cv, tmchk_lock, ddi_get_lbolt() + time);
	else
		cv_wait(cv, tmchk_lock);
	CALLB_CPR_SAFE_END(cpr, tmchk_lock);
}

void
zfs_multiclus_hash_tmchk_thr_work(void *arg)
{
	callb_cpr_t cpr;
	clock_t time;
	zfs_multiclus_hash_header_t *hash_header = (zfs_multiclus_hash_header_t *)arg;

	CALLB_CPR_INIT(&cpr, &hash_header->hash_tmchk_thr_lock, callb_generic_cpr, (char *)__func__);
	mutex_enter(&hash_header->hash_tmchk_thr_lock);
	hash_header->hash_tmchk_thr_running = B_TRUE;
	
	while(1) {
		time = drv_usectohz(ZFS_MULTICLUS_RX_HASH_CHECK);
		zfs_multiclus_hash_tmchk_thr_wait(&cpr, &hash_header->hash_tmchk_thr_cv,
		    time, &hash_header->hash_tmchk_thr_lock);

		if (kthread_should_stop()) {
			cmn_err(CE_WARN, "[%s %d] thread exit", __func__, __LINE__);
			break;
		}

		if (timeout_chk_flag)
			zfs_multiclus_rx_operate_check(hash_header);
	}

	hash_header->hash_tmchk_thr_running = B_FALSE;
	CALLB_CPR_EXIT(&cpr);
	thread_exit();
}

// static void
// zfs_multiclus_hash_tmchk_thr_stop(int hash_location)
// {

// 	if (zfs_multiclus_rx_hash[hash_location].hash_tmchk_thr_running) {
// 		zfs_multiclus_rx_hash[hash_location].hash_tmchk_thr_exit = B_TRUE;
// 		cv_broadcast(&zfs_multiclus_rx_hash[hash_location].hash_tmchk_thr_cv);
// 		kthread_stop(zfs_multiclus_rx_hash[hash_location].hash_tmchk_thread);
// 	}
// }

static int
zfs_multiclus_hash_tmchk_thr_start(int hash_location)
{
	int ret = 0;
	
	rw_enter(&zfs_multiclus_rx_hash[hash_location].zfs_multiclus_timeout_lock, RW_READER);

	zfs_multiclus_rx_hash[hash_location].hash_tmchk_thread = kthread_run(zfs_multiclus_hash_tmchk_thr_work, 
		(void*)(&zfs_multiclus_rx_hash[hash_location]), "zfs_multiclus_rx_hash_%d", hash_location);

	if (zfs_multiclus_rx_hash[hash_location].hash_tmchk_thread == NULL) {
		cmn_err(CE_WARN, "zfs_multiclus:create hash timeout check thr failed");
		ret = 1;
	}

	rw_exit(&zfs_multiclus_rx_hash[hash_location].zfs_multiclus_timeout_lock);

	return (ret);
}

int
zfs_multiclus_get_group_record_num(char *group_name, uint64_t group_name_len)
{
	int i = 0;
	int j = 0;
	int num = 0;

	for (i = 0; i < ZFS_MULTICLUS_GROUP_TABLE_SIZE; i++){
		if (zfs_multiclus_table[i].used && strncmp((char *)(zfs_multiclus_table[i].group_name),
		    group_name, group_name_len) == 0){
		    for (j = 0; j < ZFS_MULTICLUS_GROUP_NODE_NUM; j++) {
				if (zfs_multiclus_table[i].multiclus_group[j].used)
				num++;
			}
			return (num);
		}
	}
	return (-1);
}

int zfs_multiclus_get_group(char *group_name, zfs_multiclus_group_t **group)
{
	int i = ZFS_MULTICLUS_GROUP_TABLE_SIZE;
	zfs_multiclus_group_t *group_entry = NULL;
	mutex_enter(&multiclus_mtx);
	for (i = 0; i < ZFS_MULTICLUS_GROUP_TABLE_SIZE; i++){
		group_entry = &zfs_multiclus_table[i];
		if (group_entry->used && strncmp(group_entry->group_name,
		    group_name, strlen(group_name)) == 0){
			*group = group_entry;
			break;
		}
	}
	mutex_exit(&multiclus_mtx);

	return (i);
}

zfs_multiclus_group_t *
zfs_multiclus_get_current_group( uint64_t spaid )
{
	int i, j;
	zfs_multiclus_group_t *group_entry = NULL;
	mutex_enter(&multiclus_mtx);
	for (i = 0; i < ZFS_MULTICLUS_GROUP_TABLE_SIZE; i++){
		group_entry = &zfs_multiclus_table[i];
		if (group_entry->used ){
			mutex_enter(&group_entry->multiclus_group_mutex);
			for (j = 0; j < ZFS_MULTICLUS_GROUP_NODE_NUM; j++){
				if (group_entry->multiclus_group[j].used &&
					(group_entry->multiclus_group[j].spa_id == spaid)){
					break;
				}
			}
			mutex_exit(&group_entry->multiclus_group_mutex);
			if(j < ZFS_MULTICLUS_GROUP_NODE_NUM)
			{
				mutex_exit(&multiclus_mtx);
				return (group_entry);
			}
		}
	}
	
	mutex_exit(&multiclus_mtx);

	return (NULL);
}

zfs_multiclus_group_record_t *
zfs_multiclus_get_record(uint64_t spa_id, uint64_t os_id)
{
	int i = 0;
	int j = 0;

	mutex_enter(&multiclus_mtx);
	for (i = 0; i < ZFS_MULTICLUS_GROUP_TABLE_SIZE; i++){
		if(zfs_multiclus_table[i].used) {
			mutex_enter(&zfs_multiclus_table[i].multiclus_group_mutex);
			for (j = 0; j < ZFS_MULTICLUS_GROUP_NODE_NUM; j++){
				if (zfs_multiclus_table[i].multiclus_group[j].used &&
				    (zfs_multiclus_table[i].multiclus_group[j].spa_id == spa_id) &&
				    (zfs_multiclus_table[i].multiclus_group[j].os_id == os_id)){
					mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
					mutex_exit(&multiclus_mtx);
					return (&(zfs_multiclus_table[i].multiclus_group[j]));
				}
			}
			mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
		}
	}

	mutex_exit(&multiclus_mtx);
	
	return (NULL);
}

void
zfs_multiclus_destroy_reg_record(char *group_name, uint64_t spa_id, uint64_t os_id)
{
	int i = 0;
	int j = 0;

	mutex_enter(&multiclus_mtx);
	for (; i < ZFS_MULTICLUS_GROUP_TABLE_SIZE; i++){
		if(zfs_multiclus_table[i].used && strncmp(zfs_multiclus_table[i].group_name,
			group_name, strlen(group_name)) == 0) {
			mutex_enter(&zfs_multiclus_table[i].multiclus_group_mutex);
			for (j = 0; j < ZFS_MULTICLUS_GROUP_NODE_NUM; j++){
				if (zfs_multiclus_table[i].multiclus_reg[j].used
					&& (zfs_multiclus_table[i].multiclus_reg[j].spa_id == spa_id)
					&& (zfs_multiclus_table[i].multiclus_reg[j].os_id == os_id)){
					mutex_enter(&zfs_multiclus_table[i].multiclus_reg[j].reg_timer_lock);
					zfs_multiclus_table[i].multiclus_reg[j].used = B_FALSE;
					cv_broadcast(&zfs_multiclus_table[i].multiclus_reg[j].reg_timer_cv);
					mutex_exit(&zfs_multiclus_table[i].multiclus_reg[j].reg_timer_lock);
					mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
					mutex_exit(&multiclus_mtx);
					return;
				}
			}
			mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
		}
	}
	mutex_exit(&multiclus_mtx);
	return;
}

boolean_t
zfs_multiclus_valid_reg_record(char *group_name, uint64_t spa_id, uint64_t os_id)
{	
	int i = 0;
	int j = 0;
	boolean_t is_valid = B_FALSE;

	for (i = 0; i < ZFS_MULTICLUS_GROUP_TABLE_SIZE; i++) {
		if(zfs_multiclus_table[i].used && strncmp(zfs_multiclus_table[i].group_name,
			group_name, strlen(group_name)) == 0) {
			for (j = 0; j < ZFS_MULTICLUS_GROUP_NODE_NUM; j++){
				if (zfs_multiclus_table[i].multiclus_reg[j].used
					&& (zfs_multiclus_table[i].multiclus_reg[j].spa_id == spa_id)
					&& (zfs_multiclus_table[i].multiclus_reg[j].os_id == os_id)){
					mutex_enter(&zfs_multiclus_table[i].multiclus_reg[j].reg_timer_lock);
					is_valid = zfs_multiclus_table[i].multiclus_reg[j].used;
					mutex_exit(&zfs_multiclus_table[i].multiclus_reg[j].reg_timer_lock);
					return is_valid;
				}
			}
		}
	}

	return is_valid;
}

zfs_multiclus_group_record_t *
zfs_multiclus_get_group_master(char *group_name, zfs_multiclus_node_type_t type)
{
	int i;
	zfs_multiclus_group_record_t *record = NULL;
	zfs_multiclus_group_t *group_entry = NULL;
	if(type == ZFS_MULTICLUS_SLAVE){
		return (record);
	}
	mutex_enter(&multiclus_mtx);
	for (i = 0; i < ZFS_MULTICLUS_GROUP_TABLE_SIZE; i++){
		group_entry = &zfs_multiclus_table[i];
		if (group_entry->used && strncmp(group_entry->group_name,
		    group_name, strlen(group_name)) == 0){
			break;
		}
	}

	if (group_entry->used == B_TRUE && i < ZFS_MULTICLUS_GROUP_TABLE_SIZE) {
		mutex_enter(&group_entry->multiclus_group_mutex);
		for (i = 0; i < ZFS_MULTICLUS_GROUP_NODE_NUM; i ++) {
			record = &group_entry->multiclus_group[i];
			if (record->node_type == type) {
				break;
			}
			record = NULL;
		}
		mutex_exit(&group_entry->multiclus_group_mutex);
	}

	mutex_exit(&multiclus_mtx);
	return (record);
}

zfs_multiclus_register_t *
zfs_multiclus_get_reg_record(char *groupname, uint64_t spa_id, uint64_t os_id,
	int *group_index, int *reg_index)
{
	int i = 0;
	int j = 0;

	mutex_enter(&multiclus_mtx);
	for (; i < ZFS_MULTICLUS_GROUP_TABLE_SIZE; i++){
		if(zfs_multiclus_table[i].used && strncmp(zfs_multiclus_table[i].group_name,
		    groupname, strlen(groupname)) == 0)	{
			mutex_enter(&zfs_multiclus_table[i].multiclus_group_mutex);
			for (j = 0; j < ZFS_MULTICLUS_GROUP_NODE_NUM; j++){
				if (zfs_multiclus_table[i].multiclus_reg[j].used
					&& (zfs_multiclus_table[i].multiclus_reg[j].spa_id == spa_id)
					&& (zfs_multiclus_table[i].multiclus_reg[j].os_id == os_id)){
					mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
					mutex_exit(&multiclus_mtx);
					*group_index = i;
					*reg_index = j;
					return (&(zfs_multiclus_table[i].multiclus_reg[j]));
				} else {
					if (zfs_multiclus_table[i].multiclus_reg[j].used != B_TRUE) {
						*group_index = i;
						*reg_index = j;
					}
				}
			}
			mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
		}
	}

	mutex_exit(&multiclus_mtx);
	
	return (NULL);
}

void
zfs_multiclus_update_reg_record(char *groupname, uint64_t spa_id, uint64_t os_id)
{
	int i = 0;
	int j = 0;
	int reg_index = 0;

	mutex_enter(&multiclus_mtx);
	for (; i < ZFS_MULTICLUS_GROUP_TABLE_SIZE; i++){
		if(zfs_multiclus_table[i].used && strncmp(zfs_multiclus_table[i].group_name,
		    groupname, strlen(groupname)) == 0)	{
			mutex_enter(&zfs_multiclus_table[i].multiclus_group_mutex);
			for (j = 0; j < ZFS_MULTICLUS_GROUP_NODE_NUM; j++){
				if (zfs_multiclus_table[i].multiclus_reg[j].used
					&& (zfs_multiclus_table[i].multiclus_reg[j].spa_id == spa_id)
					&& (zfs_multiclus_table[i].multiclus_reg[j].os_id == os_id)){
					mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
					mutex_exit(&multiclus_mtx);
					return;
				} else {
					if (zfs_multiclus_table[i].multiclus_reg[j].used != B_TRUE) {
						reg_index = j;
					}
				}
			}
			zfs_multiclus_table[i].multiclus_reg[reg_index].used = B_TRUE;
			zfs_multiclus_table[i].multiclus_reg[reg_index].spa_id = spa_id;
			zfs_multiclus_table[i].multiclus_reg[reg_index].os_id = os_id;
			mutex_init(&zfs_multiclus_table[i].multiclus_reg[reg_index].reg_timer_lock, NULL, MUTEX_DRIVER, NULL);
			cv_init(&zfs_multiclus_table[i].multiclus_reg[reg_index].reg_timer_cv, NULL, CV_DRIVER, NULL);

			mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
		}
	}
	mutex_exit(&multiclus_mtx);
	
	return;
}

static void
zfs_multiclus_update_record_by_head(zfs_group_reg_t *reg_msg,
	zfs_multiclus_group_record_t *d_record)
{
	d_record->used = B_TRUE;
	d_record->spa_id = reg_msg->spa_id;
	d_record->os_id = reg_msg->os_id;
	d_record->hostid= reg_msg->hostid;
	d_record->node_type = reg_msg->node_type;
	d_record->avail_size = reg_msg->avail_size;
	d_record->used_size = reg_msg->used_size;
	d_record->load_ios = reg_msg->load_ios;
	d_record->node_id = reg_msg->node_id;
	d_record->node_status.status = reg_msg->node_status.status;
	if (reg_msg->root != 0)
		d_record->root = reg_msg->root;
	bcopy(reg_msg->fsname, d_record->fsname, MAX_FSNAME_LEN);
	bcopy(reg_msg->rpc_addr, d_record->rpc_addr, ZFS_MULTICLUS_RPC_ADDR_SIZE);
}

static void
zfs_multiclus_update_record_by_head_register(zfs_group_reg_t *reg_msg,
	zfs_multiclus_group_record_t *d_record)
{
	d_record->used = B_TRUE;
	d_record->spa_id = reg_msg->spa_id;
	d_record->os_id = reg_msg->os_id;
	d_record->hostid= reg_msg->hostid;
	d_record->node_type = reg_msg->node_type;
	d_record->load_ios = reg_msg->load_ios;
	d_record->node_status.status = reg_msg->node_status.status;
	d_record->node_id = reg_msg->node_id;
	if (reg_msg->root != 0)
		d_record->root = reg_msg->root;
	bcopy(reg_msg->fsname, d_record->fsname, MAX_FSNAME_LEN);
	bcopy(reg_msg->rpc_addr, d_record->rpc_addr, ZFS_MULTICLUS_RPC_ADDR_SIZE);
}

static void
zfs_multiclus_record_reg_and_update(zfs_group_header_t *msg_header, zfs_group_reg_t *reg_msg)
{
	int i = 0;
	int j = 0;

	mutex_enter(&multiclus_mtx);
	for (i = 0; i < ZFS_MULTICLUS_GROUP_TABLE_SIZE; i++){
		if (zfs_multiclus_table[i].used && strncmp((char *)(zfs_multiclus_table[i].group_name),
		    (char *)(msg_header->group_name), msg_header->group_name_len) == 0){
			mutex_enter(&zfs_multiclus_table[i].multiclus_group_mutex);
			for (j = 0; j < ZFS_MULTICLUS_GROUP_NODE_NUM; j++){
				if (zfs_multiclus_table[i].multiclus_group[j].used &&
				    (zfs_multiclus_table[i].multiclus_group[j].spa_id == reg_msg->spa_id) &&
				    (zfs_multiclus_table[i].multiclus_group[j].os_id == reg_msg->os_id)){
				 
				    zfs_multiclus_table[i].multiclus_group[j].node_status.last_update_time = gethrtime();
					zfs_multiclus_update_record_by_head_register(reg_msg, &zfs_multiclus_table[i].multiclus_group[j]);
					mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
					mutex_exit(&multiclus_mtx);
					zfs_multiclus_update_reg_record((char *)(reg_msg->group_name), reg_msg->spa_id, reg_msg->os_id);
					return;
				}
				if (zfs_multiclus_table[i].multiclus_group[j].used == B_FALSE){
					mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
					goto record_add;
				}
			}
			mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
		}
		if (zfs_multiclus_table[i].used == B_FALSE)
			break;
	}

record_add:
	
	if (zfs_multiclus_table[i].used == B_FALSE) {
		j = 0;
		mutex_init(&zfs_multiclus_table[i].multiclus_group_mutex, NULL, MUTEX_DRIVER, NULL);
		cv_init(&zfs_multiclus_table[i].multiclus_group_cv, NULL, CV_DRIVER, NULL);
		zfs_multiclus_table[i].used = B_TRUE;
		bcopy((char *)(msg_header->group_name), (char *)(zfs_multiclus_table[i].group_name), msg_header->group_name_len);
		zfs_multiclus_table[i].group_reg_timer_tq = taskq_create("ZFS_REG_TASQ", 
			ZFS_MULTICLUS_GROUP_NODE_NUM, TASKQ_DEFAULTPRI, 1, ZFS_MULTICLUS_GROUP_NODE_NUM, 0);
		zfs_multiclus_table[i].group_name_len = msg_header->group_name_len;
	}
	
	mutex_enter(&zfs_multiclus_table[i].multiclus_group_mutex);
	zfs_multiclus_update_record_by_head(reg_msg, &zfs_multiclus_table[i].multiclus_group[j]);
	mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
	mutex_exit(&multiclus_mtx);

	zfs_multiclus_update_reg_record((char *)(msg_header->group_name), reg_msg->spa_id, reg_msg->os_id);
}

// static void zfs_multiclus_check_master_change( 
// 	zfs_multiclus_group_record_t *new_group_table, 
// 	zfs_multiclus_group_record_t *old_group_table)
// {
// 	int i = 0;
// 	int err = 0;
// 	objset_t *os = NULL;
// 	zfs_multiclus_group_record_t *new_master = NULL;
// 	zfs_multiclus_group_record_t *old_master = NULL;
//	spa_t *os_spa = NULL;
//	uint64_t os_is_master = 0;
//	uint64_t os_node_type = 0;

// 	for (i = 0; i < ZFS_MULTICLUS_GROUP_NODE_NUM; i++) {
// 		if (new_group_table[i].node_type == ZFS_MULTICLUS_MASTER) {
// 			new_master = &new_group_table[i];
// 		}
// 	}

// 	for (i = 0; i < ZFS_MULTICLUS_GROUP_NODE_NUM; i++) {
// 		if (old_group_table[i].node_type == ZFS_MULTICLUS_MASTER) {
// 			old_master = &old_group_table[i];
// 		}
// 	}

// 	if ((old_master == NULL && new_master != NULL) ||
// 		(old_master != NULL && new_master != NULL &&
// 		(old_master->spa_id != new_master->spa_id || old_master->os_id != new_master->os_id))) {
// 		for (i = 0; i < ZFS_MULTICLUS_GROUP_NODE_NUM; i++) {
// 			err = dmu_objset_hold((const char*)new_group_table[i].fsname, FTAG, &os);
// 				if (err == 0) {
// 					if (spa_guid(dmu_objset_spa(os)) == new_master->spa_id && 
// 						dmu_objset_id(os) == new_master->os_id) {
//						os_is_master = B_TRUE;
// 						os->os_is_master = os_is_master;
// 					} else {
//						os_is_master = B_FALSE;
// 						os->os_is_master = os_is_master;
// 					}
//					os_node_type = zmc_node_type_to_os_type(new_group_table[i].node_type);
// 					os->os_node_type = os_node_type;
// 					os->os_last_master_spa = os->os_master_spa;
// 					os->os_last_master_os = os->os_master_os;
// 					os->os_master_spa = new_master->spa_id;
// 					os->os_master_os = new_master->os_id;
// 					os->os_master_root = new_master->root;
// 					if(debug_nas_group_dtl == 2){
// 						if (old_master) {
// 							cmn_err(CE_WARN, "%s %d (last) 0x%llx, 0x%llx, (current) x%llx, 0x%llx, (old)0x%llx, 0x%llx",__func__, __LINE__,
// 								(unsigned long long) os->os_last_master_spa,(unsigned long long)os->os_last_master_os,
// 								(unsigned long long) os->os_master_spa, (unsigned long long)os->os_master_os,
// 								(unsigned long long) old_master->spa_id,(unsigned long long)old_master->os_id);
// 						} else {
// 							cmn_err(CE_WARN, "%s %d (last) 0x%llx, 0x%llx, (current) x%llx, 0x%llx, (old is NULL)",__func__, __LINE__,
// 								(unsigned long long) os->os_last_master_spa,(unsigned long long)os->os_last_master_os,
// 								(unsigned long long) os->os_master_spa, (unsigned long long)os->os_master_os);
// 						}
// 					}
//					os_spa = dmu_objset_spa(os);
//					dmu_objset_rele(os, FTAG);
// 					dsl_prop_set_int((const char*)(new_group_table[i].fsname),  
// 						zfs_prop_to_name(ZFS_PROP_MASTER), ZPROP_SRC_LOCAL, os_is_master);     //os->os_is_master
// 					dsl_prop_set_int((const char*)(new_group_table[i].fsname), 
// 						zfs_prop_to_name(ZFS_PROP_NODE_TYPE), ZPROP_SRC_LOCAL, os_node_type);  //os->os_node_type
// 					dsl_prop_set_int((const char*)(new_group_table[i].fsname), 
// 						zfs_prop_to_name(ZFS_PROP_MASTER_SPA), ZPROP_SRC_LOCAL, new_master->spa_id);   //os->os_master_spa
// 					dsl_prop_set_int((const char*)(new_group_table[i].fsname), 
// 						zfs_prop_to_name(ZFS_PROP_MASTER_OS), ZPROP_SRC_LOCAL, new_master->os_id);     //os->os_master_os
// 					dsl_prop_set_int((const char*)(new_group_table[i].fsname), 
// 						zfs_prop_to_name(ZFS_PROP_MASTER_ROOT), ZPROP_SRC_LOCAL, new_master->root);    //os->os_master_root
//					if (os_spa != NULL)
// 						spa_async_request(dmu_objset_spa(os), SPA_ASYNC_SYSTEM_SPACE);
// 				}
// 			}
// 		}
// }

static void
zfs_multiclus_update_group(zfs_group_header_t *msg_header, zfs_msg_t *msg_data)
{
	int i = 0;
	boolean_t find = B_FALSE;
	int group_name_len = 16;
	zfs_multiclus_group_record_t *group = (zfs_multiclus_group_record_t *)msg_data;
	
	mutex_enter(&multiclus_mtx);
	if (msg_header->group_name_len == 0) {
		cmn_err(CE_WARN, "%s, %d, group_name_len is 0!", __func__, __LINE__);
		mutex_exit(&multiclus_mtx);
		return;
	}
	for (i = 0; i < ZFS_MULTICLUS_GROUP_TABLE_SIZE; i++){
		if (zfs_multiclus_table[i].used){
			if (strncmp((char *)(zfs_multiclus_table[i].group_name),
			    (char *)(msg_header->group_name), msg_header->group_name_len) == 0){
				find = B_TRUE;
				break;
			}
		} else {
			break;
		}
	}

	if (i < (ZFS_MULTICLUS_GROUP_TABLE_SIZE - 1)){
		if (find == B_FALSE){
			zfs_multiclus_table[i].used = B_TRUE;
			bcopy(msg_header->group_name, zfs_multiclus_table[i].group_name, group_name_len);
			zfs_multiclus_table[i].group_name_len = group_name_len;
			mutex_init(&zfs_multiclus_table[i].multiclus_group_mutex, NULL, MUTEX_DRIVER, NULL);
			cv_init(&zfs_multiclus_table[i].multiclus_group_cv, NULL, CV_DRIVER, NULL);
		}
		mutex_enter(&zfs_multiclus_table[i].multiclus_group_mutex);
		//zfs_multiclus_check_master_change(group, zfs_multiclus_table[i].multiclus_group);
		bcopy(group, zfs_multiclus_table[i].multiclus_group,
		    sizeof(zfs_multiclus_group_record_t) * ZFS_MULTICLUS_GROUP_NODE_NUM);
		mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
	} else {
		cmn_err(CE_WARN, "The multiclus group is full, do nothing!");
	}
	
	mutex_exit(&multiclus_mtx);
}


static int
zfs_multiclus_write_group_reply_msg(void *group_msg, zfs_group_header_t *msg_head, uint8_t reply_type)
{
	uint32_t	data_len = 0;
	char	*data = NULL;
	zfs_group_header_t	*head = NULL;

	if (!zfs_multiclus_enable()) {
		cmn_err(CE_WARN, "%s, %d: multiclus is disabled!", __func__, __LINE__);
		return (1);
	}

	head = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
	data = (char *)group_msg;
	data_len = sizeof(zfs_multiclus_group_record_t) * ZFS_MULTICLUS_GROUP_NODE_NUM;

	bcopy(msg_head, head, sizeof(zfs_group_header_t));
	head->msg_type = reply_type;
	cluster_san_broadcast_send(data, data_len, (void *)head, sizeof(zfs_group_header_t), CLUSTER_SAN_MSGTYPE_CLUSTERFS, 0);
	kmem_free(head, sizeof(zfs_group_header_t));
	return (0);
}

static int
zfs_multiclus_write_operate_reply_msg(zfs_group_header_t *msg_header, zfs_msg_t *msg_data)
{
	int	err = 0;
	uint64_t	data_len = msg_header->length;
	uint64_t	spa_id = msg_header->client_spa;
	uint64_t	os_id = msg_header->client_os;
	cluster_san_hostinfo_t	*cshi = NULL;


	if (!zfs_multiclus_get_record(spa_id, os_id)){
		cmn_err(CE_WARN, "%s, %d, Can not get the record, return; spa:0x%llx, os:0x%llx",
			__func__, __LINE__, (longlong_t)spa_id, (longlong_t)os_id);
	}

	if (!zfs_multiclus_enable()) {
		cmn_err(CE_WARN, "%s, %d: multiclus is disabled!", __func__, __LINE__);
		return (2);
	}
		
	msg_header->msg_type = ZFS_MULTICLUS_OPERATE_REPLY;

	cshi = cluster_remote_hostinfo_hold((uint32_t)msg_header->hostid);
	if (!cshi) {
		cmn_err(CE_WARN, "%s, %d, hold hostinfo(hostid: %llx) failed!", 
			__func__, __LINE__, (unsigned long long)msg_header->hostid);
		return (EOFFLINE);
	}
	zfs_multiclus_test_data_error((void *)msg_header,(void *)msg_data, (uint64_t)data_len);
	err = cluster_san_host_send(cshi, (void *)msg_data, data_len, (void *)msg_header, 
		sizeof(zfs_group_header_t), CLUSTER_SAN_MSGTYPE_CLUSTERFS, 0, B_TRUE, 2);
	zfs_multiclus_test_data_error((void *)msg_header,(void *)msg_data, (uint64_t)data_len);
	cluster_san_hostinfo_rele(cshi);
	
	return (err);
}

int zfs_multiclus_write_operate_msg(objset_t *os, zfs_group_header_t *msg_header, void *data, uint64_t data_len)
{
	int	wait = 0;
	int	err = 0;
	clock_t	time = 0;
	clock_t	ret = 0;
	boolean_t	bsame_host = B_FALSE;
	uint64_t	tx_log_time = 0;
	uint64_t	tx_log_time_tmp1 = 0;
	uint64_t	tx_log_time_tmp2 = 0;
	uint64_t	rx_log_time = 0;
	uint64_t	mm_log_index = 0;
	uint64_t	key = 0;
	uint64_t	spa_id = 0,	os_id = 0, hostid = 0;
	zfs_msg_t	*msg_data = (zfs_msg_t *)data;
	mod_hash_t	*modhash_header = NULL;
	cluster_san_hostinfo_t	*cshi = NULL;
	zfs_multiclus_hash_t	*tx_hash_member = NULL;
	zfs_multiclus_group_record_t	*record = NULL;
	status_type_t status = ZFS_MULTICLUS_NODE_STATUS_MAX;

	
	if (!zfs_multiclus_enable()) {
		cmn_err(CE_WARN, "%s, %d: multiclus is disabled!", __func__, __LINE__);
		return (2);
	}

	mm_log_index = zfs_multiclus_get_log_index();

	/* get hash_key & hash_header */
	spa_id = msg_header->client_spa;
	os_id = msg_header->client_os;
	mutex_enter(&zfs_multiclus_tx_hash_mtx);
	modhash_header = zfs_multiclus_find_hash_header(spa_id, os_id, B_TRUE);
	if (modhash_header == NULL){
		modhash_header = zfs_multiclus_fill_hash_table(spa_id, os_id, B_TRUE);
	}
	mutex_exit(&zfs_multiclus_tx_hash_mtx);
		
	tx_log_time = gethrtime();

	if ((msg_header->command == ZFS_GROUP_CMD_DATA) && (msg_header->operation == DATA_WRITE))
		time = drv_usectohz(zfs_multiclus_wait_write_io_time * ZFS_MULTICLUS_TIME_MAGNITUDE * ZFS_MULTICLUS_TIME_MAGNITUDE); /* 60s */
	else
		time = drv_usectohz(zfs_multiclus_wait_io_time * ZFS_MULTICLUS_TIME_MAGNITUDE * ZFS_MULTICLUS_TIME_MAGNITUDE); /* 10s */

trans_again:

	record = zfs_multiclus_get_record(msg_header->server_spa, msg_header->server_os);
	if (record == NULL){
		//if (trans_again_count < 20) {
			//trans_again_count++;
			//zfs_group_wait(ZFS_MULTICLUS_SECOND/2);
			//goto trans_again;
		//}
		cmn_err(CE_WARN, "Can not get the mac, spa:0x%llx, os:0x%llx", (longlong_t)msg_header->server_spa,
		    (longlong_t)msg_header->server_os);
		return (EOFFLINE);
	} else {
		hostid = record->hostid;
		status = record->node_status.status;
	}

	if(status == ZFS_MULTICLUS_NODE_OFFLINE){
		cmn_err(CE_WARN, "The record, spa:0x%llx, os:0x%llx is OFFLINE, cmd: %llx, opera: %llx", 
			(longlong_t)msg_header->server_spa, (longlong_t)msg_header->server_os, (longlong_t)msg_header->command, (longlong_t)msg_header->operation);
		/*if (record->node_type == ZFS_MULTICLUS_MASTER) {
			if (trans_again_count < 30) {
				trans_again_count++;
				zfs_group_wait(ZFS_MULTICLUS_SECOND);
				goto trans_again;
			}
		}*/
		return (EOFFLINE);
	}

	key = msg_header->seqno = zfs_group_send_seq(os);	
	tx_hash_member = (zfs_multiclus_hash_t *)zfs_multiclus_create_hash_member(key, B_FALSE);
	tx_hash_member->multiclus_segments = 1;
	tx_hash_member->omsg_header = (char *)msg_header;
	zfs_multiclus_insert_hash(modhash_header, tx_hash_member);
	

	if (hostid == zfs_multiclus_node_id) {
		bsame_host = B_TRUE;
	}
	
	if (!bsame_host) {
		
		msg_header->msg_type = ZFS_MULTICLUS_OPERATE_MSG;
		msg_header->data_index = mm_log_index;
		msg_header->hostid = zfs_multiclus_node_id;

		tx_log_time_tmp1 = gethrtime();
		cshi = cluster_remote_hostinfo_hold((uint32_t)hostid);
		if (!cshi) {
			cmn_err(CE_WARN, "%s, %d, hold hostinfo(hostid: %llx) failed!", 
				__func__, __LINE__, (unsigned long long)hostid);
			zfs_multiclus_remove_hash(modhash_header, tx_hash_member);
			zfs_multiclus_destroy_hash_member(tx_hash_member);
			return (EOFFLINE);
		}
		zfs_multiclus_test_data_error((void *)msg_header,(void *)msg_data, (uint64_t)data_len);
		err = cluster_san_host_send(cshi, (void *)msg_data, data_len, (void *)msg_header, 
			sizeof(zfs_group_header_t), CLUSTER_SAN_MSGTYPE_CLUSTERFS, 0, B_TRUE, 2);
		zfs_multiclus_test_data_error((void *)msg_header,(void *)msg_data, (uint64_t)data_len);
		cluster_san_hostinfo_rele(cshi);
		if (err) {
			cmn_err(CE_WARN, "%s, %d, send msg to host(%llx) failed!", 
				__func__, __LINE__, (unsigned long long)hostid);
			zfs_multiclus_remove_hash(modhash_header, tx_hash_member);
			zfs_multiclus_destroy_hash_member(tx_hash_member);
			return EOFFLINE;
		}
		tx_log_time_tmp2 = gethrtime();
		mutex_enter(&tx_hash_member->multiclus_hash_mutex);
		tx_hash_member->tx_no_rx = 0;
		if(tx_hash_member->multiclus_segments == 0){
		}else{
			ret = cv_timedwait(&tx_hash_member->multiclus_hash_cv,
		    	&tx_hash_member->multiclus_hash_mutex, ddi_get_lbolt() + time);
		}
		wait = tx_hash_member->multiclus_segments;
		rx_log_time = gethrtime();
		tx_hash_member->tx_no_rx = 1;
		mutex_exit(&tx_hash_member->multiclus_hash_mutex);

		zfs_multiclus_remove_hash(modhash_header, tx_hash_member);
		mutex_enter(&tx_hash_member->multiclus_hash_mutex);
		if (ret == -1 && wait) {
			zfs_group_header_t *omhr = (zfs_group_header_t *)(tx_hash_member->omsg_header);
			if (0 != omhr->nmsg_header) {
				kmem_free((zfs_group_header_t *)((uintptr_t)(omhr->nmsg_header)), sizeof(zfs_group_header_t));
				omhr->nmsg_header = 0;
			}
			if (0 != omhr->nmsg_data) {
				kmem_free((zfs_msg_t *)((uintptr_t)(omhr->nmsg_data)), omhr->nmsg_len);
				omhr->nmsg_data = 0;
			}
		}
		mutex_exit(&tx_hash_member->multiclus_hash_mutex);
		zfs_multiclus_destroy_hash_member(tx_hash_member);
		tx_hash_member = NULL;

		if (wait && ((rx_log_time - tx_log_time)/1000 < ZFS_MULTICLUS_OPERATE_TIMEOUT)) {
			cmn_err(CE_WARN, "write operate timeout, wait:%d, key:%lld, cmd:0x%llx, operate:%llx, "
			    "send time1:%lld, wait time2:%lld, data_len:%lld",
			    wait, (longlong_t)key, (longlong_t)(msg_header->command), (longlong_t)(msg_header->operation),
			    (longlong_t)(tx_log_time_tmp2 - tx_log_time_tmp1),
			    (longlong_t)(rx_log_time - tx_log_time_tmp2), (longlong_t)data_len);

			tx_log_time_tmp1 = 0;
			tx_log_time_tmp2 = 0;
			key = 0;
			goto trans_again;
		} 

	}else {
		zfs_multiclus_remove_hash(modhash_header, tx_hash_member);
		wait = tx_hash_member->multiclus_segments;
		zfs_multiclus_destroy_hash_member(tx_hash_member);
	}
	return (wait);
}

int zfs_multiclus_write_group_record(void *reg, zfs_multiclus_data_type_t data_type, 
	zfs_multiclus_node_type_t node_type)
{
	int	group_name_len = 0;
	uint64_t	mm_log_index = 0;
	zfs_msg_t	*msg_data = NULL;
	zfs_group_header_t	*head = NULL;
	zfs_group_reg_t *reg_msg = (zfs_group_reg_t*)reg;
	zfs_multiclus_group_record_t *record = NULL;


	if (!zfs_multiclus_enable()) {
		cmn_err(CE_WARN, "[%s %d] multiclus is disabled!", __func__, __LINE__);
		return (1);
	}

	if (!spa_by_guid(reg_msg->spa_id, 0)) {
		cmn_err(CE_WARN, "[%s %d] get spa by guid fail!!!", __func__, __LINE__);
		return (1);
	}

	head = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
	msg_data = kmem_zalloc(sizeof(zfs_msg_t), KM_SLEEP);
	group_name_len = strlen((const char *)reg_msg->group_name);
	mm_log_index = zfs_multiclus_get_log_index();

	head->data_index = mm_log_index;
	head->msg_type = data_type;
	head->group_name_len = group_name_len;
	head->m_node_type = node_type;
	bcopy(reg_msg->group_name, head->group_name, group_name_len);
	bcopy(reg_msg, msg_data, sizeof(zfs_group_reg_t));
	msg_data->call.regist.node_type = node_type;
	if (data_type == ZFS_MULTICLUS_GROUP_CHANGE) {
		record = zfs_multiclus_get_group_master((char *)reg_msg->group_name, node_type);
		if (record) {
			strncpy((char*)msg_data->call.regist.fsname, (char*)record->fsname, strlen((char*)record->fsname));
		}
	}
	
	cluster_san_broadcast_send((char *)msg_data, sizeof(zfs_msg_t), (void *)head, sizeof(zfs_group_header_t), CLUSTER_SAN_MSGTYPE_CLUSTERFS, 0);
	kmem_free(head, sizeof(zfs_group_header_t));
	kmem_free(msg_data, sizeof(zfs_msg_t));
	return 0;
}

// uint_t
// zfs_multiclus_walk_hash_callback(mod_hash_key_t key, mod_hash_val_t *val, void *arg)
// {
// 	zfs_multiclus_hash_t *hash_member = (zfs_multiclus_hash_t *)val;
// 	list_t *rx_timeout_list = (list_t *)arg;

// 	list_insert_tail(rx_timeout_list, hash_member);

// 	return (0);
// }
 
// static void
// zfs_multiclus_handle_walk_operate(zfs_multiclus_hash_header_t *hash_header, list_t *walk_list)
// {
// 	zfs_multiclus_hash_t *hash_member = NULL;

// 	while ((hash_member = list_remove_head(walk_list)) != NULL) {
// 		zfs_multiclus_remove_hash(hash_header->zfs_multiclus_modhash, hash_member);

// 		if (hash_member->rx_flag == 0){
// 			mutex_enter(&hash_member->multiclus_hash_mutex);
// 			/* for preventing conflict */
// 			mutex_exit(&hash_member->multiclus_hash_mutex);
// 		} else {
// 			rw_enter(&hash_member->rx_timeout_lock, RW_WRITER);
// 			/* for preventing conflict */
// 			rw_exit(&hash_member->rx_timeout_lock);
// 		}

// 		if (hash_member->datap)
// 			kmem_free(hash_member->datap, hash_member->data_len);
		
// 		zfs_multiclus_destroy_hash_member(hash_member);
// 	}
// }

// static void
// zfs_multiclus_clean_all_hash_member(zfs_multiclus_hash_header_t *hash_header)
// {
// 	list_t walk_list;

// 	list_create(&walk_list, sizeof(zfs_multiclus_hash_t),
// 	    offsetof(zfs_multiclus_hash_t, hash_list_node));
	
// 	/* walk all member */
// 	rw_enter(&hash_header->zfs_multiclus_timeout_lock, RW_WRITER);
// 	mod_hash_walk(hash_header->zfs_multiclus_modhash, 
// 		zfs_multiclus_walk_hash_callback, &walk_list);
// 	zfs_multiclus_handle_walk_operate(hash_header, &walk_list);
// 	rw_exit(&hash_header->zfs_multiclus_timeout_lock);

// 	list_destroy(&walk_list);

// }

/* for multi cluster group table */
static void
zfs_multiclus_table_init(void)
{
	mutex_init(&multiclus_mtx, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&multiclus_mtx_update_record, NULL, MUTEX_DEFAULT, NULL);
	zfs_multiclus_table = vmem_zalloc(sizeof(zfs_multiclus_group_t)*ZFS_MULTICLUS_GROUP_TABLE_SIZE,
	    KM_SLEEP);
}

// static void
// zfs_multiclus_table_fini(void)
// {
// 	int i = 0;

// 	for (i = 0; i < ZFS_MULTICLUS_GROUP_TABLE_SIZE; i++){
// 		if (zfs_multiclus_table[i].used == B_TRUE){
// 			mutex_destroy(&zfs_multiclus_table[i].multiclus_group_mutex);
// 			cv_destroy(&zfs_multiclus_table[i].multiclus_group_cv);
// 			taskq_destroy(zfs_multiclus_table[i].group_reg_timer_tq);
// //			ddi_taskq_destroy(zfs_multiclus_table[i].group_reg_timer_tq);
// 		}
// 	}
// 	mutex_destroy(&multiclus_mtx_update_record);
// 	mutex_destroy(&multiclus_mtx);
// 	bzero(zfs_multiclus_table, sizeof(zfs_multiclus_group_t) * ZFS_MULTICLUS_GROUP_TABLE_SIZE);
// 	vmem_free(zfs_multiclus_table, sizeof(zfs_multiclus_group_t)*ZFS_MULTICLUS_GROUP_TABLE_SIZE);
// }

/* use to mark tx's frame for every spa&os in multi cluster */
static void
zfs_multiclus_tx_hash_init(void)
{
	mutex_init(&zfs_multiclus_tx_hash_mtx, NULL, MUTEX_DEFAULT, NULL);
	zfs_multiclus_tx_hash =
	    vmem_zalloc(sizeof(zfs_multiclus_hash_header_t)*ZFS_MULTICLUS_MAX_OS_NUMS, KM_SLEEP);

	bzero(zfs_multiclus_tx_hash,
	    sizeof(zfs_multiclus_hash_header_t) * ZFS_MULTICLUS_MAX_OS_NUMS);
}

// static void
// zfs_multiclus_tx_hash_fini(void)
// {
// 	int i;

// 	for (i = 0; i < ZFS_MULTICLUS_MAX_OS_NUMS; i++){
// 		if (zfs_multiclus_tx_hash[i].used){
// 			zfs_multiclus_clean_all_hash_member(&zfs_multiclus_tx_hash[i]);
// 			mod_hash_destroy_idhash(zfs_multiclus_tx_hash[i].zfs_multiclus_modhash);
// 		}
// 	}
// 	vmem_free(zfs_multiclus_tx_hash,
// 	    sizeof(zfs_multiclus_hash_header_t) * ZFS_MULTICLUS_MAX_OS_NUMS);
// 	mutex_destroy(&zfs_multiclus_tx_hash_mtx);
// }

/* use to mark rx's frame for every spa&os in multi cluster */
static void
zfs_multiclus_rx_hash_init(void)
{
	mutex_init(&zfs_multiclus_rx_hash_mtx, NULL, MUTEX_DEFAULT, NULL);
	zfs_multiclus_rx_hash = vmem_zalloc(sizeof(zfs_multiclus_hash_header_t)
	    * ZFS_MULTICLUS_MAX_OS_NUMS, KM_SLEEP);
	bzero(zfs_multiclus_rx_hash, sizeof(zfs_multiclus_hash_header_t)
	    *ZFS_MULTICLUS_MAX_OS_NUMS);
}

// static void
// zfs_multiclus_rx_hash_fini(void)
// {
// 	int i;

// 	for (i = 0; i < ZFS_MULTICLUS_MAX_OS_NUMS; i++){
// 		if (zfs_multiclus_rx_hash[i].used){
// 			if (zfs_multiclus_rx_hash[i].zfs_multiclus_timeout){
// 				rw_enter(&zfs_multiclus_rx_hash[i].zfs_multiclus_timeout_lock, RW_WRITER);
// 				zfs_multiclus_hash_tmchk_thr_stop(i);
// 				rw_exit(&zfs_multiclus_rx_hash[i].zfs_multiclus_timeout_lock);
// 			}
			
// 			zfs_multiclus_clean_all_hash_member(&zfs_multiclus_rx_hash[i]);

// 			rw_destroy(&zfs_multiclus_rx_hash[i].zfs_multiclus_timeout_lock);
// 			mod_hash_destroy_idhash(zfs_multiclus_rx_hash[i].zfs_multiclus_modhash);
// 		}
// 	}
// 	vmem_free(zfs_multiclus_rx_hash,
// 	    sizeof(zfs_multiclus_hash_header_t) * ZFS_MULTICLUS_MAX_OS_NUMS);
// 	mutex_destroy(&zfs_multiclus_rx_hash_mtx);
// }

static int
zfs_multiclus_nodeid_init(void)
{
	uint32_t	hostid;

	hostid = zone_get_hostid(NULL);
	zfs_multiclus_node_id = hostid;

	return (0);
}

int zfs_multiclus_init(void)
{
	int err;
	uint32_t stat = 0;
	nvlist_t *clustersan_stat = NULL;
	
	clustersan_stat = cluster_san_get_state();
	if (clustersan_stat == NULL) {
		cmn_err(CE_WARN, "%s, %d, clustersan is disable!", __func__, __LINE__);
		return (-1);
	}

	err = nvlist_lookup_uint32(clustersan_stat, CS_NVL_STATE, &stat);
	nvlist_free(clustersan_stat);
	if (err || stat != CLUSTER_SAN_STATE_ENABLE) {
		cmn_err(CE_WARN, "%s, %d, clustersan is disable!", __func__, __LINE__);
		return (-1);
	}
	
	zfs_multiclus_load_config();
	
	cmn_err(CE_WARN, "zfs multiclus initialize");
	if (zfs_multiclus_global_workers.zfs_multiclus_action_workers.zfs_multiclus_action_worker_nodes != NULL && 
		zfs_multiclus_global_workers.zfs_multiclus_rx_workers.zfs_multiclus_rx_worker_nodes != NULL) {
		cmn_err(CE_WARN, "%s, %d, multiclus already initialized!", __func__, __LINE__);
		zfs_multiclus_mac_initialized = B_TRUE;
		return (0);
	}
	
	err = zfs_multiclus_nodeid_init();
	if (err != 0) {
		return (-1);
	}

	zfs_multiclus_table_init();
	zfs_multiclus_tx_hash_init();
	zfs_multiclus_rx_hash_init();
	zfs_multiclus_workers_init();
	csh_rx_hook_add(CLUSTER_SAN_MSGTYPE_CLUSTERFS, zfs_multiclus_rx, NULL);
		
	zfs_multiclus_mac_initialized = B_TRUE;
	cmn_err(CE_WARN, "end of initialize port multiclus");

	return 0;
}

void zfs_multiclus_fini(void)
{
	zfs_multiclus_mac_initialized = B_FALSE;
	
	if (zfs_multiclus_global_workers.zfs_multiclus_action_workers.zfs_multiclus_action_worker_nodes == NULL && 
		zfs_multiclus_global_workers.zfs_multiclus_rx_workers.zfs_multiclus_rx_worker_nodes == NULL) {
		cmn_err(CE_WARN, "%s, %d, multiclus already destroyed!", __func__, __LINE__);
		return;
	}
}

boolean_t zfs_multiclus_enable(void)
{
	return (zfs_multiclus_mac_initialized);
}

uint64_t zfs_multiclus_get_log_index(void)
{
	uint64_t log_index = 0;
	mutex_enter(&zfs_multiclus_global_workers.mm_mutex);
	atomic_add_64(&zfs_multiclus_global_workers.mm_log_index, 1);
	log_index = zfs_multiclus_global_workers.mm_log_index;
	mutex_exit(&zfs_multiclus_global_workers.mm_mutex);
	return log_index;
}

// boolean_t zfs_multiclus_done(void)
// {
// 	return (zfs_multiclus_mac_initialized);
// }

uint64_t zfs_multiclus_get_all_record(zfs_group_info_t *gs, char **gname, 
	uint64_t *master, uint64_t *num_group, uint64_t *breakmark, boolean_t* onceflag)
{
	int i = 0;
	int j = 0;
	int gnum = 0;
	mutex_enter(&multiclus_mtx);
	for (i = *breakmark; i < ZFS_MULTICLUS_GROUP_TABLE_SIZE && (*num_group) > 0; i++){
		if(zfs_multiclus_table[i].used)	{
			mutex_enter(&zfs_multiclus_table[i].multiclus_group_mutex);
			strcpy(*gname, zfs_multiclus_table[i].group_name);
			for (j = 0; j < ZFS_MULTICLUS_GROUP_NODE_NUM; j++){
				if (zfs_multiclus_table[i].multiclus_group[j].used)
				{
					gs[gnum].spa_id = 
						zfs_multiclus_table[i].multiclus_group[j].spa_id;
					gs[gnum].host_id = zfs_multiclus_table[i].multiclus_group[j].hostid;
					gs[gnum].gnode_id = zfs_multiclus_table[i].multiclus_group[j].node_id;
					strcpy(gs[gnum].gi_fsname,
					    (char *)zfs_multiclus_table[i].multiclus_group[j].fsname);
					gs[gnum].avail_size =
					    zfs_multiclus_table[i].multiclus_group[j].avail_size;
					gs[gnum].used_size =
					    zfs_multiclus_table[i].multiclus_group[j].used_size;
					gs[gnum].load_ios =
					    zfs_multiclus_table[i].multiclus_group[j].load_ios;
					gs[gnum].node_status =
					    zfs_multiclus_table[i].multiclus_group[j].node_status.status;
					switch (zfs_multiclus_table[i].multiclus_group[j].node_type)
					{
						case ZFS_MULTICLUS_MASTER:
							strncpy(gs[gnum].node_type, "master", MAX_FSNAME_LEN - 1);
							gs[gnum].node_type[MAX_FSNAME_LEN - 1] = 0;
							master[0] = zfs_multiclus_table[i].multiclus_group[j].hostid;
							break;

						case ZFS_MULTICLUS_SLAVE:
							strncpy(gs[gnum].node_type, "slave", MAX_FSNAME_LEN - 1);
							gs[gnum].node_type[MAX_FSNAME_LEN - 1] = 0;
							break;

						case ZFS_MULTICLUS_MASTER2:
							strncpy(gs[gnum].node_type, "master2", MAX_FSNAME_LEN - 1);
							gs[gnum].node_type[MAX_FSNAME_LEN - 1] = 0;
							master[1] = zfs_multiclus_table[i].multiclus_group[j].hostid;
							break;

						case ZFS_MULTICLUS_MASTER3:
							strncpy(gs[gnum].node_type, "master3", MAX_FSNAME_LEN - 1);
							gs[gnum].node_type[MAX_FSNAME_LEN - 1] = 0;
							master[2] = zfs_multiclus_table[i].multiclus_group[j].hostid;
							break;

						case ZFS_MULTICLUS_MASTER4:
							strncpy(gs[gnum].node_type, "master4", MAX_FSNAME_LEN - 1);
							gs[gnum].node_type[MAX_FSNAME_LEN - 1] = 0;
							master[3] = zfs_multiclus_table[i].multiclus_group[j].hostid;
							break;

						default:
							strncpy(gs[gnum].node_type, "(unknown)", MAX_FSNAME_LEN - 1);
							gs[gnum].node_type[MAX_FSNAME_LEN - 1] = 0;
							break;
					}

					gnum++;
				}
			}
			mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
			if((--(*num_group)) == 0){
				*onceflag = B_FALSE; 			/*the end of once zfs_start_multiclus's 
												call  */
			}else{
				*onceflag = B_TRUE;
			}
			*breakmark = (i+1) % ZFS_MULTICLUS_GROUP_TABLE_SIZE; /*next group index*/

			break;
		}
	}
	mutex_exit(&multiclus_mtx);
	return (gnum);
}


int zfs_multiclus_get_info_from_group(zfs_migrate_cmd_t *zmc, char *gname, int num_zmc)
{
	int i = 0;
	int j = 0;
	int gnum = 0;
	for (i = 0; i < ZFS_MULTICLUS_GROUP_TABLE_SIZE; i++){
		if(zfs_multiclus_table[i].used && !strncmp(gname, zfs_multiclus_table[i].group_name, strlen(gname)))	{
			mutex_enter(&zfs_multiclus_table[i].multiclus_group_mutex);
			for (j = 0; j < ZFS_MULTICLUS_GROUP_NODE_NUM; j++){
				if (zfs_multiclus_table[i].multiclus_group[j].used && !zfs_multiclus_table[i].multiclus_group[j].node_type == ZFS_MULTICLUS_MASTER)
				{
					zmc[gnum].data_spa = zfs_multiclus_table[i].multiclus_group[j].spa_id;
					zmc[gnum].data_os = zfs_multiclus_table[i].multiclus_group[j].os_id;
					zmc[gnum].cmd_type = ZFS_MIGRATE_INSERT;
					//strncpy((char*)zmc[gnum].fsname, (char*)zfs_multiclus_table[i].multiclus_group[j].fsname, strlen(zfs_multiclus_table[i].multiclus_group[j].fsname));
					bcopy((char*)zfs_multiclus_table[i].multiclus_group[j].fsname, (char*)zmc[gnum].fsname, MAX_FSNAME_LEN);
					gnum++;
					if (gnum >= num_zmc)
						break;
				}
			}
			mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
			break;
		}
	}
	
	return (gnum);
}

int zfs_get_group_ip( nvlist_t **config)
{
	boolean_t gstatus;
	char *groupip[2*ZFS_MULTICLUS_GROUP_NODE_NUM] = {0};
	int i = 0;
	int j = 0;
	int gnum = 0;
	
	gstatus = zfs_multiclus_enable();
	if(B_FALSE == gstatus)
	{
		return (1);
	}

	for (i = 0; i < ZFS_MULTICLUS_GROUP_TABLE_SIZE; i++){
		if(zfs_multiclus_table[i].used)	{
			mutex_enter(&zfs_multiclus_table[i].multiclus_group_mutex);
			for (j = 0; j < ZFS_MULTICLUS_GROUP_NODE_NUM; j++){
				if (zfs_multiclus_table[i].multiclus_group[j].used &&
					(zfs_multiclus_node_id != zfs_multiclus_table[i].multiclus_group[j].hostid))
				{
					groupip[gnum] = kmem_alloc(MAX_FSNAME_LEN, KM_SLEEP);
					bzero(groupip[gnum], MAX_FSNAME_LEN);
					strcpy(groupip[gnum], (char*)zfs_multiclus_table[i].multiclus_group[j].rpc_addr);
					gnum++;
					groupip[gnum] = kmem_alloc(MAX_FSNAME_LEN, KM_SLEEP);
					bzero(groupip[gnum], MAX_FSNAME_LEN);
					strcpy(groupip[gnum], (char*)zfs_multiclus_table[i].multiclus_group[j].fsname);					
					gnum++;
				}
				if(gnum >= 2*ZFS_MULTICLUS_GROUP_NODE_NUM)
				{
					break;
				}
			}
			mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
			if(gnum >= 2*ZFS_MULTICLUS_GROUP_NODE_NUM)
			{
				break;
			}
		}
	}
	if(0 == gnum)
	{
		return (2);
	}
	
	VERIFY(nvlist_alloc(config, NV_UNIQUE_NAME, KM_SLEEP) == 0);
	VERIFY(nvlist_add_string_array(*config,
			ZFS_RPC_GROUP_IP, groupip, (uint_t)gnum) == 0);	

	for(i=0; i<gnum; i++)
	{
		if(groupip[i])
		{
			kmem_free(groupip[i], MAX_FSNAME_LEN);
		}
	}
	return (0);
}

int zfs_get_master_ip(char *fsname, nvlist_t **config)
{
	boolean_t gstatus;
	char *masterip[4] = {0};
	char *masterfs[4] = {0};
	char *mastertype[4] = {0};
	int mastercnt = 0;
	int i = 0;
	int j = 0;
	int matchfs = 0;
	char master[] = "master";
	char bakmaster[] = "bakmaster";
	
	gstatus = zfs_multiclus_enable();
	if(B_FALSE == gstatus)
	{
		return (1);
	}
	mutex_enter(&multiclus_mtx);
	for (i = 0; i < ZFS_MULTICLUS_GROUP_TABLE_SIZE; i++){
		if(zfs_multiclus_table[i].used)	{
			mutex_enter(&zfs_multiclus_table[i].multiclus_group_mutex);
			mastercnt = 0;
			for (j = 0; j < ZFS_MULTICLUS_GROUP_NODE_NUM; j++){
				if(zfs_multiclus_table[i].multiclus_group[j].used)
				{
					if (strcmp((char*)zfs_multiclus_table[i].multiclus_group[j].fsname, 
							fsname) == 0){
						matchfs = 1;
						if(mastercnt >= 4)
						{
							break;
						}
							
					} 
					if((zfs_multiclus_table[i].multiclus_group[j].node_type == 
						ZFS_MULTICLUS_MASTER)
						||(zfs_multiclus_table[i].multiclus_group[j].node_type == 
						ZFS_MULTICLUS_MASTER2)
						||(zfs_multiclus_table[i].multiclus_group[j].node_type == 
						ZFS_MULTICLUS_MASTER3)
						||(zfs_multiclus_table[i].multiclus_group[j].node_type == 
						ZFS_MULTICLUS_MASTER4)){
						if(mastercnt < 4){
							masterip[mastercnt] = (char*)zfs_multiclus_table[i].multiclus_group[j].rpc_addr;
							masterfs[mastercnt] = (char*)zfs_multiclus_table[i].multiclus_group[j].fsname;
							if(zfs_multiclus_table[i].multiclus_group[j].node_type == 
								ZFS_MULTICLUS_MASTER){
								mastertype[mastercnt] = (char*)master;
							}else{
								mastertype[mastercnt] = (char*)bakmaster;
							}
							mastercnt++;
						}
						if((mastercnt >=4) && matchfs){
							break;
						}
					}
				}
			}
			mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
			if(matchfs){
				break;
			}
		}
	}
	mutex_exit(&multiclus_mtx);
	if(0 == matchfs)
	{
		return (2);
	}
	
	VERIFY(nvlist_alloc(config, NV_UNIQUE_NAME, KM_SLEEP) == 0);
	
	VERIFY(nvlist_add_string_array(*config,
			ZFS_RPC_MASTER_IP, masterip, (uint_t)mastercnt) == 0);	
	VERIFY(nvlist_add_string_array(*config,
			ZFS_RPC_MASTER_FS, masterfs, (uint_t)mastercnt) == 0);	
	VERIFY(nvlist_add_string_array(*config,
			ZFS_RPC_MASTER_TYPE, mastertype, (uint_t)mastercnt) == 0);	

	return (0);
}

int zfs_get_group_state(nvlist_t **config, uint64_t *num_group ,
	uint64_t *breakmark, boolean_t *onceflag)
{
	nvlist_t *nv = NULL;
	zfs_group_info_t *gs = NULL;
	char gname[MAX_FSNAME_LEN] = {0};
	char *gptr = gname;
	uint64_t master[4] ={0};
	uint64_t gnum = 0;
	int i = 0 ;
	VERIFY(nvlist_alloc(&nv, NV_UNIQUE_NAME, KM_SLEEP) == 0);

	gs = vmem_zalloc(sizeof(zfs_group_info_t)*ZFS_MULTICLUS_GROUP_NODE_NUM, KM_SLEEP);

	/* ' B_FALSE == *onceflag ' is that mean once start of zfs_start_multiclus's 
	call and in this case that need to counts number of using group in zfs_multiclus_table*/
	if(B_FALSE == *onceflag){
		mutex_enter(&multiclus_mtx);
		for (; i < ZFS_MULTICLUS_GROUP_TABLE_SIZE; i++){
			if(zfs_multiclus_table[i].used)	{
				mutex_enter(&zfs_multiclus_table[i].multiclus_group_mutex);
				(*num_group)++;
				mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
			}
		}
		mutex_exit(&multiclus_mtx);
	}

	/* every call, it will return one record of groups until num_group == 0 */
	gnum = zfs_multiclus_get_all_record(gs, &gptr, master, num_group, 
		breakmark, onceflag);

	VERIFY(nvlist_add_string(nv, ZPOOL_CONFIG_MULTICLUS_GNAME,
	    gname) == 0);
	VERIFY(nvlist_add_uint64_array(nv, ZPOOL_CONFIG_MULTICLUS_MASTER,
	    (uint64_t *)master, 4) == 0);
	VERIFY(nvlist_add_uint64(nv, ZPOOL_CONFIG_MULTICLUS_GNUM,
	    gnum) == 0);
	VERIFY(nvlist_add_uint64_array(nv, ZPOOL_CONFIG_MULTICLUS,
	    (uint64_t *)gs, ((sizeof (zfs_group_info_t))*gnum) / sizeof (uint64_t)) == 0);
	*config = nv;

	vmem_free(gs, sizeof(zfs_group_info_t)*ZFS_MULTICLUS_GROUP_NODE_NUM);
	return (0);
}

int
zfs_get_group_znode_info(char *path, nvlist_t **config)
{
	nvlist_t *nv = NULL;
	struct file *filp = NULL;
	struct inode *ip = NULL;
	znode_t *zp;
	zfs_group_object_t *zp_info = NULL;
	
	if (path == NULL) {
		*config = NULL;
		return EINVAL;
	}

	filp = filp_open(path, O_DIRECTORY, 0);
	if (IS_ERR(filp)){
		filp = filp_open(path, O_RDONLY, 0444);
		if (IS_ERR(filp)){
			cmn_err(CE_WARN, "[%s %d], the path %s is error", __func__, __LINE__, path);
			*config = NULL;
			return (EINVAL);
		}
	}

	ip = filp->f_path.dentry->d_inode;
	zp = ITOZ(ip);

	zp_info = kmem_zalloc(sizeof(zfs_group_object_t), KM_SLEEP);
	bcopy(&zp->z_group_id, zp_info, sizeof(zfs_group_object_t));
	VERIFY(nvlist_alloc(&nv, NV_UNIQUE_NAME, KM_SLEEP) == 0);
	VERIFY(nvlist_add_uint64_array(nv, ZPOOL_CONFIG_MULTICLUS_ZNODEINFO,
	    (uint64_t *)zp_info, (sizeof(zfs_group_object_t) / sizeof(uint64_t)) ) == 0);
	VERIFY(nvlist_add_string(nv, ZPOOL_CONFIG_MULTICLUS_ZFILENAME, 
		(const char *)zp->z_filename) == 0);

	*config = nv;
	kmem_free(zp_info, sizeof(zfs_group_object_t));
	filp_close(filp, NULL);
	return (0);
}


// int zfs_get_group_name(char *poolname, nvlist_t **rmconfig)
// {
// 	int err=0;
// 	objset_t *os = NULL;
// 	uint64_t spa_id;
// 	uint64_t dsl_id;
// 	zfs_multiclus_group_t *group = NULL;

// 	if (zfs_multiclus_enable() == B_FALSE)
// 	{
// 		cmn_err(CE_WARN, "%s: Multiclus is disable !!!", __func__);
// 		return (-1);
// 	}
	
// 	if (err = dmu_objset_hold(poolname, FTAG, &os)){
// 		cmn_err(CE_WARN, "%s: dmu_objset_hold FAIL !!!", __func__);
// 		return (err);
// 	}
	
// 	spa_id = spa_guid(dmu_objset_spa(os));
// 	dsl_id = os->os_dsl_dataset->ds_object;

// 	group = zfs_multiclus_get_current_group(spa_id );
// 	if(NULL == group )
// 	{
// 		cmn_err(CE_WARN, "%s: FAIL to find the Group!!!", __func__);
// 		dmu_objset_rele(os, FTAG);
// 		return (-1);
// 	}

// 	VERIFY(nvlist_alloc(rmconfig, NV_UNIQUE_NAME, KM_SLEEP) == 0);
// 	VERIFY(nvlist_add_string(*rmconfig, ZPOOL_CONFIG_MULTICLUS_GNAME,
// 			group->group_name) == 0);

// 	dmu_objset_rele(os, FTAG);

// 	return (0);
// }


int zfs_multiclus_get_fsname(uint64_t spa_guid, uint64_t objset, char *fsname)
{
	int err;
	spa_t *spa = NULL;
	dsl_pool_t *dp = NULL;
	dsl_dataset_t *dsl_dataset = NULL;
	
	mutex_enter(&spa_namespace_lock);
	spa = spa_by_guid(spa_guid, 0);
	if (spa == NULL) {
		mutex_exit(&spa_namespace_lock);
		return (-1);
	}
		
	dp = spa_get_dsl(spa);
	rrw_enter(&dp->dp_config_rwlock, RW_READER, FTAG);
	err = dsl_dataset_hold_obj(dp, objset, FTAG, &dsl_dataset);
	rrw_exit(&dp->dp_config_rwlock, FTAG);
	if (err != 0)
		cmn_err(CE_WARN, "dsl_dataset_hold_obj errno:%d", err);
	mutex_exit(&spa_namespace_lock);
	if (dsl_dataset == NULL)
		return (-1);

	dsl_dataset_name(dsl_dataset, fsname);
	dsl_dataset_rele(dsl_dataset, FTAG);
	return (0);
}

//only master can enter this function
static void
zfs_multiclus_refresh_nodes_status(char * group_name)
{
	int i;
	zfs_multiclus_group_record_t *master_record = NULL;
	zfs_multiclus_group_record_t *node_record = NULL;
	zfs_multiclus_group_t *group_entry = NULL;
	zfs_sb_t *zsb = NULL;
	
	for (i = 0; i < ZFS_MULTICLUS_GROUP_TABLE_SIZE; i++){
		group_entry = &zfs_multiclus_table[i];
		if (group_entry->used && strncmp(group_entry->group_name,
		    group_name, strlen(group_name)) == 0){
			break;
		}
	}

	if (group_entry->used == B_TRUE) {
		for (i = 0; i < ZFS_MULTICLUS_GROUP_NODE_NUM; i ++) {
			master_record = &group_entry->multiclus_group[i];
			if (master_record->node_type == ZFS_MULTICLUS_MASTER) {
				break;
			}
			master_record = NULL;
		}
		for(i = 0; i < ZFS_MULTICLUS_GROUP_NODE_NUM; i++) {
			node_record = &group_entry->multiclus_group[i];
			if (node_record->used) {
				if(node_record->node_type == ZFS_MULTICLUS_MASTER || 
					(master_record != NULL  && (node_record->hostid) == (master_record->hostid)))
				{	
					zsb = zfs_sb_group_hold(node_record->spa_id, node_record->os_id, FTAG, B_FALSE);
					if (zsb == NULL){
						node_record->node_status.status = ZFS_MULTICLUS_NODE_OFFLINE;
					}else{
						node_record->node_status.status = ZFS_MULTICLUS_NODE_ONLINE;
						zfs_sb_group_rele(zsb, FTAG);
					}
				}
				else{
					switch(node_record->node_status.status){
						case ZFS_MULTICLUS_NODE_OFFLINE:
							{
								break;
							}
						case ZFS_MULTICLUS_NODE_CHECKING:
							{
							 /*
								Just only switch to ZFS_MULTICLUS_NODE_CHECKING 
								from ZFS_MULTICLUS_NODE_ONLINE
							 */
							 	if ((gethrtime() - node_record->node_status.last_update_time)/1000 > 60*ZFS_MULTICLUS_SECOND){
									node_record->node_status.status
										= ZFS_MULTICLUS_NODE_OFFLINE;
							 	}
								break;
							}
						case ZFS_MULTICLUS_NODE_ONLINE:
							{
								if ((gethrtime() - node_record->node_status.last_update_time)/1000 > 10*ZFS_MULTICLUS_SECOND){
									node_record->node_status.status
										= ZFS_MULTICLUS_NODE_CHECKING;
								}
								break;
							}
						default:
							{ }	
						}
					}
				}
			node_record = NULL;
			}
	}
}

int masterX_wait_count = 2;
static void
zfs_multiclus_register_tq(zfs_group_reg_t *reg_data)
{
	clock_t time = 0, left_time = 0;
	int err = 0;
	boolean_t record_reinit = B_FALSE;
	boolean_t First_wait = B_TRUE;
	boolean_t will_be_master = B_FALSE;
	int group_num = 0;
	int group_index = 0;
	int reg_index = 0;
	int waitcount = 0;
	zfs_multiclus_group_record_t *record = NULL;
	zfs_multiclus_group_record_t *tmp_record = NULL;
	zfs_multiclus_group_record_t *group_master = NULL;
	zfs_multiclus_register_t *reg_record = NULL;
	zfs_multiclus_group_t *group = NULL;
	objset_t *os = NULL;
	zfs_multiclus_node_type_t node_type = ZFS_MULTICLUS_SLAVE;
	zfs_multiclus_node_type_t tmp_type = ZFS_MULTICLUS_MASTER;
	zfs_group_header_t *msg_header = NULL;
	uint64_t refdbytesp = 0;
	uint64_t availbytesp = 0;
	uint64_t usedobjsp = 0;
	uint64_t availobjsp = 0;
	uint64_t node_id = 0;
	
	while (1) {
		mutex_enter(&multiclus_mtx_update_record);
		group_num = zfs_multiclus_get_group((char *)reg_data->group_name, &group);
		if (group == NULL) {
			cmn_err(CE_WARN, "[%s %d] Can not get group info, there is a serious problem!", 
				__func__, __LINE__);
			mutex_exit(&multiclus_mtx_update_record);
			break;
		}

		reg_record = zfs_multiclus_get_reg_record((char *)reg_data->group_name, 
			reg_data->spa_id, reg_data->os_id, &group_index, &reg_index);
		if (reg_record == NULL) {
			cmn_err(CE_WARN, "[%s %d] zfs_multiclus_register_tq exit.",__func__, __LINE__);
			mutex_exit(&multiclus_mtx_update_record);
			break;
		}

		record = zfs_multiclus_get_record(reg_data->spa_id, reg_data->os_id);
		if (record == NULL) {
			record_reinit = B_TRUE;
			cmn_err(CE_WARN, "[%s %d] Cannot get the record! will reinit!", __func__, __LINE__);
			
			if ((err = dmu_objset_hold((char *)reg_data->fsname, FTAG, &os))) {
				zfs_multiclus_destroy_reg_record((char*)(reg_data->group_name),
					record->spa_id, record->os_id);
				cmn_err(CE_WARN, "[%s %d] zfs_multiclus_register_tq exit: can't hold %s",
					__func__, __LINE__, (char *)reg_data->fsname);
				mutex_exit(&multiclus_mtx_update_record);
				break;
			}
			node_id = os->os_group_node_id;
			node_type = zmc_get_node_type(os);
			dmu_objset_space(os, &refdbytesp, &availbytesp, &usedobjsp, &availobjsp);
			dmu_objset_rele(os, FTAG);
			reg_data->avail_size = availbytesp;
			reg_data->used_size = refdbytesp;
			reg_data->node_type = node_type;
			reg_data->node_id = node_id;
		} else {
			node_type = record->node_type ;
			reg_data->avail_size = record->avail_size;
			reg_data->used_size = record->used_size;
			reg_data->node_id = record->node_id;
			reg_data->node_type = node_type;
		}

		if(record_reinit) {
			if (node_type != ZFS_MULTICLUS_SLAVE) {
				tmp_record = zfs_multiclus_get_group_master((char*)(reg_data->group_name), node_type);
				if (tmp_record != NULL) {
					for (tmp_type = ZFS_MULTICLUS_MASTER; tmp_type < ZFS_MULTICLUS_NODE_TYPE_NUM; tmp_type++) {
						if (NULL == zfs_multiclus_get_group_master((char*)(reg_data->group_name), tmp_type)) {
							break;
						}
					}
					if (tmp_type == ZFS_MULTICLUS_NODE_TYPE_NUM) {
						tmp_type = ZFS_MULTICLUS_SLAVE;
					}

					if ((err = dmu_objset_hold((char *)reg_data->fsname, FTAG, &os))) {
						zfs_multiclus_destroy_reg_record((char*)(reg_data->group_name),
							record->spa_id, record->os_id);
						cmn_err(CE_WARN, "[%s %d] zfs_multiclus_register_tq exit: can't hold %s",
							__func__, __LINE__, (char *)reg_data->fsname);
						mutex_exit(&multiclus_mtx_update_record);
						break;
					}
					(void)zmc_change_objset_node_type((char*)(reg_data->group_name), 
						(char *)reg_data->fsname, os, tmp_type);
					node_type = tmp_type;
					reg_data->node_type = node_type;
				}
			}
			zfs_multiclus_group_record_init((char*)reg_data->group_name,
				(char*)reg_data->fsname, reg_data->spa_id, 
				reg_data->os_id, reg_data->root,
				node_type, reg_data->avail_size,
				reg_data->used_size, reg_data->load_ios, reg_data->node_id);
			record_reinit = B_FALSE;
			waitcount = 0;
			cmn_err(CE_WARN, "[%s %d] zfs_multiclus_register_tq reinit record: %s, node_type:%d, cache_head->node_type: %d",
				__func__, __LINE__, (char *)reg_data->fsname, node_type, reg_data->node_type);
			mutex_exit(&multiclus_mtx_update_record);
			continue;
		}

		err = zfs_multiclus_write_group_record((void *)reg_data, ZFS_MULTICLUS_GROUP_MSG, node_type);
		mutex_exit(&multiclus_mtx_update_record);
		
		mutex_enter(&reg_record->reg_timer_lock);
		if (node_type == ZFS_MULTICLUS_MASTER) {
			time = drv_usectohz(zfs_multiclus_master_wait_time);
			left_time = cv_timedwait(&reg_record->reg_timer_cv, &reg_record->reg_timer_lock, ddi_get_lbolt() + time); 
			mutex_exit(&reg_record->reg_timer_lock);
			mutex_enter(&multiclus_mtx);
			mutex_enter(&group->multiclus_group_mutex);
			if (zfs_multiclus_valid_reg_record((char *)reg_data->group_name, reg_data->spa_id, reg_data->os_id)) {
				zfs_multiclus_refresh_nodes_status((char *)reg_data->group_name);
				mutex_exit(&group->multiclus_group_mutex);
				mutex_exit(&multiclus_mtx);
			} else {
				record->node_status.status = ZFS_MULTICLUS_NODE_OFFLINE;
				msg_header = kmem_zalloc(sizeof(zfs_group_header_t), KM_SLEEP);
				bcopy(reg_data->group_name, msg_header->group_name, reg_data->group_name_len);
				msg_header->group_name_len = reg_data->group_name_len;
				(void)zfs_multiclus_write_group_reply_msg((void *)(&(group->multiclus_group)), msg_header,
				    ZFS_MULTICLUS_GROUP_REPLY);
				kmem_free(msg_header, sizeof(zfs_group_header_t));
				mutex_exit(&group->multiclus_group_mutex);
				mutex_exit(&multiclus_mtx);
				goto break_out;
			}
		}else if(node_type == ZFS_MULTICLUS_MASTER2 ||
			node_type == ZFS_MULTICLUS_MASTER3 ||
			node_type == ZFS_MULTICLUS_MASTER4 ) {
			if (First_wait) {
				time = drv_usectohz(zfs_multiclus_master_wait_time * 8);
				First_wait = B_FALSE;
			} else {
				time = drv_usectohz(zfs_multiclus_master_wait_time * masterX_wait_count);
			}
			left_time = cv_timedwait(&reg_record->reg_timer_cv, 
				&reg_record->reg_timer_lock, ddi_get_lbolt() + time);
			mutex_exit(&reg_record->reg_timer_lock);
		} else {
			time = drv_usectohz(zfs_multiclus_slave_wait_time);
			left_time = cv_timedwait(&reg_record->reg_timer_cv, 
				&reg_record->reg_timer_lock, ddi_get_lbolt() + time);
			mutex_exit(&reg_record->reg_timer_lock);
		}
		mutex_enter(&multiclus_mtx_update_record);
		mutex_enter(&multiclus_mtx);
		mutex_enter(&group->multiclus_group_mutex);
		if (!zfs_multiclus_valid_reg_record((char *)reg_data->group_name, reg_data->spa_id, reg_data->os_id)) {
			mutex_exit(&group->multiclus_group_mutex);
			mutex_exit(&multiclus_mtx);
			mutex_exit(&multiclus_mtx_update_record);
			goto break_out;
		}
		mutex_exit(&group->multiclus_group_mutex);
		mutex_exit(&multiclus_mtx);

		if((left_time == -1 || waitcount >= 20) && node_type != ZFS_MULTICLUS_SLAVE)/* ||
			node_type == ZFS_MULTICLUS_MASTER3 || 
			node_type == ZFS_MULTICLUS_MASTER4))*/
		{	
			++waitcount;
			group_master = zfs_multiclus_get_group_master(
				(char*)reg_data->group_name, ZFS_MULTICLUS_MASTER);
			if((group_master != NULL) && (group_master->hostid == reg_data->hostid)
				&& (group_master->node_status.status != ZFS_MULTICLUS_NODE_OFFLINE) 
				&& will_be_master == B_FALSE)
			{
				/* master and master2 are online on the same host,
				 * master2 can't receive the broadcast from master so that 
				 * master2 will be timeout and switch to master in cycle!
				 * To avoid this case */
				waitcount = 0;
			}else{
				switch(node_type)
				{
					case ZFS_MULTICLUS_MASTER2:
						if(waitcount > zfs_multiclus_master2_wait_count)
						{
							cmn_err(CE_WARN, "%s, %d, I am master%d, name:%s, i'll change to be master!", 
								__func__, __LINE__, ZFS_MULTICLUS_MASTER2, (char*)reg_data->fsname);
							err = zfs_multiclus_set_node_type_to_os((char*)reg_data->group_name, (char*)reg_data->fsname, 
								ZFS_MULTICLUS_MASTER, reg_data->spa_id, reg_data->os_id, reg_data->root);
							if (!err && !zfs_multiclus_write_group_record((void *)reg_data, ZFS_MULTICLUS_GROUP_CHANGE, node_type)) {
								cmn_err(CE_WARN, "%s, %d, Send master change to others!", __func__, __LINE__);
								zfs_multiclus_clear_group((char*)reg_data->group_name);
							}
							waitcount = 0;
							will_be_master = B_FALSE;
						}
						break;
					case ZFS_MULTICLUS_MASTER3:
						if(waitcount > zfs_multiclus_master3_wait_count)
						{
							cmn_err(CE_WARN, "%s, %d, I am master%d, name:%s, i'll change to be master!", 
								__func__, __LINE__, ZFS_MULTICLUS_MASTER3, (char*)reg_data->fsname);
							err = zfs_multiclus_set_node_type_to_os((char*)reg_data->group_name, (char*)reg_data->fsname, 
								ZFS_MULTICLUS_MASTER, reg_data->spa_id, reg_data->os_id, reg_data->root);
							if (!err && !zfs_multiclus_write_group_record((void *)reg_data, ZFS_MULTICLUS_GROUP_CHANGE, node_type)) {
								cmn_err(CE_WARN, "%s, %d, Send master change to others!", __func__, __LINE__);
								zfs_multiclus_clear_group((char*)reg_data->group_name);
							}
							waitcount = 0;
							will_be_master = B_FALSE;
						}
						break;
					case ZFS_MULTICLUS_MASTER4:
						if(waitcount > zfs_multiclus_master4_wait_count)
						{
							cmn_err(CE_WARN, "%s, %d, I am master%d, name:%s, i'll change to be master!", 
								__func__, __LINE__, ZFS_MULTICLUS_MASTER4, (char*)reg_data->fsname);
							err = zfs_multiclus_set_node_type_to_os((char*)reg_data->group_name, (char*)reg_data->fsname, 
								ZFS_MULTICLUS_MASTER, reg_data->spa_id, reg_data->os_id, reg_data->root);
							if (!err && !zfs_multiclus_write_group_record((void *)reg_data, ZFS_MULTICLUS_GROUP_CHANGE, node_type)) {
								cmn_err(CE_WARN, "%s, %d, Send master change to others!", __func__, __LINE__);
								zfs_multiclus_clear_group((char*)reg_data->group_name);
							}
							waitcount = 0;
							will_be_master = B_FALSE;
						}
						break;
					default:
						if (node_type == ZFS_MULTICLUS_MASTER && will_be_master) {
							cmn_err(CE_WARN, "%s, %d, I am master%d, name:%s, i'll be set to be master!", 
								__func__, __LINE__, ZFS_MULTICLUS_MASTER, (char*)reg_data->fsname);
							err = zfs_multiclus_set_node_type_to_os((char*)reg_data->group_name, (char*)reg_data->fsname, 
								ZFS_MULTICLUS_MASTER, reg_data->spa_id, reg_data->os_id, reg_data->root);
							if (!err && !zfs_multiclus_write_group_record((void *)reg_data, ZFS_MULTICLUS_GROUP_CHANGE, node_type)) {
								cmn_err(CE_WARN, "%s, %d, Send master change to others!", __func__, __LINE__);
								zfs_multiclus_clear_group((char*)reg_data->group_name);
							}
							waitcount = 0;
							will_be_master = B_FALSE;
						} else {
							cmn_err(CE_WARN, "Error master nodetype.");
						}
				}
			}
		}else{
			waitcount = 0;
		}
		mutex_exit(&multiclus_mtx_update_record);
break_out:
		mutex_enter(&multiclus_mtx);
		mutex_enter(&group->multiclus_group_mutex);
		if (reg_record->used == B_FALSE) {
			reg_record->spa_id = 0;
			reg_record->os_id = 0;
			cmn_err(CE_WARN, "zfs_multiclus_register_tq exit.line:%d",__LINE__);
		}
		mutex_exit(&group->multiclus_group_mutex);
		mutex_exit(&multiclus_mtx);
	}

	kmem_free(reg_data, sizeof(zfs_group_reg_t));
	return;
}

int zmc_change_objset_node_type(char* group_name, char *fsname, objset_t* os, zfs_multiclus_node_type_t new_type)
{
	char fs_name[MAX_FSNAME_LEN] = { 0 };
	zfs_multiclus_group_record_t* master = NULL;
	uint64_t os_is_master = 0;
	uint64_t os_node_type = 0;
	uint64_t os_master_spa = 0;
	uint64_t os_master_os = 0;
	uint64_t os_master_root = 0;
	spa_t *os_spa = NULL;

	master = zfs_multiclus_get_group_master(group_name, ZFS_MULTICLUS_MASTER);
	if (master != NULL && (master->spa_id != spa_guid(dmu_objset_spa(os))
		|| master->os_id != dmu_objset_id(os))) {
		os->os_is_master = 0;
		os->os_master_spa = master->spa_id;
		os->os_master_os = master->os_id;
		os->os_master_root = master->root;
	}

	if (new_type == ZFS_MULTICLUS_MASTER) {
		os->os_is_master = 1;
		os->os_master_spa = spa_guid(dmu_objset_spa(os));
		os->os_master_os = dmu_objset_id(os);
		os->os_master_root = os->os_self_root;
	}
	
	os_is_master = os->os_is_master;
	os_master_spa = os->os_master_spa;
	os_master_os = os->os_master_os;
	os_master_root = os->os_master_root;
	os_node_type = zmc_node_type_to_os_type(new_type);
	os->os_node_type = os_node_type;

	dmu_objset_name(os, fs_name);

	os_spa = dmu_objset_spa(os);

	if (NULL != fsname)
		dmu_objset_rele(os, FTAG);

	dsl_prop_set_int((const char*)fs_name, zfs_prop_to_name(ZFS_PROP_MASTER),
		ZPROP_SRC_LOCAL, os_is_master);      /*os->os_is_master*/
	dsl_prop_set_int((const char*)fs_name, zfs_prop_to_name(ZFS_PROP_MASTER_SPA),
		ZPROP_SRC_LOCAL, os_master_spa);     /*os->os_master_spa*/
	dsl_prop_set_int((const char*)fs_name, zfs_prop_to_name(ZFS_PROP_MASTER_OS),
		ZPROP_SRC_LOCAL, os_master_os);      /*os->os_master_os*/
	dsl_prop_set_int((const char*)fs_name, zfs_prop_to_name(ZFS_PROP_MASTER_ROOT),
		ZPROP_SRC_LOCAL, os_master_root);    /*os->os_master_root*/
	dsl_prop_set_int((const char*)fs_name, zfs_prop_to_name(ZFS_PROP_NODE_TYPE),
		ZPROP_SRC_LOCAL, os_node_type);      /*os->os_node_type*/

	spa_async_request(os_spa, SPA_ASYNC_SYSTEM_SPACE);
	return 0;
}

int zfs_multiclus_update_record(char *group_name, objset_t *os)
{
	char fsname[MAX_FSNAME_LEN] = {0};
	zfs_multiclus_group_record_t *record = NULL;
	zfs_multiclus_group_t *group = NULL;
	zfs_group_reg_t	*reg_data = NULL;
	uint64_t spa_id = 0;
	uint64_t os_id = 0;
	uint64_t usedobjs = 0;
	uint64_t availobjs = 0;
	uint64_t avail_size = 0;
	uint64_t used_size = 0;
	uint64_t load_ios = 0;
	int count = 0;
	
	if (!zfs_multiclus_enable()) {
		cmn_err(CE_WARN, "[%s %d] multiclus is disabled.", __func__, __LINE__);
		return (-1);
	}

	if ((spa_import_flags(dmu_objset_spa(os)) & ZFS_IMPORT_MULTICLUS_UPDATE) == 0) {
		cmn_err(CE_WARN, "[%s %d] ZFS_IMPORT_MULTICLUS_UPDATE is not in import flags.", 
			__func__, __LINE__);
		return (-1);
	}
	mutex_enter(&multiclus_mtx_update_record);
	spa_id = spa_guid(dmu_objset_spa(os));
	os_id = dmu_objset_id(os);
	load_ios = spa_get_ios(dmu_objset_spa(os));
	dmu_objset_name(os, fsname);
	dmu_objset_space(os, &used_size, &avail_size, &usedobjs, &availobjs);

	spa_async_request(dmu_objset_spa(os), SPA_ASYNC_SYSTEM_SPACE);
	
	/*
	 * dispatch the reg task, it's return until reg success.
	 */
	reg_data = kmem_zalloc(sizeof(zfs_group_reg_t), KM_SLEEP);
	reg_data->spa_id = spa_id;
	reg_data->os_id = os_id;
	reg_data->root = os->os_self_root;
	reg_data->node_id = os->os_group_node_id;
	reg_data->node_type = ZFS_MULTICLUS_MASTER;
	reg_data->avail_size = avail_size;
	reg_data->used_size = used_size;
	reg_data->load_ios = load_ios;
	reg_data->node_status.status = ZFS_MULTICLUS_NODE_ONLINE;
	reg_data->node_status.last_update_time = gethrtime();
	reg_data->hostid = zfs_multiclus_node_id;
	reg_data->group_name_len = strlen(group_name);
	bcopy(group_name, reg_data->group_name, MAXNAMELEN);
	reg_data->group_name[reg_data->group_name_len] = '\0';
	bcopy(fsname, reg_data->fsname, MAX_FSNAME_LEN);
	reg_data->fsname[strlen(fsname)] = '\0';
	bcopy(rpc_port_addr, reg_data->rpc_addr, ZFS_MULTICLUS_RPC_ADDR_SIZE);


	/*
	 * record != NULL:
	 * more than one objset in the cluster are in a same host, and the
	 * target objset is being import, set the new node type of the objset
	 * in the cluster based on the info in the record table
	 *
	 * record == NULL:
	 * the host holding the target objset is power cycled, need to set
	 * the node type of the objset based on the new received record table,
	 * and solve the master conflict if needed
	 */
	record = zfs_multiclus_get_record(spa_id, os_id);
	if (record != NULL) {
		zmc_change_objset_node_type(group_name, NULL, os, record->node_type);
	} else {
		/*
		 * add the objset into a cluster group, then it can receive the
		 * record table from the master, see zfs_multiclus_handle_frame(),
		 * the handler of message ZFS_MULTICLUS_GROUP_REPLY
		 */
		zfs_multiclus_node_type_t cur_type = zmc_get_node_type(os);

		zfs_multiclus_group_record_init(group_name, fsname, spa_id, os_id, os->os_self_root,
			(cur_type == ZFS_MULTICLUS_MASTER) ? ZFS_MULTICLUS_SLAVE : cur_type,
			reg_data->avail_size, reg_data->used_size, reg_data->load_ios, reg_data->node_id);
		if (cur_type == ZFS_MULTICLUS_MASTER || cur_type == ZFS_MULTICLUS_SLAVE) {
			zfs_multiclus_write_group_record((void *)reg_data, ZFS_MULTICLUS_GROUP_MSG, 
				ZFS_MULTICLUS_SLAVE);
			zfs_group_wait(zfs_multiclus_master_update_wait_time);
		}

		record = zfs_multiclus_get_record(spa_id, os_id);
		if (record == NULL) {
			/*
			 * record == NULL:
			 * there must be a master in this cluster, and there is no record for
			 * this objset; however, we do not know what the actual node type this
			 * objset is in this cluster, so just set it as Slave
			 */
			zmc_change_objset_node_type(group_name, NULL, os,
				(cur_type == ZFS_MULTICLUS_MASTER) ? ZFS_MULTICLUS_SLAVE : cur_type);
		} else {
			if (zfs_multiclus_get_group_master(group_name, ZFS_MULTICLUS_MASTER) != NULL) {
				zmc_change_objset_node_type(group_name, NULL, os, record->node_type);
			} else {
				zmc_change_objset_node_type(group_name, NULL, os, cur_type);
			}
		}
	}
	count = zfs_multiclus_check_group_master_count((const char *)group_name);
	if (count >= 2){
		if (DOUBLE_MASTER_PANIC) {
			zfs_panic_recover("[%s %d] %d, DOUBLE_MASTER A Found too many master in group: %s", 
				__func__, __LINE__, count, group_name);
		} else {
			cmn_err(CE_WARN, "[%s %d] %d, DOUBLE_MASTER A Found too many master in group: %s", 
				__func__, __LINE__, count, group_name);
		}
	}

	reg_data->node_type = zmc_get_node_type(os);
	zfs_multiclus_group_record_init(group_name, fsname, spa_id, os_id, os->os_self_root,
		reg_data->node_type, reg_data->avail_size, reg_data->used_size, reg_data->load_ios, reg_data->node_id);
	count = zfs_multiclus_check_group_master_count((const char *)group_name);
	if (count >= 2){
		if (DOUBLE_MASTER_PANIC) {
			zfs_panic_recover("%s, %d, %d, DOUBLE_MASTER B Found too many master in group: %s", 
				__func__, __LINE__, count, group_name);
		} else {
			cmn_err(CE_WARN, "%s, %d, %d, DOUBLE_MASTER B Found too many master in group: %s", 
				__func__, __LINE__, count, group_name);
		}
	}

	zfs_multiclus_get_group(group_name, &group);
	VERIFY(group != NULL);
	mutex_exit(&multiclus_mtx_update_record);
	if (group->group_reg_timer_tq) {
		if (taskq_dispatch(group->group_reg_timer_tq,
			(void (*)(void *))zfs_multiclus_register_tq,
			reg_data, TQ_NOSLEEP) == 0) {
			kmem_free(reg_data, sizeof(zfs_group_reg_t));
			cmn_err(CE_WARN, "[%s %d] dispatch reg thread fail,to do directly", __func__, __LINE__);
			return (-1);
		}
	} else {
		kmem_free(reg_data, sizeof(zfs_group_reg_t));
		cmn_err(CE_WARN, "[%s %d] group_reg_timer_tq is NULL, groupname: %s, fsname: %s!", 
			__func__, __LINE__, group_name, fsname);
		return (-1);
	}

	return (0);
}

int zfs_multiclus_create_group(char *group_name, char *fs_name)
{
	objset_t *os = NULL;
	uint64_t spa_id = 0;
	uint64_t dsl_id = 0;
	uint64_t root_id = 0;
	zfs_sb_t *zsb;
	int group_num = 0;
	zfs_multiclus_group_t *group = NULL;
	zfs_multiclus_group_record_t *record = NULL;
	zfs_group_reg_t	*reg_data;
	int error;

	uint64_t os_master_spa = 0;
	uint64_t os_master_os = 0;

	uint64_t avail_size = 0;
	uint64_t used_size = 0;
	uint64_t usedobjs = 0;
	uint64_t availobjs = 0;
	uint64_t load_ios = 0;
		
	if (zfs_multiclus_enable() == B_FALSE) {
		cmn_err(CE_WARN, "[%s %d] multiclus is disabled.", __func__, __LINE__);
		return (-1);
	}
	
	if ((error = dmu_objset_hold(fs_name, FTAG, &os))) {
		cmn_err(CE_WARN, "[%s %d] %s may not exist.", __func__, __LINE__, fs_name);
		return (error);
	}
	
	spa_id = spa_guid(dmu_objset_spa(os));
	dsl_id = dmu_objset_id(os);

	group_num = zfs_multiclus_get_group(group_name, &group);
	if (group != NULL) {
		cmn_err(CE_WARN, "the group %s has been exist", group_name);
		dmu_objset_rele(os, FTAG);
		return (-1);
	}

	record = zfs_multiclus_get_record(spa_id, dsl_id);
	if (record != NULL){
		cmn_err(CE_WARN, "the fs:%s has been registed in group %s", fs_name,
		    zfs_multiclus_table[group_num].group_name);
		dmu_objset_rele(os, FTAG);
		return (-1);
	}

	if(os->os_is_group){
		dmu_objset_rele(os, FTAG);
		cmn_err(CE_WARN, "[%s %d] %s may be already in a nas group.", __func__, __LINE__, fs_name);
		return (-1);
	}else {
		os->os_is_group = 1;
		os->os_is_master = 1;
		os->os_node_type = OS_NODE_TYPE_SLAVE; /* os_is_master == 1, OS_NODE_TYPE_SLAVE is ignored */
		os->os_master_spa = os_master_spa = spa_guid(dmu_objset_spa(os));
		os->os_master_os = os_master_os = dmu_objset_id(os);
		os->os_group_node_id = 1;
		strcpy(os->os_group_name, group_name);
		
		dmu_objset_rele(os, FTAG);
		dsl_prop_set_string(fs_name, zfs_prop_to_name(ZFS_PROP_GROUP_NAME),
			ZPROP_SRC_LOCAL, group_name);
		dsl_prop_set_int(fs_name, zfs_prop_to_name(ZFS_PROP_GROUP),
			ZPROP_SRC_LOCAL, 1);  /*os->os_is_group*/
		dsl_prop_set_int(fs_name, zfs_prop_to_name(ZFS_PROP_MASTER),
		    ZPROP_SRC_LOCAL, 1);	 /*os->os_is_master*/
		dsl_prop_set_int(fs_name, zfs_prop_to_name(ZFS_PROP_MASTER_SPA),
		    ZPROP_SRC_LOCAL, os_master_spa);
		dsl_prop_set_int(fs_name, zfs_prop_to_name(ZFS_PROP_MASTER_OS),
		    ZPROP_SRC_LOCAL, os_master_os);
		dsl_prop_set_int(fs_name, zfs_prop_to_name(ZFS_PROP_MULTILUS_NODE_ID),
			ZPROP_SRC_LOCAL, 1);
		if ((error = dmu_objset_hold(fs_name, FTAG, &os))) {
			return (error);
		}
	}

	if (os->os_phys->os_type == DMU_OST_ZFS) {
		mutex_enter(&os->os_user_ptr_lock);
		zsb = (zfs_sb_t *)dmu_objset_get_user(os);
		if (NULL == zsb){
			/*fs may not be mounted. */
			cmn_err(CE_WARN, "[%s %d]: dmu_objset_get_user error.", __func__, __LINE__);
			mutex_exit(&os->os_user_ptr_lock);
			/*operation rolled back*/
			os->os_is_group = 0;
			os->os_is_master = 0;
			os->os_master_spa = os_master_spa = 0;
			os->os_master_os = os_master_os = 0;
			os->os_group_node_id = 0;
			bzero(os->os_group_name, MAXNAMELEN);
			dmu_objset_rele(os, FTAG);
			
			dsl_prop_set_string(fs_name, zfs_prop_to_name(ZFS_PROP_GROUP_NAME),
				ZPROP_SRC_LOCAL, os->os_group_name);
			dsl_prop_set_int(fs_name, zfs_prop_to_name(ZFS_PROP_GROUP),
				ZPROP_SRC_LOCAL, 0);  /*os->os_is_group*/
			dsl_prop_set_int(fs_name, zfs_prop_to_name(ZFS_PROP_MASTER),
				ZPROP_SRC_LOCAL, 0);	 /*os->os_is_master*/
			dsl_prop_set_int(fs_name, zfs_prop_to_name(ZFS_PROP_MASTER_SPA),
		    		ZPROP_SRC_LOCAL, os_master_spa);
			dsl_prop_set_int(fs_name, zfs_prop_to_name(ZFS_PROP_MASTER_OS),
		    		ZPROP_SRC_LOCAL, os_master_os);
			dsl_prop_set_int(fs_name, zfs_prop_to_name(ZFS_PROP_MULTILUS_NODE_ID),
		    		ZPROP_SRC_LOCAL, 0);
			return (-1);
		}

		root_id = zsb->z_root;
		mutex_exit(&os->os_user_ptr_lock);
		os->os_master_root = root_id;
		os->os_self_root = root_id;

		dmu_objset_rele(os, FTAG);
		error = dsl_prop_set_int(fs_name, zfs_prop_to_name(ZFS_PROP_MASTER_ROOT),
		    ZPROP_SRC_LOCAL, root_id);    /*os->os_master_root*/
		error = dsl_prop_set_int(fs_name, zfs_prop_to_name(ZFS_PROP_SELF_ROOT),
		    ZPROP_SRC_LOCAL, root_id);    /*os->os_self_root*/
		if ((error = dmu_objset_hold(fs_name, FTAG, &os))){
			return (error);
		}
	}

	spa_async_request(dmu_objset_spa(os), SPA_ASYNC_SYSTEM_SPACE);
	
	dmu_objset_space(os, &used_size, &avail_size, &usedobjs, &availobjs);
	
	load_ios = spa_get_ios(dmu_objset_spa(os));

	zfs_multiclus_group_record_init(group_name, fs_name, spa_id,
	    dsl_id, root_id, ZFS_MULTICLUS_MASTER, avail_size, used_size, load_ios, 1);

	reg_data = kmem_zalloc(sizeof(zfs_group_reg_t), KM_SLEEP);
	reg_data->spa_id = spa_id;
	reg_data->os_id = dsl_id;
	reg_data->root = root_id;
	reg_data->node_type = ZFS_MULTICLUS_MASTER;
	reg_data->avail_size = avail_size;
	reg_data->used_size = used_size;
	reg_data->load_ios = load_ios;
	reg_data->node_status.status = ZFS_MULTICLUS_NODE_ONLINE;
	reg_data->hostid = zfs_multiclus_node_id;
	reg_data->group_name_len = strlen(group_name);
	reg_data->node_id = 1;
	bcopy(group_name, reg_data->group_name, MAXNAMELEN);
	reg_data->group_name[reg_data->group_name_len] = '\0';
	bcopy(fs_name, reg_data->fsname, MAX_FSNAME_LEN);
	reg_data->fsname[strlen(fs_name)] = '\0';
	bcopy(rpc_port_addr, reg_data->rpc_addr, ZFS_MULTICLUS_RPC_ADDR_SIZE);
	
	group_num = zfs_multiclus_get_group(group_name, &group);
	VERIFY(group != NULL);

	dmu_objset_rele(os, FTAG);
	
	if (group->group_reg_timer_tq) {
		if (taskq_dispatch(group->group_reg_timer_tq,
			(void (*)(void *))zfs_multiclus_register_tq,
			reg_data,TQ_NOSLEEP) == 0){
			kmem_free(reg_data, sizeof(zfs_group_reg_t));
			return (-1);
		}
	} else {
		cmn_err(CE_WARN, "%s, %d, group_reg_timer_tq is NULL, groupname: %s, fsname: %s!", 
			__func__, __LINE__, group_name, fs_name);
		kmem_free(reg_data, sizeof(zfs_group_reg_t));
		return (-1);
	}
	return (error);
}

int zfs_multiclus_add_group(char *group_name, char *fs_name, uint64_t node_id)
{
	int	error = 0;
	int group_num = 0;
	int wait_count = 0;
	uint64_t	spa_id;
	uint64_t	dsl_id;
	uint64_t	root_id = 0;
	uint64_t	avail_size = 0;
	uint64_t	used_size = 0;
	uint64_t	load_ios = 0;
	uint64_t	usedobjs = 0;
	uint64_t	availobjs = 0;
	zfs_multiclus_group_record_t *record = NULL;
	zfs_multiclus_group_t *group = NULL;
	zfs_group_reg_t *reg_data = NULL;
	objset_t *os = NULL;
	zfs_sb_t *zsb = NULL;

	spa_t *os_spa = NULL;
	uint64_t os_master_spa = 0;
	uint64_t os_master_os = 0;
	uint64_t os_master_root = 0;
	uint64_t os_node_id = 0;


	if (zfs_multiclus_enable() == B_FALSE) {
		cmn_err(CE_WARN, "[%s %d] multiclus is disabled.", __func__, __LINE__);
		return (-1);
	}
	
	if ((error = dmu_objset_hold(fs_name, FTAG, &os))) {
		cmn_err(CE_WARN, "[%s %d] %s may not exist.", __func__, __LINE__, fs_name);
		return (error);
	}
	
	spa_id = spa_guid(dmu_objset_spa(os));
	dsl_id = os->os_dsl_dataset->ds_object;

	record = zfs_multiclus_get_group_master(group_name, ZFS_MULTICLUS_MASTER);
	if (record != NULL) {
		dmu_objset_set_group(os, record->spa_id, record->os_id, record->root);
		cmn_err(CE_NOTE, "register master and os");
	}

	if (zfs_multiclus_get_record(spa_id, dsl_id) != NULL){
		cmn_err(CE_WARN, "the fs:%s has been registed", fs_name);
		dmu_objset_rele(os, FTAG);
		return (-1);
	}

	if(os->os_is_group){
		dmu_objset_rele(os, FTAG);
		cmn_err(CE_WARN, "[%s %d] %s may be already in a nas group.", __func__, __LINE__, fs_name);
		return (-1);
	}else {
		os->os_is_group = 1;
		os->os_is_master = 0;
		os->os_node_type = OS_NODE_TYPE_SLAVE;
		os->os_group_node_id = node_id;
		strcpy(os->os_group_name, group_name);

		dmu_objset_rele(os, FTAG);
		dsl_prop_set_string(fs_name, zfs_prop_to_name(ZFS_PROP_GROUP_NAME),
		    ZPROP_SRC_LOCAL, group_name);
		dsl_prop_set_int(fs_name, zfs_prop_to_name(ZFS_PROP_GROUP),
		    ZPROP_SRC_LOCAL, 1);   /*os->os_is_group*/
		dsl_prop_set_int(fs_name, zfs_prop_to_name(ZFS_PROP_MASTER),
		    ZPROP_SRC_LOCAL, 0);   /*os->os_is_master*/
		dsl_prop_set_int(fs_name, zfs_prop_to_name(ZFS_PROP_MULTILUS_NODE_ID),
			ZPROP_SRC_LOCAL, node_id);
		if ((error = dmu_objset_hold(fs_name, FTAG, &os))) {
			return (error);
		}
	}

	if (os->os_phys->os_type == DMU_OST_ZFS) {
		mutex_enter(&os->os_user_ptr_lock);
		zsb = (zfs_sb_t *)dmu_objset_get_user(os);
		if (NULL == zsb){
			/*fs may not be mounted.*/
			cmn_err(CE_WARN, "[%s %d]: dmu_objset_get_user error.", __func__, __LINE__);
			mutex_exit(&os->os_user_ptr_lock);
			/*operation rolled back*/
			os->os_is_group = 0;
			os->os_master_spa = 0;
			os->os_master_os = 0;
			os->os_master_root = 0;
			os->os_group_node_id = 0;
			bzero(os->os_group_name, MAXNAMELEN);
			dmu_objset_rele(os, FTAG);

			dsl_prop_set_string(fs_name, zfs_prop_to_name(ZFS_PROP_GROUP_NAME),
		    		ZPROP_SRC_LOCAL, os->os_group_name);
			dsl_prop_set_int(fs_name, zfs_prop_to_name(ZFS_PROP_GROUP),
				ZPROP_SRC_LOCAL, 0);
			dsl_prop_set_int(fs_name, zfs_prop_to_name(ZFS_PROP_MULTILUS_NODE_ID),
				ZPROP_SRC_LOCAL, 0);
			return (-1);
		}
		root_id = zsb->z_root;
		mutex_exit(&os->os_user_ptr_lock);
	}

	spa_async_request(dmu_objset_spa(os), SPA_ASYNC_SYSTEM_SPACE);

	dmu_objset_space(os, &used_size, &avail_size, &usedobjs, &availobjs);

	load_ios = spa_get_ios(dmu_objset_spa(os));
	
	zfs_multiclus_group_record_init(group_name, fs_name, spa_id,
	    dsl_id, root_id, ZFS_MULTICLUS_SLAVE, avail_size, used_size, load_ios, node_id);

	reg_data = kmem_zalloc(sizeof(zfs_group_reg_t), KM_SLEEP);
	reg_data->spa_id = spa_id;
	reg_data->os_id = dsl_id;
	reg_data->root = root_id;
	reg_data->node_type = ZFS_MULTICLUS_MASTER;
	reg_data->avail_size = avail_size;
	reg_data->used_size = used_size;
	reg_data->load_ios = load_ios;
	reg_data->node_status.status = ZFS_MULTICLUS_NODE_ONLINE;
	reg_data->node_status.last_update_time = gethrtime();
	reg_data->hostid = zfs_multiclus_node_id;
	reg_data->group_name_len = strlen(group_name);
	reg_data->node_id = node_id;
	bcopy(group_name, reg_data->group_name, MAXNAMELEN);
	reg_data->group_name[reg_data->group_name_len] = '\0';
	bcopy(fs_name, reg_data->fsname, MAX_FSNAME_LEN);
	reg_data->fsname[strlen(fs_name)] = '\0';
	bcopy(rpc_port_addr, reg_data->rpc_addr, ZFS_MULTICLUS_RPC_ADDR_SIZE);

	if ((record == NULL) || record->hostid != zfs_multiclus_node_id){
		zfs_multiclus_write_group_record((void*)reg_data, ZFS_MULTICLUS_GROUP_MSG, 
			ZFS_MULTICLUS_SLAVE);
		delay(drv_usectohz(500000));
	}

	/*waitting for master response*/
	record = NULL;
	do {
		wait_count++;
		delay(drv_usectohz(500000));
		record = zfs_multiclus_get_group_master(group_name, ZFS_MULTICLUS_MASTER);
	} while(record == NULL && wait_count < 10);

	/* set group again */
	if (record != NULL) {
		dmu_objset_set_group(os, record->spa_id, record->os_id, record->root);
		os->os_self_root = root_id;
		os_spa = dmu_objset_spa(os);
		os_master_spa = os->os_master_spa;
		os_master_os = os->os_master_os;
		os_master_root = os->os_master_root;
		os_node_id = os->os_group_node_id;
		
		dmu_objset_rele(os, FTAG);
		dsl_prop_set_int(fs_name, zfs_prop_to_name(ZFS_PROP_MASTER_SPA),
		    ZPROP_SRC_LOCAL, os_master_spa);    /*os->os_master_spa*/
		dsl_prop_set_int(fs_name, zfs_prop_to_name(ZFS_PROP_MASTER_OS),
		    ZPROP_SRC_LOCAL, os_master_os);     /*os->os_master_os*/
		error = dsl_prop_set_int(fs_name, zfs_prop_to_name(ZFS_PROP_MASTER_ROOT),
		    ZPROP_SRC_LOCAL, os_master_root);   /*os->os_master_root*/
		error = dsl_prop_set_int(fs_name, zfs_prop_to_name(ZFS_PROP_SELF_ROOT),
		    ZPROP_SRC_LOCAL, root_id);          /*os->os_self_root*/
		dsl_prop_set_int(fs_name, zfs_prop_to_name(ZFS_PROP_MULTILUS_NODE_ID),
		    ZPROP_SRC_LOCAL, os_node_id);
		spa_async_request(os_spa, SPA_ASYNC_SYSTEM_SPACE);
		if ((error = dmu_objset_hold(fs_name, FTAG, &os))) {
			return (error);
		}	
	} else {
		record = zfs_multiclus_get_record(spa_id, dsl_id);
		if (record) {
			record->used = B_FALSE;
		}
		group_num = zfs_multiclus_get_group(group_name, &group);
		if (group) {
			group->used = B_FALSE;
		}
		/*operation rolled back*/
		os->os_is_group = 0;
		bzero(os->os_group_name, MAXNAMELEN);
		dmu_objset_rele(os, FTAG);

		dsl_prop_set_string(fs_name, zfs_prop_to_name(ZFS_PROP_GROUP_NAME),
			ZPROP_SRC_LOCAL, os->os_group_name);
		dsl_prop_set_int(fs_name, zfs_prop_to_name(ZFS_PROP_GROUP),
			ZPROP_SRC_LOCAL, 0);
		dsl_prop_set_int(fs_name, zfs_prop_to_name(ZFS_PROP_MULTILUS_NODE_ID),
			ZPROP_SRC_LOCAL, 0);
		kmem_free(reg_data, sizeof(zfs_group_reg_t));
		cmn_err(CE_WARN, "%s, %d, There is no master when add into group %s", __func__, __LINE__, group_name);
		return (-1);
	}

	group_num = zfs_multiclus_get_group(group_name, &group);
	VERIFY(group != NULL);

	dmu_objset_rele(os, FTAG);

	if (group->group_reg_timer_tq) {
		if (taskq_dispatch(group->group_reg_timer_tq,
			(void (*)(void *))zfs_multiclus_register_tq,
			reg_data, TQ_NOSLEEP) == 0){
			kmem_free(reg_data, sizeof(zfs_group_reg_t));
			return (-1);
		}
	} else {
		kmem_free(reg_data, sizeof(zfs_group_reg_t));
		cmn_err(CE_WARN, "%s, %d, group_reg_timer_tq is NULL, groupname: %s, fsname: %s!", 
			__func__, __LINE__, group_name, fs_name);
			return (-1);
	}
	return (error);
}

/* The following function is for hash table */
static void 
zfs_multiclus_insert_hash(mod_hash_t *modhash, zfs_multiclus_hash_t *blk_hash)
{
	uint64_t hash_key;

	hash_key = blk_hash->hash_key;
	(void) mod_hash_insert(modhash,
	    (mod_hash_key_t)(uintptr_t)hash_key,
	    (mod_hash_val_t)blk_hash);
}

static int 
zfs_multiclus_remove_hash(mod_hash_t *modhash, zfs_multiclus_hash_t *blk_hash)
{
	zfs_multiclus_hash_t *blk_hash_tmp;
	uint64_t hash_key;
	int ret = 0;

	blk_hash_tmp = NULL;
	hash_key = blk_hash->hash_key;
	ret = mod_hash_remove(modhash,
	    (mod_hash_key_t)(uintptr_t)hash_key,
	    (mod_hash_val_t *)&blk_hash_tmp);

	return (ret);
}

static void 
zfs_multiclus_hash_member_find_cb(mod_hash_key_t hash_key, mod_hash_val_t hash_tmp)
{
	zfs_multiclus_hash_t *hash_member = (zfs_multiclus_hash_t *)hash_tmp;
	boolean_t rx_flag = hash_member->rx_flag;

	if (rx_flag)
		rw_enter(&hash_member->rx_timeout_lock, RW_READER);
	else
		mutex_enter(&hash_member->multiclus_hash_mutex);
}

static zfs_multiclus_hash_t *
zfs_multiclus_find_hash_member(mod_hash_t *modhash, uint64_t hash_key)
{
	mod_hash_val_t blk_hash_tmp;
	int ret = 0;

	ret = mod_hash_find_cb(modhash, (mod_hash_key_t)(uintptr_t)hash_key,
	    (mod_hash_val_t *)&blk_hash_tmp,
	    zfs_multiclus_hash_member_find_cb);

	if (ret == 0)
		return ((zfs_multiclus_hash_t *)blk_hash_tmp);
	else
		return (NULL);
}

static zfs_multiclus_hash_t *
zfs_multiclus_create_hash_member(uint64_t hash_key, boolean_t rx_flag)
{
	zfs_multiclus_hash_t *hash_tmp = NULL;
	
	hash_tmp = kmem_zalloc(sizeof(zfs_multiclus_hash_t), KM_SLEEP);
	hash_tmp->hash_key = hash_key;
	hash_tmp->rx_flag = rx_flag;
	rw_init(&hash_tmp->rx_timeout_lock, NULL, RW_DEFAULT, NULL);
	mutex_init(&hash_tmp->multiclus_hash_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&hash_tmp->multiclus_hash_cv, NULL, CV_DRIVER, NULL);
	
	return ((void *)hash_tmp);
}

static void 
zfs_multiclus_destroy_hash_member(zfs_multiclus_hash_t *hash_member)
{
	if (hash_member == NULL)
		return;

	cv_destroy(&hash_member->multiclus_hash_cv);
	mutex_destroy(&hash_member->multiclus_hash_mutex);
	rw_destroy(&hash_member->rx_timeout_lock);
	kmem_free(hash_member, sizeof(zfs_multiclus_hash_t));
}

/* find out this operation is for which fs */
static mod_hash_t *
zfs_multiclus_find_hash_header(uint64_t spa_id, uint64_t os_id, boolean_t tx)
{
	int i;

	if (tx) {
		for (i = 0; i < ZFS_MULTICLUS_MAX_OS_NUMS; i++){
			if ((zfs_multiclus_tx_hash[i].spa_id == spa_id) &&
			    (zfs_multiclus_tx_hash[i].os_id == os_id)){
				return (zfs_multiclus_tx_hash[i].zfs_multiclus_modhash);
			}
		}
	} else {
		for (i = 0; i < ZFS_MULTICLUS_MAX_OS_NUMS; i++){
			if ((zfs_multiclus_rx_hash[i].spa_id == spa_id) &&
			    (zfs_multiclus_rx_hash[i].os_id == os_id)){
				return (zfs_multiclus_rx_hash[i].zfs_multiclus_modhash);
			}
		}
	}
	return (NULL);
}

// static int
// zfs_multiclus_get_rx_hash_header(uint64_t spa_id, uint64_t os_id, boolean_t tx)
// {
// 	int i;

// 	mutex_enter(&zfs_multiclus_rx_hash_mtx);
// 	for (i = 0; i < ZFS_MULTICLUS_MAX_OS_NUMS; i++){
// 		if ((zfs_multiclus_rx_hash[i].spa_id == spa_id) &&
// 		    (zfs_multiclus_rx_hash[i].os_id == os_id)){
// 			mutex_exit(&zfs_multiclus_rx_hash_mtx);
// 			return (i);
// 		}
// 	}
// 	mutex_exit(&zfs_multiclus_rx_hash_mtx);
// 	return (-1);
// }


uint_t
walk_hash_rx_timeout_callback(mod_hash_key_t key, mod_hash_val_t *val,
    void *arg)
{
	zfs_multiclus_hash_t *hash_member = (zfs_multiclus_hash_t *)val;
	list_t *rx_timeout_list = (list_t *)arg;
	zfs_group_header_t *msg_header = (zfs_group_header_t *)hash_member->omsg_header;
	uint64_t time_tmp = 0;
	int timeout = 0;

	if ((msg_header->command == ZFS_GROUP_CMD_DATA) && (msg_header->operation == DATA_WRITE))
		timeout = zfs_multiclus_write_timeout;
	else
		timeout = zfs_multiclus_timeout;
	
	rw_enter(&hash_member->rx_timeout_lock, RW_WRITER);
	if (hash_member->rx_done == 0) {
		time_tmp = gethrtime();
		if (((time_tmp - hash_member->start_time)/1000) > timeout * ZFS_MULTICLUS_RX_TIMEOUT){
			hash_member->rx_timeout = 1;
			list_insert_tail(rx_timeout_list, hash_member);
			cmn_err(CE_WARN, "%s: removed!, key:%lld, cmd:0x%llx, operate:%llx, wait time:%lld"
			    " receive num:%lld", __func__,
			    (longlong_t)(msg_header->seqno), (longlong_t)(msg_header->command),
			    (longlong_t)(msg_header->operation),
			    (longlong_t)(time_tmp - hash_member->start_time),
				(longlong_t)(hash_member->cache_num));
		}
	}
	rw_exit(&hash_member->rx_timeout_lock);
	return (0);
}

static void
zfs_multiclus_handle_rx_timeout_operate(zfs_multiclus_hash_header_t *rx_hash, list_t *rx_timeout_list)
{
	zfs_multiclus_hash_t *hash_member = NULL;


	while ((hash_member = list_remove_head(rx_timeout_list)) != NULL) {
		zfs_multiclus_remove_hash(rx_hash->zfs_multiclus_modhash, hash_member);

		/* 
		 *	there still need empty lock to prevent conflict, 
		 *	which a lot READ lock hold before we remove, 
		 *	but still not complete after we removed !! ****
		 */
		rw_enter(&hash_member->rx_timeout_lock, RW_WRITER);
		rw_exit(&hash_member->rx_timeout_lock);

		if (hash_member->datap)
			kmem_free(hash_member->datap, hash_member->data_len);
		
		zfs_multiclus_destroy_hash_member(hash_member);
	}
}

static void
zfs_multiclus_rx_operate_check(void *arg)
{
	list_t rx_timeout_list;
	zfs_multiclus_hash_header_t *rx_hash_header = (zfs_multiclus_hash_header_t *)arg;

	list_create(&rx_timeout_list, sizeof(zfs_multiclus_hash_t),
	    offsetof(zfs_multiclus_hash_t, hash_list_node));

	mod_hash_walk(rx_hash_header->zfs_multiclus_modhash,
	    walk_hash_rx_timeout_callback, &rx_timeout_list);
	zfs_multiclus_handle_rx_timeout_operate(rx_hash_header, &rx_timeout_list);

	list_destroy(&rx_timeout_list);
}

/* fill this fs's operation in a new hash entry */
static mod_hash_t *
zfs_multiclus_fill_hash_table(uint64_t spa_id, uint64_t os_id, boolean_t tx)
{
	int i;

	if (tx) {
		for (i = 0; i < ZFS_MULTICLUS_MAX_OS_NUMS; i++){
			if (zfs_multiclus_tx_hash[i].used == B_FALSE){
				zfs_multiclus_tx_hash[i].spa_id = spa_id;
				zfs_multiclus_tx_hash[i].os_id = os_id;
				zfs_multiclus_tx_hash[i].used = B_TRUE;
				zfs_multiclus_tx_hash[i].zfs_multiclus_modhash =
				    mod_hash_create_idhash("zfs multiclus tx modhash",
				    ZFS_MULTICLUS_HOLD_FRAME_HASH_SIZE, mod_hash_null_valdtor);
				return (zfs_multiclus_tx_hash[i].zfs_multiclus_modhash);
			}
		}
	} else {
		for (i = 0; i < ZFS_MULTICLUS_MAX_OS_NUMS; i++){
			if (zfs_multiclus_rx_hash[i].used == B_FALSE){
				zfs_multiclus_rx_hash[i].spa_id = spa_id;
				zfs_multiclus_rx_hash[i].os_id = os_id;
				zfs_multiclus_rx_hash[i].used = B_TRUE;
				zfs_multiclus_rx_hash[i].zfs_multiclus_modhash =
				    mod_hash_create_idhash("zfs multiclus rx modhash",
				    ZFS_MULTICLUS_HOLD_FRAME_HASH_SIZE, mod_hash_null_valdtor);
				rw_init(&zfs_multiclus_rx_hash[i].zfs_multiclus_timeout_lock,
				    NULL, RW_DEFAULT, NULL);
				zfs_multiclus_hash_tmchk_thr_start(i);
				return (zfs_multiclus_rx_hash[i].zfs_multiclus_modhash);
			}
		}
	}
	return (NULL);
}

static void 
zfs_multiclus_load_config(void)
{
	struct _buf *file;
	uint64_t fsize;
	char *buf = NULL;
	char *buf_tmp = NULL;
	int j = 0;

	file = kobj_open_file("/etc/fsgroup/rpc_port.conf");

	if (file == (struct _buf *)-1){
		cmn_err(CE_WARN, "zfs multiclus open rpc conf failed");
		return;
	} 

	if (kobj_get_filesize(file, &fsize) != 0){
		cmn_err(CE_WARN, "zfs multiclus get rpc conf filesize failed");
		goto out;
	}

	if (fsize == 0){
		cmn_err(CE_WARN, "zfs multiclus get rpc conf filesize 0");
		goto out;
	}

	buf_tmp = (char *)kmem_zalloc(fsize, KM_SLEEP);
	if (buf_tmp == NULL  || kobj_read_file(file, buf_tmp, fsize, 0) < 0){
		cmn_err(CE_WARN, "zfs multiclus read rpc conf failed");
		goto out;
	}  	

	buf = buf_tmp;
	cmn_err(CE_WARN, "zfs multiclus read file 1:buf:0x%p", buf);
	cmn_err(CE_WARN, "zfs multiclus read file 2: %s", buf);
	for(; *buf != -1; buf++){
		if (bcmp(buf, "rpc_port=", 9) == 0){
			buf += 9;	
			bcopy(buf, rpc_port_name, strlen(buf));
			for (j = 0; j < strlen(buf); j++){
				if (rpc_port_name[j] == ';') {
					rpc_port_name[j] = '\0';
					break;
				}
			}
		}
		if (bcmp(buf, "rpc_addr=", 9) == 0){
			buf += 9;
			bcopy(buf, rpc_port_addr, strlen(buf));
			for (j = 0; j < strlen(buf); j++){
				if (rpc_port_addr[j] == ';') {
					rpc_port_addr[j] = '\0';
					break;
				}
			}
			break;
		}
	}
	cmn_err(CE_WARN, "zfs multiclus get rpc: name:%s, addr:%s", rpc_port_name, rpc_port_addr);
	
out:
	if (buf_tmp != NULL)
		kmem_free(buf_tmp, fsize);

	kobj_close_file(file);
}

int zfs_multiclus_check_group_master_count(const char *group_name)
{
	int master_count = 0;
	int i, j;
	mutex_enter(&multiclus_mtx);
	for (i = 0; i < ZFS_MULTICLUS_GROUP_TABLE_SIZE; i++) {
		if (zfs_multiclus_table[i].used && strncmp(zfs_multiclus_table[i].group_name,
		    group_name, strlen(group_name)) == 0) {
		    mutex_enter(&zfs_multiclus_table[i].multiclus_group_mutex);
			for (j = 0; j < ZFS_MULTICLUS_GROUP_NODE_NUM; j++) {
				if (zfs_multiclus_table[i].multiclus_group[j].used &&
					zfs_multiclus_table[i].multiclus_group[j].node_type == ZFS_MULTICLUS_MASTER) {
					master_count++;
				}
			}
			mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
		}
	}
	mutex_exit(&multiclus_mtx);
	return master_count;
}

int
zfs_multiclus_set_node_type(uint64_t spa_id, uint64_t os_id, 
zfs_multiclus_node_type_t node_type)
{
	int i = 0;
	int j = 0;
	int ret = 1;
	
	if(node_type > ZFS_MULTICLUS_NODE_TYPE_NUM)
		return(ret);
	
	mutex_enter(&multiclus_mtx);
	for (; i < ZFS_MULTICLUS_GROUP_TABLE_SIZE; i++){
		if(zfs_multiclus_table[i].used)	{
			mutex_enter(&zfs_multiclus_table[i].multiclus_group_mutex);
			for (j = 0; j < ZFS_MULTICLUS_GROUP_NODE_NUM; j++){
				if (zfs_multiclus_table[i].multiclus_group[j].used &&
				    (zfs_multiclus_table[i].multiclus_group[j].spa_id == spa_id) &&
				    (zfs_multiclus_table[i].multiclus_group[j].os_id == os_id)){
				    	zfs_multiclus_table[i].multiclus_group[j].node_type =
							node_type;
					mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
					mutex_exit(&multiclus_mtx);
					ret = 0;
					return (ret);
				}
			}
			mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
		}
	}
	mutex_exit(&multiclus_mtx);
	return(ret);
}

int zfs_multiclus_set_slave(char* group_name, char* fs_name)
{
	if (group_name == NULL || fs_name == NULL) {
		cmn_err(CE_WARN, "[%s %d] multiclus group_name=%s, fs_name=%s.",
			__func__, __LINE__, group_name, fs_name);
		return -1;
	}

	return zmc_set_node_type(group_name, fs_name, ZFS_MULTICLUS_SLAVE);
}

int zfs_multiclus_set_master(char* group_name, char* fs_name, 
	zfs_multiclus_node_type_t node_type)
{
	if (group_name == NULL || fs_name == NULL) {
		cmn_err(CE_WARN, "[%s %d] multiclus group_name=%s, fs_name=%s.",
			__func__, __LINE__, group_name, fs_name);
		return -1;
	}

	return zmc_set_node_type(group_name, fs_name, node_type);
}

void zfs_multiclus_clear_group(char *group_name)
{
	int i = 0;

	mutex_enter(&multiclus_mtx);
	for (; i < ZFS_MULTICLUS_GROUP_TABLE_SIZE; i++){
		if(zfs_multiclus_table[i].used && 
			!strncmp(zfs_multiclus_table[i].group_name, group_name, zfs_multiclus_table[i].group_name_len))	{
			mutex_enter(&zfs_multiclus_table[i].multiclus_group_mutex);
			bzero(zfs_multiclus_table[i].multiclus_group, sizeof(zfs_multiclus_group_record_t) * ZFS_MULTICLUS_GROUP_NODE_NUM);
			mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
		}
	}
	mutex_exit(&multiclus_mtx);
	
	return;
}

int zfs_multiclus_set_node_type_to_os(char *group_name, char *fs_name, zfs_multiclus_node_type_t node_type,
	uint64_t master_spa, uint64_t master_os, uint64_t master_root)
{
	int i = 0;
	int j = 0;
	int err = 0;
	objset_t *os = NULL;
	char fsname[MAX_FSNAME_LEN] = { 0 };
	uint64_t os_is_master = 0;
	uint64_t os_node_type = 0;
	spa_t *os_spa = NULL;
	

	if (!fs_name || !group_name) {
		cmn_err(CE_WARN, "%s, %d, fs_name or group_name is NULL!", __func__, __LINE__);
		return -1;
	}

	mutex_enter(&multiclus_mtx);
	for (i = 0; i < ZFS_MULTICLUS_GROUP_TABLE_SIZE; i++) {
		if (zfs_multiclus_table[i].used && 
			!strncmp(group_name, zfs_multiclus_table[i].group_name, strlen(group_name))) {
			mutex_enter(&zfs_multiclus_table[i].multiclus_group_mutex);
			for (j = 0; j < ZFS_MULTICLUS_GROUP_NODE_NUM; j++) {
				if (zfs_multiclus_table[i].multiclus_group[j].used) {
					err = dmu_objset_hold((char*)zfs_multiclus_table[i].multiclus_group[j].fsname, FTAG, &os);
					if (err == 0) {
						if (!strncmp((char*)zfs_multiclus_table[i].multiclus_group[j].fsname, fs_name, strlen(fs_name))) {
							if (node_type == ZFS_MULTICLUS_MASTER) {
								os_is_master = 1;
								os->os_is_master = os_is_master;
							} else {
								os_is_master = 0;
								os->os_is_master = os_is_master;
							}
							os_node_type = zmc_node_type_to_os_type(node_type);
							os->os_node_type = os_node_type;
						}
						os->os_last_master_spa = os->os_master_spa;
						os->os_last_master_os = os->os_master_os;
						os->os_master_spa = master_spa;
						os->os_master_os = master_os;
						os->os_master_root = master_root;
						dmu_objset_name(os, fsname);
						os_spa = dmu_objset_spa(os);
						
						dmu_objset_rele(os, FTAG);
						dsl_prop_set_int((const char*)fsname, zfs_prop_to_name(ZFS_PROP_MASTER), 
							ZPROP_SRC_LOCAL, os_is_master);    //os->os_is_master
						dsl_prop_set_int((const char*)fsname, zfs_prop_to_name(ZFS_PROP_NODE_TYPE), 
							ZPROP_SRC_LOCAL, os_node_type);    //os->os_node_type
						dsl_prop_set_int((const char*)fsname, zfs_prop_to_name(ZFS_PROP_MASTER_SPA), 
							ZPROP_SRC_LOCAL, master_spa);      //os->os_master_spa
						dsl_prop_set_int((const char*)fsname, zfs_prop_to_name(ZFS_PROP_MASTER_OS), 
							ZPROP_SRC_LOCAL, master_os);       //os->os_master_os
						dsl_prop_set_int((const char*)fsname, zfs_prop_to_name(ZFS_PROP_MASTER_ROOT), 
							ZPROP_SRC_LOCAL, master_root);	   //os->os_master_root	
						if (os_spa != NULL)
							spa_async_request(os_spa, SPA_ASYNC_SYSTEM_SPACE);
					}				
				}
			}
			mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
		}
	}
	mutex_exit(&multiclus_mtx);
	return 0;
}

// void zfs_multiclus_set_node_status(char* group_name, uint64_t spa_id, uint64_t os_id, status_type_t status)
// {
// 	int i = 0;
// 	int j = 0;

// 	mutex_enter(&multiclus_mtx);
// 	for (i = 0; i < ZFS_MULTICLUS_GROUP_TABLE_SIZE; i++) {
// 		if (zfs_multiclus_table[i].used && 
// 			!strncmp(group_name, zfs_multiclus_table[i].group_name, strlen(group_name))) {
// 			mutex_enter(&zfs_multiclus_table[i].multiclus_group_mutex);
// 			for (j = 0; j < ZFS_MULTICLUS_GROUP_NODE_NUM; j++) {
// 				if (zfs_multiclus_table[i].multiclus_group[j].spa_id == spa_id && 
// 					zfs_multiclus_table[i].multiclus_group[j].os_id == os_id) {
// 					zfs_multiclus_table[i].multiclus_group[j].node_status.status = status;
// 					break;
// 				}
// 			}
// 			mutex_exit(&zfs_multiclus_table[i].multiclus_group_mutex);
// 			break;
// 		}
// 	}
// 	mutex_exit(&multiclus_mtx);
// 	return;
// }

int zmc_set_node_type(char* group_name, char* fs_name, zfs_multiclus_node_type_t node_type)
{
	zfs_multiclus_group_t* group = NULL;
	zfs_multiclus_group_record_t* record = NULL;
	objset_t* os = NULL;
	int ret = 0;

	if (!zfs_multiclus_enable()) {
		cmn_err(CE_WARN, "[%s %d] multiclus is disabled.", __func__, __LINE__);
		return -1;
	}

	zfs_multiclus_get_group(group_name, &group);
	if (group == NULL) {
		cmn_err(CE_WARN, "[%s %d] failed to get group %s.", __func__, __LINE__, group_name);
		return -1;
	}

	/*
	 * there is only one master node, one master2 node in a group,
	 * and the others are slave nodes
	 */
	if (node_type != ZFS_MULTICLUS_SLAVE 
		&& node_type != ZFS_MULTICLUS_MASTER
		&& zmc_find_record(group, node_type) != NULL) {
		cmn_err(CE_WARN, "[%s %d] node type %d is existed.", __func__, __LINE__, node_type);
		return -1;
	}

	ret = dmu_objset_hold(fs_name, FTAG, &os);
	if (ret != 0) {
		cmn_err(CE_WARN, "[%s %d] failed to get fs %s.", __func__, __LINE__, fs_name);
		return ret;
	}

	if (os->os_phys->os_type != DMU_OST_ZFS || os->os_is_group == 0) {
		cmn_err(CE_WARN, "[%s %d] fs %s is invalid.", __func__, __LINE__, fs_name);
		dmu_objset_rele(os, FTAG);
		return -1;
	}

	record = zfs_multiclus_get_record(spa_guid(dmu_objset_spa(os)), dmu_objset_id(os));
	if (record == NULL) {
		cmn_err(CE_WARN, "[%s %d] fs %s is not in the group %s.", __func__, __LINE__, 
			fs_name, group_name);
		dmu_objset_rele(os, FTAG);
		return -1;
	}
	
	dmu_objset_rele(os, FTAG);
	
	ret = zmc_do_set_node_type(record, fs_name, node_type);
	
	return ret;
}

int 
zmc_do_set_node_type(zfs_multiclus_group_record_t* record, char *fs_name, zfs_multiclus_node_type_t node_type)
{
	zfs_sb_t *zsb = NULL;
	objset_t *os = NULL;
	zfs_multiclus_group_record_t *old_master = NULL;
	zfs_multiclus_node_type_t old_nodetype = record->node_type;
	int err = 0;

	char os_group_name[MAXNAMELEN] = {0};
	uint64_t new_master_spa = 0;
	uint64_t new_master_os = 0;
	uint64_t old_master_spa = 0;
	uint64_t old_master_os = 0;

	err = dmu_objset_hold(fs_name, FTAG, &os);
	if (err != 0) {
		cmn_err(CE_WARN, "[%s %d] failed to get fs %s.", __func__, __LINE__, fs_name);
		return err;
	}

	if (node_type != ZFS_MULTICLUS_MASTER && 
		zfs_multiclus_set_node_type(record->spa_id, record->os_id, node_type)) {
		cmn_err(CE_WARN, "[%s %d] Set node type %d failed!", __func__, __LINE__, node_type);
	} else {
		cmn_err(CE_WARN, "[%s %d] Set node type %d succeed!", __func__, __LINE__, node_type);
	}
	
	switch (node_type)
	{
		case ZFS_MULTICLUS_SLAVE:
			os->os_is_master = 0;
			os->os_node_type = OS_NODE_TYPE_SLAVE;
			dmu_objset_rele(os, FTAG);
			dsl_prop_set_int((const char*)(record->fsname), zfs_prop_to_name(ZFS_PROP_MASTER),
				ZPROP_SRC_LOCAL, 0);  		/*os->os_is_master*/
			dsl_prop_set_int((const char*)(record->fsname), zfs_prop_to_name(ZFS_PROP_NODE_TYPE),
				ZPROP_SRC_LOCAL, OS_NODE_TYPE_SLAVE);   /*os->os_node_type*/
			err = dmu_objset_hold(fs_name, FTAG, &os);
			if (err == 0)
				spa_async_request(dmu_objset_spa(os), SPA_ASYNC_SYSTEM_SPACE);
			break;

		case ZFS_MULTICLUS_MASTER:
			zsb = (zfs_sb_t *)dmu_objset_get_user(os);
			if (zsb == NULL) {
				cmn_err(CE_WARN, "[%s %d] zfsvfs is NULL!", __func__, __LINE__);
				return (-1);
			}
			os->os_will_be_master = B_TRUE;
			strncpy(os_group_name, os->os_group_name, strlen(os->os_group_name));
			new_master_spa = spa_guid(dmu_objset_spa(os));
			new_master_os = dmu_objset_id(os);
			
			old_master = zfs_multiclus_get_record(os->os_master_spa, os->os_master_os);
			if (NULL != old_master) {
				old_master_spa = old_master->spa_id;
				old_master_os = old_master->os_id;
			} else {
				old_master_spa = os->os_master_spa;
				old_master_os = os->os_master_os;
			}
			dmu_objset_rele(os, FTAG);

			zfs_multiclus_change_master_to_record((char *)os_group_name, (char *)record->fsname,
				new_master_spa, new_master_os, zsb->z_root, old_master_spa, old_master_os, old_nodetype);

			err = dmu_objset_hold(fs_name, FTAG, &os);
				/* wake up the new master */
			if (err == 0)
				zfs_multiclus_start_reg((char *)os->os_group_name, os->os_master_spa, os->os_master_os, WAKEUP_SOMEONE);
			break;

		case ZFS_MULTICLUS_MASTER2:
			os->os_is_master = 0;
			os->os_node_type = OS_NODE_TYPE_MASTER2;
			dmu_objset_rele(os, FTAG);
			dsl_prop_set_int((const char*)(record->fsname), zfs_prop_to_name(ZFS_PROP_MASTER),
				ZPROP_SRC_LOCAL, 0);    					/*os->os_is_master*/
			dsl_prop_set_int((const char*)(record->fsname), zfs_prop_to_name(ZFS_PROP_NODE_TYPE),
				ZPROP_SRC_LOCAL, OS_NODE_TYPE_MASTER2);     /*os->os_node_type*/
			err = dmu_objset_hold(fs_name, FTAG, &os);
			if (err == 0)
				spa_async_request(dmu_objset_spa(os), SPA_ASYNC_SYSTEM_SPACE);
			break;

		case ZFS_MULTICLUS_MASTER3:
			os->os_is_master = 0;
			os->os_node_type = OS_NODE_TYPE_MASTER3;
			dmu_objset_rele(os, FTAG);
			dsl_prop_set_int((const char*)(record->fsname), zfs_prop_to_name(ZFS_PROP_MASTER),
				ZPROP_SRC_LOCAL, 0);                       /*os->os_is_master*/
			dsl_prop_set_int((const char*)(record->fsname), zfs_prop_to_name(ZFS_PROP_NODE_TYPE),
				ZPROP_SRC_LOCAL, OS_NODE_TYPE_MASTER3);    /*os->os_node_type*/
			err = dmu_objset_hold(fs_name, FTAG, &os);
			if (err == 0)
				spa_async_request(dmu_objset_spa(os), SPA_ASYNC_SYSTEM_SPACE);
			break;

		case ZFS_MULTICLUS_MASTER4:
			os->os_is_master = 0;
			os->os_node_type = OS_NODE_TYPE_MASTER4;
			dmu_objset_rele(os, FTAG);
			dsl_prop_set_int((const char*)(record->fsname), zfs_prop_to_name(ZFS_PROP_MASTER),
				ZPROP_SRC_LOCAL, 0);                       /*os->os_is_master*/
			dsl_prop_set_int((const char*)(record->fsname), zfs_prop_to_name(ZFS_PROP_NODE_TYPE),
				ZPROP_SRC_LOCAL, OS_NODE_TYPE_MASTER4);    /*os->os_node_type*/
			err = dmu_objset_hold(fs_name, FTAG, &os);
			if (err == 0)
				spa_async_request(dmu_objset_spa(os), SPA_ASYNC_SYSTEM_SPACE);
			break;

		default:
			cmn_err(CE_WARN, "invalid node type: %d.", node_type);
			os->os_is_master = 0;
			os->os_node_type = OS_NODE_TYPE_SLAVE;
			dmu_objset_rele(os, FTAG);
			dsl_prop_set_int((const char*)(record->fsname), zfs_prop_to_name(ZFS_PROP_MASTER),
				ZPROP_SRC_LOCAL, 0);                     /*os->os_is_master*/
			dsl_prop_set_int((const char*)(record->fsname), zfs_prop_to_name(ZFS_PROP_NODE_TYPE),
				ZPROP_SRC_LOCAL, OS_NODE_TYPE_SLAVE);    /*os->os_node_type*/
			err = dmu_objset_hold(fs_name, FTAG, &os);
			if (err == 0)
				spa_async_request(dmu_objset_spa(os), SPA_ASYNC_SYSTEM_SPACE);
			break;
	}

	if (err != 0)
		return (err);
	
	if (ZFS_GROUP_DTL_ENABLE)
		zfs_group_dtl_reset(os, NULL);
	dmu_objset_rele(os, FTAG);
	return err;
}

zfs_multiclus_group_record_t*
zmc_find_record(zfs_multiclus_group_t* group, zfs_multiclus_node_type_t node_type)
{
	zfs_multiclus_group_record_t* record = NULL;
	int index = 0;

	mutex_enter(&(group->multiclus_group_mutex));

	for (index = 0; index < ZFS_MULTICLUS_GROUP_NODE_NUM; ++index)
	{
		if (group->multiclus_group[index].used
			&& group->multiclus_group[index].node_type == node_type)
		{
			record = &(group->multiclus_group[index]);
			break;
		}
	}

	mutex_exit(&(group->multiclus_group_mutex));

	return record;
}

zfs_multiclus_node_type_t zmc_get_node_type(objset_t* os)
{
	zfs_multiclus_node_type_t node_type = ZFS_MULTICLUS_SLAVE;

	if (os->os_is_master == 1)
	{
		return ZFS_MULTICLUS_MASTER;
	}

	switch (os->os_node_type)
	{
		case OS_NODE_TYPE_SLAVE:
			node_type = ZFS_MULTICLUS_SLAVE;
			break;

		case OS_NODE_TYPE_MASTER2:
			node_type = ZFS_MULTICLUS_MASTER2;
			break;

		case OS_NODE_TYPE_MASTER3:
			node_type = ZFS_MULTICLUS_MASTER3;
			break;

		case OS_NODE_TYPE_MASTER4:
			node_type = ZFS_MULTICLUS_MASTER4;
			break;

		default:
			node_type = ZFS_MULTICLUS_SLAVE;
			break;
	}

	return node_type;
}

uint64_t zmc_node_type_to_os_type(zfs_multiclus_node_type_t node_type)
{
	uint64_t os_type = 0;
	
	switch (node_type) {
		case ZFS_MULTICLUS_MASTER:
			os_type = OS_NODE_TYPE_SLAVE;
			break;
		case ZFS_MULTICLUS_MASTER2:
			os_type = OS_NODE_TYPE_MASTER2;
			break;
		case ZFS_MULTICLUS_MASTER3:
			os_type = OS_NODE_TYPE_MASTER3;
			break;			
		case ZFS_MULTICLUS_MASTER4:
			os_type = OS_NODE_TYPE_MASTER4;
			break;		
		case ZFS_MULTICLUS_SLAVE:
			os_type = OS_NODE_TYPE_SLAVE;
			break;
		default:
			os_type = OS_NODE_TYPE_SLAVE;
			break;
	}
	return os_type;
}

#endif
