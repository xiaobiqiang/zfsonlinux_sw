#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/scsi/generic/commands.h>
#include <sys/scsi/generic/persist.h>
#include <sys/scsi/generic/status.h>
#include <sys/scsi/generic/mode.h>
/*
#include <sys/scsi/scsi.h>
#include <sys/scsi/impl/scsi_reset_notify.h>
#include <sys/scsi/generic/mode.h>
*/
#include <sys/disp.h>
#include <sys/byteorder.h>
#include <sys/atomic.h>
#include <sys/sdt.h>
#include <sys/dkio.h>
#include <sys/dmu.h>
#include <sys/arc.h>
#include <sys/zvol.h>
#include <sys/dmu_tx.h>
#include <sys/dmu_impl.h>
#include <sys/zfs_rlock.h>
#include <sys/zil.h>

#include <sys/stmf.h>
#include <sys/lpif.h>
#include <sys/portif.h>
#include <sys/stmf_ioctl.h>
#include <sys/stmf_sbd_ioctl.h>
#include <sys/stmf_sbd.h>
#include <sys/sbd_impl.h>
#include <sys/lun_migrate.h>

extern int highbit(ulong_t i);

/*
 * Take direct control of the volume instead of using the driver
 * interfaces provided by zvol.c. Gather parameters and handles
 * needed to make direct calls into zfs/dmu/zvol. The driver is
 * opened exclusively at this point, so these parameters cannot change.
 *
 * NOTE: the object size and WCE can change while the device
 * is open, so they must be fetched for every operation.
 */
int
sbd_zvol_get_volume_params(sbd_lu_t *sl)
{
	int ret;

	ret = zvol_get_volume_params(sl->sl_zvol_minor,
	    &sl->sl_blksize,		/* volume block size */
	    &sl->sl_max_xfer_len,	/* max data chunk size */
	    &sl->sl_zvol_minor_hdl,	/* minor soft state */
	    &sl->sl_zvol_objset_hdl,	/* dmu_tx_create */
	    &sl->sl_zvol_zil_hdl,	/* zil_commit */
	    &sl->sl_zvol_rl_hdl,	/* zfs_range_lock */
	    &sl->sl_zvol_bonus_hdl);	/* dmu_buf_hold_array_by_bonus, */
					/* dmu_request_arcbuf, */
					/* dmu_assign_arcbuf */

	if (ret == 0 && sl->sl_blksize < PAGE_SIZE) {
		cmn_err(CE_NOTE, " reduced copy disabled due to "
		    "small  blocksize (%d)\n", (int)sl->sl_blksize);
		ret = ENOTSUP;
	}

	return (ret);
}

/*
 * Return the number of elements in a scatter/gather list required for
 * the given span in the zvol. Elements are 1:1 with zvol blocks.
 */
uint32_t
sbd_zvol_numsegs(sbd_lu_t *sl, uint64_t off, uint32_t len)
{
	uint64_t blksz = sl->sl_blksize;
	uint64_t endoff = off + len;
	uint64_t numsegs;

	numsegs = (P2ROUNDUP(endoff, blksz) - P2ALIGN(off, blksz)) / blksz;
	return ((uint32_t)numsegs);
}

/*
 * Return an array of dmu_buf_t pointers for the requested range.
 * The dmu buffers are either in cache or read in synchronously.
 * Fill in the dbuf sglist from the dmu_buf_t array.
 */
static void *RDTAG = "sbd_zvol_read";

int
sbd_zvol_alloc_read_bufs(sbd_lu_t *sl, stmf_data_buf_t *dbuf, char *initiator_wwn)
{
	uint64_t lock_off;
	uint64_t lock_len;
	sbd_zvol_io_t	*zvio = dbuf->db_lu_private;
	rl_t 		*rl;
	int 		numbufs, error, ret;
	uint64_t 	len = dbuf->db_data_size;
	uint64_t 	offset = zvio->zvio_offset;
	dmu_buf_t	**dbpp, *dbp;
	boolean_t	b_lun_migrate;

	/* Make sure request is reasonable */
	if (len > sl->sl_max_xfer_len)
		return (E2BIG);
	if (offset + len  > zvol_get_volume_size(sl->sl_zvol_minor_hdl))
		return (EIO);

	b_lun_migrate = lun_migrate_is_work(sl->sl_zvol_objset_hdl) == 1 ? B_TRUE : B_FALSE;
	if (b_lun_migrate) {
		void *data = NULL;
		stmf_sglist_ent_t *sgl;
		dbuf->db_sglist_length = 1;
		sgl = &dbuf->db_sglist[0];
		data = zio_data_buf_alloc(len);
		zvio->zvio_is_migrate = B_TRUE;
		zvio->zvio_crypt_data = kmem_zalloc(sizeof(void *) * 1, KM_SLEEP);
		ret = lun_migrate_zvol_sgl_read(sl->sl_name, offset, len, data);
		if (ret == 0) {
			sgl->seg_addr = (uint8_t *)data;
			sgl->seg_length = (uint32_t)len;
			zvio->zvio_crypt_data[0] = data;
			return (0);
		} else {
			return (EIO);
		}
	}

	/*
	 * The range lock is only held until the dmu buffers read in and
	 * held; not during the callers use of the data.
	 */
	dmu_get_lock_para(sl->sl_zvol_bonus_hdl, offset, len, &lock_off, &lock_len);
	rl = zfs_range_lock(sl->sl_zvol_rl_hdl, lock_off, lock_len, RL_READER);
	error = dmu_buf_hold_array_by_bonus(sl->sl_zvol_bonus_hdl, offset,
	    len, TRUE, RDTAG, &numbufs, &dbpp);

	zfs_range_unlock(rl);

	if (error == ECKSUM)
		error = EIO;

	if (error == 0)
		zvio->zvio_dbp = dbpp;

	if (dbuf->db_sglist_length != numbufs) {
		cmn_err(CE_PANIC, "wrong size sglist: dbuf %d != %d\n",
			dbuf->db_sglist_length, numbufs);
	}

	if (error == 0) {
		int		i;
		stmf_sglist_ent_t *sgl;
		uint64_t	odiff, seglen;

		zvio->zvio_crypt_data = kmem_zalloc(sizeof(void *) * numbufs, KM_SLEEP);

		zvio->zvio_dbp = dbpp;
		if (dbuf->db_sglist_length != numbufs) {
			cmn_err(CE_PANIC, "wrong size sglist: dbuf %d != %d\n",
			    dbuf->db_sglist_length, numbufs);
		}

		sgl = &dbuf->db_sglist[0];
		for (i = 0; i < numbufs; i++) {
			void *data;
			boolean_t free_data = B_FALSE;
			dbp = dbpp[i];
			odiff =  offset - dbp->db_offset;
			ASSERT(odiff == 0 || i == 0);

			data = dmu_get_crypt_data(dbp, &free_data);
			if (free_data) {
				zvio->zvio_crypt_data[i] = data;
			}

			sgl->seg_addr = (uint8_t *)data + odiff;
			seglen = MIN(len, dbp->db_size - odiff);
			sgl->seg_length = (uint32_t)seglen;
			offset += seglen;
			len -= seglen;
			sgl++;
		}
		ASSERT(len == 0);

	}

	return (error);
}

/*
 * Release a dmu_buf_t array.
 */
/*ARGSUSED*/
void
sbd_zvol_rele_read_bufs(sbd_lu_t *sl, stmf_data_buf_t *dbuf)
{
	int i;
	dmu_buf_t *dbp, **dbpp;
	sbd_zvol_io_t *zvio = dbuf->db_lu_private;

	if (zvio->zvio_is_migrate) {
		if (zvio->zvio_crypt_data[0] != NULL)
			dmu_free_crypt_data(zvio->zvio_crypt_data[0], dbuf->db_data_size);

		kmem_free(zvio->zvio_crypt_data, sizeof(void *));
		return;
	}

	ASSERT(zvio->zvio_dbp);
	ASSERT(dbuf->db_sglist_length);

	dbpp = (dmu_buf_t **) zvio->zvio_dbp;
	for (i = 0; i < dbuf->db_sglist_length; i ++) {
		dbp = dbpp[i];
		if (zvio->zvio_crypt_data[i] != NULL)
			dmu_free_crypt_data(zvio->zvio_crypt_data[i], dbp->db_size);
	}

	kmem_free(zvio->zvio_crypt_data, sizeof(void *)*dbuf->db_sglist_length);
	dmu_buf_rele_array(zvio->zvio_dbp, (int)dbuf->db_sglist_length, RDTAG);
}

/*
void *sbd_zvol_create_parent_io(sbd_lu_t *sl)
{
	objset_t *os;
	zio_t *write_zio;
	os = (objset_t *) sl->sl_zvol_objset_hdl;
	write_zio = zio_root(dmu_objset_spa(os), NULL, NULL, ZIO_FLAG_CANFAIL);

	return ((void *) write_zio);
}
*/

/*
 * Allocate enough loaned arc buffers for the requested region.
 * Mimic the handling of the dmu_buf_t array used for reads as closely
 * as possible even though the arc_buf_t's are anonymous until released.
 * The buffers will match the zvol object blocks sizes and alignments
 * such that a data copy may be avoided when the buffers are assigned.
 */
int
sbd_zvol_alloc_write_bufs(sbd_lu_t *sl, stmf_data_buf_t *dbuf)
{
	sbd_zvol_io_t	*zvio = dbuf->db_lu_private;
	int		blkshift, numbufs, i;
	uint64_t	blksize;
	arc_buf_t	**abp;
	stmf_sglist_ent_t *sgl;
	uint64_t 	len = dbuf->db_data_size;
	uint64_t 	offset = zvio->zvio_offset;

	/* Make sure request is reasonable */
	if (len > sl->sl_max_xfer_len)
		return (E2BIG);
	if (offset + len  > zvol_get_volume_size(sl->sl_zvol_minor_hdl))
		return (EIO);

	/*
	 * Break up the request into chunks to match
	 * the volume block size. Only full, and aligned
	 * buffers will avoid the data copy in the dmu.
	 */
	/*
	 * calculate how may dbufs are needed
	 */
	blksize = sl->sl_blksize;
	ASSERT(ISP2(blksize));
	blkshift = highbit(blksize - 1);
	/*
	 * taken from dmu_buf_hold_array_by_dnode()
	 */
	numbufs = (P2ROUNDUP(offset+len, 1ULL<<blkshift) -
	    P2ALIGN(offset, 1ULL<<blkshift)) >> blkshift;
	if (dbuf->db_sglist_length != numbufs) {
		cmn_err(CE_PANIC, "wrong size sglist: dbuf %d != %d\n",
		    dbuf->db_sglist_length, numbufs);
	}

	/*
	 * allocate a holder for the needed arc_buf pointers
	 */
	abp = kmem_alloc(sizeof (arc_buf_t *) * numbufs, KM_SLEEP);
	/*
	 * The write operation uses loaned arc buffers so that
	 * the xfer_data is done outside of a dmu transaction.
	 * These buffers will exactly match the request unlike
	 * the dmu buffers obtained from the read operation.
	 */
	/*
	 * allocate the arc buffers and fill in the stmf sglist
	 */
	sgl = &dbuf->db_sglist[0];
	for (i = 0; i < numbufs; i++) {
		uint64_t seglen;

		/* first block may not be aligned */
		seglen = P2NPHASE(offset, blksize);
		if (seglen == 0)
			seglen = blksize;
		seglen = MIN(seglen, len);
		abp[i] = dmu_request_arcbuf(sl->sl_zvol_bonus_hdl, (int)seglen);
		ASSERT(arc_buf_size(abp[i]) == (int)seglen);
		sgl->seg_addr = abp[i]->b_data;
		sgl->seg_length = (uint32_t)seglen;
		sgl++;
		offset += seglen;
		len -= seglen;
	}
	ASSERT(len == 0);
	
	zvio->zvio_abp = abp;
	return (0);
}

/*ARGSUSED*/
void
sbd_zvol_rele_write_bufs_abort(sbd_lu_t *sl, stmf_data_buf_t *dbuf)
{
	sbd_zvol_io_t *zvio = dbuf->db_lu_private;
	int i;
	arc_buf_t **abp = zvio->zvio_abp;

	/* free arcbufs */
	for (i = 0; i < dbuf->db_sglist_length; i++)
		dmu_return_arcbuf(*abp++);
	kmem_free(zvio->zvio_abp,
	    sizeof (arc_buf_t *) * dbuf->db_sglist_length);
	zvio->zvio_abp = NULL;
}


void sbd_direct_write_start(uint64_t num)
{
}


void sbd_direct_write_end(uint64_t bufnum, uint64_t direct_num)
{
}

/*
void remote_write(dev_t dev,  uint64_t offset, uint64_t len, uint8_t *data) 
{
    int err;
	struct uio uio;
	struct iovec iov;

	iov.iov_base = (void*)data;
	iov.iov_len = len;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_loffset = offset;
	uio.uio_segflg = (short)UIO_SYSSPACE;
	uio.uio_resid = len;
	uio.uio_limit = RLIM64_INFINITY;
	err = cdev_write(dev, &uio, CRED());

	if(err)
		cmn_err(CE_NOTE, "cdev_write: err %d when remote_write call it", err);
}
*/

/*
void sbd_zvol_sgl_write_remote_mirror(sbd_lu_t *sl, stmf_data_buf_t *dbuf)
{
	uint64_t toffset;
	dev_t dev;
	boolean_t b_remote;
	sbd_zvol_io_t	*zvio = dbuf->db_lu_private;
	arc_buf_t	**abp = zvio->zvio_abp;

	toffset = zvio->zvio_offset;
	dev = sl->sl_data_vp->v_rdev;
	b_remote = devopsp[getmajor(dev)]->devo_cb_ops->cb_flag & D_REMOTE_MIRROR;
	if (b_remote) {
		int i;
		for (i = 0; i < dbuf->db_sglist_length; i ++) {
			arc_buf_t *abuf;
			int size;
			abuf = abp[i];
			size = arc_buf_size(abuf);
			remote_write(dev, toffset, size, abuf->b_data);
			toffset += size;
		}
	}
}
*/

uint8_t zvol_direct_write = 1;

typedef struct direct_para {
	uint64_t size;
	uint64_t offset;
	boolean_t b_cache;
}direct_para_t;

/*
 * Release the arc_buf_t array allocated above and handle these cases :
 *
 * flags == 0 - create transaction and assign all arc bufs to offsets
 * flags == ZVIO_COMMIT - same as above and commit to zil on sync devices
 */
int
sbd_zvol_rele_write_bufs(sbd_lu_t *sl, stmf_data_buf_t *dbuf)
{
	uint64_t txg;
	uint64_t lock_off;
	uint64_t lock_len;
	boolean_t write_direct;
	boolean_t write_meta = (dbuf->db_flags & DB_WRITE_META_DATA) ? B_TRUE : B_FALSE;
	sbd_zvol_io_t	*zvio = dbuf->db_lu_private;
	dmu_tx_t	*tx;
	int		sync, i, error, ret;
	rl_t 		*rl;
	arc_buf_t	**abp = zvio->zvio_abp;
	int		flags = zvio->zvio_flags;
	uint64_t	coffset, toffset, offset = zvio->zvio_offset;
	uint64_t	resid, len = dbuf->db_data_size;

	/* sbd_zvol_sgl_write_remote_mirror(sl, dbuf); */
	write_direct = B_FALSE;
	sync = !zvol_get_volume_wce(sl->sl_zvol_minor_hdl);
	ASSERT(flags == 0 || flags == ZVIO_COMMIT || flags == ZVIO_ABORT);
	dmu_get_lock_para(sl->sl_zvol_bonus_hdl, offset, len, &lock_off, &lock_len);
	rl = zfs_range_lock(sl->sl_zvol_rl_hdl, lock_off, lock_len, RL_WRITER);

	if (lun_migrate_is_work(sl->sl_zvol_objset_hdl)) {
		toffset = offset;
		resid = len;
		coffset = lun_migrate_get_offset(sl->sl_name);
		for (i = 0; i < dbuf->db_sglist_length; i++) {
			arc_buf_t *abuf;
			int size;
			abuf = abp[i];
			size = arc_buf_size(abuf);

			ret = lun_migrate_zvol_sgl_write(sl->sl_name, toffset, size, abuf->b_data);

			if (ret == -1) {
				zfs_range_unlock(rl);
				sbd_zvol_rele_write_bufs_abort(sl, dbuf);
				return (EIO);
			}

			toffset += size;
			resid -= size;
		}
		if (coffset < offset) {
			zfs_range_unlock(rl);
			sbd_zvol_rele_write_bufs_abort(sl, dbuf);
			return (0);
		}
	}

	tx = dmu_tx_create(sl->sl_zvol_objset_hdl);
	dmu_tx_hold_write(tx, ZVOL_OBJ, offset, (int)len);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		zfs_range_unlock(rl);
		sbd_zvol_rele_write_bufs_abort(sl, dbuf);
		return (error);
	}

	toffset = offset;
	resid = len;
	for (i = 0; i < dbuf->db_sglist_length; i++) {
		arc_buf_t *abuf;
		int size;
		abuf = abp[i];
		size = arc_buf_size(abuf);
		/* TODO: */
		/* dmu_assign_arcbuf(sl->sl_zvol_bonus_hdl, toffset, abuf, tx, sync, write_meta); */
		dmu_assign_arcbuf(sl->sl_zvol_bonus_hdl, toffset, abuf, tx, sync);
		toffset += size;
		resid -= size;
	}
	ASSERT(resid == 0);
	txg = tx->tx_txg;
	write_direct = dmu_tx_sync_log(tx);
	dmu_tx_commit(tx);
	zfs_range_unlock(rl);
	kmem_free(zvio->zvio_abp,
	    sizeof (arc_buf_t *) * dbuf->db_sglist_length);
	zvio->zvio_abp = NULL;
	if (sync && write_direct) {
		zil_commit(sl->sl_zvol_zil_hdl, ZVOL_OBJ);
	}
	return (0);
}

/*
 * Copy interface for callers using direct zvol access.
 * Very similar to zvol_read but the uio may have multiple iovec entries.
 */
int
sbd_zvol_copy_read(sbd_lu_t *sl, uio_t *uio, char *initiator_wwn)
{
	uint64_t lock_off;
	uint64_t lock_len;
	int		error;
	rl_t 		*rl;
	uint64_t	len = (uint64_t)uio->uio_resid;
	uint64_t	offset = (uint64_t)uio->uio_loffset;

	/* Make sure request is reasonable */
	if (len > sl->sl_max_xfer_len)
		return (E2BIG);
	if (offset + len  > zvol_get_volume_size(sl->sl_zvol_minor_hdl))
		return (EIO);

	if(sl->sl_access_state!=SBD_LU_ACTIVE){
		cmn_err(CE_WARN,   "%s  sl_access_state=%x is not allowed",__func__, sl->sl_access_state);
		return (EIO);
	}

	/* lun migrate add */
	if (lun_migrate_is_work(sl->sl_zvol_objset_hdl)) {
		error = lun_migrate_zvol_read(sl->sl_name, uio);
		if (error != 0) {
			return (EIO);
		} else {
			return (0);
		}
	}
	/* lun migrate add end */

	dmu_get_lock_para(sl->sl_zvol_bonus_hdl, offset, len, &lock_off, &lock_len);
#if 1
	rl = zfs_range_lock(sl->sl_zvol_rl_hdl, lock_off, lock_len, RL_READER);
#endif

#if 1
	error =  dmu_read_uio(sl->sl_zvol_objset_hdl, ZVOL_OBJ, uio, len);
	/*
	error =  dmu_read_uio(sl->sl_zvol_objset_hdl, ZVOL_OBJ, uio, len,
	    initiator_wwn, ZFS_PROP_ACL_WWN);
	*/
#else
	error =  dmu_read_uio(sl->sl_zvol_objset_hdl, ZVOL_OBJ, uio, len);
#endif

#if 1
	zfs_range_unlock(rl);
#endif
	if (error == ECKSUM)
		error = EIO;
	return (error);
}

void
sbd_zvol_check_remote(int flag, int remote)
{
}

/*
 * Copy interface for callers using direct zvol access.
 * Very similar to zvol_write but the uio may have multiple iovec entries.
 */
int
sbd_zvol_copy_write(sbd_lu_t *sl, uio_t *uio, int flags,char *initiator_wwn)
{
	int ret;
	int error;
	int sync;
	uint64_t len;
	uint64_t offset;
	uint64_t lock_off;
	uint64_t lock_len;
	int mirror_sucess;
	dev_t dev;
	boolean_t b_remote;
	boolean_t write_direct;
	rl_t *rl;
	dmu_tx_t *tx;
    uint64_t write_flag;
    boolean_t write_meta;

    write_flag = 0;
    if (flags & DB_WRITE_META_DATA) {
        write_flag |= WRITE_FLAG_APP_META;
    }

	if(sl->sl_access_state!=SBD_LU_ACTIVE){
		cmn_err(CE_WARN,   "%s sl_access_state=%x is not allowed",__func__, sl->sl_access_state);
		return (EIO);
	}

	write_direct = B_FALSE;
	len = (uint64_t)uio->uio_resid;
	offset = (uint64_t)uio->uio_loffset;

	/* Make sure request is reasonable */
	if (len > sl->sl_max_xfer_len)
		return (E2BIG);
	if (offset + len  > zvol_get_volume_size(sl->sl_zvol_minor_hdl))
		return (EIO);

	dev = sl->sl_data_vp->v_rdev;
	/*
	b_remote = devopsp[getmajor(dev)]->devo_cb_ops->cb_flag & D_REMOTE_MIRROR;

	sbd_zvol_check_remote(devopsp[getmajor(dev)]->devo_cb_ops->cb_flag, b_remote);
	if (b_remote) {
		uio_t d_uio;
		iovec_t *d_iovec;
		d_iovec = kmem_alloc(uio->uio_iovcnt * sizeof(iovec_t), KM_SLEEP);
		uiodup(uio, &d_uio, d_iovec, uio->uio_iovcnt );
		cdev_write(dev, &d_uio, CRED());
		kmem_free(d_iovec, uio->uio_iovcnt * sizeof(iovec_t));
	}
	*/

	dmu_get_lock_para(sl->sl_zvol_bonus_hdl, offset, len, &lock_off, &lock_len);
	rl = zfs_range_lock(sl->sl_zvol_rl_hdl, lock_off, lock_len, RL_WRITER);

	if (lun_migrate_is_work(sl->sl_zvol_objset_hdl)) {
		ret = lun_migrate_zvol_write(sl->sl_name, uio);
		if (ret != 1) {
			zfs_range_unlock(rl);
			return (ret);
		}
	}

	sync = !zvol_get_volume_wce(sl->sl_zvol_minor_hdl);
    if (sync) {
		write_flag |= WRITE_FLAG_APP_SYNC;
    }

	tx = dmu_tx_create(sl->sl_zvol_objset_hdl);
	dmu_tx_hold_write(tx, ZVOL_OBJ, offset, (int)uio->uio_resid);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
	} else {
		error = dmu_write_uio(sl->sl_zvol_objset_hdl, ZVOL_OBJ,
		    uio, len, tx, write_flag);
		/*
		error = dmu_write_uio(sl->sl_zvol_objset_hdl, ZVOL_OBJ,
		    uio, len, tx, write_flag, initiator_wwn);
		*/
		write_direct = dmu_tx_sync_log(tx);
		dmu_tx_commit(tx);
	}
	zfs_range_unlock(rl);
	if (sync && write_direct) {
		zil_commit(sl->sl_zvol_zil_hdl, ZVOL_OBJ);
	}
	if (error == ECKSUM)
		error = EIO;
	return (error);
}

void sbd_zvol_mirror_replay_wait(sbd_lu_t *sl)
{
	if ((sl->sl_access_state == SBD_LU_ACTIVE) &&
		((sl->sl_flags & SL_CALL_ZVOL) != 0)) {
		zvol_mirror_replay_wait(sl->sl_zvol_minor_hdl);
	}
}

