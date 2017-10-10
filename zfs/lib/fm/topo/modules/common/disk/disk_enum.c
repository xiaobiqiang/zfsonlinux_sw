#include <stdio.h>
#include <syslog.h>
#include <ipmitool/ipmi.h>
#include <ipmitool/ipmi_sel.h>
#include <sys/dkio.h>
#include <sys/fm/protocol.h>
#include <libipmi.h>
#include <topo_module.h>
#include <topo_mod.h>
#include <disklist.h>
#include <libdiskstatus.h>

#include "disk_enum.h"


static int disk_bay_present(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int disk_bay_status(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
    nvlist_t **);
static int disk_status(topo_mod_t *, tnode_t *, topo_version_t, nvlist_t *,
	nvlist_t **);


static int disk_enum(topo_mod_t *mod, tnode_t *t_node, const char *name,
		topo_instance_t min, topo_instance_t max, void *arg, void *unused);


static const topo_method_t disk_methods[] = {
	{ TOPO_METH_DISK_STATUS, TOPO_METH_DISK_STATUS_DESC,
	    TOPO_METH_DISK_STATUS_VERSION, TOPO_STABILITY_INTERNAL, disk_status },
	{ NULL }
};

static const topo_method_t bay_methods[] = {
	{ TOPO_METH_PRESENT, TOPO_METH_PRESENT_DESC,
		TOPO_METH_PRESENT_VERSION0, TOPO_STABILITY_INTERNAL, disk_bay_present },
	{ TOPO_METH_STATUS, TOPO_METH_STATUS_DESC,
		TOPO_METH_PRESENT_VERSION0, TOPO_STABILITY_INTERNAL, disk_bay_status },
	{ NULL }
};

static const topo_pgroup_info_t io_pgroup = {
	TOPO_PGROUP_IO,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static const topo_pgroup_info_t disk_auth_pgroup = {
	TOPO_FMRI_AUTHORITY,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static const topo_pgroup_info_t storage_pgroup = {
	TOPO_PGROUP_STORAGE,
	TOPO_STABILITY_PRIVATE,
	TOPO_STABILITY_PRIVATE,
	1
};

static void
disk_data_free(disk_enum_data_t *data)
{
	disk_info_t *temp = NULL;
	disk_info_t *current = NULL;
	disk_table_t *dt;
	topo_mod_t *mod = data->ded_mod;

	dt = &data->ded_disk;
	for (current = dt->next; current != NULL; ) {
		temp = current->next;
		free(current);
		current = temp;
	}

	topo_mod_free(mod, data, sizeof (disk_enum_data_t));
}

static int
disk_status(topo_mod_t *mod, tnode_t *nodep, topo_version_t vers,
    nvlist_t *in_nvl, nvlist_t **out_nvl)
{
	disk_status_t	*dsp;
	char		*devpath, *fullpath;
	size_t		pathlen;
	nvlist_t	*status;
	int		err;
	
	*out_nvl = NULL;

	if (vers != TOPO_METH_DISK_STATUS_VERSION)
		return (topo_mod_seterrno(mod, EMOD_VER_NEW));

	/*
	 * If the caller specifies the "path" parameter, then this indicates
	 * that we should use this instead of deriving it from the topo node
	 * itself.
	 */
	if (nvlist_lookup_string(in_nvl, "path", &fullpath) == 0) {
		devpath = NULL;
	} else {
		fullpath = "/dev/xxx";
	}
	if ((dsp = disk_status_open(fullpath, &err)) == NULL) {
		syslog(LOG_ERR, "disk_status open error");
		if (devpath)
			topo_mod_free(mod, fullpath, pathlen);
		topo_mod_seterrno(mod, err == EDS_NOMEM ?
		    EMOD_NOMEM : EMOD_METHOD_NOTSUP);
		printf("open %s failed\n", fullpath);
		return (-2);		/* open disk failed */
	}

	if (devpath)
		topo_mod_free(mod, fullpath, pathlen);

	if ((status = disk_status_get(dsp)) == NULL) {
		err = (disk_status_errno(dsp) == EDS_NOMEM ?
		    EMOD_NOMEM : EMOD_METHOD_NOTSUP);
		disk_status_close(dsp);
		return (topo_mod_seterrno(mod, err));
	}
	*out_nvl = status;
	disk_status_close(dsp);
	return (0);
}


static int
disk_bay_present(topo_mod_t *mod, tnode_t *tn, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	uint32_t create = 0;
	nvlist_t *nvl;
	tnode_t *node;
	int32_t err;

	if((node = topo_node_lookup(tn, "disk", 0)) != NULL) {
		if(topo_prop_get_uint32(node, TOPO_PGROUP_PROTOCOL, "state",
			&create, &err) != 0){
			return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
		}
	}

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	if (nvlist_add_string(nvl, TOPO_PROP_VAL_NAME,
	    TOPO_PROP_PRESENT) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE, TOPO_TYPE_UINT32) != 0 ||
	    nvlist_add_uint32(nvl, TOPO_PROP_VAL_VAL, create) != 0) {
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	*out = nvl;

	return (0);
}

static int
disk_bay_status(topo_mod_t *mod, tnode_t *tn, topo_version_t version,
    nvlist_t *in, nvlist_t **out)
{
	uint32_t create = 0;
	nvlist_t *nvl;
	tnode_t *node;
	int err;

	if((node = topo_node_lookup(tn, "disk", 0)) != NULL) {
		if(topo_prop_get_uint32(node, TOPO_PGROUP_PROTOCOL, "state",
			&create, &err) != 0) {
			return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
		}
	}

	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0)
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));

	if (nvlist_add_string(nvl, TOPO_PROP_VAL_NAME,
		TOPO_PROP_STATUS) != 0 ||
		nvlist_add_uint32(nvl, TOPO_PROP_VAL_TYPE, TOPO_TYPE_UINT64) != 0 ||
		nvlist_add_uint64(nvl, TOPO_PROP_VAL_VAL, create) != 0) {
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, EMOD_FMRI_NVL));
	}

	*out = nvl;

	return (0);
}

/*
 * Sets standard properties for a ses node (enclosure or bay).  This includes
 * setting the FRU to be the same as the resource, as well as setting the
 * authority information.
 */
static int
disk_set_standard_props(topo_mod_t *mod, tnode_t *tn, nvlist_t *auth,
    uint64_t nodeid, const char *path)
{
	int err;
	char *product, *chassis;
	nvlist_t *fmri;
	topo_pgroup_info_t pgi;

	/*
	 * Set the authority explicitly if specified.
	 */
	if (auth) {
		verify(nvlist_lookup_string(auth, FM_FMRI_AUTH_PRODUCT,
		    &product) == 0);
		verify(nvlist_lookup_string(auth, FM_FMRI_AUTH_CHASSIS,
		    &chassis) == 0);
		if (topo_prop_set_string(tn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_PRODUCT, TOPO_PROP_IMMUTABLE, product,
		    &err) != 0 ||
		    topo_prop_set_string(tn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_CHASSIS, TOPO_PROP_IMMUTABLE, chassis,
		    &err) != 0 ||
		    topo_prop_set_string(tn, FM_FMRI_AUTHORITY,
		    FM_FMRI_AUTH_SERVER, TOPO_PROP_IMMUTABLE, "",
		    &err) != 0) {
			topo_mod_dprintf(mod, "failed to add authority "
			    "properties: %s\n", topo_strerror(err));
			return (topo_mod_seterrno(mod, err));
		}
	}

	/*
	 * Copy the resource and set that as the FRU.
	 */
	if (topo_node_resource(tn, &fmri, &err) != 0) {
		topo_mod_dprintf(mod,
		    "topo_node_resource() failed : %s\n",
		    topo_strerror(err));
		return (topo_mod_seterrno(mod, err));
	}

	if (topo_node_fru_set(tn, fmri, 0, &err) != 0) {
		topo_mod_dprintf(mod,
		    "topo_node_fru_set() failed : %s\n",
		    topo_strerror(err));
		nvlist_free(fmri);
		return (topo_mod_seterrno(mod, err));
	}

	nvlist_free(fmri);

	/*
	 * Set the SES-specific properties so that consumers can query
	 * additional information about the particular SES element.
	 */
	pgi.tpi_name = TOPO_PGROUP_SES;
	pgi.tpi_namestab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_datastab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_version = TOPO_VERSION;
	if (topo_pgroup_create(tn, &pgi, &err) != 0) {
		topo_mod_dprintf(mod, "failed to create propgroup "
		    "%s: %s\n", TOPO_PGROUP_SES, topo_strerror(err));
		return (-1);
	}

	if (topo_prop_set_uint64(tn, TOPO_PGROUP_SES,
	    TOPO_PROP_NODE_ID, TOPO_PROP_IMMUTABLE,
	    nodeid, &err) != 0) {
		topo_mod_dprintf(mod,
		    "failed to create property %s: %s\n",
		    TOPO_PROP_NODE_ID, topo_strerror(err));
		return (-1);
	}

	if (topo_prop_set_string(tn, TOPO_PGROUP_SES,
	    TOPO_PROP_TARGET_PATH, TOPO_PROP_IMMUTABLE,
	    path, &err) != 0) {
		topo_mod_dprintf(mod,
		    "failed to create property %s: %s\n",
		    TOPO_PROP_TARGET_PATH, topo_strerror(err));
		return (-1);
	}

	return (0);
}

static int
disk_set_specific_props(topo_mod_t *mod, tnode_t *tn)
{
	int err;
	nvlist_t *nvl;
	topo_pgroup_info_t pgi;

	pgi.tpi_name = TOPO_PGROUP_FACILITY;
	pgi.tpi_namestab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_datastab = TOPO_STABILITY_PRIVATE;
	pgi.tpi_version = 1;

	if (topo_pgroup_create(tn, &pgi, &err) != 0) {
		topo_mod_dprintf(mod, "failed to create facility property "
			"group: %s\n", topo_strerror(err));
		return (topo_mod_seterrno(mod, err));
	}
	nvl = NULL;
	if (topo_mod_nvalloc(mod, &nvl, NV_UNIQUE_NAME) != 0 ) {
		topo_mod_dprintf(mod, "nvalloc failed\n");
		return (topo_mod_seterrno(mod, ETOPO_PROP_NOMEM));
	}

	/* 'state' property */
	if (topo_prop_method_register(tn, TOPO_PGROUP_FACILITY,
		TOPO_PROP_PRESENT, TOPO_TYPE_UINT32, TOPO_METH_PRESENT,
		nvl, &err) != 0) {
		topo_mod_dprintf(mod, "failed to register state method: %s\n",
			topo_strerror(err));
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, err));
	}
	/* 'status' property */
	if (topo_prop_method_register(tn, TOPO_PGROUP_FACILITY,
		TOPO_PROP_STATUS, TOPO_TYPE_UINT64, TOPO_METH_STATUS,
		nvl, &err) != 0) {
		topo_mod_dprintf(mod, "failed to register state method: %s\n",
			topo_strerror(err));
		nvlist_free(nvl);
		return (topo_mod_seterrno(mod, err));
	}

	nvlist_free(nvl);

	return 0;
}

static int
disk_set_props(topo_mod_t *mod, tnode_t *parent,
    tnode_t *dtn, disk_info_t *dnode, const char *lpath,
    const char *en_id, const char *slot_id)
{
	nvlist_t	*asru = NULL;
	char		*label = NULL;
	nvlist_t	*fmri = NULL;
	int		err;

	/* form and set the asru */
	if ((asru = topo_mod_devfmri(mod, FM_DEV_SCHEME_VERSION,
	    dnode->dk_name, dnode->dk_scsid)) == NULL) {
		err = ETOPO_FMRI_UNKNOWN;
		topo_mod_dprintf(mod, "disk_set_props: "
		    "asru error %s\n", topo_strerror(err));
		goto error;
	}
	if (topo_node_asru_set(dtn, asru, 0, &err) != 0) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "asru_set error %s\n", topo_strerror(err));
		goto error;
	}

	/* pull the label property down from our parent 'bay' node */
	if (topo_node_label(parent, &label, &err) != 0) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "label error %s\n", topo_strerror(err));
		goto error;
	}
	if (topo_node_label_set(dtn, label, &err) != 0) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "label_set error %s\n", topo_strerror(err));
		goto error;
	}

	/* get the resource fmri, and use it as the fru */
	if (topo_node_resource(dtn, &fmri, &err) != 0) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "resource error: %s\n", topo_strerror(err));
		goto error;
	}
	if (topo_node_fru_set(dtn, fmri, 0, &err) != 0) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "fru_set error: %s\n", topo_strerror(err));
		goto error;
	}

	/* create/set the authority group */
	if ((topo_pgroup_create(dtn, &disk_auth_pgroup, &err) != 0) &&
	    (err != ETOPO_PROP_DEFD)) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "create disk_auth error %s\n", topo_strerror(err));
		goto error;
	}

	/* create/set the devfs-path and devid in the io group */
	if (topo_pgroup_create(dtn, &io_pgroup, &err) != 0) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "create io error %s\n", topo_strerror(err));
		goto error;
	}

	if (topo_prop_set_string(dtn, TOPO_PGROUP_IO, TOPO_IO_DEV_PATH,
	    TOPO_PROP_IMMUTABLE, dnode->dk_name, &err) != 0) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "set dev error %s\n", topo_strerror(err));
		goto error;
	}

	if (topo_prop_set_string(dtn, TOPO_PGROUP_IO, TOPO_IO_DEVID,
	    TOPO_PROP_IMMUTABLE, dnode->dk_scsid, &err) != 0) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "set devid error %s\n", topo_strerror(err));
		goto error;
	}

	/* to support disk monitor process in SBB enclosuure */
	if((lpath != NULL) && (topo_prop_set_string(dtn, TOPO_PGROUP_IO,
		TOPO_IO_LINK_PATH, TOPO_PROP_IMMUTABLE, lpath, &err) != 0)) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "set lpath error %s\n", topo_strerror(err));
		goto error;
	}
	
	if ( (en_id != NULL) && (topo_prop_set_string(dtn, TOPO_PGROUP_IO,
		TOPO_IO_EN_ID, TOPO_PROP_IMMUTABLE, en_id, &err) != 0)) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "set en_id error %s\n", topo_strerror(err));
		goto error;
	}

	if ((slot_id != NULL) && (topo_prop_set_string(dtn, TOPO_PGROUP_IO, 
		TOPO_IO_SLOT_ID, TOPO_PROP_IMMUTABLE, slot_id, &err) != 0)) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "set slot_id error %s\n", topo_strerror(err));
		goto error;
	}
	
	/* create the storage group */
	if (topo_pgroup_create(dtn, &storage_pgroup, &err) != 0) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "create storage error %s\n", topo_strerror(err));
		goto error;
	}

	/* populate other misc storage group properties */
	if (dnode->dk_vendor && (topo_prop_set_string(dtn, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_MANUFACTURER, TOPO_PROP_IMMUTABLE,
	    dnode->dk_vendor, &err) != 0)) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "set mfg error %s\n", topo_strerror(err));
		goto error;
	}
	if (topo_prop_set_string(dtn, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_MODEL, TOPO_PROP_IMMUTABLE,
	    "0123456789", &err) != 0) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "set model error %s\n", topo_strerror(err));
		goto error;
	}
	if (dnode->dk_serial && (topo_prop_set_string(dtn, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_SERIAL_NUM, TOPO_PROP_IMMUTABLE,
	    dnode->dk_serial, &err) != 0)) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "set serial error %s\n", topo_strerror(err));
		goto error;
	}
	if (topo_prop_set_string(dtn, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_FIRMWARE_REV, TOPO_PROP_IMMUTABLE,
	    "0103", &err) != 0) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "set firm error %s\n", topo_strerror(err));
		goto error;
	}
	if (dnode->dk_gsize && (topo_prop_set_string(dtn, TOPO_PGROUP_STORAGE,
	    TOPO_STORAGE_CAPACITY, TOPO_PROP_IMMUTABLE,
	    dnode->dk_gsize, &err) != 0)) {
		topo_mod_dprintf(mod, "disk_set_props: "
		    "set cap error %s\n", topo_strerror(err));
		goto error;
	}
	err = 0;

out:	if (fmri)
		nvlist_free(fmri);
	if (label)
		topo_mod_strfree(mod, label);
	if (asru)
		nvlist_free(asru);
	return (err);

error:	err = topo_mod_seterrno(mod, err);
	goto out;
}


char *
disk_auth_clean(topo_mod_t *mod, const char *str)
{
	char *buf, *p;

	if (str == NULL)
		return (NULL);

	if ((buf = topo_mod_strdup(mod, str)) == NULL)
		return (NULL);

	while ((p = strpbrk(buf, " :=")) != NULL)
		*p = '-';

	return (buf);
}

/* create the disk topo node */
static tnode_t *
disk_tnode_create(topo_mod_t *mod, tnode_t *parent,
    disk_info_t *dnode, const char *name, topo_instance_t i,
    const char *lpath, const char *en_id, const char *slot_id)
{
	nvlist_t	*fmri;
	tnode_t		*dtn;
	nvlist_t	*auth;
	char		*mfg, *firm, *serial;

	mfg = disk_auth_clean(mod, dnode->dk_vendor);
	firm = disk_auth_clean(mod, "0103");
	serial = disk_auth_clean(mod, dnode->dk_serial);

	auth = topo_mod_auth(mod, parent);
	fmri = topo_mod_hcfmri(mod, parent, FM_HC_SCHEME_VERSION, name, i, NULL,
	    auth, "0123456789", firm, serial);
	nvlist_free(auth);

	topo_mod_strfree(mod, mfg);
	topo_mod_strfree(mod, firm);
	topo_mod_strfree(mod, serial);

	if (fmri == NULL) {
		topo_mod_dprintf(mod, "disk_tnode_create: "
		    "hcfmri (%s%d/%s%d) error %s\n",
		    topo_node_name(parent), topo_node_instance(parent),
		    name, i, topo_strerror(topo_mod_errno(mod)));
		return (NULL);
	}

	if ((dtn = topo_node_bind(mod, parent, name, i, fmri)) == NULL) {
		topo_mod_dprintf(mod, "disk_tnode_create: "
		    "bind (%s%d/%s%d) error %s\n",
		    topo_node_name(parent), topo_node_instance(parent),
		    name, i, topo_strerror(topo_mod_errno(mod)));
		nvlist_free(fmri);
		return (NULL);
	}
	nvlist_free(fmri);

	/* add the properties of the disk */
	if (disk_set_props(mod, parent, dtn, dnode, lpath,
		en_id, slot_id) != 0) {
		topo_mod_dprintf(mod, "disk_tnode_create: "
		    "disk_set_props (%s%d/%s%d) error %s\n",
		    topo_node_name(parent), topo_node_instance(parent),
		    name, i, topo_strerror(topo_mod_errno(mod)));
		topo_node_unbind(dtn);
		return (NULL);
	}

	return (dtn);
}

static int
disk_declare(topo_mod_t *mod, tnode_t *parent, disk_info_t *dnode,
	const char *lpath, const char *en_id, const char *slot_id)
{
	tnode_t		*dtn;

	/* create the disk topo node: one disk per 'bay' */
	dtn = disk_tnode_create(mod, parent, dnode, DISK, 0, lpath,
		en_id, slot_id);
	if (dtn == NULL) {
		topo_mod_dprintf(mod, "disk_declare: "
		    "disk_tnode_create error %s\n",
		    topo_strerror(topo_mod_errno(mod)));
		return (-1);
	}
	/* register disk_methods against the disk topo node */
	if (topo_method_register(mod, dtn, disk_methods) != 0) {
		topo_mod_dprintf(mod, "disk_declare: "
		    "topo_method_register error %s\n",
		    topo_strerror(topo_mod_errno(mod)));
		topo_node_unbind(dtn);
		return (-1);
	}
	return (0);
}

int
disk_declare_addr(topo_mod_t *mod, tnode_t *parent, disk_info_t *dnode)
{
	char enc[32];
	char slot[32];

	(void) snprintf(enc, sizeof (enc), "%d", dnode->dk_enclosure);
	(void) snprintf(slot, sizeof (slot), "%d", dnode->dk_slot);

	return (disk_declare(mod, parent, dnode, dnode->dk_scsid, enc, slot));
}

static int
disk_create_disknode(disk_enum_data_t *data, tnode_t *pnode, disk_info_t *dnode)
{
	topo_mod_t *mod = data->ded_mod;
	int err = 0;

	/*
	 * Create the disk range.
	 */
	if (topo_node_range_create(mod, pnode, DISK, 0, 0) != 0) {
		topo_mod_dprintf(mod,
			"topo_node_create_range() failed: %s",
			topo_mod_errmsg(mod));
		return (-1);
	}

	if (disk_declare_addr(mod, pnode, dnode) != 0 &&
		topo_mod_errno(mod) != EMOD_NODE_BOUND) {
		err = -1;
	}
	return (err);
}


static int
disk_node_create(disk_enum_data_t *data, tnode_t *pnode)
{
	topo_mod_t *mod = data->ded_mod;
	disk_info_t *dnode;
	tnode_t *tn;
	nvlist_t *auth = NULL, *fmri = NULL;
	uint64_t instance;
	int err, ret;
	char *rpath = NULL;

	if ((ret = disk_get_info(&data->ded_disk)) != 0) {
		syslog(LOG_ERR, "get disk info failed\n");
		return (-1);
	}
	
	if (topo_node_range_create(mod, pnode,
		"bay", 0, 1024) != 0) {
		topo_mod_dprintf(mod,
			"topo_node_create_range() failed: %s",
			topo_mod_errmsg(mod));
		return (-1);
	}

	instance = 0;
	for (dnode = data->ded_disk.next; dnode != NULL; dnode = dnode->next) {
		topo_mod_dprintf(mod, "adding disk %llu, lpath: %s",
			instance, dnode->dk_scsid);

		/*
		 * Create the node.  The interesting information is all copied from the
		 * parent enclosure node, so there is not much to do.
		 */
		if ((auth = topo_mod_auth(mod, pnode)) == NULL)
			goto error;
		if ((fmri = topo_mod_hcfmri(mod, NULL, FM_HC_SCHEME_VERSION,
			"bay", (topo_instance_t)instance, NULL, auth, 
			"xxx", "0102",
			dnode->dk_serial)) == NULL) {
			topo_mod_dprintf(mod, "topo_mod_hcfmri() failed: %s",
				topo_mod_errmsg(mod));
			goto error;
		}

		if ((tn = topo_node_bind(mod, pnode, "bay",
			instance, fmri)) == NULL) {
			topo_mod_dprintf(mod, "topo_node_bind() failed: %s",
				topo_mod_errmsg(mod));
			goto error;
		}
		if (topo_node_label_set(tn, "bay", &err) != 0)
			goto error;
		if (disk_set_standard_props(mod, tn, NULL, instance, dnode->dk_scsid) != 0)
			goto error;
		
		if (disk_create_disknode(data, tn, dnode) != 0)
			goto error;

		if (topo_method_register(mod, tn, bay_methods) != 0) {
			topo_mod_dprintf(mod,
				"topo_method_register() failed: %s",
				topo_mod_errmsg(mod));
			goto error;
		}
		if (disk_set_specific_props(mod, tn) != 0) {
			topo_mod_dprintf(mod,
				"disk_set_specific_props() failed: %s",
				topo_mod_errmsg(mod));
			goto error;
		}
		nvlist_free(auth);
		nvlist_free(fmri);
		instance++;
	}
	topo_mod_strfree(mod, rpath);
	return (0);

error:
	topo_mod_strfree(mod, rpath);
	nvlist_free(auth);
	nvlist_free(fmri);
	return (-1);
}

static int 
disk_enum(topo_mod_t *mod, tnode_t *rnode, const char *name,
		topo_instance_t min, topo_instance_t max, void *arg, void *unused)
{
	disk_enum_data_t *data;

	/*
	 * Check to make sure we're being invoked sensibly, and that we're not
	 * being invoked as part of a post-processing step.
	 */
	if (strcmp(name, SES_DISK) != 0) {
		return (0);
	}

	if ((data = topo_mod_getspecific(mod)) == NULL) {
		if ((data = topo_mod_zalloc(mod, sizeof (disk_enum_data_t))) ==
			NULL)
			return (-1);

		data->ded_mod = mod;
		topo_mod_setspecific(mod, data);
	}

	/*
	 * This is a request to enumerate all disk underneath
	 *  the root chassis
	 */syslog(LOG_ERR, "disk topo upate\n");
	if (disk_node_create(data, rnode) != 0)
		goto error;

	disk_data_free(data);
	topo_mod_setspecific(mod, NULL);
	return (0);

error:
	disk_data_free(data);
	topo_mod_setspecific(mod, NULL);
	return (-1);
}


static const topo_modops_t disk_ops =
	{disk_enum, NULL};

static const topo_modinfo_t disk_info =
	{SES_DISK, FM_FMRI_SCHEME_HC, TOPO_VERSION, &disk_ops};

int
_topo_init(topo_mod_t *mod, topo_version_t version)
{
	topo_mod_dprintf(mod, "initializing disk enumerator\n");
	
	return (topo_mod_register(mod, &disk_info, TOPO_VERSION));
}

void
_topo_fini(topo_mod_t *mod)
{
	topo_mod_unregister(mod);
}
