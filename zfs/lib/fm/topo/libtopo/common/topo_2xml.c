/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#include <syslog.h>
#include <stdio.h>
#include <strings.h>
#include <time.h>
#include <sys/types.h>
#include <sys/fm/protocol.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <unistd.h>

#include <topo_parse.h>
#include <topo_prop.h>
#include <topo_tree.h>
#include <topo_fruhash.h>

#define	INT32BUFSZ	sizeof (UINT32_MAX) + 1
/* 2 bytes for "0x" + 16 bytes for the hex value + 1 for sign + null */
#define	INT64BUFSZ	20
#define	XML_VERSION	"1.0"
#define TIMEBUFLEN 26
#define TIMEBUFVALlen 24

#define	SELFTESTFAIL	0x01
#define	OVERTEMPFAIL	0x02
#define	PREDICTIVEFAIL	0x04
#define SLOWDISK		0x08

const char *ses_element_status_string[] = {
	"UNSUPPORTED", /* SES_ESC_UNSUPPORTED = 0 */
	"OK", /* SES_ESC_OK = 1 */
	"CRITICAL", /* SES_ESC_CRITICAL = 2 */
	"NONCRITICAL", /* SES_ESC_NONCRITICAL = 3 */
	"UNRECOVERABLE", /* SES_ESC_UNRECOVERABLE = 4 */
	"NOT_INSTALLED", /* SES_ESC_NOT_INSTALLED = 5 */
	"UNKNOWN", /* SES_ESC_UNKNOWN = 6 */
	"UNAVAILABLE", /* SES_ESC_UNAVAIL = 7 */
	"NO_ACCESS", /* SES_ESC_NO_ACCESS = 8 */
	"ONLINE",
	"OFFLINE",
	"UP",
	"DOWN",
	"ERROR"
};

typedef struct ds_info {
	xmlChar *devpath;
	xmlChar *routepath;
	xmlChar *linkpath;
	xmlChar * ds_self;
	xmlChar * ds_overtem;
	xmlChar * ds_predictive;
	struct ds_info *ds_next;
} ds_info_t;
static ds_info_t *g_disk_status = NULL;


static int txml_print_range(topo_hdl_t *, FILE *, tnode_t *, int);
static int ctxml_print_range(topo_hdl_t *, FILE *, tnode_t *, int);
 
void
ctxml_dsinfo_free(ds_info_t *dip)
{ 
	ds_info_t *dsinfo = NULL;
	while(dip)
	{
		/*printf("%s,%s %s %s\n",(xmlChar *)dip->devpath,(xmlChar *)dip->ds_self,
			(xmlChar *)dip->ds_predictive, (xmlChar *)dip->ds_overtem);*/
		dsinfo = dip->ds_next;
		if(dip->devpath != NULL)
			xmlFree(dip->devpath);
		if(dip->routepath != NULL)
			xmlFree(dip->routepath);
		if(dip->linkpath != NULL)
			xmlFree(dip->linkpath);
		if(dip->ds_self != NULL)
			xmlFree(dip->ds_self);
		if(dip->ds_overtem != NULL)
			xmlFree(dip->ds_overtem);
		if(dip->ds_predictive != NULL)
			xmlFree(dip->ds_predictive);
		free(dip);
		dip = dsinfo;
	}
}


void
ctxml_node_status(xmlNodePtr rn,ds_info_t *dip)
{
	xmlNodePtr cn;

	for (cn = rn->xmlChildrenNode; cn != NULL; cn = cn->next)
	{
		if (xmlStrcmp(cn->name, (xmlChar *)"self-test-failure") == 0)
			dip->ds_self = xmlNodeGetContent(cn);
		else if(xmlStrcmp(cn->name, (xmlChar *)"over-temperature") == 0)
			dip->ds_overtem = xmlNodeGetContent(cn);
		else if(xmlStrcmp(cn->name, (xmlChar *)"predictive-failure") == 0)
			dip->ds_predictive = xmlNodeGetContent(cn);
	}
}

void
ctxml_dsfile_parse(int fd, const char *filenm, ds_info_t **dip)
{
	xmlNodePtr rn,cn,ccn;
	xmlDocPtr document;  
	int readflags = 0; 
	ds_info_t *dsinfo =NULL;

	if ((document = xmlReadFd(fd, filenm, NULL, readflags)) == NULL) {
		(void) fprintf(stderr, "fmtopo_file_parse: couldn't parse document.\n");
		return;
	}

	if ((rn = xmlDocGetRootElement(document)) == NULL) {
		(void) fprintf(stderr, "document is empty.\n");
		xmlFreeDoc(document);
		return;
	}

	for (cn = rn->xmlChildrenNode; cn != NULL; cn = cn->next)
	{
		if (xmlStrcmp(cn->name, (xmlChar *)"disk") == 0)
		{
			dsinfo = (ds_info_t*)malloc(sizeof(ds_info_t));
			if(dsinfo ==NULL)
			{
				ctxml_dsinfo_free(*dip);
				xmlFreeDoc(document);
				return;
			}
			memset(dsinfo, 0, sizeof(ds_info_t));
			for(ccn = cn->xmlChildrenNode; ccn != NULL; ccn = ccn->next)
			{
				if (xmlStrcmp(ccn->name, (xmlChar *)"devpath") == 0)
					dsinfo->devpath = xmlNodeGetContent(ccn);
				else if(xmlStrcmp(ccn->name, (xmlChar *)"status") == 0)
					ctxml_node_status(ccn, dsinfo);
			}
			if(*dip == NULL)
				*dip = dsinfo;
			else
			{
				dsinfo->ds_next = (*dip)->ds_next;
				(*dip)->ds_next = dsinfo;
				dsinfo = NULL;
			}
		}
	}
	xmlFreeDoc(document);
	return;
}

void
ctxml_disk_status_get(const char *path)
{
	int fd;

	if ((fd = open(path, O_RDONLY)) < 0) {
		(void) fprintf(stderr, "%s: open failed.", path);
		return;
	}
	ctxml_dsfile_parse(fd, path, &g_disk_status);
	(void) close(fd);
}

void 
ctxml_ds_print(void)
{
	ds_info_t *ds=g_disk_status;
	while(ds != NULL)
	{
		printf("%s,%s %s %s\n",(xmlChar *)ds->devpath,(xmlChar *)ds->ds_self,
			(xmlChar *)ds->ds_predictive, (xmlChar *)ds->ds_overtem);
		ds = ds->ds_next;
	}

}


void
print_header(FILE *fp)
{
	char buf[32];
	time_t tod = time(NULL);
	struct utsname uts;

	(void) fprintf(fp, "<?xml version=\"%s\"?>\n", XML_VERSION);
	/*(void) fprintf(fp, "<!DOCTYPE topology SYSTEM \"%s\">\n",
	    TOPO_DTD_PATH);*/

	(void) uname(&uts);
	(void) strftime(buf, sizeof (buf), "%b %d %T", localtime(&tod));
	(void) fprintf(fp, "<!--\n");
	(void) fprintf(fp, " This topology map file was generated on "
	    "%-15s for %s\n", buf, uts.nodename);
	(void) fprintf(fp, "<-->\n\n");
}

void
begin_element(FILE *fp, const char *ename, ...)
{
	char *name, *value;
	va_list ap;

	(void) fprintf(fp, "<%s ", ename);
	va_start(ap, ename);
	name = va_arg(ap, char *);
	while (name != NULL) {
		value = va_arg(ap, char *);
		(void) fprintf(fp, "%s='%s' ", name, value);
		name = va_arg(ap, char *);
	}
	(void) fprintf(fp, ">\n");
}

void
begin_end_element(FILE *fp, const char *ename, ...)
{
	char *name, *value;
	va_list ap;

	(void) fprintf(fp, "<%s ", ename);
	va_start(ap, ename);
	name = va_arg(ap, char *);
	while (name != NULL) {
		value = va_arg(ap, char *);
		(void) fprintf(fp, "%s='%s' ", name, value);
		name = va_arg(ap, char *);
	}
	(void) fprintf(fp, "/>\n");
}

void
end_element(FILE *fp, const char *ename)
{
	(void) fprintf(fp, "</%s>\n", ename);
}

static void
txml_print_prop(topo_hdl_t *thp, FILE *fp, tnode_t *node, const char *pgname,
    topo_propval_t *pv)
{
	int err;
	char *fmri = NULL;
	char vbuf[INT64BUFSZ], tbuf[32], *pval = NULL, *aval = NULL;

	switch (pv->tp_type) {
		case TOPO_TYPE_INT32: {
			int32_t val;
			if (topo_prop_get_int32(node, pgname, pv->tp_name, &val,
			    &err) == 0) {
				(void) snprintf(vbuf, INT64BUFSZ, "%d", val);
				(void) snprintf(tbuf, 10, "%s", Int32);
				pval = vbuf;
			} else
				return;
			break;
		}
		case TOPO_TYPE_UINT32: {
			uint32_t val;
			if (topo_prop_get_uint32(node, pgname, pv->tp_name,
			    &val, &err) == 0) {
				(void) snprintf(vbuf, INT64BUFSZ, "0x%x", val);
				(void) snprintf(tbuf, 10, "%s", UInt32);
				pval = vbuf;
			} else
				return;
			break;
		}
		case TOPO_TYPE_INT64: {
			int64_t val;
			if (topo_prop_get_int64(node, pgname, pv->tp_name, &val,
			    &err) == 0) {
				(void) snprintf(vbuf, INT64BUFSZ, "0x%llx",
				    (longlong_t)val);
				(void) snprintf(tbuf, 10, "%s", Int64);
				pval = vbuf;
			} else
				return;
			break;
		}
		case TOPO_TYPE_UINT64: {
			uint64_t val;
			if (topo_prop_get_uint64(node, pgname, pv->tp_name,
			    &val, &err) == 0) {
				(void) snprintf(vbuf, INT64BUFSZ, "0x%llx",
				    (u_longlong_t)val);
				(void) snprintf(tbuf, 10, "%s", UInt64);
				pval = vbuf;
			} else
				return;
			break;
		}
		case TOPO_TYPE_STRING: {
			if (topo_prop_get_string(node, pgname, pv->tp_name,
			    &pval, &err) != 0)
				return;
			(void) snprintf(tbuf, 10, "%s", "string");
			break;
		}
		case TOPO_TYPE_FMRI: {
			nvlist_t *val;

			if (topo_prop_get_fmri(node, pgname, pv->tp_name, &val,
			    &err) == 0) {
				if (topo_fmri_nvl2str(thp, val, &fmri, &err)
				    == 0) {
					nvlist_free(val);
					pval = fmri;
				} else {
					nvlist_free(val);
					return;
				}
			} else
				return;
			(void) snprintf(tbuf, 10, "%s", FMRI);
			break;
		}
		case TOPO_TYPE_UINT32_ARRAY: {
			uint32_t *val;
			uint_t nelem, i;
			if (topo_prop_get_uint32_array(node, pgname,
			    pv->tp_name, &val, &nelem, &err) != 0)
				return;

			if (nelem > 0) {
				if ((aval = calloc((nelem * 9 - 1),
				    sizeof (uchar_t))) == NULL) {

					topo_hdl_free(thp, val,
					    nelem * sizeof (uint32_t));
					return;
				}

				(void) sprintf(aval, "0x%x", val[0]);
				for (i = 1; i < nelem; i++) {
					(void) sprintf(vbuf, " 0x%x", val[i]);
					(void) strcat(aval, vbuf);
				}
				topo_hdl_free(thp, val,
				    nelem * sizeof (uint32_t));
				(void) snprintf(tbuf, 10, "%s", UInt32_Arr);
				pval = aval;
			}
			break;
		}
		default:
			return;
	}

	begin_end_element(fp, Propval, Name, pv->tp_name, Type, tbuf,
	    Value, pval, NULL);

	if (pval != NULL && pv->tp_type == TOPO_TYPE_STRING)
		topo_hdl_strfree(thp, pval);

	if (fmri != NULL)
		topo_hdl_strfree(thp, fmri);

	if (aval != NULL)
		free(aval);
}

static void
txml_print_pgroup(topo_hdl_t *thp, FILE *fp, tnode_t *node, topo_pgroup_t *pg)
{
	topo_ipgroup_info_t *pip = pg->tpg_info;
	topo_proplist_t *plp;
	const char *namestab, *datastab;
	char version[INT32BUFSZ];

	namestab = topo_stability2name(pip->tpi_namestab);
	datastab = topo_stability2name(pip->tpi_datastab);
	(void) snprintf(version, INT32BUFSZ, "%d", pip->tpi_version);
	begin_element(fp, Propgrp, Name, pip->tpi_name, Namestab,
	    namestab, Datastab, datastab, Version, version, NULL);
	for (plp = topo_list_next(&pg->tpg_pvals); plp != NULL;
	    plp = topo_list_next(plp)) {
		txml_print_prop(thp, fp, node, pip->tpi_name, plp->tp_pval);
	}
	end_element(fp, Propgrp);
}

static void
ctxml_print_pgroup(topo_hdl_t *thp, FILE *fp, tnode_t *node, topo_pgroup_t *pg)
{
	topo_ipgroup_info_t *pip = pg->tpg_info;
	topo_proplist_t *plp;

	for (plp = topo_list_next(&pg->tpg_pvals); plp != NULL;
	    plp = topo_list_next(plp)) {
		txml_print_prop(thp, fp, node, pip->tpi_name, plp->tp_pval);
	}
	
}


static void
txml_print_dependents(topo_hdl_t *thp, FILE *fp, tnode_t *node)
{
	if (topo_list_next(&node->tn_children) == NULL)
		return;

	if (txml_print_range(thp, fp, node, 1) == 1)
		end_element(fp, Dependents);
}

static void
ctxml_print_dependents(topo_hdl_t *thp, FILE *fp, tnode_t *node, int dependent)
{
	if (topo_list_next(&node->tn_children) == NULL)
		return;

	dependent++;
	(void) ctxml_print_range(thp, fp, node, dependent);
}

static void
ctxml_get_prop(topo_hdl_t *thp, tnode_t *node, const char *pgname,
    topo_propval_t *pv, int32_t *value)
{
	int err;

	*value = SXML_ERROR;
	switch (pv->tp_type) {
		case TOPO_TYPE_INT32: {
			int32_t val;
			if (topo_prop_get_int32(node, pgname, pv->tp_name, &val,
			    &err) == 0) {
				*value = val;
			} else
				return;
			break;
		}
		case TOPO_TYPE_UINT32: {
			uint32_t val;
			if (topo_prop_get_uint32(node, pgname, pv->tp_name,
			    &val, &err) == 0) {
				*value = (uint32_t)val;
			} else
				return;
			break;
		}
		case TOPO_TYPE_INT64: {
			int64_t val;
			if (topo_prop_get_int64(node, pgname, pv->tp_name, &val,
			    &err) == 0) {
				*value = (int64_t)val;
			} else
				return;
			break;
		}
		case TOPO_TYPE_UINT64: {
			uint64_t val;
			if (topo_prop_get_uint64(node, pgname, pv->tp_name,
			    &val, &err) == 0) {
				*value = (uint64_t)val;
			} else
				return;
			break;
		}

		default:
			return;
	}
}

static int
ctxml_get_node_prop(topo_hdl_t *thp, tnode_t *node, const char *prop, int32_t *val)
{
	topo_pgroup_t *pg;
	topo_ipgroup_info_t *pip;
	topo_proplist_t *plp;

	for (pg = topo_list_next(&node->tn_pgroups); pg != NULL;
		pg = topo_list_next(pg)) {
		pip = pg->tpg_info;
		for (plp = topo_list_next(&pg->tpg_pvals); plp != NULL;
			plp = topo_list_next(plp)) {
			if(strcmp(prop, plp->tp_pval->tp_name) == 0)
			{
				ctxml_get_prop(thp, node, pip->tpi_name, plp->tp_pval, val);
				return 1;
			}
		}
	}
	return 0;

}

static void
ctxml_print_node(topo_hdl_t *thp, FILE *fp, tnode_t *node, int dependent)
{
	topo_pgroup_t *pg;
	char inst[INT32BUFSZ];
	char buf[TIMEBUFLEN];
	int32_t status = SXML_ERROR, present = 0;
	int ret = 0;
	int err = 0;
	char *devpath = NULL;
	ds_info_t *ds;
	topo_fru_t *fru = NULL;
	nvlist_t *val;
	char *fmri = NULL;

	(void) snprintf(inst, INT32BUFSZ, "%d", node->tn_instance);

	if(ctxml_get_node_prop(thp, node, "present", &present))
		ret = ctxml_get_node_prop(thp, node, "status", &status);

	if(ret) {
		memset(buf, 0, TIMEBUFLEN);
		if (topo_prop_get_fmri(node, "protocol", "resource", &val,
		    &err) == 0) {
			if (topo_fmri_nvl2str(thp, val, &fmri, &err)
			    == 0) {
	    		if ((fru = topo_fru_hash_lookup(fmri)) != NULL &&
					fru->tf_time != 0){
					(void) snprintf(buf, TIMEBUFLEN, "%s", ctime(&fru->tf_time));
					buf[TIMEBUFVALlen] = '\0';
				} else {
					(void) snprintf(buf, TIMEBUFLEN, "%s", "none");
				}
				topo_hdl_strfree(thp, fmri);
			} else {
				(void) snprintf(buf, TIMEBUFLEN, "%s", "none");
			}
			nvlist_free(val);
		} else {
			(void) snprintf(buf, TIMEBUFLEN, "%s", "none");
		}
		if(status > SXML_ERROR)
			status = SXML_ERROR;
		begin_element(fp, Node, Instance, inst,
			"present", present==0 ? "no" : "yes",
			"status", ses_element_status_string[status],
			"time", buf, NULL);
	}else {
		begin_element(fp, Node, Instance, inst, NULL);
	}

	if(strcmp(topo_node_name(node), "disk") == 0)
	{
		topo_prop_get_string(node, "io", "devfs-path", &devpath, &err);
		for (pg = topo_list_next(&node->tn_pgroups); pg != NULL;
		    pg = topo_list_next(pg)) {
			ctxml_print_pgroup(thp, fp, node, pg);
		}
		for(ds = g_disk_status; ds != NULL; ds = ds->ds_next) {
			if(strcmp(devpath, (char *)ds->devpath) == 0) {
				begin_end_element(fp, Propval, Name, "self-test-failure",
					Type, "string",Value, (char *)ds->ds_self, NULL);
 				begin_end_element(fp, Propval, Name, "over-temperature",
					Type, "string",Value, (char *)ds->ds_overtem, NULL);
				begin_end_element(fp, Propval, Name, "predictive-failure",
					Type, "string",Value, (char *)ds->ds_predictive, NULL);
				break;
			}
		}
		topo_hdl_strfree(thp, devpath);
	}

	ctxml_print_dependents(thp, fp, node, dependent);
	end_element(fp, Node);

}


static int
ctxml_print_range(topo_hdl_t *thp, FILE *fp, tnode_t *node, int dependent)
{
	int i, create = 0, ret = 0;
	topo_nodehash_t *nhp;
	char count[INT32BUFSZ];
	char buf[20];
	char *product=NULL;
	int err = 0;
	char product_buf[32];

	for (nhp = topo_list_next(&node->tn_children); nhp != NULL;
	    nhp = topo_list_next(nhp)) {

		/*
		 * Some enumerators create empty ranges: make sure there
		 * are real nodes before creating this range
		 */
		create = 0;
		for (i = 0; i < nhp->th_arrlen; ++i) {
			if (nhp->th_nodearr[i] != NULL)
				++create;
		}
		if (!create)
			continue;

		if(strcmp("ident", nhp->th_name) == 0 ||
			strcmp("fail", nhp->th_name) == 0 ||
			strcmp("fault", nhp->th_name) == 0 ||
			strcmp("speed", nhp->th_name) == 0 ||
			strcmp("status", nhp->th_name) == 0 ||
			strcmp("ok2rm", nhp->th_name) == 0 ||
			strstr(nhp->th_name, "Temperature") != NULL ||
			strstr(nhp->th_name, "temperature") != NULL ||
			strstr(nhp->th_name, "voltage") != NULL ||
			strstr(nhp->th_name, "Voltage") != NULL ||
			strstr(nhp->th_name, "current") != NULL ||
			strstr(nhp->th_name, "Current") != NULL ||
			strcmp("5V", nhp->th_name) == 0 ||
			strcmp("12V", nhp->th_name) == 0 ||
			strstr(nhp->th_name, "Sensor") != NULL ||
			strcmp("controller", nhp->th_name) == 0)
			continue;

		(void) snprintf(count, INT32BUFSZ, "%d", create);
		(void) snprintf(buf, 20, "range%d", dependent);

		/* print ses-enclosure children's product-id */
		if (strcmp(topo_node_name(node), "ses-enclosure") == 0){

			if (topo_prop_get_string(node, "authority", "product-id", &product,
				&err) == 0) {
				(void) snprintf(product_buf, 32, "%s", product);
				topo_hdl_strfree(thp, product);
			} else {
				(void) snprintf(product_buf, 32, "%s", "none");
			}
		
			begin_element(fp, buf, Name, nhp->th_name, "count", count, "product",product_buf, NULL);
		}else{
			begin_element(fp, buf, Name, nhp->th_name, "count", count, NULL);
		}
		
		for (i = 0; i < nhp->th_arrlen; ++i) {
			if (nhp->th_nodearr[i] != NULL)
				ctxml_print_node(thp, fp, nhp->th_nodearr[i], dependent);
		}
		end_element(fp, buf);
	}

	return (ret);
}

static void
ctxml_print_topology(topo_hdl_t *thp, FILE *fp, char *scheme, tnode_t *node)
{
	char *name;

	if (thp->th_product != NULL)
		name = thp->th_product;
	else
		name = thp->th_platform;

	begin_element(fp, Topology, Name, name, Scheme, scheme,
	    NULL);
	(void) ctxml_print_range(thp, fp, node, 0);
	end_element(fp, Topology);

}

static void
txml_print_node(topo_hdl_t *thp, FILE *fp, tnode_t *node)
{
	char inst[INT32BUFSZ];
	topo_pgroup_t *pg;

	(void) snprintf(inst, INT32BUFSZ, "%d", node->tn_instance);
	begin_element(fp, Node, Instance, inst, Static, True, NULL);
	for (pg = topo_list_next(&node->tn_pgroups); pg != NULL;
	    pg = topo_list_next(pg)) {
		txml_print_pgroup(thp, fp, node, pg);
	}
	txml_print_dependents(thp, fp, node);
	end_element(fp, Node);

}

static int
txml_print_range(topo_hdl_t *thp, FILE *fp, tnode_t *node, int dependent)
{
	int i, create = 0, ret = 0;
	topo_nodehash_t *nhp;
	char min[INT32BUFSZ], max[INT32BUFSZ];

	for (nhp = topo_list_next(&node->tn_children); nhp != NULL;
	    nhp = topo_list_next(nhp)) {
		(void) snprintf(min, INT32BUFSZ, "%d", nhp->th_range.tr_min);
		(void) snprintf(max, INT32BUFSZ, "%d", nhp->th_range.tr_max);

		/*
		 * Some enumerators create empty ranges: make sure there
		 * are real nodes before creating this range
		 */
		for (i = 0; i < nhp->th_arrlen; ++i) {
			if (nhp->th_nodearr[i] != NULL)
				++create;
		}
		if (!create)
			continue;

		if (dependent) {
			begin_element(fp, Dependents, Grouping, Children, NULL);
			dependent = 0;
			ret = 1;
		}
		begin_element(fp, Range, Name, nhp->th_name, Min, min, Max,
		    max, NULL);
		for (i = 0; i < nhp->th_arrlen; ++i) {
			if (nhp->th_nodearr[i] != NULL)
				txml_print_node(thp, fp, nhp->th_nodearr[i]);
		}
		end_element(fp, Range);
	}

	return (ret);
}

#if 0
static void
txml_print_topology(topo_hdl_t *thp, FILE *fp, char *scheme, tnode_t *node)
{
	char *name;

	if (thp->th_product != NULL)
		name = thp->th_product;
	else
		name = thp->th_platform;

	begin_element(fp, Topology, Name, name, Scheme, scheme,
	    NULL);
	(void) txml_print_range(thp, fp, node, 0);
	end_element(fp, Topology);

}
#endif
int
topo_xml_print(topo_hdl_t *thp,  FILE *fp, const char *scheme, int *err)
{
	ttree_t *tp;
	FILE * filep = NULL;

	filep = fopen("/tmp/topo.xml","w");
	if(filep == NULL){
		printf("open /tmp/topo.xml error\n");
		return -1;
	}
	ctxml_disk_status_get("/tmp/fmd_disk.xml");
	print_header(filep);
	for (tp = topo_list_next(&thp->th_trees); tp != NULL;
	    tp = topo_list_next(tp)) {
		if (strcmp(scheme, tp->tt_scheme) == 0) {
			ctxml_print_topology(thp, filep, tp->tt_scheme,
			    tp->tt_root);
			ctxml_dsinfo_free(g_disk_status);
			g_disk_status = NULL;
			fclose(filep);
			return (0);
		}
	}
	
	ctxml_dsinfo_free(g_disk_status);
	g_disk_status = NULL;
	fclose(filep);
	*err = EINVAL;
	return (-1);
}

int
topo_warning_xml_print(topo_hdl_t *thp,  FILE *fp, const char *scheme, int *err)
{
	topo_fruhash_t *tfhp;
	FILE * filep = NULL;
	char *name;
	int i;
	int status;
	topo_fru_t *fru;
	char buf[TIMEBUFLEN];

	filep = fopen("/tmp/topo_warning.xml","w");
	if(filep == NULL){
		printf("open /tmp/topo_warning.xml error\n");
		return -1;
	}
	print_header(filep);

	if (thp->th_product != NULL)
		name = thp->th_product;
	else
		name = thp->th_platform;

	
	begin_element(filep, Topology, Name, name, Scheme, scheme,
	    NULL);
	
	tfhp = topo_get_fruhash();
	for (i = 0; i < TOPO_FRUHASH_BUCKETS; ++i) {
		fru = tfhp->fh_hash[i];
		while (fru != NULL) {
			if (fru->tf_time != 0 && fru->tf_ignore == 0) {
				if ((name = strstr(fru->tf_name, "chassis=")) != NULL) {
					status = SXML_CRITICAL;
				} else if ((name = strstr(fru->tf_name, "card_link")) != NULL) {
					status = fru->tf_status;
				}else if  ((name = strstr(fru->tf_name, "fanpsu")) != NULL) {
					status = fru->tf_status;
				}else if ((name = strstr(fru->tf_name, "ses-enclosure")) != NULL) {
					if (strstr(name, "disk") != 0)
						status = SXML_CRITICAL;
					else
						status = fru->tf_status;
				} else {
					goto out;
				}
				(void) snprintf(buf, TIMEBUFLEN, "%s", ctime(&fru->tf_time));
					buf[TIMEBUFVALlen] = '\0';
				begin_element(filep, Node,
					"status", ses_element_status_string[status],
					"time", buf, NULL);
				begin_end_element(filep, Propval, Name, "resource",
					Type, "string",Value, name, NULL);
				if(strstr(name, "disk") != NULL) {
					if(fru->tf_status & SELFTESTFAIL)
						begin_end_element(filep, Propval, Name, "type",
							Type, "string",Value, "self-test-failure", NULL);
					if(fru->tf_status & OVERTEMPFAIL)
						begin_end_element(filep, Propval, Name, "type",
							Type, "string",Value, "over-temperature", NULL);
					if (fru->tf_status & PREDICTIVEFAIL)
						begin_end_element(filep, Propval, Name, "type",
							Type, "string",Value, "over-temperature", NULL);
					if (fru->tf_status & SLOWDISK)
						begin_end_element(filep, Propval, Name, "type",
							Type, "string",Value, "slow-disk", NULL);
				}
				end_element(filep, Node);
			}
			fru = fru->tf_next;
		}
	}
out:
	end_element(filep, Topology);
	fclose(filep);

	return 0;
}

