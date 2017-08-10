#ifndef _VIEWLIST_H
#define _VIEWLIST_H

#ifdef __cplusplus
extern "C" {
#endif

#ifndef TEXT_DOMAIN
#define TEXT_DOMAIN "SUNW_OST_OSCMD"
#endif

#include <stdlib.h>
#include <stdio.h>

typedef struct _view_data_field
{
	char _LUName[256];
	char _SerialNum[256];
	char _hostGroup[256];
	char _targetGroup[256];
	char _hgtgname[513];
	uint16_t LUNIndex;
	uint32_t veindex;
	stmfGuid lunguid;
}viewdatafield;


typedef struct _view_info
	{
		struct _view_data_field view_data;
		list_node_t listlink;
	}view;     /*保存LUN所属每个主机组和目标组的信息 */

typedef struct _lun_relate_datafield
{
	char lunalias[256];
	stmfGuid lunguid;
}lunrelatefield;

typedef struct _lun_relate
{
	struct _lun_relate_datafield lundatafield;
	list_node_t lunrelatelink;
}lunrelated;

#define	OPERANDSTRING_INITIATOR	    "initiator-name"
#define	OPERANDSTRING_LU	    "pool-name/lu-name"
#define	OPERANDSTRING_DEL_LU	    "pool-name/lu-name or guid"
#define	OPERANDSTRING_GROUP_MEMBER  "group-name group-member"
#define	OPERANDSTRING_GROUP_NAME    "group-name"
#define	OPERANDSTRING_TARGET	    "target-name"
#define	OPERANDSTRING_VIEW_ENTRY    "ve-number"
#define OPERANDSTRING_LUNID  "lun-number"
#define OPERANDSTRING_HOSTTARGETGROUP "hostname,groupname"
#define OPERANDSTRING_VIEWINFO 		"hostname,targetname [lun-number]"
#define OPERANDSTRING_ADD_VIEW_INFO  "hostname,targetname [lun-number] Lu-Name"
#define VERSION_STRING_MAX_LEN   10


#ifdef __cplusplus
}
#endif

#endif

