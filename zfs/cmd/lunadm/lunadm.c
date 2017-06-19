#include<stdlib.h>
#include<stdio.h>
#include<libstmf.h>
#include<strings.h>
#include<string.h>
#include<errno.h>
#include<ctype.h>
#include<libintl.h>
#include<stddef.h>
#include<locale.h>
#include<syslog.h>
#include <wctype.h>
#include<wchar.h>
#include<cmdparse.h>
#include<sys/list.h>
#include<sys/list_impl.h>
#include"lunadm.h"

static int addhostgroupmember(int, char **, cmdOptions_t *, void *);
static int addtargetgroupmember(int, char **, cmdOptions_t *, void *);
static int addview(int, char **, cmdOptions_t *, void *);
static int createhostgroupfunc(int, char **, cmdOptions_t *, void *);
static int createtargetgroupfunc(int, char **, cmdOptions_t *, void *);
static int listlunmapFunc(int, char **, cmdOptions_t *, void *);
static int printlunformat(int, char **, cmdOptions_t *, void *);
static int listtargetgroup(int, char **, cmdOptions_t *, void *);
static int listhostgroup(int, char **, cmdOptions_t *, void *);
static int listlufunc(int, char **, cmdOptions_t *, void *);
static int deletelufunc(int, char **, cmdOptions_t *, void *);
static int importlufunc(int, char **, cmdOptions_t *, void *);
static int listview(int, char **, cmdOptions_t *, void *);
static int removegroupview(int, char **, cmdOptions_t *, void *);
/*static int addgroupview(int, char **, cmdOptions_t *, void *);*/
static void printLuProps(stmfLogicalUnitProperties *luProps);
static int printExtLuProps(stmfGuid *guid);
static void printGuid(stmfGuid *guid, FILE *printWhere);
static int listinitiator(int, char **, cmdOptions_t *, void *);
static int listtarget(int, char **, cmdOptions_t *, void *);
static int deletehostgroupfunc(int, char **, cmdOptions_t *, void *);
static int deletetargetgroupfunc(int, char **, cmdOptions_t *, void *);
static int removehostgroupmemberfunc(int, char **, cmdOptions_t *, void *);
static int removetargetgroupmemberfunc(int, char **, cmdOptions_t *, void *);
static int onlinetarget(int, char **, cmdOptions_t *, void *);
static int offlinetarget(int, char **, cmdOptions_t *, void *);
static int onlineOfflineTarget(char *, int);
/*static int removeview(int, char **, cmdOptions_t *, void *);*/
static char *getExecBasename(char *);
void extractlunalias(char *,char *);
static int getgroupmember(stmfGroupName *, stmfGroupProperties **, int, int);
static int checkScsiNameString(wchar_t *, stmfDevid *);
static int checkIscsiName(wchar_t *);
static int checkHexUpper(char *);
static void printGroupProps(stmfGroupProperties *groupProps);
static int parseDevid(char *input, stmfDevid *devid);
static void printTargetProps(stmfTargetProperties *);
static void printSessionProps(stmfSessionList *);
static int getlunviewprop(list_t *);
static int getlu_name(char *, stmfGuid *);
static int getlu_prop(list_t *);


/*
 *  MAJOR - This should only change when there is an incompatible change made
 *  to the interfaces or the output.
 *
 *  MINOR - This should change whenever there is a new command or new feature
 *  with no incompatible change.
 */
 #define VERSION_STRING_MAJOR	"1"
 #define VERSION_STRING_MINOR	"1"
 #define ONLINE_TARGET			2
 #define OFFLINE_TARGET			3
 #define MAX_LU_NBR				16383
 #define MAX_DEVID_INPUT		256
 #define GUID_INPUT				32
 #define PROPS_FORMAT			"    %-18s: "
 #define LVL3_FORMAT		    "        %s"
 #define LVL4_FORMAT		    "            %s"
 #define LUNMAPLIST_FORMAT      "      %-5d       %-25s %s\n"
 #define PRINT_FORMAT           "lunid:%-5d       volume:%-25s SN:%s\n"
 #define VIEW_FORMAT		    "    %-13s: "
 #define LUNAMELENGTH			32
 #define LISTLUNMAP             0
 #define PRINTLUNFORMAT         1

#define	UNUSED_PARAMETER(x)	x = x


 /* SCSI Name String length definitions */
#define	SNS_EUI_16		    16
#define	SNS_WWN_16		    16
#define	SNS_IQN_223		    223


#define	ADD_VIEW_HELP "\n"\
"Description: Add a view entry to a logical unit. \n" \
"A view entry is comprised of three elements; the \n" \
"logical unit number, the target group name and the\n" \
"host group name. These three elements combine together\n" \
"to form a view for a given COMSTAR logical unit.\n" \
"This view is realized by a client, a SCSI initiator,\n" \
"via a REPORT LUNS command. \n"

 
/* tables set up based on cmdparse instructions */

/* add new options here */
optionTbl_t longOptions[] = {
		/*{"map", no_arg, 'a', NULL},
		{"host-group", no_arg, 'h', NULL},
		{"target-group", no_arg, 'g', NULL},
		{"initiator", no_arg, 'i', NULL},
		{"target", no_arg, 't',NULL},*/
		{"hg,tg", required_arg, 'm', "host-group-name,target-group-name"},
		{"pool/lun", required_arg, 'l', "Pool-name/LUN-name"},
		{"all", no_arg, 'a', NULL},
		{"group-name", required_arg, 'g', "group-name"},
		{"lun", required_arg, 'n', "logical-unit-number"},
		{"target-group", required_arg, 't', "group-name"},
		{"host-group", required_arg, 'h', "group-name"},
		{"verbose", no_arg, 'v', NULL},
		{NULL, 0, 0, 0}
 };


/*
 * Add new subcommands here
 */
subCommandProps_t subcommands[] = {
		{"add-hg-member", addhostgroupmember, NULL, NULL, NULL,
			OPERAND_MANDATORY_MULTIPLE, OPERANDSTRING_GROUP_MEMBER, NULL},
		{"add-tg-member", addtargetgroupmember, NULL, NULL, NULL,
			OPERAND_MANDATORY_MULTIPLE, OPERANDSTRING_GROUP_MEMBER, NULL},
		{"add-view", addview, NULL, NULL, NULL,
			OPERAND_MANDATORY_MULTIPLE, OPERANDSTRING_ADD_VIEW_INFO, ADD_VIEW_HELP},
		/*{"add-group-view", addgroupview, "nm", "m", NULL,
			OPERAND_MANDATORY_SINGLE, OPERANDSTRING_LU, NULL},*/
		{"create-hg", createhostgroupfunc, NULL, NULL, NULL,
			OPERAND_MANDATORY_SINGLE, OPERANDSTRING_GROUP_NAME, NULL},
		{"create-tg", createtargetgroupfunc, NULL, NULL, NULL,
			OPERAND_MANDATORY_SINGLE, OPERANDSTRING_GROUP_NAME, NULL},
		{"delete-hg", deletehostgroupfunc, NULL, NULL, NULL,
			OPERAND_MANDATORY_SINGLE, OPERANDSTRING_GROUP_NAME, NULL},
		{"delete-tg", deletetargetgroupfunc, NULL, NULL, NULL,
			OPERAND_MANDATORY_SINGLE, OPERANDSTRING_GROUP_NAME, NULL},
		{"remove-hg-member", removehostgroupmemberfunc, NULL, NULL, NULL,
			OPERAND_MANDATORY_MULTIPLE, OPERANDSTRING_GROUP_MEMBER, NULL},
		{"remove-tg-member", removetargetgroupmemberfunc, NULL, NULL, NULL,
			OPERAND_MANDATORY_MULTIPLE, OPERANDSTRING_GROUP_MEMBER, NULL},
		/*{"remove-view", removeview, "al", "l", NULL,
			OPERAND_OPTIONAL_MULTIPLE, OPERANDSTRING_VIEW_ENTRY, NULL},*/
		{"remove-view", removegroupview, NULL, NULL, NULL,
			OPERAND_MANDATORY_MULTIPLE, OPERANDSTRING_VIEWINFO, NULL},
		{"list-hg", listhostgroup, "v", NULL, NULL, 
			OPERAND_OPTIONAL_MULTIPLE, OPERANDSTRING_GROUP_NAME, NULL},
		{"list-tg", listtargetgroup, "v", NULL, NULL,
			OPERAND_OPTIONAL_MULTIPLE, OPERANDSTRING_GROUP_NAME, NULL},
		{"online-target", onlinetarget, NULL, NULL, NULL,
			OPERAND_MANDATORY_SINGLE, OPERANDSTRING_TARGET, NULL},
		{"offline-target", offlinetarget, NULL, NULL, NULL,
			OPERAND_MANDATORY_SINGLE, OPERANDSTRING_TARGET, NULL},
		{"list-lu", listlufunc, "v", NULL, NULL, OPERAND_NONE,
			NULL, NULL},
		{"delete-lu", deletelufunc, NULL, NULL, NULL,
			OPERAND_MANDATORY_MULTIPLE, OPERANDSTRING_DEL_LU, NULL},
		{"import-lu", importlufunc, NULL, NULL, NULL,
			OPERAND_MANDATORY_SINGLE, OPERANDSTRING_LU, NULL},
		{"list-view", listview, NULL, NULL, NULL,
		OPERAND_MANDATORY_SINGLE, OPERANDSTRING_LU, NULL},
		{"list-initiator", listinitiator, NULL, NULL, NULL,
			OPERAND_NONE, NULL, NULL},
		{"list-target", listtarget, "v", NULL, NULL,
			OPERAND_OPTIONAL_MULTIPLE, OPERANDSTRING_TARGET, NULL},
		{"list-lunmap", listlunmapFunc, "v", NULL, NULL,
			OPERAND_OPTIONAL_MULTIPLE, OPERANDSTRING_HOSTTARGETGROUP, NULL},
		{"list-formatlun", printlunformat, NULL, NULL, NULL,
			OPERAND_NONE, NULL, NULL},
		{NULL, 0, NULL, NULL, NULL, 0, NULL, NULL}
};


char *cmdName;


/*   extractlunalais
 *   
 *   extract poolname/lunname from the data file
 *   return the pointer to the extracted string
 *    
 */
void extractlunalias(char *stringtoextract, char *stringtostore)
{
	/*提取池名/lun名*/
	char *fileNamep;
	int c;
	int countline;
	fileNamep = stringtoextract;
	countline = 0;
	for(c=0; c < strlen(stringtoextract);c++)   
	{
		if(*fileNamep== '/')
		{
			++countline;
		}	
		fileNamep++;
		if (countline == 4)
		{
			stringtostore = strcpy(stringtostore,fileNamep);
			break;
		}
	}
}

/*   getgroupmember
 *   
 *   list the member in the host group or target group
 *    
 */

static int getgroupmember(stmfGroupName *groupname, stmfGroupProperties **groupProp, int grouptype, int format)
{
	wchar_t memberIdent[sizeof ((*groupProp)->name[0].ident) + 1] = {0};
	int ret;
	int i;
	if (grouptype == HOST_GROUP)
	{
		ret = stmfGetHostGroupMembers (groupname, groupProp);
		if (ret != STMF_STATUS_SUCCESS)
		{
			(void) fprintf(stderr, "Get group member faild.\n");
			return (ret);
		}
	}
	else if (grouptype == TARGET_GROUP)
	{
		ret = stmfGetTargetGroupMembers (groupname, groupProp);
		if (ret != STMF_STATUS_SUCCESS)
		{
			(void) fprintf(stderr, "Get target member faild.\n");
			return (ret);
		}
	}
	else 
	{
		(void) fprintf(stderr,"Invalid group type.\n");
		return (STMF_ERROR_INVALID_ARG);
	}
	if (((*groupProp)->cnt) >= 1)
	{
		if (format == LISTLUNMAP)
		{
			(void) printf("%s Member:\n", *groupname);
		}
	}
	for (i = 0; i < (*groupProp)->cnt; i++) 
	{
		(void) mbstowcs(memberIdent, (char *)(*groupProp)->name[i].ident,
		sizeof ((*groupProp)->name[0].ident));
		if (format == LISTLUNMAP)
		{
			(void) printf("   %ls\n", memberIdent);
		}
		if (format == PRINTLUNFORMAT)
		{
			(void) printf("port:%ls\n", memberIdent);
		}
	}
	stmfFreeMemory(*groupProp);
	return (ret);
}



/*
 * printGroupProps
 *
 * Prints group members for target or host groups
 *
 */
static void
printGroupProps(stmfGroupProperties *groupProps)
{
	int i;
	wchar_t memberIdent[sizeof (groupProps->name[0].ident) + 1] = {0};


	for (i = 0; i < groupProps->cnt; i++) {
		(void) mbstowcs(memberIdent, (char *)groupProps->name[i].ident,
		    sizeof (groupProps->name[0].ident));
		(void) printf("\tMember: %ls\n", memberIdent);
	}
}




/*
 * checkIscsiName
 *
 * Purpose: Basic string checking on name
 */
static int
checkIscsiName(wchar_t *input)
{
	int i;

	for (i = 0; input[i] != 0; i++) {
		if (!iswalnum(input[i]) && input[i] != '-' &&
		    input[i] != '.' && input[i] != ':') {
			return (-1);
		}
	}

	return (0);
}



/*
 * Checks whether the entire string is in hex and converts to upper
 */
static int
checkHexUpper(char *input)
{
	int i;

	for (i = 0; i < strlen(input); i++) {
		if (isxdigit(input[i])) {
			input[i] = toupper(input[i]);
			continue;
		}
		return (-1);
	}

	return (0);
}



/*
 * checkScsiNameString
 *
 * Validates known SCSI name string formats and converts to stmfDevid
 * format
 *
 * input - input SCSI name string
 * devid - pointer to stmfDevid structure allocated by the caller
 *         on successful return, contains the devid based on input
 *
 * returns:
 *         0 on success
 *         -1 on failure
 */
static int
checkScsiNameString(wchar_t *input, stmfDevid *devid)
{
	char *mbString = NULL;
	int mbStringLen;
	int len;
	int i;

	/*
	 * Convert to multi-byte string
	 *
	 * This is used for either eui or naa formats
	 */
	mbString = calloc(1, (mbStringLen = wcstombs(mbString, input, 0)) + 1);
	if (mbString == NULL) {
		(void) fprintf(stderr, "%s: %s\n",
		    cmdName, "Insufficient memory\n");
		return (-1);
	}
	if (wcstombs(mbString, input, mbStringLen) == (size_t)-1) {
		return (-1);
	}

	/*
	 * check for iqn format
	 */
	if (strncmp(mbString, "iqn.", 4) == 0) {
		if ((len = strlen(mbString)) > (SNS_IQN_223)) {
			return (-1);
		}
		for (i = 0; i < len; i++) {
			mbString[i] = tolower(mbString[i]);
		}
		if (checkIscsiName(input + 4) != 0) {
			return (-1);
		}
	} else if (strncmp(mbString, "wwn.", 4) == 0) {
		if ((len = strlen(mbString + 4)) != SNS_WWN_16) {
			return (-1);
		} else if (checkHexUpper(mbString + 4) != 0) {
			return (-1);
		}
	} else if (strncmp(mbString, "eui.", 4) == 0) {
		if ((len = strlen(mbString + 4)) != SNS_EUI_16) {
			return (-1);
		} else if (checkHexUpper(mbString + 4) != 0) {
			return (-1);
		}
	} else {
		return (-1);
	}

	/*
	 * We have a validated name string.
	 * Go ahead and set the length and copy it.
	 */
	devid->identLength = strlen(mbString);
	bzero(devid->ident, STMF_IDENT_LENGTH);
	bcopy(mbString, devid->ident, devid->identLength);

	return (0);
}




/*
 * parseDevid
 *
 * Converts char * input to a stmfDevid
 *
 * input - this should be in the following format with either a
 * wwn. iqn. or eui. representation.
 * A name string of the format:
 *	wwn.<WWN> (FC/SAS address)
 *	iqn.<iSCSI name> (iSCSI iqn)
 *	eui.<WWN> (iSCSI eui name)
 *
 * devid - pointer to stmfDevid structure allocated by the caller.
 *
 * Returns:
 *  0 on success
 *  non-zero on failure
 */
static int
parseDevid(char *input, stmfDevid *devid)
{
	wchar_t inputWc[MAX_DEVID_INPUT + 1] = {0};

	/* convert to wcs */
	(void) mbstowcs(inputWc, input, MAX_DEVID_INPUT);

	/*
	 * Check for known scsi name string formats
	 * If one is found, we're done
	 * If not, then it's a failure to parse
	 */
	if (checkScsiNameString(inputWc, devid) == 0) {
		return (0);
	}

	return (-1);
}




/*
 * printTargetProps
 *
 * Prints the properties for a target
 *
 */
static void
printTargetProps(stmfTargetProperties *targetProps)
{
	(void) printf(PROPS_FORMAT, "Operational Status");
	switch (targetProps->status) {
		case STMF_TARGET_PORT_ONLINE:
			(void) printf("Online");
			break;
		case STMF_TARGET_PORT_OFFLINE:
			(void) printf("Offline");
			break;
		case STMF_TARGET_PORT_ONLINING:
			(void) printf("Onlining");
			break;
		case STMF_TARGET_PORT_OFFLINING:
			(void) printf("Offlining");
			break;
		default:
			(void) printf("unknown");
			break;
	}
	(void) printf("\n");
	(void) printf(PROPS_FORMAT, "Provider Name");
	if (targetProps->providerName[0] != 0) {
		(void) printf("%s", targetProps->providerName);
	}
	(void) printf("\n");
	(void) printf(PROPS_FORMAT, "Alias");
	if (targetProps->alias[0] != 0) {
		(void) printf("%s", targetProps->alias);
	} else {
		(void) printf("-");
	}
	(void) printf("\n");
	(void) printf(PROPS_FORMAT, "Protocol");
	switch (targetProps->protocol) {
		case STMF_PROTOCOL_FIBRE_CHANNEL:
			(void) printf("%s", "Fibre Channel");
			break;
		case STMF_PROTOCOL_ISCSI:
			(void) printf("%s", "iSCSI");
			break;
		case STMF_PROTOCOL_SRP:
			(void) printf("%s", "SRP");
			break;
		case STMF_PROTOCOL_SAS:
			(void) printf("%s", "SAS");
			break;
		default:
			(void) printf("%s", "unknown");
			break;
	}

	(void) printf("\n");
}

/*
 * printSessionProps
 *
 * Prints the session data
 *
 */
static void
printSessionProps(stmfSessionList *sessionList)
{
	int i;
	char *cTime;
	wchar_t initiator[STMF_IDENT_LENGTH + 1];

	(void) printf(PROPS_FORMAT, "Sessions");
	(void) printf("%d\n", sessionList->cnt);
	for (i = 0; i < sessionList->cnt; i++) {
		(void) mbstowcs(initiator,
		    (char *)sessionList->session[i].initiator.ident,
		    STMF_IDENT_LENGTH);
		initiator[STMF_IDENT_LENGTH] = 0;
		(void) printf(LVL3_FORMAT, "Initiator: ");
		(void) printf("%ls\n", initiator);
		(void) printf(LVL4_FORMAT, "Alias: ");
		if (sessionList->session[i].alias[0] != 0) {
			(void) printf("%s", sessionList->session[i].alias);
		} else {
			(void) printf("-");
		}
		(void) printf("\n");
		(void) printf(LVL4_FORMAT, "Logged in since: ");
		cTime = ctime(&(sessionList->session[i].creationTime));
		if (cTime != NULL) {
			(void) printf("%s", cTime);
		} else {
			(void) printf("unknown\n");
		}
	}
}

/*
 * addview
 *
 * Adds a view entry to a logical unit
 *
 */
/*ARGSUSED*/
static int
addview(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	stmfViewEntry viewEntry;
	stmf_add_proxy_view_t *proxy_view_entry;
	stmfGuid inGuid;
	uint16_t inputLuNbr;
	int ret = 0;
	int stmfRet;
	char inputhost[256], inputtarget[256];
	char *chartosplit, *operandstringp;
	char *nextinputoperand = NULL;
	/*char *emptyp = "all";*/

	/*uint32_t buf_len;
	char *buf;*/

	bzero(&viewEntry, sizeof (viewEntry));
	/* init view entry structure */
	viewEntry.allHosts = B_TRUE;
	viewEntry.allTargets = B_TRUE;
	viewEntry.luNbrValid = B_FALSE;
	if (operandLen > 3 || operandLen == 1)
	{
		(void) fprintf(stderr, "%s\n", gettext("input format incorrect"));
		(void) printf("Usage:  lunadm add-view <hostname,targetname [lun-number] Lu-Name ...>\n");
		ret = 1;
		return (ret);
	}

	if ((operandstringp = (char *)malloc(512*sizeof(char))) == NULL)
	{
		(void) fprintf(stderr, "Allocate memory faild.\n");
		exit (1);
	}
	operandstringp = strncpy(operandstringp, operands[0],512*sizeof(char));
	/*判断操作数格式*/
	chartosplit = strchr(operandstringp,',');
	if (chartosplit == NULL)
	{
		(void) fprintf(stderr, "%s : %s: %s\n", cmdName, operands[0], gettext("not found"));
		free(operandstringp);
		ret = 1;
		return (ret);
	}

	/*提取操作数的值，使其分别为输入的主机组和目标组的名字*/
	if ((chartosplit = strtok_r(operandstringp, ",", &nextinputoperand)) != NULL)
	{
		(void) strncpy (inputhost, chartosplit, sizeof(inputhost));
		(void) strncpy (inputtarget, nextinputoperand, sizeof(inputtarget));
	}
	free(operandstringp);
	if ((strcmp(inputhost, "all")) != 0)
	{
		viewEntry.allHosts = B_FALSE;
		bcopy(inputhost, viewEntry.hostGroup,
				   strlen(inputhost));
	}
	if ((strcmp(inputtarget, "all")) != 0)
	{
		viewEntry.allTargets = B_FALSE;
		bcopy(inputtarget, viewEntry.targetGroup,
				  strlen(inputtarget));
	}
	if (operandLen == 2)
	{
		ret = getlu_name(operands[1], &inGuid);
		if(ret == 1)
		{
			return ret;
		}
	}
	if (operandLen == 3)
	{
		ret = getlu_name(operands[2], &inGuid);
		if(ret == 1)
		{
			return ret;
		}
		viewEntry.luNbrValid = B_TRUE;
		inputLuNbr = atoi(operands[1]);
		if (inputLuNbr > MAX_LU_NBR) {
			(void) fprintf(stderr, "%s: %d: %s\n",
					  cmdName, inputLuNbr,
					  gettext("Logical unit number"
					  " must be less than 16384"));
			return (1);
		}
		viewEntry.luNbr[0] = inputLuNbr >> 8;
		viewEntry.luNbr[1] = inputLuNbr & 0xff;
	}
	#if 0
	for (; options->optval; options++) {
		switch (options->optval) {
			/* logical unit number */
			case 'n':
				viewEntry.luNbrValid = B_TRUE;
				inputLuNbr = atoi(options->optarg);
				if (inputLuNbr > MAX_LU_NBR) {
					(void) fprintf(stderr, "%s: %d: %s\n",
					    cmdName, inputLuNbr,
					    gettext("Logical unit number"
					    " must be less than 16384"));
					return (1);
				}
				viewEntry.luNbr[0] = inputLuNbr >> 8;
				viewEntry.luNbr[1] = inputLuNbr & 0xff;
				break;
			/* host group */
			case 'h':
				viewEntry.allHosts = B_FALSE;
				bcopy(options->optarg, viewEntry.hostGroup,
				    strlen(options->optarg));
				break;
			/* target group */
			case 't':
				viewEntry.allTargets = B_FALSE;
				bcopy(options->optarg, viewEntry.targetGroup,
				    strlen(options->optarg));
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, options->optval,
				    gettext("unknown option"));
				return (1);
		}
	}
	#endif
	/* add the view entry */
	stmfRet = stmfAddViewEntry(&inGuid, &viewEntry);
	switch (stmfRet) {
		case STMF_STATUS_SUCCESS:
			proxy_view_entry = malloc(sizeof(stmf_add_proxy_view_t));
			bzero(proxy_view_entry, sizeof(stmf_add_proxy_view_t));
			proxy_view_entry->head.op_type = STMF_OP_ADD;
			proxy_view_entry->head.item_type = STMF_VIEW_OP;
			bcopy(&inGuid, &proxy_view_entry->lu_guid, sizeof(stmfGuid));
			bcopy(&viewEntry, &proxy_view_entry->view_entry, sizeof(stmfViewEntry));
			free(proxy_view_entry);
			break;
		case STMF_ERROR_EXISTS:
			(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
			    operands[0], gettext("already exists"));
			ret++;
			break;
		case STMF_ERROR_BUSY:
			(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
			    operands[0], gettext("resource busy"));
			ret++;
			break;
		case STMF_ERROR_SERVICE_NOT_FOUND:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("STMF service not found"));
			ret++;
			break;
		case STMF_ERROR_PERM:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("permission denied"));
			ret++;
			break;
		case STMF_ERROR_LUN_IN_USE:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("LUN already in use"));
			ret++;
			break;
		case STMF_ERROR_VE_CONFLICT:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("view entry exists"));
			ret++;
			break;
		case STMF_ERROR_CONFIG_NONE:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("STMF service is not initialized"));
			ret++;
			break;
		case STMF_ERROR_SERVICE_DATA_VERSION:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("STMF service version incorrect"));
			ret++;
			break;
		case STMF_ERROR_INVALID_HG:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("invalid host group"));
			ret++;
			break;
		case STMF_ERROR_INVALID_TG:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("invalid target group"));
			ret++;
			break;
		default:
			(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
			    operands[0], gettext("unknown error"));
			ret++;
			break;
	}

	return (ret);
}


/*
 * createhostgroupfunc
 *
 * Create a host group
 *
 */
/*ARGSUSED*/
static int
createhostgroupfunc(int operandLen, char *operands[],
    cmdOptions_t *options, void *args)
{
	int ret = 0;
	int stmfRet;
	wchar_t groupNamePrint[sizeof (stmfGroupName)] = {0};
	stmfGroupName groupName = {0};
	stmf_proxy_device_t *proxy_device;

	if (strcmp(operands[0], "all") == 0)
	{
		(void)fprintf(stderr, "'all' is reserved name\n");
		return (1);
	}
	(void) strlcpy(groupName, operands[0], sizeof (groupName));
	(void) mbstowcs(groupNamePrint, (char *)groupName,
	    sizeof (stmfGroupName) - 1);
	/* call create group */
	stmfRet = stmfCreateHostGroup(&groupName);
	switch (stmfRet) {
		case STMF_STATUS_SUCCESS:
			proxy_device = malloc(sizeof(stmf_proxy_device_t));
			proxy_device->head.item_type = STMF_HG_OP;
			proxy_device->head.op_type = STMF_OP_ADD;
			bcopy(&groupName, &proxy_device->name, sizeof(stmfGroupName));
			free(proxy_device);
			break;
		case STMF_ERROR_EXISTS:
			(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
			    operands[0], gettext("already exists"));
			ret++;
			break;
		case STMF_ERROR_BUSY:
			(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
			    operands[0], gettext("resource busy"));
			ret++;
			break;
		case STMF_ERROR_SERVICE_NOT_FOUND:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("STMF service not found"));
			ret++;
			break;
		case STMF_ERROR_PERM:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("permission denied"));
			ret++;
			break;
		case STMF_ERROR_SERVICE_DATA_VERSION:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("STMF service version incorrect"));
			ret++;
			break;
		default:
			(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
			    operands[0], gettext("unknown error"));
			ret++;
			break;
	}

	return (ret);
}


/*
 * createtargetgroupfunc
 *
 * Create a target group
 *
 */
/*ARGSUSED*/
static int
createtargetgroupfunc(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	int ret = 0;
	int stmfRet;
	wchar_t groupNamePrint[sizeof (stmfGroupName)] = {0};
	stmfGroupName groupName = {0};
	stmf_proxy_device_t *proxy_device;

	if (strcmp(operands[0], "all") == 0)
	{
		(void)fprintf(stderr, "'all' is reserved name\n");
		return (1);
	}
	(void) strlcpy(groupName, operands[0], sizeof (groupName));
	(void) mbstowcs(groupNamePrint, (char *)groupName,
	    sizeof (stmfGroupName) - 1);
	/* call create group */
	stmfRet = stmfCreateTargetGroup(&groupName);
	switch (stmfRet) {
		case STMF_STATUS_SUCCESS:
			proxy_device = malloc(sizeof(stmf_proxy_device_t));
			proxy_device->head.item_type = STMF_TG_OP;
			proxy_device->head.op_type = STMF_OP_ADD;
			bcopy(&groupName, &proxy_device->name, sizeof(stmfGroupName));
			free(proxy_device);
			break;
		case STMF_ERROR_EXISTS:
			(void) fprintf(stderr, "%s: %ls: %s\n", cmdName,
			    groupNamePrint, gettext("already exists"));
			ret++;
			break;
		case STMF_ERROR_BUSY:
			(void) fprintf(stderr, "%s: %ls: %s\n", cmdName,
			    groupNamePrint, gettext("resource busy"));
			ret++;
			break;
		case STMF_ERROR_PERM:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("permission denied"));
			ret++;
			break;
		case STMF_ERROR_SERVICE_NOT_FOUND:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("STMF service not found"));
			ret++;
			break;
		case STMF_ERROR_SERVICE_DATA_VERSION:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("STMF service version incorrect"));
			ret++;
			break;
		default:
			(void) fprintf(stderr, "%s: %ls: %s\n", cmdName,
			    groupNamePrint, gettext("unknown error"));
			ret++;
			break;
	}

	return (ret);
}

/*
 * deletehostgroupfunc
 *
 * Delete a host group
 *
 */
/*ARGSUSED*/
static int
deletehostgroupfunc(int operandLen, char *operands[],
    cmdOptions_t *options, void *args)
{
	int ret = 0;
	int stmfRet;
	wchar_t groupNamePrint[sizeof (stmfGroupName)] = {0};
	stmfGroupName groupName = {0};
	stmf_proxy_device_t *proxy_device;
	(void) strlcpy(groupName, operands[0], sizeof (groupName));
	(void) mbstowcs(groupNamePrint, (char *)groupName,
	    sizeof (stmfGroupName) - 1);
	/* call delete group */
	stmfRet = stmfDeleteHostGroup(&groupName);
	switch (stmfRet) {
		case STMF_STATUS_SUCCESS:
			proxy_device = malloc(sizeof(stmf_proxy_device_t));
			proxy_device->head.item_type = STMF_HG_OP;
			proxy_device->head.op_type = STMF_OP_DELETE;
			bcopy(&groupName, &proxy_device->name, sizeof(stmfGroupName));
			free(proxy_device);
			break;
		case STMF_ERROR_NOT_FOUND:
			(void) fprintf(stderr, "%s: %ls: %s\n", cmdName,
			    groupNamePrint, gettext("not found"));
			ret++;
			break;
		case STMF_ERROR_BUSY:
			(void) fprintf(stderr, "%s: %ls: %s\n", cmdName,
			    groupNamePrint, gettext("resource busy"));
			ret++;
			break;
		case STMF_ERROR_SERVICE_NOT_FOUND:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("STMF service not found"));
			ret++;
			break;
		case STMF_ERROR_PERM:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("permission denied"));
			ret++;
			break;
		case STMF_ERROR_GROUP_IN_USE:
			(void) fprintf(stderr, "%s: %ls: %s\n", cmdName,
			    groupNamePrint,
			    gettext("group is in use by existing view entry"));
			ret++;
			break;
		case STMF_ERROR_SERVICE_DATA_VERSION:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("STMF service version incorrect"));
			ret++;
			break;
		default:
			(void) fprintf(stderr, "%s: %ls: %s\n", cmdName,
			    groupNamePrint, gettext("unknown error"));
			ret++;
			break;
	}

	return (ret);
}


/*
 * deletetargetgroupfunc
 *
 * Delete a target group
 *
 */
/*ARGSUSED*/
static int
deletetargetgroupfunc(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	int ret = 0;
	int stmfRet;
	wchar_t groupNamePrint[sizeof (stmfGroupName)] = {0};
	stmfGroupName groupName = {0};
	stmf_proxy_device_t *proxy_device;

	(void) strlcpy(groupName, operands[0], sizeof (groupName));
	(void) mbstowcs(groupNamePrint, (char *)groupName,
	    sizeof (stmfGroupName) - 1);
	/* call delete group */
	stmfRet = stmfDeleteTargetGroup(&groupName);
	switch (stmfRet) {
		case STMF_STATUS_SUCCESS:
			proxy_device = malloc(sizeof(stmf_proxy_device_t));
			proxy_device->head.item_type = STMF_TG_OP;
			proxy_device->head.op_type = STMF_OP_DELETE;
			bcopy(&groupName, &proxy_device->name, sizeof(stmfGroupName));
			free(proxy_device);
			break;
		case STMF_ERROR_NOT_FOUND:
			(void) fprintf(stderr, "%s: %ls: %s\n", cmdName,
			    groupNamePrint, gettext("not found"));
			ret++;
			break;
		case STMF_ERROR_BUSY:
			(void) fprintf(stderr, "%s: %ls: %s\n", cmdName,
			    groupNamePrint, gettext("resource busy"));
			ret++;
			break;
		case STMF_ERROR_SERVICE_NOT_FOUND:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("STMF service not found"));
			ret++;
			break;
		case STMF_ERROR_PERM:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("permission denied"));
			ret++;
			break;
		case STMF_ERROR_GROUP_IN_USE:
			(void) fprintf(stderr, "%s: %ls: %s\n", cmdName,
			    groupNamePrint,
			    gettext("group is in use by existing view entry"));
			ret++;
			break;
		case STMF_ERROR_SERVICE_DATA_VERSION:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("STMF service version incorrect"));
			ret++;
			break;
		default:
			(void) fprintf(stderr, "%s: %ls: %s\n", cmdName,
			    groupNamePrint, gettext("unknown error"));
			ret++;
			break;
	}

	return (ret);
}





/*
 * addhostgroupmember
 *
 * Add members to a host group
 *
 */
/*ARGSUSED*/
static int
addhostgroupmember(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	int i;
	int ret = 0;
	int stmfRet;
	stmfGroupName groupName = {0};
	wchar_t groupNamePrint[sizeof (stmfGroupName)] = {0};
	stmfDevid devid;
	stmf_proxy_device_t *proxy_device;
	#if 0
	for (; options->optval; options++) {
		switch (options->optval) {
			/* host group name */
			case 'g':
				(void) mbstowcs(groupNamePrint, options->optarg,
				    sizeof (stmfGroupName) - 1);
				bcopy(options->optarg, groupName,
				    strlen(options->optarg));
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, options->optval,
				    gettext("unknown option"));
				return (1);
		}
	}
	#endif
	(void) mbstowcs(groupNamePrint, operands[0],
		 sizeof (stmfGroupName) - 1);
	bcopy(operands[0], groupName,
		strlen(operands[0]));
	if (operandLen == 1)
	{
		(void) fprintf(stderr, "%s\n", gettext("input format incorrect"));
		(void) printf("\nUsage:  lunadm add-hg-member <group-name group-member ...>\n");
		ret = 1;
		return (ret);
	}

	for (i = 1; i < operandLen; i++) {
		if (parseDevid(operands[i], &devid) != 0) {
			(void) fprintf(stderr, "%s: %s: %s\n",
			    cmdName, operands[i],
			    gettext("unrecognized device id"));
			ret++;
			continue;
		}
		stmfRet = stmfAddToHostGroup(&groupName, &devid);
		switch (stmfRet) {
			case STMF_STATUS_SUCCESS:
				proxy_device = malloc(sizeof(stmf_proxy_device_t));
				proxy_device->head.item_type = STMF_HG_MEMBER_OP;
				proxy_device->head.op_type = STMF_OP_ADD;
				bcopy(&groupName, &proxy_device->name, sizeof(stmfGroupName));
				bcopy(&devid, &proxy_device->device, sizeof(stmfDevid));
				free(proxy_device);
				break;
			case STMF_ERROR_EXISTS:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], gettext("already exists"));
				ret++;
				break;
			case STMF_ERROR_GROUP_NOT_FOUND:
				(void) fprintf(stderr, "%s: %ls: %s\n", cmdName,
				    groupNamePrint, gettext("not found"));
				ret++;
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], gettext("resource busy"));
				ret++;
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				ret++;
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				ret++;
				break;
			default:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], gettext("unknown error"));
				ret++;
				break;
		}
	}

	return (ret);
}


/*
 * addtargetgroupmember
 *
 * Add members to a target group
 *
 */
/*ARGSUSED*/
static int
addtargetgroupmember(int operandLen, char *operands[],
    cmdOptions_t *options, void *args)
{
	int i;
	int ret = 0;
	int stmfRet;
	stmfGroupName groupName = {0};
	wchar_t groupNamePrint[sizeof (stmfGroupName)] = {0};
	stmfDevid devid;
	stmf_proxy_device_t *proxy_device;
	#if 0
	for (; options->optval; options++) {
		switch (options->optval) {
			/* target group name */
			case 'g':
				(void) mbstowcs(groupNamePrint, options->optarg,
				    sizeof (stmfGroupName) - 1);
				bcopy(options->optarg, groupName,
				    strlen(options->optarg));
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, options->optval,
				    gettext("unknown option"));
				return (1);
		}
	}
	#endif
	(void) mbstowcs(groupNamePrint, operands[0],
		 sizeof (stmfGroupName) - 1);
	bcopy(operands[0], groupName,
		strlen(operands[0]));
	if (operandLen == 1)
	{
		(void) fprintf(stderr, "%s\n", gettext("input format incorrect"));
		(void) printf("\nUsage:  lunadm add-tg-member <group-name group-member ...>\n");
		ret = 1;
		return (ret);
	}
	for (i = 1; i < operandLen; i++) {
		if (parseDevid(operands[i], &devid) != 0) {
			(void) fprintf(stderr, "%s: %s: %s\n",
			    cmdName, operands[i],
			    gettext("unrecognized device id"));
			ret++;
			continue;
		}
		stmfRet = stmfAddToTargetGroup(&groupName, &devid);
		switch (stmfRet) {
			case STMF_STATUS_SUCCESS:
				proxy_device = malloc(sizeof(stmf_proxy_device_t));
				proxy_device->head.item_type = STMF_TG_MEMBER_OP;
				proxy_device->head.op_type = STMF_OP_ADD;
				bcopy(&groupName, &proxy_device->name, sizeof(stmfGroupName));
				bcopy(&devid, &proxy_device->device, sizeof(stmfDevid));
				free(proxy_device);
				break;
			case STMF_ERROR_EXISTS:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], gettext("already exists"));
				ret++;
				break;
			case STMF_ERROR_GROUP_NOT_FOUND:
				(void) fprintf(stderr, "%s: %ls: %s\n", cmdName,
				    groupNamePrint, gettext("not found"));
				ret++;
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], gettext("resource busy"));
				ret++;
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				ret++;
				break;
			case STMF_ERROR_SERVICE_ONLINE:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service must be offline"));
				ret++;
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				ret++;
				break;
			case STMF_ERROR_TG_ONLINE:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF target must be offline"));
				ret++;
				break;
			default:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], gettext("unknown error"));
				ret++;
				break;
		}
	}

	return (ret);
}


/*ARGSUSED*/
static int
removehostgroupmemberfunc(int operandLen, char *operands[],
    cmdOptions_t *options, void *args)
{
	int i;
	int ret = 0;
	int stmfRet;
	stmfGroupName groupName = {0};
	stmfDevid devid;
	wchar_t groupNamePrint[sizeof (stmfGroupName)] = {0};
	stmf_proxy_device_t *proxy_device;
	#if 0
	for (; options->optval; options++) {
		switch (options->optval) {
			case 'g':
				(void) mbstowcs(groupNamePrint, options->optarg,
				    sizeof (stmfGroupName) - 1);
				bcopy(options->optarg, groupName,
				    strlen(options->optarg));
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, options->optval,
				    gettext("unknown option"));
				return (1);
		}
	}
	#endif
	(void) mbstowcs(groupNamePrint, operands[0],
		 sizeof (stmfGroupName) - 1);
	bcopy(operands[0], groupName,
		strlen(operands[0]));
	if (operandLen == 1)
	{
		(void) fprintf(stderr, "%s\n", gettext("input format incorrect"));
		(void) printf("\nUsage:  lunadm remove-hg-member <group-name group-member ...>\n");
		ret = 1;
		return (ret);
	}
	for (i = 1; i < operandLen; i++) {
		if (parseDevid(operands[i], &devid) != 0) {
			(void) fprintf(stderr, "%s: %s: %s\n",
			    cmdName, operands[i],
			    gettext("unrecognized device id"));
			ret++;
			continue;
		}
		stmfRet = stmfRemoveFromHostGroup(&groupName, &devid);
		switch (stmfRet) {
			case STMF_STATUS_SUCCESS:
				proxy_device = malloc(sizeof(stmf_proxy_device_t));
				proxy_device->head.item_type = STMF_HG_MEMBER_OP;
				proxy_device->head.op_type = STMF_OP_DELETE;
				bcopy(&groupName, &proxy_device->name, sizeof(stmfGroupName));
				bcopy(&devid, &proxy_device->device, sizeof(stmfDevid));
				free(proxy_device);
				break;
			case STMF_ERROR_MEMBER_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], gettext("not found"));
				ret++;
				break;
			case STMF_ERROR_GROUP_NOT_FOUND:
				(void) fprintf(stderr, "%s: %ls: %s\n", cmdName,
				    groupNamePrint, gettext("not found"));
				ret++;
				break;
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], "resource busy");
				ret++;
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				ret++;
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				ret++;
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				ret++;
				break;
			default:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], gettext("unknown error"));
				ret++;
				break;
		}
	}

	return (ret);
}

/*
 * removetargetgroupmemberfunc
 *
 * Removes one or more members from a target group
 *
 */
/*ARGSUSED*/
static int
removetargetgroupmemberfunc(int operandLen, char *operands[],
    cmdOptions_t *options, void *args)
{
	int i;
	int ret = 0;
	int stmfRet;
	stmfGroupName groupName = {0};
	stmfDevid devid;
	wchar_t groupNamePrint[sizeof (stmfGroupName)] = {0};
	stmf_proxy_device_t *proxy_device;
	#if 0
	for (; options->optval; options++) {
		switch (options->optval) {
			case 'g':
				(void) mbstowcs(groupNamePrint, options->optarg,
				    sizeof (stmfGroupName) - 1);
				bcopy(options->optarg, groupName,
				    strlen(options->optarg));
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, options->optval,
				    gettext("unknown option"));
				return (1);
		}
	}
	#endif
	(void) mbstowcs(groupNamePrint, operands[0],
		 sizeof (stmfGroupName) - 1);
	bcopy(operands[0], groupName,
		strlen(operands[0]));
	if (operandLen == 1)
	{
		(void) fprintf(stderr, "%s\n", gettext("input format incorrect"));
		(void) printf("\nUsage:  lunadm remove-tg-member <group-name group-member ...>\n");
		ret = 1;
		return (ret);
	}
	for (i = 1; i < operandLen; i++) {
		if (parseDevid(operands[i], &devid) != 0) {
			(void) fprintf(stderr, "%s: %s: %s\n",
			    cmdName, operands[i],
			    gettext("unrecognized device id"));
			ret++;
			continue;
		}
		stmfRet = stmfRemoveFromTargetGroup(&groupName, &devid);
		switch (stmfRet) {
			case STMF_STATUS_SUCCESS:
				proxy_device = malloc(sizeof(stmf_proxy_device_t));
				proxy_device->head.item_type = STMF_TG_MEMBER_OP;
				proxy_device->head.op_type = STMF_OP_DELETE;
				bcopy(&groupName, &proxy_device->name, sizeof(stmfGroupName));
				bcopy(&devid, &proxy_device->device, sizeof(stmfDevid));
				free(proxy_device);
				break;
			case STMF_ERROR_MEMBER_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], gettext("not found"));
				ret++;
				break;
			case STMF_ERROR_GROUP_NOT_FOUND:
				(void) fprintf(stderr, "%s: %ls: %s\n", cmdName,
				    groupNamePrint, gettext("not found"));
				ret++;
				break;
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], gettext("resource busy"));
				ret++;
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				ret++;
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				ret++;
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				ret++;
				break;
			case STMF_ERROR_TG_ONLINE:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF target must be offline"));
				ret++;
				break;
			default:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], gettext("unknown error"));
				ret++;
				break;
		}
	}

	return (ret);
}
#if 0
/*
 * removeview
 *
 * Removes one or more view entries from a logical unit
 *
 */
/*ARGSUSED*/
static int
removeview(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	stmfViewEntryList *viewEntryList;
	stmfGuid inGuid;
	uint32_t count;
	char *endPtr;
	uint32_t veNbr;
	int i;
	char optionargs[256];
	boolean_t all = B_FALSE;
	boolean_t luInput = B_FALSE;
	int ret = 0;
	int stmfRet;
stmf_remove_proxy_view_t *proxy_remove_view_entry;
	if(ret == 1)
	{
		return ret;
	}
	/* Note: 'l' is required */
	for (; options->optval; options++) {
		switch (options->optval) {
			case 'l':
				ret = getlu_name(options->optarg, &inGuid);
				if(ret == 1)
				{
					return ret;
				}
				luInput = B_TRUE;
				(void) strncpy(optionargs, options->optarg, 256);
				break;
			case 'a':
				/* removing all view entries for this GUID */
				all = B_TRUE;
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, options->optval,
				    "unknown option");
				return (1);
		}
	}

	if (!all && operandLen == 0) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    gettext("no view entries specified"));
		return (1);
	}

	if (!luInput) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    gettext("logical unit (-l) not specified"));
		return (1);
	}
   #if 0
	for (i = 0; i < 32; i++)
		sGuid[i] = tolower(sGuid[i]);
	sGuid[i] = 0;

	(void) sscanf(sGuid, "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
	    &guid[0], &guid[1], &guid[2], &guid[3], &guid[4], &guid[5],
	    &guid[6], &guid[7], &guid[8], &guid[9], &guid[10], &guid[11],
	    &guid[12], &guid[13], &guid[14], &guid[15]);

	for (i = 0; i < sizeof (stmfGuid); i++) {
		inGuid.guid[i] = guid[i];
	}
	#endif
	if ((stmfRet = stmfGetViewEntryList(&inGuid, &viewEntryList))
	    != STMF_STATUS_SUCCESS) {

		switch (stmfRet) {
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    optionargs, gettext("resource busy"));
				break;
			case STMF_ERROR_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    optionargs, gettext("no views found"));
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			default:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    optionargs, gettext("unknown error"));
				break;
		}
		return (1);
	}

	if (all) {
		count = viewEntryList->cnt;
	} else {
		count = operandLen;
	}

	for (i = 0; i < count; i++) {
		if (all) {
			veNbr = viewEntryList->ve[i].veIndex;
		} else {
			endPtr = NULL;
			veNbr = strtol(operands[i], &endPtr, 10);
			if (endPtr && *endPtr != 0) {
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[i], gettext("invalid input"));
				continue;
			}
		}
		stmfRet = stmfRemoveViewEntry(&inGuid, veNbr);
		switch (stmfRet) {
			case STMF_STATUS_SUCCESS:
			proxy_remove_view_entry = malloc(sizeof(stmf_remove_proxy_view_t));
			bzero(proxy_remove_view_entry, sizeof(stmf_remove_proxy_view_t));
			proxy_remove_view_entry->head.op_type = STMF_OP_DELETE;
			proxy_remove_view_entry->head.item_type = STMF_VIEW_OP;
			bcopy(&inGuid, &proxy_remove_view_entry->lu_guid, sizeof(stmfGuid));
			proxy_remove_view_entry->view_index = veNbr;
			free(proxy_remove_view_entry);
				break;
			case STMF_ERROR_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s: %d: %s\n",
				    cmdName, optionargs, veNbr,
				    gettext("not found"));
				ret++;
				break;
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    optionargs, gettext("resource busy"));
				ret++;
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				ret++;
				break;
			case STMF_ERROR_CONFIG_NONE:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service is not initialized"));
				ret++;
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				ret++;
				break;
			default:
				(void) fprintf(stderr, "%s: %s: %d: %s",
				    cmdName, optionargs, veNbr,
				    gettext("unknown error"));
				ret++;
				break;
		}
	}

	return (ret);
}
#endif
/*
 * removegroupview
 *
 * remove the lun view in the specified host-group,target-group
 *
 */
/*ARGSUSED*/
static int
removegroupview(int operandLen, char *operands[], cmdOptions_t *options, void *args)
{
	int i, stmfRet, ret, outerloop, operandentered;
	stmf_remove_proxy_view_t *proxy_remove_view_entry;
	boolean_t found, foundgroup;
	list_t view_list;
	view *viewstart;
	char hgtg[513];
	found = foundgroup = B_FALSE;
	ret = 0;
	(void) strncpy(hgtg, operands[0], sizeof(hgtg));
	
	if (operandLen == 1) {
		outerloop = 2;
		operandentered = B_FALSE;
	} else {
		outerloop = operandLen;
		operandentered = B_TRUE;
	}
	list_create(&view_list, sizeof(view), offsetof(struct _view_info, listlink));
	stmfRet = getlunviewprop(&view_list);
	if (stmfRet == 1)
	{
		return (1);
	}
	
	for (i = 1; i < outerloop; i++)
	{
		/*移除指定组内指定ID的lun所对应的视图*/
		if (operandentered)
		{
			int m, isstringflag = 0;
			/*判断输入是否为数字，如有字符，则跳出进行下一次循环*/
			for(m = 0; m < strlen(operands[i]); m++)
			{
				if (isdigit(operands[i][m]) == 0)
				{
					isstringflag = 1;
					(void) fprintf(stderr, "%s: %s: %s: %s\n",
							    cmdName, hgtg, operands[i],
						    gettext("not found"));
					break;
				}
			}
			/*是否存在字符标志位*/
			if (isstringflag == 1)
			{
				isstringflag = 0;
				continue;
			}
			for(viewstart = list_head(&view_list); viewstart; viewstart = list_next(&view_list, viewstart))
			{
				if ((strncmp(viewstart->view_data._hgtgname, hgtg, 513)) == 0 && 
						(atoi(operands[i])) == viewstart->view_data.LUNIndex)
				{
					stmfRet = stmfRemoveViewEntry(&(viewstart->view_data.lunguid), viewstart->view_data.veindex);
					switch (stmfRet) {
						case STMF_STATUS_SUCCESS:
							proxy_remove_view_entry = malloc(sizeof(stmf_remove_proxy_view_t));
							bzero(proxy_remove_view_entry, sizeof(stmf_remove_proxy_view_t));
							proxy_remove_view_entry->head.op_type = STMF_OP_DELETE;
							proxy_remove_view_entry->head.item_type = STMF_VIEW_OP;
							bcopy(&(viewstart->view_data.lunguid), &proxy_remove_view_entry->lu_guid, sizeof(stmfGuid));
								proxy_remove_view_entry->view_index = viewstart->view_data.LUNIndex;
							free(proxy_remove_view_entry);
							break;
						case STMF_ERROR_NOT_FOUND:
							(void) fprintf(stderr, "%s: %s: %d: %s\n",
							    cmdName, viewstart->view_data._LUName, viewstart->view_data.LUNIndex,
						    gettext("not found"));
							ret++;
							break;
						case STMF_ERROR_BUSY:
							(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
							    viewstart->view_data._LUName, gettext("resource busy"));
							ret++;
							break;
						case STMF_ERROR_SERVICE_NOT_FOUND:
							(void) fprintf(stderr, "%s: %s\n", cmdName,
							    gettext("STMF service not found"));
							ret++;
							break;
						case STMF_ERROR_CONFIG_NONE:
							(void) fprintf(stderr, "%s: %s\n", cmdName,
							    gettext("STMF service is not initialized"));
							ret++;
							break;
						case STMF_ERROR_SERVICE_DATA_VERSION:
							(void) fprintf(stderr, "%s: %s\n", cmdName,
							    gettext("STMF service version incorrect"));
							ret++;
							break;
						default:
							(void) fprintf(stderr, "%s: %s, %d: %s",
							    cmdName, viewstart->view_data._LUName, viewstart->view_data.LUNIndex,
							    gettext("unknown error"));
							ret++;
							break;
					}
					found = B_TRUE;
				}
				if (found)
				{
					break;
				}
			}
			if (!found)
			{
				(void) fprintf(stderr, "%s: %s: %d: %s\n",
							    cmdName, hgtg, atoi(operands[i]),
						    gettext("not found"));
			}
			found = B_FALSE;
		}
		/*移除指定组内所有lun的视图*/
		else
		{
			for(viewstart = list_head(&view_list); viewstart; viewstart = list_next(&view_list, viewstart))
			{
				if ((strncmp(viewstart->view_data._hgtgname, hgtg, 513)) == 0)
				{
					foundgroup = B_TRUE;
					stmfRet = stmfRemoveViewEntry(&(viewstart->view_data.lunguid), viewstart->view_data.veindex);
					switch (stmfRet) {
						case STMF_STATUS_SUCCESS:
							proxy_remove_view_entry = malloc(sizeof(stmf_remove_proxy_view_t));
							bzero(proxy_remove_view_entry, sizeof(stmf_remove_proxy_view_t));
							proxy_remove_view_entry->head.op_type = STMF_OP_DELETE;
							proxy_remove_view_entry->head.item_type = STMF_VIEW_OP;
							bcopy(&(viewstart->view_data.lunguid), &proxy_remove_view_entry->lu_guid, sizeof(stmfGuid));
								proxy_remove_view_entry->view_index = viewstart->view_data.LUNIndex;
							free(proxy_remove_view_entry);
							break;
						case STMF_ERROR_NOT_FOUND:
							(void) fprintf(stderr, "%s: %s: %d: %s\n",
							    cmdName, viewstart->view_data._LUName, viewstart->view_data.LUNIndex,
						    gettext("not found"));
							ret++;
							break;
						case STMF_ERROR_BUSY:
							(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
							    viewstart->view_data._LUName, gettext("resource busy"));
							ret++;
							break;
						case STMF_ERROR_SERVICE_NOT_FOUND:
							(void) fprintf(stderr, "%s: %s\n", cmdName,
							    gettext("STMF service not found"));
							ret++;
							break;
						case STMF_ERROR_CONFIG_NONE:
							(void) fprintf(stderr, "%s: %s\n", cmdName,
							    gettext("STMF service is not initialized"));
							ret++;
							break;
						case STMF_ERROR_SERVICE_DATA_VERSION:
							(void) fprintf(stderr, "%s: %s\n", cmdName,
							    gettext("STMF service version incorrect"));
							ret++;
							break;
						default:
							(void) fprintf(stderr, "%s: %s, %d: %s",
							    cmdName, viewstart->view_data._LUName, viewstart->view_data.LUNIndex,
							    gettext("unknown error"));
							ret++;
							break;
					}
				}
			}
			if (!foundgroup)
			{
				(void) fprintf(stderr, "%s: %s: %s\n",
							    cmdName, hgtg,
						    gettext("not found"));
			}
			foundgroup = B_FALSE;
		}
	}
	for(viewstart = list_head(&view_list); viewstart; viewstart = list_next(&view_list, viewstart))
	{
		free(viewstart);
	}
	list_destroy(&view_list);
	return (ret);
}






/*
 * listtarget
 *
 * list the targets and optionally their properties
 *
 */
/*ARGSUSED*/
static int
listtarget(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	cmdOptions_t *optionList = options;
	int ret = 0;
	int stmfRet;
	int i, j;
	int outerLoop;
	stmfSessionList *sessionList;
	stmfDevid devid;
	boolean_t operandEntered, found, verbose = B_FALSE;
	stmfDevidList *targetList;
	wchar_t targetIdent[STMF_IDENT_LENGTH + 1];
	stmfTargetProperties targetProps;

	if ((stmfRet = stmfGetTargetList(&targetList)) != STMF_STATUS_SUCCESS) {
		switch (stmfRet) {
			case STMF_ERROR_NOT_FOUND:
				ret = 0;
				break;
			case STMF_ERROR_SERVICE_OFFLINE:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service offline"));
				break;
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("resource busy"));
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			default:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("unknown error"));
				break;
		}
		return (1);
	}

	for (; optionList->optval; optionList++) {
		switch (optionList->optval) {
			case 'v':
				verbose = B_TRUE;
				break;
		}
	}

	if (operandLen > 0) {
		outerLoop = operandLen;
		operandEntered = B_TRUE;
	} else {
		outerLoop = 1;
		operandEntered = B_FALSE;
	}

	for (i = 0; i < outerLoop; i++) {
		if (operandEntered) {
			bzero(&devid, sizeof (devid));
			(void) parseDevid(operands[i], &devid);
		}
		for (found = B_FALSE, j = 0; j < targetList->cnt; j++) {
			if (operandEntered) {
				if (bcmp(&devid, &(targetList->devid[j]),
				    sizeof (devid)) == 0) {
					found = B_TRUE;
				}
			}
			if ((found && operandEntered) || !operandEntered) {
				(void) mbstowcs(targetIdent,
				    (char *)targetList->devid[j].ident,
				    STMF_IDENT_LENGTH);
				targetIdent[STMF_IDENT_LENGTH] = 0;
				(void) printf("Target: %ls\n", targetIdent);
				if (verbose) {
					stmfRet = stmfGetTargetProperties(
					    &(targetList->devid[j]),
					    &targetProps);
					if (stmfRet == STMF_STATUS_SUCCESS) {
						printTargetProps(&targetProps);
					} else {
						(void) fprintf(stderr, "%s:",
						    cmdName);
						(void) fprintf(stderr, "%s\n",
						    gettext(" get properties"
						    " failed"));
					}
					stmfRet = stmfGetSessionList(
					    &(targetList->devid[j]),
					    &sessionList);
					if (stmfRet == STMF_STATUS_SUCCESS) {
						printSessionProps(sessionList);
					} else {
						(void) fprintf(stderr, "%s:",
						    cmdName);
						(void) fprintf(stderr, "%s\n",
						    gettext(" get session info"
						    " failed"));
					}
					stmfFreeMemory(sessionList);
				}
				if (found && operandEntered) {
					break;
				}
			}

		}
		if (operandEntered && !found) {
			(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
			    operands[i], "not found");
			ret = 1;
		}
	}
	stmfFreeMemory(targetList);
	return (ret);
}






/*   listtargetgroup
 *   
 *   list the target group in the system
 *    
 */

static int listtargetgroup(int operandLen, char *operands[], cmdOptions_t *options, void *args)
{
	int ret = 0;
	int stmfRet;
	int i, j, outerLoop;
	boolean_t verbose = B_FALSE;
	boolean_t found = B_TRUE;
	boolean_t operandEntered;
	stmfGroupList *groupList;
	stmfGroupProperties *groupProps;
	wchar_t operandName[sizeof (stmfGroupName)];
	wchar_t groupNamePrint[sizeof (stmfGroupName)];

	UNUSED_PARAMETER(args);

	for (; options->optval; options++) {
		switch (options->optval) {
			case 'v':
				verbose = B_TRUE;
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, options->optval,
				    gettext("unknown option"));
				return (1);
		}
	}

	if (operandLen > 0) {
		outerLoop = operandLen;
		operandEntered = B_TRUE;
	} else {
		outerLoop = 1;
		operandEntered = B_FALSE;
	}

	stmfRet = stmfGetTargetGroupList(&groupList);
	if (stmfRet != STMF_STATUS_SUCCESS) {
		switch (stmfRet) {
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("resource busy"));
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			default:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("unknown error"));
				break;
		}
		return (1);
	}

	for (i = 0; i < outerLoop; i++) {
		for (found = B_FALSE, j = 0; j < groupList->cnt; j++) {
			(void) mbstowcs(groupNamePrint,
			    (char *)groupList->name[j],
			    sizeof (stmfGroupName) - 1);
			groupNamePrint[sizeof (stmfGroupName) - 1] = 0;
			if (operandEntered) {
				(void) mbstowcs(operandName, operands[i],
				    sizeof (stmfGroupName) - 1);
				operandName[sizeof (stmfGroupName) - 1] = 0;
				if (wcscmp(operandName, groupNamePrint)
				    == 0) {
					found = B_TRUE;
				}
			}
			if ((found && operandEntered) || !operandEntered) {
				(void) printf("Target Group: %ls\n",
				    groupNamePrint);
				if (verbose) {
					stmfRet = stmfGetTargetGroupMembers(
					    &(groupList->name[j]), &groupProps);
					if (stmfRet != STMF_STATUS_SUCCESS) {
						return (1);
					}
					printGroupProps(groupProps);
					stmfFreeMemory(groupProps);
				}
				if (found && operandEntered) {
					break;
				}
			}

		}
		if (operandEntered && !found) {
			(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
			    operands[i], gettext("not found"));
			ret = 1;
		}
	}
	stmfFreeMemory(groupList);
	return (ret);
}


/*   listhostgroup
 *   
 *   list the host group in the system
 *    
 */

static int listhostgroup(int operandLen, char *operands[], cmdOptions_t *options, void *args)
{
	int ret = 0;
	int stmfRet;
	int i, j, outerLoop;
	boolean_t verbose = B_FALSE;
	boolean_t found = B_TRUE;
	boolean_t operandEntered;
	stmfGroupList *groupList;
	stmfGroupProperties *groupProps;
	wchar_t operandName[sizeof (stmfGroupName)];
	wchar_t groupNamePrint[sizeof (stmfGroupName)];
	UNUSED_PARAMETER(args);

	for (; options->optval; options++) {
		switch (options->optval) {
			case 'v':
				verbose = B_TRUE;
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, options->optval,
				    gettext("unknown option"));
				return (1);
		}
	}

	if (operandLen > 0) {
		outerLoop = operandLen;
		operandEntered = B_TRUE;
	} else {
		outerLoop = 1;
		operandEntered = B_FALSE;
	}

	stmfRet = stmfGetHostGroupList(&groupList);
	if (stmfRet != STMF_STATUS_SUCCESS) {
		switch (stmfRet) {
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("resource busy"));
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				break;
			default:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("unknown error"));
				break;
		}
		return (1);
	}

	for (i = 0; i < outerLoop; i++) {
		for (found = B_FALSE, j = 0; j < groupList->cnt; j++) {
			(void) mbstowcs(groupNamePrint,
			    (char *)groupList->name[j],
			    sizeof (stmfGroupName) - 1);
			groupNamePrint[sizeof (stmfGroupName) - 1] = 0;
			if (operandEntered) {
				(void) mbstowcs(operandName, operands[i],
				    sizeof (stmfGroupName) - 1);
				operandName[sizeof (stmfGroupName) - 1] = 0;
				if (wcscmp(operandName, groupNamePrint)
				    == 0) {
					found = B_TRUE;
				}
			}
			if ((found && operandEntered) || !operandEntered) {
				(void) printf("Host Group: %ls\n",
				    groupNamePrint);
				if (verbose) {
					stmfRet = stmfGetHostGroupMembers(
					    &(groupList->name[j]), &groupProps);
					if (stmfRet != STMF_STATUS_SUCCESS) {
						return (1);
					}
					printGroupProps(groupProps);
					stmfFreeMemory(groupProps);
				}
				if (found && operandEntered) {
					break;
				}
			}

		}
		if (operandEntered && !found) {
			(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
			    operands[i], gettext("not found"));
			ret = 1;
		}
	}
	stmfFreeMemory(groupList);
	return (ret);
}

/*
 * listview
 *
 * list the view entries for the specified logical unit
 *
 */
/*ARGSUSED*/
static int
listview(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	int stmfRet ,ret = 0;
	list_t view_list;
	view *view_info_start;
	int printflag = 0;
	list_create(&view_list, sizeof(view), offsetof(struct _view_info, listlink));
	stmfRet = getlunviewprop(&view_list);
	if (stmfRet == 1)
	{
		return(1);
	}
	for(view_info_start = list_head(&view_list); view_info_start; view_info_start= list_next(&view_list, view_info_start))
	{
		if ((strcmp(operands[0], view_info_start->view_data._LUName)) == 0)
		{
			if (printflag == 0)
			{
				(void) printf("    Lu-Number     LUN NAME                    SN\n");
			}
			printflag++;
			(void) printf("%s\n", view_info_start->view_data._hgtgname);
			(void) printf(LUNMAPLIST_FORMAT, view_info_start->view_data.LUNIndex, view_info_start->view_data._LUName,
												view_info_start->view_data._SerialNum);
		}
	}
	if (printflag == 0)
	{
		ret = 1;
		(void) fprintf(stderr, "%s: %s: %s:\n", cmdName, operands[0], gettext("view not found"));
	}
	#if 0
	if ((stmfRet = stmfGetViewEntryList(&inGuid, &viewEntryList))
	    != STMF_STATUS_SUCCESS) {

		switch (stmfRet) {
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[0], gettext("resource busy"));
				break;
			case STMF_ERROR_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[0], gettext("no views found"));
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			default:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    operands[0], gettext("unknown error"));
				break;
		}
		return (1);
	}

		for ( j = 0; j < viewEntryList->cnt; j++) {
				(void) printf("View Entry: %d\n",
				    viewEntryList->ve[j].veIndex);
				(void) printf(VIEW_FORMAT, "Host group");
				if (viewEntryList->ve[j].allHosts) {
					(void) printf("All\n");
				} else {
					(void) mbstowcs(groupName,
					    viewEntryList->ve[j].hostGroup,
					    sizeof (stmfGroupName) - 1);
					groupName[sizeof (stmfGroupName) - 1]
					    = 0;
					(void) printf("%ls\n", groupName);
				}
				(void) printf(VIEW_FORMAT, "Target group");
				if (viewEntryList->ve[j].allTargets) {
					(void) printf("All\n");
				} else {
					(void) mbstowcs(groupName,
					    viewEntryList->ve[j].targetGroup,
					    sizeof (stmfGroupName) - 1);
					groupName[sizeof (stmfGroupName) - 1]
					    = 0;
					(void) printf("%ls\n", groupName);
				}
				outputLuNbr = ((viewEntryList->ve[j].luNbr[0] &
				    0x3F) << 8) | viewEntryList->ve[j].luNbr[1];
				(void) printf(VIEW_FORMAT, "LUN");
				(void) printf("%d\n", outputLuNbr);
		#if 0
		if (operandEntered && !found) {
			(void) fprintf(stderr, "%s: %s, %s: %s\n", cmdName,
			    optionargs, operands[i], gettext("not found"));
			ret = 1;
		}
		#endif
	}
	#endif
	for(view_info_start = list_head(&view_list); view_info_start; view_info_start= list_next(&view_list, view_info_start)) 
	{
		free(view_info_start);
	}
	list_destroy(&view_list);
	return (ret);
}



/*
 * listlufunc
 *
 * List the logical units and optionally the properties
 *
 */
/*ARGSUSED*/
static int
listlufunc(int operandLen, char *operands[], cmdOptions_t *options, void *args)
{
	cmdOptions_t *optionList = options;
	boolean_t operandEntered;
	int i, j;
	int ret = 0;
	int stmfRet;
	int outerLoop;
	list_t lun_relate_list;
	stmfGuid cmpGuid;
	boolean_t verbose = B_FALSE;
	boolean_t found;
	stmfGuidList *luList;
	stmfViewEntryList *viewEntryList;
	stmfLogicalUnitProperties luProps;
	lunrelated *lun_end;

	for (; optionList->optval; optionList++) {
		switch (optionList->optval) {
			case 'v':
				verbose = B_TRUE;
				break;
		}
	}

	if (operandLen > 0) {
		operandEntered = B_TRUE;
		outerLoop = operandLen;
	} else {
		operandEntered = B_FALSE;
		outerLoop = 1;
	}
	
	list_create(&lun_relate_list, sizeof(lunrelated), offsetof(struct _lun_relate, lunrelatelink));
	stmfRet = getlu_prop(&lun_relate_list);
	if (stmfRet == 1)
	{
		return (1);
	}
	
	if ((stmfRet = stmfGetLogicalUnitList(&luList))
	    != STMF_STATUS_SUCCESS) {
		switch (stmfRet) {
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				break;
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("resource busy"));
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				break;
			default:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("list failed"));
				break;
		}
		return (1);
	}


	for (i = 0; i < outerLoop; i++) {
		for (found = B_FALSE, j = 0; j < luList->cnt; j++) {
			if (operandEntered) {
				if (bcmp(luList->guid[j].guid, cmpGuid.guid,
				    sizeof (stmfGuid)) == 0) {
					found = B_TRUE;
				}
			}
			if ((found && operandEntered) || !operandEntered) {
				for(lun_end = list_head(&lun_relate_list); lun_end; lun_end= list_next(&lun_relate_list, lun_end))
				{
					int m;
					for (m = 0; m < 16; m++)
					{
						if (luList->guid[j].guid[m] != lun_end->lundatafield.lunguid.guid[m])
						{
							break;
						}
					}
					if (m == 16)
					{
						(void) printf("LU Name: %s",lun_end->lundatafield.lunalias);
						/*printGuid(&luList->guid[j], stdout);*/
						(void) printf("\n");
						break;
					}
				}
				if (lun_end == NULL)
				{
					(void) printf("LU GUID: ");
					printGuid(&luList->guid[j], stdout);
					(void) printf("\n");
				}

				if (verbose) {
					stmfRet = stmfGetLogicalUnitProperties(
					    &(luList->guid[j]), &luProps);
					if (stmfRet == STMF_STATUS_SUCCESS) {
						printLuProps(&luProps);
					} else {
						(void) fprintf(stderr, "%s:",
						    cmdName);
						printGuid(&luList->guid[j],
						    stderr);
						(void) fprintf(stderr, "%s\n",
						    gettext(" get properties "
						    "failed"));
					}
					stmfRet = stmfGetViewEntryList(
					    &(luList->guid[j]),
					    &viewEntryList);
					(void) printf(PROPS_FORMAT,
					    "View Entry Count");
					if (stmfRet == STMF_STATUS_SUCCESS) {
						(void) printf("%d",
						    viewEntryList->cnt);
					} else if (stmfRet ==
					    STMF_ERROR_NOT_FOUND) {
						(void) printf("0");
					} else {
						(void) printf("unknown");
					}
					(void) printf("\n");
					ret = printExtLuProps(
					    &(luList->guid[j]));
					stmfFreeMemory(viewEntryList);
				}
				if (found && operandEntered) {
					break;
				}
			}

		}
		if (operandEntered && !found) {
			(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
			    operands[i], gettext("not found"));
			ret = 1;
		}
	}
	/*while(lun_start != lun_end)
	{
		free(lun_start->lunalias);
		lun_start++;
	}*/
	stmfFreeMemory(luList);
	for(lun_end = list_head(&lun_relate_list); lun_end; lun_end= list_next(&lun_relate_list, lun_end)) 
	{
		free(lun_end);
	}
	list_destroy(&lun_relate_list);
	return (ret);
}

/*
 * deletelufunc
 *
 * Delete a logical unit
 *
 */
/*ARGSUSED*/
static int
deletelufunc(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	int i, j;
	int ret = 0;
	int stmfRet;
	unsigned int inGuid[sizeof (stmfGuid)];
	stmfGuid delGuid;
	boolean_t keepViews = B_FALSE;
	boolean_t viewEntriesRemoved = B_FALSE;
	boolean_t noLunFound = B_FALSE;
	boolean_t views = B_FALSE;
	char sGuid[GUID_INPUT + 1];
	stmfViewEntryList *viewEntryList = NULL;



	for (i = 0; i < operandLen; i++) {
		for (j = 0; j < GUID_INPUT; j++) {
			if (!isxdigit(operands[i][j])) {
				break;
			}
			sGuid[j] = tolower(operands[i][j]);
		}
		if (j != GUID_INPUT) {
			stmfRet = getlu_name(operands[i], &delGuid);
			if(stmfRet == 1)
			{
				continue;
			}
		}
		else{
			sGuid[j] = 0;
			(void) sscanf(sGuid, "%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x%2x",
		         &inGuid[0], &inGuid[1], &inGuid[2], &inGuid[3],
		         &inGuid[4], &inGuid[5], &inGuid[6], &inGuid[7],
                 &inGuid[8], &inGuid[9], &inGuid[10], &inGuid[11],
                 &inGuid[12], &inGuid[13], &inGuid[14], &inGuid[15]);
			for (j = 0; j < sizeof (stmfGuid); j++) {
				delGuid.guid[j] = inGuid[j];
			}
		}
		stmfRet = stmfDeleteLu(&delGuid);
		switch (stmfRet) {
			case STMF_STATUS_SUCCESS:
				break;
			case STMF_ERROR_NOT_FOUND:
				noLunFound = B_TRUE;
				break;
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("resource busy"));
				ret++;
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				ret++;
				break;
			default:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("unknown error"));
				ret++;
				break;
		}

		if (!keepViews) {
			stmfRet = stmfGetViewEntryList(&delGuid,
			    &viewEntryList);
			if (stmfRet == STMF_STATUS_SUCCESS) {
				for (j = 0; j < viewEntryList->cnt; j++) {
					(void) stmfRemoveViewEntry(&delGuid,
					    viewEntryList->ve[j].veIndex);
				}
				viewEntriesRemoved = B_TRUE;
				stmfFreeMemory(viewEntryList);
			} else if (stmfRet != STMF_ERROR_NOT_FOUND) {
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("unable to remove view entries\n"));
				ret++;
			} /* No view entries to remove */
		}
		if (keepViews) {
			stmfRet = stmfGetViewEntryList(&delGuid,
			    &viewEntryList);
			if (stmfRet == STMF_STATUS_SUCCESS) {
				views = B_TRUE;
				stmfFreeMemory(viewEntryList);
			}
		}

		if ((!viewEntriesRemoved && noLunFound && !views) ||
		    (!views && keepViews && noLunFound)) {
			(void) fprintf(stderr, "%s: %s: %s\n",
			    cmdName, sGuid,
			    gettext("not found"));
			ret++;
		}
		noLunFound = viewEntriesRemoved = views = B_FALSE;
	}
	return (ret);
}


/*
 * importlufunc
 *
 * Create a logical unit
 *
 */
/*ARGSUSED*/
static int
importlufunc(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	int stmfRet = 0;
	int ret = 0;
	char guidAsciiBuf[33];
	char filename[280]= "/dev/zvol/rdsk/";
	stmfGuid createdGuid;
	(void) strncat(filename, operands[0], 256*sizeof(char));
	stmfRet = stmfImportLu(STMF_DISK, filename, &createdGuid);
	switch (stmfRet) {
		case STMF_STATUS_SUCCESS:
			break;
		case STMF_ERROR_BUSY:
		case STMF_ERROR_LU_BUSY:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("resource busy"));
			ret++;
			break;
		case STMF_ERROR_PERM:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("permission denied"));
			ret++;
			break;
		case STMF_ERROR_FILE_IN_USE:
			(void) fprintf(stderr, "%s: filename %s: %s\n", cmdName,
			    operands[0], gettext("in use"));
			ret++;
			break;
		case STMF_ERROR_GUID_IN_USE:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("guid in use"));
			ret++;
			break;
		case STMF_ERROR_META_FILE_NAME:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("meta file error"));
			ret++;
			break;
		case STMF_ERROR_DATA_FILE_NAME:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("data file error"));
			ret++;
			break;
		case STMF_ERROR_META_CREATION:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("could not create meta file"));
			ret++;
			break;
		case STMF_ERROR_WRITE_CACHE_SET:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("could not set write cache"));
			ret++;
			break;
		default:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("unknown error"));
			ret++;
			break;
	}

	if (ret != STMF_STATUS_SUCCESS) {
		goto done;
	}

	(void) snprintf(guidAsciiBuf, sizeof (guidAsciiBuf),
	    "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X"
	    "%02X%02X%02X%02X%02X%02X",
	    createdGuid.guid[0], createdGuid.guid[1], createdGuid.guid[2],
	    createdGuid.guid[3], createdGuid.guid[4], createdGuid.guid[5],
	    createdGuid.guid[6], createdGuid.guid[7], createdGuid.guid[8],
	    createdGuid.guid[9], createdGuid.guid[10], createdGuid.guid[11],
	    createdGuid.guid[12], createdGuid.guid[13], createdGuid.guid[14],
	    createdGuid.guid[15]);
	(void) printf("Logical unit imported: %s\n", guidAsciiBuf);

done:
	return (ret);
}


static void
printGuid(stmfGuid *guid, FILE *stream)
{
	int i;
	for (i = 0; i < 16; i++) {
		(void) fprintf(stream, "%02X", guid->guid[i]);
	}
}

static int
printExtLuProps(stmfGuid *guid)
{
	int stmfRet;
	luResource hdl = NULL;
	int ret = 0;
	char propVal[MAXNAMELEN];
	size_t propValSize = sizeof (propVal);

	if ((stmfRet = stmfGetLuResource(guid, &hdl))
	    != STMF_STATUS_SUCCESS) {
		switch (stmfRet) {
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("resource busy"));
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			case STMF_ERROR_NOT_FOUND:
				/* No error here */
				return (0);
				/*break;*/
			default:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("get extended properties failed"));
				break;
		}
		return (1);
	}

	#if 0
	stmfRet = stmfGetLuProp(hdl, STMF_LU_PROP_FILENAME, propVal,
	    &propValSize);
	(void) printf(PROPS_FORMAT, "Data File");
	if (stmfRet == STMF_STATUS_SUCCESS) {
		(void) printf("%s\n", propVal);
	} else if (stmfRet == STMF_ERROR_NO_PROP) {
		(void) printf("not set\n");
	} else if (stmfRet == STMF_ERROR_NO_PROP_STANDBY) {
		(void) printf("prop unavailable in standby\n");
	} else {
		(void) printf("<error retrieving property>\n");
		ret++;
	}

	stmfRet = stmfGetLuProp(hdl, STMF_LU_PROP_META_FILENAME, propVal,
	    &propValSize);
	(void) printf(PROPS_FORMAT, "Meta File");
	if (stmfRet == STMF_STATUS_SUCCESS) {
		(void) printf("%s\n", propVal);
	} else if (stmfRet == STMF_ERROR_NO_PROP) {
		(void) printf("not set\n");
	} else if (stmfRet == STMF_ERROR_NO_PROP_STANDBY) {
		(void) printf("prop unavailable in standby\n");
	} else {
		(void) printf("<error retrieving property>\n");
		ret++;
	}
	#endif

	stmfRet = stmfGetLuProp(hdl, STMF_LU_PROP_SIZE, propVal,
	    &propValSize);
	(void) printf(PROPS_FORMAT, "Size");
	if (stmfRet == STMF_STATUS_SUCCESS) {
		(void) printf("%s\n", propVal);
	} else if (stmfRet == STMF_ERROR_NO_PROP) {
		(void) printf("not set\n");
	} else if (stmfRet == STMF_ERROR_NO_PROP_STANDBY) {
		(void) printf("prop unavailable in standby\n");
	} else {
		(void) printf("<error retrieving property>\n");
		ret++;
	}

	stmfRet = stmfGetLuProp(hdl, STMF_LU_PROP_BLOCK_SIZE, propVal,
	    &propValSize);
	(void) printf(PROPS_FORMAT, "Block Size");
	if (stmfRet == STMF_STATUS_SUCCESS) {
		(void) printf("%s\n", propVal);
	} else if (stmfRet == STMF_ERROR_NO_PROP) {
		(void) printf("not set\n");
	} else if (stmfRet == STMF_ERROR_NO_PROP_STANDBY) {
		(void) printf("prop unavailable in standby\n");
	} else {
		(void) printf("<error retrieving property>\n");
		ret++;
	}

	#if 0
	stmfRet = stmfGetLuProp(hdl, STMF_LU_PROP_MGMT_URL, propVal,
	    &propValSize);
	(void) printf(PROPS_FORMAT, "Management URL");
	if (stmfRet == STMF_STATUS_SUCCESS) {
		(void) printf("%s\n", propVal);
	} else if (stmfRet == STMF_ERROR_NO_PROP) {
		(void) printf("not set\n");
	} else if (stmfRet == STMF_ERROR_NO_PROP_STANDBY) {
		(void) printf("prop unavailable in standby\n");
	} else {
		(void) printf("<error retrieving property>\n");
		ret++;
	}
	#endif

	stmfRet = stmfGetLuProp(hdl, STMF_LU_PROP_VID, propVal,
	    &propValSize);
	(void) printf(PROPS_FORMAT, "Vendor ID");
	if (stmfRet == STMF_STATUS_SUCCESS) {
		(void) printf("%s\n", propVal);
	} else if (stmfRet == STMF_ERROR_NO_PROP) {
		(void) printf("not set\n");
	} else if (stmfRet == STMF_ERROR_NO_PROP_STANDBY) {
		(void) printf("prop unavailable in standby\n");
	} else {
		(void) printf("<error retrieving property>\n");
		ret++;
	}

	stmfRet = stmfGetLuProp(hdl, STMF_LU_PROP_PID, propVal,
	    &propValSize);
	(void) printf(PROPS_FORMAT, "Product ID");
	if (stmfRet == STMF_STATUS_SUCCESS) {
		(void) printf("%s\n", propVal);
	} else if (stmfRet == STMF_ERROR_NO_PROP) {
		(void) printf("not set\n");
	} else if (stmfRet == STMF_ERROR_NO_PROP_STANDBY) {
		(void) printf("prop unavailable in standby\n");
	} else {
		(void) printf("<error retrieving property>\n");
		ret++;
	}

	stmfRet = stmfGetLuProp(hdl, STMF_LU_PROP_SERIAL_NUM, propVal,
	    &propValSize);
	(void) printf(PROPS_FORMAT, "Serial Num");
	if (stmfRet == STMF_STATUS_SUCCESS) {
		(void) printf("%s\n", propVal);
	} else if (stmfRet == STMF_ERROR_NO_PROP) {
		(void) printf("not set\n");
	} else if (stmfRet == STMF_ERROR_NO_PROP_STANDBY) {
		(void) printf("prop unavailable in standby\n");
	} else {
		(void) printf("<error retrieving property>\n");
		ret++;
	}

	(void) printf(PROPS_FORMAT, "LU Guid");
	printGuid(guid, stdout);
	(void) printf("\n");

	stmfRet = stmfGetLuProp(hdl, STMF_LU_PROP_WRITE_PROTECT, propVal,
	    &propValSize);
	(void) printf(PROPS_FORMAT, "Write Protect");
	if (stmfRet == STMF_STATUS_SUCCESS) {
		(void) printf("%s\n",
		    strcasecmp(propVal, "true") ? "Disabled" : "Enabled");
	} else if (stmfRet == STMF_ERROR_NO_PROP) {
		(void) printf("not set\n");
	} else if (stmfRet == STMF_ERROR_NO_PROP_STANDBY) {
		(void) printf("prop unavailable in standby\n");
	} else {
		(void) printf("<error retrieving property>\n");
		ret++;
	}

	stmfRet = stmfGetLuProp(hdl, STMF_LU_PROP_WRITE_CACHE_DISABLE, propVal,
	    &propValSize);
	(void) printf(PROPS_FORMAT, "Writeback Cache");
	if (stmfRet == STMF_STATUS_SUCCESS) {
		(void) printf("%s\n",
		    strcasecmp(propVal, "true") ? "Enabled" : "Disabled");
	} else if (stmfRet == STMF_ERROR_NO_PROP) {
		(void) printf("not set\n");
	} else if (stmfRet == STMF_ERROR_NO_PROP_STANDBY) {
		(void) printf("prop unavailable in standby\n");
	} else {
		(void) printf("<error retrieving property>\n");
		ret++;
	}

	stmfRet = stmfGetLuProp(hdl, STMF_LU_PROP_ACCESS_STATE, propVal,
	    &propValSize);
	(void) printf(PROPS_FORMAT, "Access State");
	if (stmfRet == STMF_STATUS_SUCCESS) {
		if (strcmp(propVal, STMF_ACCESS_ACTIVE) == 0) {
			(void) printf("%s\n", "Active");
		} else if (strcmp(propVal,
		    STMF_ACCESS_ACTIVE_TO_STANDBY) == 0) {
			(void) printf("%s\n", "Active->Standby");
		} else if (strcmp(propVal, STMF_ACCESS_STANDBY) == 0) {
			(void) printf("%s\n", "Standby");
		} else if (strcmp(propVal,
		    STMF_ACCESS_STANDBY_TO_ACTIVE) == 0) {
			(void) printf("%s\n", "Standby->Active");
		} else {
			(void) printf("%s\n", "Unknown");
		}
	} else if (stmfRet == STMF_ERROR_NO_PROP) {
		(void) printf("not set\n");
	} else {
		(void) printf("<error retrieving property>\n");
		ret++;
	}

done:
	(void) stmfFreeLuResource(hdl);
	return (ret);

}


/*
 * printLuProps
 *
 * Prints the properties for a logical unit
 *
 */
static void
printLuProps(stmfLogicalUnitProperties *luProps)
{
	(void) printf(PROPS_FORMAT, "Operational Status");
	switch (luProps->status) {
		case STMF_LOGICAL_UNIT_ONLINE:
			(void) printf("Online");
			break;
		case STMF_LOGICAL_UNIT_OFFLINE:
			(void) printf("Offline");
			break;
		case STMF_LOGICAL_UNIT_ONLINING:
			(void) printf("Onlining");
			break;
		case STMF_LOGICAL_UNIT_OFFLINING:
			(void) printf("Offlining");
			break;
		case STMF_LOGICAL_UNIT_UNREGISTERED:
			(void) printf("unregistered");
			(void) strncpy(luProps->providerName, "unregistered",
			    sizeof (luProps->providerName));
			break;
		default:
			(void) printf("unknown");
			break;
	}
	(void) printf("\n");
	#if 0
	(void) printf(PROPS_FORMAT, "Provider Name");
	if (luProps->providerName[0] != 0) {
		(void) printf("%s", luProps->providerName);
	} else {
		(void) printf("unknown");
	}
	(void) printf("\n");
	(void) printf(PROPS_FORMAT, "Alias");
	if (luProps->alias[0] != 0) {
		(void) printf("%s", luProps->alias);
	} else {
		(void) printf("-");
	}
	(void) printf("\n");
	#endif
}



/*   listinitiator
 *   
 *   list the connectd initiator 
 *    
 */

static int listinitiator(int operandLen, char *operands[], cmdOptions_t *options, void *args)
{
	int stmfRet;
	int ret = 0;
	int i;
	stmfSessionList *sessionlist;
	stmfDevidList *targetlist;
	wchar_t initiator[STMF_IDENT_LENGTH + 1];
	UNUSED_PARAMETER(operandLen);
	UNUSED_PARAMETER(operands);
	UNUSED_PARAMETER(options);
	UNUSED_PARAMETER(args);
	if ((stmfRet = stmfGetTargetList(&targetlist)) != STMF_STATUS_SUCCESS)
	{
		switch (stmfRet) {
			case STMF_ERROR_NOT_FOUND:
				ret = 0;
				break;
			case STMF_ERROR_SERVICE_OFFLINE:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service offline"));
				break;
			case STMF_ERROR_BUSY:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("resource busy"));
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				break;
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			default:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("unknown error"));
				break;
		}
		return (1);
	}

	for (i=0; i < targetlist->cnt; i++)
	{
		int j;
		stmfRet = stmfGetSessionList(&(targetlist->devid[i]), &sessionlist);
		if (stmfRet == STMF_STATUS_SUCCESS)
		{
			for (j = 0; j < sessionlist->cnt; j++)
			{
				(void) mbstowcs(initiator,(char *)sessionlist->session[j].initiator.ident,
					STMF_IDENT_LENGTH);
				initiator[STMF_IDENT_LENGTH] = 0;
				(void) printf("Initiator:%ls\n", initiator);
			}
			stmfFreeMemory(sessionlist);
		}
		else 
		{
			(void) fprintf(stderr, "%s\n", gettext("Get certain session info faild.\n"));
			ret = 1;
		}
	}	
	stmfFreeMemory(targetlist);
	return (ret);
}

static int
getStmfState(stmfState *state)
{
	int ret;

	ret = stmfGetState(state);
	switch (ret) {
		case STMF_STATUS_SUCCESS:
			break;
		case STMF_ERROR_PERM:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("permission denied"));
			break;
		case STMF_ERROR_SERVICE_NOT_FOUND:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("STMF service not found"));
			break;
		case STMF_ERROR_BUSY:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("resource busy"));
			break;
		case STMF_ERROR_SERVICE_DATA_VERSION:
			(void) fprintf(stderr, "%s: %s\n", cmdName,
			    gettext("STMF service version incorrect"));
			break;
		default:
			(void) fprintf(stderr, "%s: %s: %d\n", cmdName,
			    gettext("unknown error"), ret);
			break;
	}
	return (ret);
}

/*
 * online or offline all pppt target for clusterd
 */
static int
onlineOfflinePpptTarget(int state)
{
	int ret = 0, i;
	stmfDevidList *targetList;
	stmfTargetProperties targetProps;
	wchar_t targetIdent[STMF_IDENT_LENGTH + 1];

	if ((ret = stmfGetTargetList(&targetList)) != STMF_STATUS_SUCCESS) {
		syslog(LOG_ERR, "online offline pppt get target list failed, ret:0x%x", ret);
		return (1);
	} else {
		for (i = 0; i < targetList->cnt; i++) {
			ret = stmfGetTargetProperties(&(targetList->devid[i]),
				&targetProps);
			if (ret == STMF_STATUS_SUCCESS) {
				(void) mbstowcs(targetIdent, (char *)targetList->devid[i].ident,
					STMF_IDENT_LENGTH);
				targetIdent[STMF_IDENT_LENGTH] = 0;
				if (strcmp(targetProps.providerName, "pppt") == 0) {
					if (state == ONLINE_TARGET) {
						ret = stmfOnlineTarget(&(targetList->devid[i]));
					} else if (state == OFFLINE_TARGET) {
						ret = stmfOfflineTarget(&(targetList->devid[i]));
					}
					if (ret != STMF_STATUS_SUCCESS) {
						syslog(LOG_ERR, "online offline pppt target failed,"
							" %ls, state:%d", targetIdent, state);
					} else {
						(void)printf("target:%ls, provider:%s\n",
							targetIdent, targetProps.providerName);
					}
				}
			} else {
				syslog(LOG_ERR, "offline ppt get target props failed");
			}
		}
	}

	return (0);
}


/*
 * onlineOfflineTarget
 *
 * Purpose: Online or offline a target
 *
 * target - target to online or offline
 *
 * state - ONLINE_TARGET
 *         OFFLINE_TARGET
 */
static int
onlineOfflineTarget(char *target, int state)
{
	int ret = 0;
	stmfDevid devid;

	if (parseDevid(target, &devid) != 0) {
		(void) fprintf(stderr, "%s: %s: %s\n",
		    cmdName, target, gettext("unrecognized device id"));
		return (1);
	}
	if (state == ONLINE_TARGET) {
		ret = stmfOnlineTarget(&devid);
	} else if (state == OFFLINE_TARGET) {
		ret = stmfOfflineTarget(&devid);
	}
	if (ret != STMF_STATUS_SUCCESS) {
		switch (ret) {
			case STMF_ERROR_PERM:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("permission denied"));
				break;
			case STMF_ERROR_SERVICE_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service not found"));
				break;
			case STMF_ERROR_NOT_FOUND:
				(void) fprintf(stderr, "%s: %s: %s\n", cmdName,
				    target, gettext("not found"));
				break;
			case STMF_ERROR_SERVICE_DATA_VERSION:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("STMF service version incorrect"));
				break;
			default:
				(void) fprintf(stderr, "%s: %s\n", cmdName,
				    gettext("unknown error"));
				break;
		}
	}
	return (ret);
}



/*
 * onlinetarget
 *
 * Purpose: Online a target
 *
 */
/*ARGSUSED*/
static int
onlinetarget(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	int ret;
	stmfState state;

	ret = getStmfState(&state);
	if (ret != STMF_STATUS_SUCCESS)
		return (ret);
	if (state.operationalState == STMF_SERVICE_STATE_OFFLINE ||
	    state.operationalState == STMF_SERVICE_STATE_OFFLINING) {
		(void) fprintf(stderr, "%s: %s\n", cmdName,
		    gettext("STMF service is offline"));
		return (1);
	}

	if (operands[0] != NULL && strcmp(operands[0], "pppt") == 0) {
		return (onlineOfflinePpptTarget(ONLINE_TARGET));
	} else {
		return (onlineOfflineTarget(operands[0], ONLINE_TARGET));
	}
}


/*
 * offlinetarget
 *
 * Purpose: Offline a target
 *
 */
/*ARGSUSED*/
static int
offlinetarget(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	if (operands[0] != NULL && strcmp(operands[0], "pppt") == 0) {
		return (onlineOfflinePpptTarget(OFFLINE_TARGET));
	} else {
		return (onlineOfflineTarget(operands[0], OFFLINE_TARGET));
	}
}



/*   getlu_prop
 *   
 *   Get the lun name and its guid
 *    return pointer point to the end of the  arrays of structures
 */
static int getlu_prop(list_t *lunrelatelistp)
{
	stmfGuidList *lulist;
	lunrelated *lunend;
	char *unavail = "unavailable";
	luResource hdl;
	char dataFileName[MAXNAMELEN];
	size_t fileNameSize;
	stmfLogicalUnitProperties luProps;
	int stmfRet, i, s, ret=0;
	fileNameSize = sizeof(dataFileName);
	/*获取系统中所有的lun*/
	if ((stmfRet = stmfGetLogicalUnitList(&lulist)) != STMF_STATUS_SUCCESS)  
	{
		switch (stmfRet) {
			case STMF_ERROR_SERVICE_NOT_FOUND: 
				(void) printf("STMF service not found\n");
				break;
			case STMF_ERROR_BUSY:
				(void) printf ("resource busy\n");
				break;
			case STMF_ERROR_PERM:
			    (void) printf("permission denid\n");
                break;
            case STMF_ERROR_SERVICE_DATA_VERSION:
                (void) printf ("STMF service version incorrect\n");
                break;
            default:
                (void) printf ("list faild\n");
                break;
           }
	     stmfFreeMemory(lulist);
		 list_destroy(lunrelatelistp);
         return (1);
    }
	for (i =0; i < lulist->cnt; i++)
    {
		/*获取lun的相关资源*/
		if ((stmfRet = stmfGetLuResource(&(lulist->guid[i]), &hdl))
            != STMF_STATUS_SUCCESS){
			switch (stmfRet) {
				case STMF_ERROR_BUSY:
					(void) fprintf(stderr, "%s\n",
					    gettext("resource busy"));
					break;
				case STMF_ERROR_PERM:
					(void) fprintf(stderr, "%s\n",
					    gettext("permission denied"));
					break;
				case STMF_ERROR_NOT_FOUND:
					/* No error here */
					break;
				default:
					(void) fprintf(stderr, "%s\n",
					    gettext("get LUN Resource failed"));
					break;
			}
			continue;
	    }
		lunend = (lunrelated *)malloc(sizeof(lunrelated));
		if (lunend == NULL)
		{
			(void) printf("allocate memory faild.\n");
			goto lu_exit;
		}
		(void) memset(lunend, 0, sizeof(lunrelated));
		for(s=0; s < 16; s++)
		{
			lunend->lundatafield.lunguid.guid[s] = lulist->guid[i].guid[s];
		}
		stmfRet = stmfGetLuProp(hdl, STMF_LU_PROP_ACCESS_STATE, dataFileName, &fileNameSize);
		if (stmfRet != STMF_STATUS_SUCCESS)
		{
			(void) printf("Get the LUN Access State fails.\n");
			free(lunend);
			goto lu_exit;
		}
		if (strcmp(dataFileName, STMF_ACCESS_ACTIVE)  == 0)
		{
			stmfRet = stmfGetLuProp(hdl, STMF_LU_PROP_FILENAME, dataFileName, &fileNameSize);
			/*if(stmfRet != STMF_STATUS_SUCCESS)
			{
				printf("Get Data File fail.");
			}*/
			if (stmfRet == STMF_STATUS_SUCCESS)
			{
				extractlunalias(dataFileName, lunend->lundatafield.lunalias);
			}
			else 
			{
				(void) printf("Get LUN property fails.\n");
				free(lunend);
				goto lu_exit;
			}
		}
		/*提取在standby状态下的lun别名*/
		else if (strcmp(dataFileName, STMF_ACCESS_STANDBY)  == 0)
		{
			stmfRet = stmfGetLogicalUnitProperties(
				    &(lulist->guid[i]), &luProps);
			if (stmfRet == STMF_STATUS_SUCCESS)
			{
				extractlunalias(luProps.alias, lunend->lundatafield.lunalias);
			}
			else
			{
				(void) printf("Get standby lun alias faild.\n");
				free(lunend);
				goto lu_exit;
			}
		}
		else
		{
			(void) strncpy(lunend->lundatafield.lunalias, unavail, 256);
		}
		list_insert_tail(lunrelatelistp, lunend);
		(void) stmfFreeLuResource(hdl);
	}
	stmfFreeMemory(lulist);
	
	return (ret);

lu_exit:
	stmfFreeMemory(lulist);
	(void) stmfFreeLuResource(hdl);
	for(lunend = list_head(lunrelatelistp); lunend; lunend= list_next(lunrelatelistp, lunend)) 
	{
		free(lunend);
	}
	list_destroy(lunrelatelistp);
	ret = 1;
	return (ret);
}


/*   getlu_name
 *   
 *   transform the lun alias and return the lun name
 *    
 */
static int getlu_name(char *aliasp, stmfGuid *lunuidp)
{
	int s, ret, stmfRet;
	list_t lu_name_list;
	lunrelated *lunstart;
	ret = 0;
	list_create(&lu_name_list, sizeof(lunrelated), offsetof(struct _lun_relate, lunrelatelink));
	stmfRet = getlu_prop(&lu_name_list);
	if (stmfRet == 1)
	{
		return (1);
	}
	for(lunstart = list_head(&lu_name_list); lunstart; lunstart = list_next(&lu_name_list, lunstart))
	{
		if ((strcmp(lunstart->lundatafield.lunalias, aliasp)) == 0)
		{
			for(s=0; s < 16; s++)
			{
				lunuidp->guid[s] = lunstart->lundatafield.lunguid.guid[s];
			}
			break;
		}
	}
	if (lunstart == NULL)
	{
		(void) fprintf(stderr, "%s: %s\n", aliasp,
					    gettext("not found"));
		ret = 1;
	}
	for(lunstart = list_head(&lu_name_list); lunstart; lunstart = list_next(&lu_name_list, lunstart))
	{
		free(lunstart);
	}
	list_destroy(&lu_name_list);
	return (ret);

}




/*   getlunviewprop
 *   
 *   get the lun property and related view entry info
 *   return the pointer point to the struct view 
 *    
 */

static int getlunviewprop(list_t *view_list_p)
{
	int stmfRet, i, ret = 0;
	char *emptyp = "all"; 
	char *unavail = "unavailable";
	char *noset = "not set";
	char *propunavail = "prop unavailable in standby";
	char *properror = "error retrieving property";
	view *viewp;
	luResource hdl;
	stmfGuidList *lulist;
	stmfViewEntryList *viewEntryList;
	stmfLogicalUnitProperties luProps;
	char dataFileName[MAXNAMELEN];
	size_t fileNameSize;
	view *viewprint;
	int lundamageflag = 0;
	int freelunresource = 0;
	viewEntryList = NULL;
	fileNameSize = sizeof(dataFileName);
	
	/*获取系统中所有的lun*/
	if ((stmfRet = stmfGetLogicalUnitList(&lulist)) != STMF_STATUS_SUCCESS)  
	{
		switch (stmfRet) {
			case STMF_ERROR_SERVICE_NOT_FOUND: 
				(void) printf("STMF service not found\n");
				break;
			case STMF_ERROR_BUSY:
				(void) printf ("resource busy\n");
				break;
			case STMF_ERROR_PERM:
			    (void) printf("permission denid\n");
                break;
            case STMF_ERROR_SERVICE_DATA_VERSION:
                (void) printf ("STMF service version incorrect\n");
                break;
            default:
                (void) printf ("list faild\n");
                break;
           }
		ret++;
         return (ret);
    }
	
	for (i =0; i < lulist->cnt; i++)
    {
		int j;
		if ((stmfRet = stmfGetLuResource(&(lulist->guid[i]), &hdl))   
	    	== STMF_ERROR_NOT_FOUND)
		{
			lundamageflag =1;
		}
		else if(stmfRet != STMF_STATUS_SUCCESS)
		{
			switch (stmfRet) {
				case STMF_ERROR_BUSY:
					(void) fprintf(stderr, "%s\n",
					    gettext("resource busy"));
					break;
				case STMF_ERROR_PERM:
					(void) fprintf(stderr, "%s\n",
					    gettext("permission denied"));
					break;
				default:
					(void) fprintf(stderr, "%s\n",
					    gettext("get LUN Resource failed"));
					break;
			}
			continue;
		}
		/*若成功获取lun资源，把释放lun资源标志位置为1*/
		if (lundamageflag != 1)
		{
			freelunresource = 1;
		}
		/*获取每个lun的所有viewentry信息*/
      	stmfRet = stmfGetViewEntryList (&(lulist->guid[i]), &viewEntryList);  
		if (stmfRet != STMF_STATUS_SUCCESS)
		{
			/*printf("%s don't have view entry.\n",luProps.alias);*/
			lundamageflag = 0;
			(void)stmfFreeLuResource(hdl);
			continue;
		}
		/*保存viewentry信息*/
		for (j=0; j < viewEntryList->cnt; j++)    
		{
			int s;
			viewp = (view *)malloc(sizeof(struct _view_info));
			if (viewp == NULL)
			{
				(void) printf("allocate memory faild.\n");
				goto lunview_exit;
			}
			(void) memset(viewp, 0, sizeof(struct _view_info));
			
			/*viewp->view_data._LUName = (char *)malloc(256*sizeof(char));
			viewp->view_data._SerialNum = (char *) malloc(256*sizeof(char));
			viewp->view_data._hostGroup = (char *)malloc(256*sizeof(char));
			viewp->view_data._targetGroup = (char *)malloc(256*sizeof(char));
			viewp->view_data._hgtgname = (char *)malloc(513*sizeof(char));*/
			/*if (viewp->_LUName == NULL || viewp->_SerialNum == NULL ||
				viewp->_hostGroup == NULL || viewp->_targetGroup == NULL || viewp->_hgtgname == NULL)
			{
				(void) printf("allocate memory faild.\n");
				goto lunview_exit;
			}*/
			/*(void) memset(viewp->view_data._LUName,0,256*sizeof(char));
			(void) memset(viewp->view_data._SerialNum,0,256*sizeof(char));
			(void) memset(viewp->view_data._hostGroup,0,256*sizeof(char));
			(void) memset(viewp->view_data._targetGroup,0,256*sizeof(char));
			(void) memset(viewp->view_data._hgtgname,0,513*sizeof(char));*/
 			for(s=0; s < 16; s++)
			{
				viewp->view_data.lunguid.guid[s] = lulist->guid[i].guid[s];
			}
			viewp->view_data.veindex = viewEntryList->ve[j].veIndex;
			if (lundamageflag == 1)
			{
				(void)strncpy(viewp->view_data._LUName, unavail, 256);
				(void)strncpy(viewp->view_data._SerialNum, unavail, 256);
			}
			else
			{
				stmfRet = stmfGetLuProp(hdl, STMF_LU_PROP_ACCESS_STATE, dataFileName, &fileNameSize);
				if (stmfRet != STMF_STATUS_SUCCESS)
				{
					(void) printf("Get the LUN Access State fails.\n");
					free(viewp);
					goto lunview_exit;
				}
				/*提取active状态下的lun的data file*/
				if (strcmp(dataFileName, STMF_ACCESS_ACTIVE)  == 0)
				{
					stmfRet = stmfGetLuProp(hdl, STMF_LU_PROP_FILENAME, dataFileName, &fileNameSize);
					/*if(stmfRet != STMF_STATUS_SUCCESS)
					{
						printf("Get Data File fail.");
					}*/
					if (stmfRet == STMF_STATUS_SUCCESS)
					{
						extractlunalias(dataFileName, viewp->view_data._LUName);
					}
					else 
					{
						(void) printf("Get LUN property fails.\n");
						free(viewp);
						goto lunview_exit;
					}
				}
				/*提取在standby状态下的lun别名*/
				else if (strcmp(dataFileName, STMF_ACCESS_STANDBY)  == 0)
				{
					stmfRet = stmfGetLogicalUnitProperties(
						    &(lulist->guid[i]), &luProps);
					if (stmfRet == STMF_STATUS_SUCCESS)
					{
						extractlunalias(luProps.alias, viewp->view_data._LUName);
					}
					else
					{
						(void) printf("Get standby lun alias faild.\n");
						free(viewp);
						goto lunview_exit;
					}
				}
				else
				{
					(void)strncpy(viewp->view_data._LUName, unavail, 256);
				}
				/*获取lun的serial num*/
				stmfRet = stmfGetLuProp(hdl, STMF_LU_PROP_SERIAL_NUM, dataFileName, &fileNameSize);  
				if (stmfRet == STMF_STATUS_SUCCESS) {
					(void) strcpy(viewp->view_data._SerialNum, dataFileName);
				} else if (stmfRet == STMF_ERROR_NO_PROP) {
					(void) strncpy(viewp->view_data._SerialNum, noset, 256);
				} else if (stmfRet == STMF_ERROR_NO_PROP_STANDBY) {
					(void) strncpy(viewp->view_data._SerialNum, propunavail, 256);
				} else {
					(void) strncpy(viewp->view_data._SerialNum, properror, 256);
				}
				
			}
			(void)strcpy(viewp->view_data._hostGroup,viewEntryList->ve[j].hostGroup);
			(void) strcpy(viewp->view_data._targetGroup,viewEntryList->ve[j].targetGroup);
			viewp->view_data.LUNIndex = (((viewEntryList->ve[j].luNbr[0]) & 0x3F) << 8) | (viewEntryList->ve[j].luNbr[1]);
			/*若lun的target组为空，保存为all*/
			if (viewEntryList->ve[j].allTargets)   
			{
				(void)strcpy(viewp->view_data._targetGroup, emptyp);
			}
			/*若lun的host组为空，保存为all*/
			if (viewEntryList->ve[j].allHosts)    
			{
				(void) strcpy(viewp->view_data._hostGroup, emptyp);
			}
			(void) strncpy(viewp->view_data._hgtgname, viewp->view_data._hostGroup, 513*sizeof(char));
			*(viewp->view_data._hgtgname + strlen(viewp->view_data._hostGroup)) = ',';
			(void) strncat(viewp->view_data._hgtgname, viewp->view_data._targetGroup, 256*sizeof(char));
			#ifdef DEBUG
			{
				(void) printf("LUName\t\tLUIndex\t\tHostGroup\tTargetGroup\n%s\t%d\t\t%s\t\t%s\n",viewp->_LUName,viewp->LUNIndex,viewp->_hostGroup,viewp->_targetGroup);
			}
			#endif
			list_insert_tail(view_list_p, viewp);
		}
		lundamageflag = 0;
		if (freelunresource == 1)
		{
			freelunresource = 0;
			(void) stmfFreeLuResource(hdl); 
		}
		stmfFreeMemory(viewEntryList);
    }
	  /*对保存的lun view信息按ID号排序*/
	for(viewprint = list_head(view_list_p); viewprint; viewprint = list_next(view_list_p, viewprint))  
	{
		view *viewcmp;
		view *viewtmp;
		viewtmp= (view *)malloc(sizeof(struct _view_info));
		viewcmp = list_next(view_list_p, viewprint);
		/*printf("$$$LUName: %s\n",viewcmp->view_data._LUName);
		(void) printf("***\nLUName\t\tLUIndex\t\tHostGroup\tTargetGroup\tHgTgName\n%s\t%d\t\t%s\t\t%s\t\t%s\n",
			viewprint->view_data._LUName,viewprint->view_data.LUNIndex,viewprint->view_data._hostGroup,viewprint->view_data._targetGroup,viewprint->view_data._hgtgname);*/
		for (; viewcmp; viewcmp = list_next(view_list_p, viewcmp))
		{
			if((viewprint->view_data.LUNIndex) > (viewcmp->view_data.LUNIndex))
			{
				(void) memcpy(&viewtmp->view_data,&viewcmp->view_data, sizeof(struct _view_data_field));
				(void) memcpy(&viewcmp->view_data,&viewprint->view_data, sizeof(struct _view_data_field));
				(void) memcpy(&viewprint->view_data,&viewtmp->view_data, sizeof(struct _view_data_field));
				/*viewtmp->view_data = viewcmp->view_data;
				viewcmp->view_data = viewprint->view_data;
				viewprint->view_data = viewtmp->view_data;*/
			}
		}
		free(viewtmp);
	}
	/*释放先前分配的资源*/
	/*if (freelunresource == 1)
	{
		(void) stmfFreeLuResource(hdl); 
	}
	stmfFreeMemory(viewEntryList);*/
	stmfFreeMemory(lulist);
	return (ret);

lunview_exit:
	for(viewprint = list_head(view_list_p); viewprint; viewprint = list_next(view_list_p, viewprint)) 
	{
		free(viewprint);
	}
	list_destroy(view_list_p);
	stmfFreeMemory(lulist);
	(void)stmfFreeLuResource(hdl);
	stmfFreeMemory(viewEntryList);
	ret = 1;
	return (ret);
}



/*   listlunmap
 *   
 *   list every group contains which LUN and its ID\Serial Num in the group
 *    
 */

static int listlunmapFunc(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	int stmfRet;
	view *viewprint;
	list_t view_list;
	char *emptyp;
	/*只打印含有lun的组的标志*/
	int printflag;
	stmfGroupList *hostgrouplist;
	stmfGroupList *targetgrouplist;
	stmfGroupProperties *groupProps;
	char inputhost[256], inputtarget[256];
	int n, m, l, outerloop, ret=0;
	boolean_t operandenter;
	boolean_t found1, found2, found3, found4;
	boolean_t verbose = B_FALSE;	
	emptyp = "all";	
	/*用于遍历所保存的lun的viewentry信息*/
	printflag = 0;	
	found1 = found2 = found3 = found4 = B_FALSE;
	UNUSED_PARAMETER(args);
	for (; options->optval; options++) {
		switch (options->optval) {
			case 'v':
				verbose = B_TRUE;
				break;
			default:
				(void) fprintf(stderr, "%s: %c: %s\n",
				    cmdName, options->optval,
				    gettext("unknown option"));
				return (1);
		}
	}
	if (operandLen > 0)
	{
		outerloop = operandLen;
		operandenter = B_TRUE;
	}else {
		outerloop = 1;
		operandenter = B_FALSE;
	}
	/*建立链表*/
	list_create(&view_list, sizeof(view), offsetof(struct _view_info, listlink));
	
	stmfRet= getlunviewprop(&view_list);
	if (stmfRet == 1)
	{
		return (1);
	}
	/*获取系统中存在的所有主机组信息*/
	stmfRet = stmfGetHostGroupList(&hostgrouplist);  
	if (stmfRet == STMF_ERROR_NOMEM)
	{
		(void) printf("Don't have enough memory for host group list.\n");
		ret = 1;
		goto lunmapdone;
	}
	/*获取所有target组名字*/
	stmfRet=stmfGetTargetGroupList(&targetgrouplist); 
	if (stmfRet == STMF_ERROR_NOMEM)
	{
		(void) printf("Don't have enough memory for target group list.\n");
		ret = 1;
		stmfFreeMemory(hostgrouplist);
		goto lunmapdone;
	}
	if (verbose == B_TRUE)
	{
		/*打印主机组内成员*/
		for (n=0; n < hostgrouplist->cnt; n++)
		{
			for(viewprint = list_head(&view_list); viewprint; viewprint = list_next(&view_list, viewprint))
			{
				if ((strcmp(viewprint->view_data._hostGroup, hostgrouplist->name[n])) == 0)
				{
					stmfRet = getgroupmember(&(hostgrouplist->name[n]), &groupProps,HOST_GROUP, LISTLUNMAP);
					if (stmfRet != 0)
					{
						ret = 1;
						stmfFreeMemory(hostgrouplist);
						stmfFreeMemory(targetgrouplist);
						goto lunmapdone;
					}
					break;
				}
			}
		}
		/*打印目标组内成员*/
		for (n=0; n < targetgrouplist->cnt; n++)
		{
			for(viewprint = list_head(&view_list); viewprint; viewprint = list_next(&view_list, viewprint))
			{
				if ((strcmp(viewprint->view_data._targetGroup, targetgrouplist->name[n])) == 0)
				{
					stmfRet = getgroupmember(&(targetgrouplist->name[n]), &groupProps,TARGET_GROUP,LISTLUNMAP);
					if (stmfRet != 0)
					{
						ret = 1;
						stmfFreeMemory(hostgrouplist);
						stmfFreeMemory(targetgrouplist);
						goto lunmapdone;
					}
					break;
				}
			}
		}
	}
    /*按需打印组内信息*/
	(void) printf("    Lu-Number     LUN NAME                    SN\n");
	for (l = 0; l < outerloop; l++)
	{
		if (operandenter)
		{
			char *chartosplit, *operandstringp;
			char *nextinputoperand = NULL;
			if ((operandstringp = (char *)malloc(512*sizeof(char))) == NULL)
			{
				(void) fprintf(stderr, "Allocate memory faild.\n");
				ret = 1;
				stmfFreeMemory(hostgrouplist);
				stmfFreeMemory(targetgrouplist);
				goto lunmapdone;
			}
			operandstringp = strncpy(operandstringp, operands[l],512*sizeof(char));
			/*判断操作数格式*/
			chartosplit = strchr(operandstringp,',');
			if (chartosplit == NULL)
			{
				(void) fprintf(stderr, "%s : %s: %s\n", cmdName, operands[l], gettext("not found"));
				ret = 1;
				continue;
			}
			#if 0
			/*提取输入的操作数*/
			while ((chartosplit = strtok(operandstringp, ",")) != NULL)
			{
				 /*(void) strncpy (p[in], chartosplit, sizeof(inputhost));*/
				 p[in] = chartosplit;
				 in++;
				 operandstringp = NULL;
			}
			if (in >= 3)
			{
				(void) fprintf(stderr, "%s : %s: %s\n", cmdName, operands[l], gettext("not found"));
				ret = 1;
				break;
			}
			if (chartosplit == NULL)
			{
				(void) printf("Input %s incorrect!Please input like this \"hg1,tg1\"\n", operandstringp);
				exit(1);
			}
			printf("%d\n", (chartosplit - operandstringp));
			inputhost[strlen (inputhost)] = '\0';
			(void) strncpy (inputhost, p[0], sizeof(inputhost));
			(void) strncpy (inputtarget, p[1], sizeof(inputtarget));
			#endif
			/*提取操作数的值，使其分别为输入的主机组和目标组的名字*/
			if ((chartosplit = strtok_r(operandstringp, ",", &nextinputoperand)) != NULL)
			{
				(void) strncpy (inputhost, chartosplit, sizeof(inputhost));
				(void) strncpy (inputtarget, nextinputoperand, sizeof(inputtarget));
			}
			if (((strcmp(inputhost, "all")) == 0) && ((strcmp(inputtarget, "all")) == 0))
			{
				found1 = B_TRUE;
			}
			free(operandstringp);
			operandstringp = NULL;
		}
		/*打印host组和target组均为空的情况*/
		if((found1 && operandenter) || !operandenter)
		{
			for(viewprint = list_head(&view_list); viewprint; viewprint = list_next(&view_list, viewprint))
			{
				if ((strcmp(viewprint->view_data._hostGroup, emptyp) == 0) && (strcmp(viewprint->view_data._targetGroup, emptyp) == 0))
				{
					++printflag;
					if (printflag == 1)
					{
						(void) printf("all,all:\n");
					}
					(void) printf(LUNMAPLIST_FORMAT,viewprint->view_data.LUNIndex, viewprint->view_data._LUName,viewprint->view_data._SerialNum);
				}
			}
			printflag = 0;	
		}

		for (n=0; n < hostgrouplist->cnt; n++)
		{
			int j;
			if (operandenter)
			{
				if (((strcmp(hostgrouplist->name[n], inputhost)) == 0) && ((strcmp(inputtarget, "all")) == 0))
				{
					found2 = B_TRUE;
				}
			}
			if ((found2 && operandenter) || !operandenter)
			{
				for(viewprint = list_head(&view_list); viewprint; viewprint = list_next(&view_list, viewprint))   
				{
					/*打印只包含相同主机组的lun*/
					if (((strcmp(viewprint->view_data._hostGroup, hostgrouplist->name[n])) == 0) && ((strcmp(viewprint->view_data._targetGroup, emptyp)) == 0))  
					{
						++printflag;
						if(printflag == 1)
						{
							(void) printf("%s,all:\n", hostgrouplist->name[n]);
							/*if(verbose == B_TRUE)
							{
								stmfRet = getgroupmember(&(hostgrouplist->name[n]), &groupProps,HOST_GROUP);
								if (stmfRet != 0)
								{
									ret = 1;
									stmfFreeMemory(hostgrouplist);
									stmfFreeMemory(targetgrouplist);
									goto lunmapdone;
								}
							}*/
						}
						(void) printf(LUNMAPLIST_FORMAT, viewprint->view_data.LUNIndex,viewprint->view_data._LUName,viewprint->view_data._SerialNum);
					}
				}
				printflag = 0;
				if (found2 && operandenter)
				{
					break;
				}
			}
			/*打印*/
			for(j=0; j < targetgrouplist->cnt; j++)
			{
				if (operandenter)
				{
					if (((strcmp(hostgrouplist->name[n], inputhost)) == 0) && ((strcmp(inputtarget, targetgrouplist->name[j])) == 0))
					{
						found3 = B_TRUE;
					}
				}
				if ((found3 && operandenter) || !operandenter)
				{
					for(viewprint = list_head(&view_list); viewprint; viewprint = list_next(&view_list, viewprint))    
					{
						if (((strcmp(viewprint->view_data._hostGroup, hostgrouplist->name[n])) == 0) && ((strcmp(viewprint->view_data._targetGroup, targetgrouplist->name[j])) == 0))
						{
							++printflag;
							if(printflag == 1)
							{
								(void) printf("%s,%s:\n", hostgrouplist->name[n],targetgrouplist->name[j]);
								/*if (verbose == B_TRUE)
								{
									stmfRet = getgroupmember(&(hostgrouplist->name[n]), &groupProps,HOST_GROUP);
									if (stmfRet != 0)
									{
										ret = 1;
										stmfFreeMemory(hostgrouplist);
										stmfFreeMemory(targetgrouplist);
										goto lunmapdone;
									}
									stmfRet = getgroupmember(&(targetgrouplist->name[j]), &groupProps,TARGET_GROUP);
									if (stmfRet != 0)
									{
										ret = 1;
										stmfFreeMemory(hostgrouplist);
										stmfFreeMemory(targetgrouplist);
										goto lunmapdone;
									}
								}*/
							}
							(void) printf(LUNMAPLIST_FORMAT,viewprint->view_data.LUNIndex, viewprint->view_data._LUName,viewprint->view_data._SerialNum);
						}
					}
					printflag = 0;
					if (found3 && operandenter)
					{
						break;
					}
				}
			}	
		}

		/*打印host组为空的情况*/
		for(m=0; m < targetgrouplist->cnt; m++)  
		{
			if (operandenter)
			{
				if (((strcmp(inputhost, "all")) == 0) && ((strcmp(inputtarget, targetgrouplist->name[m])) == 0))
				{
					found4 = B_TRUE;
				}
			}
			if ((found4 && operandenter) || !operandenter)
			{
				for(viewprint = list_head(&view_list); viewprint; viewprint = list_next(&view_list, viewprint))    
				{
					if (((strcmp(viewprint->view_data._hostGroup, emptyp)) == 0) && ((strcmp(viewprint->view_data._targetGroup, targetgrouplist->name[m])) == 0))
					{
						++printflag;
						if(printflag == 1)
						{
							(void) printf("all,%s:\n", targetgrouplist->name[m]);
							/*if (verbose == B_TRUE)
							{
								stmfRet = getgroupmember(&(targetgrouplist->name[m]), &groupProps,TARGET_GROUP);
								if (stmfRet != 0)
								{
									ret = 1;
									stmfFreeMemory(hostgrouplist);
									stmfFreeMemory(targetgrouplist);
									goto lunmapdone;
								}
							}*/
						}
						(void) printf(LUNMAPLIST_FORMAT, viewprint->view_data.LUNIndex,viewprint->view_data._LUName,viewprint->view_data._SerialNum);
					}
				}
				if (found4 && operandenter)
				{
					break;
				}
			}
			printflag = 0;
		}
		
		if (operandenter && !(found1 || found2 || found3 || found4))
		{
			(void) fprintf(stderr, "%s : %s: %s\n", cmdName, operands[l], gettext("not found"));
			ret = 1;
		}
		found1 = found2 = found3 = found4 = B_FALSE;
	}
	
	
	/*释放先前分配的内存*/
	stmfFreeMemory(hostgrouplist);
	stmfFreeMemory(targetgrouplist);
lunmapdone:
	for(viewprint = list_head(&view_list); viewprint; viewprint = list_next(&view_list, viewprint)) 
	{
		free(viewprint);
	}
	list_destroy(&view_list);
	return (ret);
}


/*   printlunfomat
 *   
 *   list every group contains which LUN and its ID\Serial Num in the group
 *   print another type
 *    
 */

static int printlunformat(int operandLen, char *operands[], cmdOptions_t *options,
    void *args)
{
	int stmfRet, firstprint = 0;
	view *viewprint;
	list_t view_list;
	/*只打印含有lun的组的标志*/
	int printflag;
	stmfGroupList *hostgrouplist;
	stmfGroupList *targetgrouplist;
	stmfGroupProperties *groupProps;
	int n, j, ret=0;	
	/*用于遍历所保存的lun的viewentry信息*/
	printflag = 0;	
	UNUSED_PARAMETER(args);
	UNUSED_PARAMETER(operandLen);
	UNUSED_PARAMETER(operands);
	UNUSED_PARAMETER(options);
	/*建立链表*/
	list_create(&view_list, sizeof(view), offsetof(struct _view_info, listlink));
	
	stmfRet= getlunviewprop(&view_list);
	if (stmfRet == 1)
	{
		return (1);
	}
	/*获取系统中存在的所有主机组信息*/
	stmfRet = stmfGetHostGroupList(&hostgrouplist);  
	if (stmfRet == STMF_ERROR_NOMEM)
	{
		(void) printf("Don't have enough memory for host group list.\n");
		ret = 1;
		goto lunmapdone;
	}
	/*获取所有target组名字*/
	stmfRet=stmfGetTargetGroupList(&targetgrouplist); 
	if (stmfRet == STMF_ERROR_NOMEM)
	{
		(void) printf("Don't have enough memory for target group list.\n");
		ret = 1;
		stmfFreeMemory(hostgrouplist);
		goto lunmapdone;
	}
	for (n=0; n < hostgrouplist->cnt; n++)
	{
		for(viewprint = list_head(&view_list); viewprint; viewprint = list_next(&view_list, viewprint))   
		{
			/*打印只包含相同主机组的lun*/
			if ((strcmp(viewprint->view_data._hostGroup, hostgrouplist->name[n])) == 0)  
			{
				++printflag;
				if(printflag == 1)
				{
					if (firstprint != 0)
					{
						(void) printf("\n**********************\n");
					}
					(void) printf("host:%s\n", hostgrouplist->name[n]);
					stmfRet = getgroupmember(&(hostgrouplist->name[n]), &groupProps,HOST_GROUP,PRINTLUNFORMAT);
					if (stmfRet != 0)
					{
						ret = 1;
						stmfFreeMemory(hostgrouplist);
						stmfFreeMemory(targetgrouplist);
						goto lunmapdone;
					}
					++firstprint;
				}
				(void) printf(PRINT_FORMAT, viewprint->view_data.LUNIndex,viewprint->view_data._LUName,viewprint->view_data._SerialNum);
			}
		}
		printflag = 0;
	}
		/*打印*/
			for(j=0; j < targetgrouplist->cnt; j++)
			{
				for(viewprint = list_head(&view_list); viewprint; viewprint = list_next(&view_list, viewprint))    
				{
					if ((strcmp(viewprint->view_data._targetGroup, targetgrouplist->name[j])) == 0)
					{
						++printflag;
						if(printflag == 1)
						{
							if (firstprint != 0)
							{
								(void) printf("\n**********************\n");
							}
							(void) printf("target:%s\n", targetgrouplist->name[j]);
							stmfRet = getgroupmember(&(targetgrouplist->name[j]), &groupProps,TARGET_GROUP,PRINTLUNFORMAT);
							if (stmfRet != 0)
							{
								ret = 1;
								stmfFreeMemory(hostgrouplist);
								stmfFreeMemory(targetgrouplist);
								goto lunmapdone;
							}
							++firstprint;
						}
						(void) printf(PRINT_FORMAT,viewprint->view_data.LUNIndex, viewprint->view_data._LUName,viewprint->view_data._SerialNum);
					}
				}
				printflag = 0;
			}	
		printflag = 0;
	
	
	/*释放先前分配的内存*/
	stmfFreeMemory(hostgrouplist);
	stmfFreeMemory(targetgrouplist);
lunmapdone:
	for(viewprint = list_head(&view_list); viewprint; viewprint = list_next(&view_list, viewprint)) 
	{
		free(viewprint);
	}
	list_destroy(&view_list);
	return (ret);
}
	

/*
 * input:
 *  execFullName - exec name of program (argv[0])
 *
 *  copied from stmfadm.c in OS/Net
 *  (changed name to lowerCamelCase to keep consistent with this file)
 *
 * Returns:
 *  command name portion of execFullName
 */
static char *
getExecBasename(char *execFullname)
{
	char *lastSlash, *execBasename;

	/* guard against '/' at end of command invocation */
	for (;;) {
		lastSlash = strrchr(execFullname, '/');
		if (lastSlash == NULL) {
			execBasename = execFullname;
			break;
		} else {
			execBasename = lastSlash + 1;
			if (*execBasename == '\0') {
				*lastSlash = '\0';
				continue;
			}
			break;
		}
	}
	return (execBasename);
}



int main(int argc, char *argv[])
{
	int ret;
	int funcRet;
	void *subcommandArgs = NULL;
	synTables_t synTables;
	char versionString[VERSION_STRING_MAX_LEN];
	
	(void) setlocale (LC_ALL, "");
	(void) textdomain (TEXT_DOMAIN);
	
	/* set global command name */
	cmdName = getExecBasename(argv[0]);
	(void) snprintf(versionString, VERSION_STRING_MAX_LEN, "%s.%s",
	    VERSION_STRING_MAJOR, VERSION_STRING_MINOR);
	synTables.versionString = versionString;
	synTables.longOptionTbl = &longOptions[0];
	synTables.subCommandPropsTbl = &subcommands[0];

	ret = cmdParse(argc, argv, synTables, subcommandArgs, &funcRet);
	if (ret != 0) {
		return (ret);
	}
	return(funcRet);
}

