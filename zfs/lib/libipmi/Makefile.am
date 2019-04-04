include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include \
	-I$(top_srcdir)/lib/libipmi

lib_LTLIBRARIES = libipmi.la

USER_C = \
	ipmi_bmc.c	\
	ipmi_event.c	\
	ipmi_hash.c	\
	ipmi_lan.c	\
	ipmi_misc.c	\
	ipmi_sel.c	\
	ipmi_sunoem.c	\
	ipmi_user.c	\
	libipmi.c	\
	ipmi_entity.c	\
	ipmi_fru.c	\
	ipmi_list.c	\
	ipmi_sdr.c	\
	ipmi_sensor.c	\
	ipmi_tables.c	\
	ipmi_util.c	\
	ipmitool_sdr.c	\
	ipmitool_sdradd.c	\
	ipmitool_strings.c	\
	ipmitool_sensor.c	\
	ipmitool_open.c	\
	ipmitool_sel.c	\
	ipmitool_md5.c	\
	helper.c	\
	log.c

libipmi_la_LDFLAGS = -lc -lm

libipmi_la_LIBADD = $(top_builddir)/lib/libnvpair/libnvpair.la

dist_libipmi_la_SOURCES = \
	$(USER_C)
