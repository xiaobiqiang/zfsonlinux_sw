include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += 				\
	-I$(top_srcdir)/include 		\
	-I$(top_srcdir)/lib/libspl/include	\
	-I$(top_srcdir)/lib/fm/libdiskstatus/common	\
	-I$(top_srcdir)/cmd/fm/fmd/common

lib_LTLIBRARIES = libdiskstatus.la

USER_C = 		\
	libdiskstatus.c \
	ds_util.c	\
	ds_scsi_uscsi.c	\
	ds_scsi_sim.c	\
	ds_scsi.c

dist_libdiskstatus_la_SOURCES = \
	$(USER_C)

