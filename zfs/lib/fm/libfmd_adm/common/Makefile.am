include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += 				\
	-I$(top_srcdir)/include 		\
	-I$(top_srcdir)/lib/libspl/include	\
	-I$(top_srcdir)/lib/fm/libfmd_adm/common\
	-I$(top_srcdir)/cmd/fm/fmd/common

lib_LTLIBRARIES = libfmd_adm.la

USER_C = 		\
	fmd_adm.c	\
	fmd_rpc.c	\
	fmd_xdr.c

dist_libfmd_adm_la_SOURCES = \
	$(USER_C)

