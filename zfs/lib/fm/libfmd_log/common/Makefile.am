include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include	\
	-I$(top_srcdir)/lib/fm/libexacct/common	\
	-I$(top_srcdir)/lib/fm/libfmd_log/common

lib_LTLIBRARIES = libfmd_log.la

USER_C = \
	fmd_filter.c	\
	fmd_log.c	\
	gmatch.c

dist_libfmd_log_la_SOURCES = \
	$(USER_C)

libfmd_log_la_LIBADD = \
        $(top_builddir)/lib/libnvpair/libnvpair.la	\
        $(top_builddir)/lib/fm/libexacct/common/libexacct.la 

libfmd_log_la_LIBADD += -lc
