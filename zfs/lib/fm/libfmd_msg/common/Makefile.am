include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

lib_LTLIBRARIES = libfmd_msg.la

USER_C = \
	fmd_msg.c
USER_H = \
	fmd_msg.h

dist_libfmd_msg_la_SOURCES = \
	$(USER_C)

libfmd_msg_la_LIBADD = \
        $(top_builddir)/lib/libnvpair/libnvpair.la 
