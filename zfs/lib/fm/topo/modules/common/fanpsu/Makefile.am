include $(top_srcdir)/config/Rules.am

libfanpsu_ladir=/usr/local/lib/topo/plugins

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include \
	-I$(top_srcdir)/lib/fm/topo/libtopo/common \
	-I$(top_srcdir)/lib/libipmi

libfanpsu_la_LTLIBRARIES = libfanpsu.la

USER_C = \
	fanpsu_enum.c

libfanpsu_la_LIBADD = $(top_builddir)/lib/libnvpair/libnvpair.la \
			$(top_builddir)/lib/libipmi/libipmi.la

dist_libfanpsu_la_SOURCES = \
	$(USER_C)
