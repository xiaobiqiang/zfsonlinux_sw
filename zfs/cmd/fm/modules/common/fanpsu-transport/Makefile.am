include $(top_srcdir)/config/Rules.am

libfanpsu_transport_ladir=/usr/local/lib/fmd

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include	\
	-I$(top_srcdir)/lib/libspl/include	\
	-I$(top_srcdir)/cmd/fm/fmd/common	\
	-I$(top_srcdir)/lib/fm/topo/libtopo/common	\
	-I$(top_srcdir)/lib/fm/topo/modules/common/fanpsu

libfanpsu_transport_la_LTLIBRARIES = libfanpsu_transport.la

USER_C = \
	fanpsu-transport.c

libfanpsu_transport_la_LIBADD = 					\
	$(top_builddir)/lib/fm/topo/libtopo/common/libtopo.la

dist_libfanpsu_transport_la_SOURCES = \
	$(USER_C)
