include $(top_srcdir)/config/Rules.am

liblink_transport_ladir=/usr/local/lib/fmd

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include	\
	-I$(top_srcdir)/lib/libspl/include	\
	-I$(top_srcdir)/cmd/fm/fmd/common	\
	-I$(top_srcdir)/lib/fm/topo/libtopo/common	\
	-I$(top_srcdir)/lib/fm/topo/modules/common/link_transport \
	-I/usr/include/libxml2

liblink_transport_la_LTLIBRARIES = liblink_transport.la
liblink_transport_la_DATA = liblink_transport.conf

USER_C = \
	link_transport.c

liblink_transport_la_LIBADD = 					\
	$(top_builddir)/lib/fm/topo/libtopo/common/libtopo.la	\
	$(top_builddir)/lib/libzfs/libzfs.la 

liblink_transport_la_LIBADD += -lxml2

dist_liblink_transport_la_SOURCES = \
	$(USER_C)
