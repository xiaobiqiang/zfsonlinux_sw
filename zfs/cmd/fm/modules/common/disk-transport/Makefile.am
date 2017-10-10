include $(top_srcdir)/config/Rules.am

libdisk_transport_ladir=/usr/local/lib/fmd

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include	\
	-I$(top_srcdir)/lib/libspl/include	\
	-I$(top_srcdir)/cmd/fm/fmd/common	\
	-I$(top_srcdir)/lib/libdiskmgt/include \
	-I$(top_srcdir)/lib/fm/topo/libtopo/common	\
	-I$(top_srcdir)/lib/fm/topo/modules/common/disk \
	-I/usr/include/libxml2

libdisk_transport_la_LTLIBRARIES = libdisk_transport.la

USER_C = \
	disk-transport.c

libdisk_transport_la_LIBADD = 					\
	$(top_builddir)/lib/fm/topo/libtopo/common/libtopo.la

libdisk_transport_la_LIBADD +=  -lxml2 

dist_libdisk_transport_la_SOURCES = \
	$(USER_C)
