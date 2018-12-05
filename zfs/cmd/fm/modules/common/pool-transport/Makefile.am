include $(top_srcdir)/config/Rules.am

libpool_transport_ladir=/usr/local/lib/fmd

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include	\
	-I$(top_srcdir)/lib/libspl/include	\
	-I$(top_srcdir)/cmd/fm/fmd/common	\
	-I$(top_srcdir)/cmd/zfs/	\
	-I$(top_srcdir)/lib/fm/libdiskstatus/common	\
	-I$(top_srcdir)/lib/libdiskmgt/include	\
	-I$(top_srcdir)/lib/fm/topo/libtopo/common	\
	-I$(top_srcdir)/lib/fm/topo/modules/common/pool_transport \
	-I/usr/include/libxml2

libpool_transport_la_LTLIBRARIES = libpool_transport.la
libpool_transport_la_DATA = libpool_transport.conf

USER_C =  pool_transport.c pt_zfs.c


libpool_transport_la_LIBADD = 					\
	$(top_builddir)/lib/fm/topo/libtopo/common/libtopo.la	\
	$(top_builddir)/lib/libdiskmgt/libdiskmgt.la	\
	$(top_builddir)/lib/libzfs/libzfs.la 

libpool_transport_la_LIBADD += -lxml2 -ldiskstatus -luutil -lstmf

dist_libpool_transport_la_SOURCES = \
	$(USER_C)
