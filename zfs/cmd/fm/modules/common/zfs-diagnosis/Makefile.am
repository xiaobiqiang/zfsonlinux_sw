include $(top_srcdir)/config/Rules.am

libzfs_etf_ladir=/usr/local/lib/fmd

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/fm/topo/libtopo/common \
	-I$(top_srcdir)/lib/libspl/include

libzfs_etf_la_LTLIBRARIES = libzfs_etf.la
libzfs_etf_la_DATA = libzfs_etf.conf

USER_C = \
	zfs_de.c
libzfs_etf_la_LIBADD = 					\
	$(top_builddir)/lib/libuutil/libuutil.la	\
	$(top_builddir)/lib/libzfs/libzfs.la

dist_libzfs_etf_la_SOURCES = \
	$(USER_C)
