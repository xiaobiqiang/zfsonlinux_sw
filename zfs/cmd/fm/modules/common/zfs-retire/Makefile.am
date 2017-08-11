include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I/usr/include/libxml2 \
	-I$(top_srcdir)/lib/libspl/include

lib_LTLIBRARIES = libzfs_retire.la

USER_C = \
	make_vdev.c	\
	zfs_retire.c
USER_H = \
	make_vdev.h

libzfs_retire_la_LIBADD =			\
$(top_builddir)/lib/libzfs/libzfs.la		\
$(top_builddir)/lib/libdiskmgt/libdiskmgt.la	\
$(top_builddir)/lib/libefi/libefi.la

libzfs_retire_la_LIBADD += -lxml2 

dist_libzfs_retire_la_SOURCES = \
	$(USER_C)
