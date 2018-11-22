include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include \
	-I/usr/include/libxml2

sbin_PROGRAMS = zfs

zfs_SOURCES = \
	zfs_iter.c \
	zfs_iter.h \
	zfs_main.c \
	zfs_util.h

zfs_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	$(top_builddir)/lib/libzfs/libzfs.la \
	$(top_builddir)/lib/libzfs_core/libzfs_core.la \
	$(top_builddir)/lib/libstmf/libstmf.la 

zfs_LDADD += $(ZLIB) -lxml2 -lrt
zfs_LDFLAGS = -pthread
