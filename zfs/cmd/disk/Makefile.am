include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include \
	-I$(top_srcdir)/lib/libdiskmgt/include

sbin_PROGRAMS = disk

disk_SOURCES = 	\
	disk.c

disk_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	$(top_builddir)/lib/libzfs/libzfs.la \
	$(top_builddir)/lib/libdiskmgt/libdiskmgt.la \
	$(top_builddir)/lib/libzfs_core/libzfs_core.la

disk_LDADD += $(ZLIB)
disk_LDFLAGS = -pthread
