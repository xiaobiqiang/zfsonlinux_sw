include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

sbin_PROGRAMS = clusterd

clusterd_SOURCES = \
	clusterd.c \
	clusterd.h \
	cn_cluster.c \
	cn_cluster.h \
	deflt.c \
	deflt.h

clusterd_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	$(top_builddir)/lib/libzfs/libzfs.la \
	$(top_builddir)/lib/libzfs_core/libzfs_core.la

clusterd_LDADD += $(ZLIB)
clusterd_LDFLAGS = -pthread
