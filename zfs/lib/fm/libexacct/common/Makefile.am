include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

lib_LTLIBRARIES = libexacct.la

USER_C = \
	exacct_ops.c \
	exacct_core.c

dist_libexacct_la_SOURCES = \
	$(USER_C)
libexacct_la_LIBDADD = \
        $(top_builddir)/lib/libnvpair/libnvpair.la \
        $(top_builddir)/lib/libuutil/libuutil.la \
        $(top_builddir)/lib/libzpool/libzpool.la \
        $(top_builddir)/lib/libzfs/libzfs.la \
        $(top_builddir)/lib/libzfs_core/libzfs_core.la

