include $(top_srcdir)/config/Rules.am

libdisk_ladir=/usr/local/lib/topo/plugins

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include \
	-I$(top_srcdir)/lib/libdiskmgt/include \
	-I$(top_srcdir)/lib/fm/libdiskstatus/common \
	-I$(top_srcdir)/lib/fm/topo/libtopo/common \
	-I$(top_srcdir)/lib/libipmi

libdisk_la_LTLIBRARIES = libdisk.la

USER_C = \
	disk_enum.c

libdisk_la_LIBADD = $(top_builddir)/lib/libnvpair/libnvpair.la \
			$(top_builddir)/lib/libdiskmgt/libdiskmgt.la \
			$(top_builddir)/lib/fm/libdiskstatus/common/libdiskstatus.la

dist_libdisk_la_SOURCES = \
	$(USER_C)

install:
        cp $(top_srcdir)/lib/fm/topo/modules/common/disk/.libs/libdisk.so.0.0.0 /usr/local/lib/topo/plugins/libdisk.so
