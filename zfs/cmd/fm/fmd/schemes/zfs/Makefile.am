include $(top_srcdir)/config/Rules.am

libscheme_zfs_ladir=/usr/local/lib/fmd/schemes

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

libscheme_zfs_la_LTLIBRARIES = libscheme_zfs.la

USER_C = \
	scheme.c

dist_libscheme_zfs_la_SOURCES = \
	$(USER_C)
