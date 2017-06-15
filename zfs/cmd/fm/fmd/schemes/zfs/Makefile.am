include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

lib_LTLIBRARIES = libscheme_zfs.la

USER_C = \
	scheme.c

dist_libscheme_zfs_la_SOURCES = \
	$(USER_C)
