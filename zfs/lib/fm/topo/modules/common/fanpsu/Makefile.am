include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include \
	-I$(top_srcdir)/lib/fm/topo/libtopo/common \
	-I$(top_srcdir)/lib/libipmi

lib_LTLIBRARIES = libfanpsumod.la

USER_C = \
	fanpsu_enum.c

libfanpsumod_la_LIBADD = $(top_builddir)/lib/libnvpair/libnvpair.la \
			$(top_builddir)/lib/libipmi/libipmi.la

dist_libfanpsumod_la_SOURCES = \
	$(USER_C)
