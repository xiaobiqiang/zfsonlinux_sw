include $(top_srcdir)/config/Rules.am

libipmi_ladir=/usr/local/lib/topo/plugins

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include \
	-I$(top_srcdir)/lib/fm/topo/libtopo/common \
	-I$(top_srcdir)/lib/libipmi

libipmi_la_LTLIBRARIES = libipmi.la

USER_C = \
	ipmi_enum.c	\
	ipmi_methods.c 	

libipmi_la_LIBADD = $(top_builddir)/lib/libnvpair/libnvpair.la \
			$(top_builddir)/lib/libipmi/libipmi.la

dist_libipmi_la_SOURCES = \
	$(USER_C)
