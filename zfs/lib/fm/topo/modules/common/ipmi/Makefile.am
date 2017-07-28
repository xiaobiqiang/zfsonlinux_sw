include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include \
	-I$(top_srcdir)/lib/fm/topo/libtopo/common \
	-I$(top_srcdir)/lib/libipmi

lib_LTLIBRARIES = libipmimod.la

USER_C = \
	ipmi_enum.c	\
	ipmi_methods.c 	

libipmimod_la_LIBADD = $(top_builddir)/lib/libnvpair/libnvpair.la \
			$(top_builddir)/lib/libipmi/libipmi.la

dist_libipmimod_la_SOURCES = \
	$(USER_C)
