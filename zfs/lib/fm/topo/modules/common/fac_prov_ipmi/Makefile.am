include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include \
	-I$(top_srcdir)/lib/fm/topo/libtopo/common \
	-I$(top_srcdir)/lib/libipmi

lib_LTLIBRARIES = libfacprovipmimod.la

USER_C = \
	fac_prov_ipmi.c

libfacprovipmimod_la_LIBADD = $(top_builddir)/lib/libnvpair/libnvpair.la \
			$(top_builddir)/lib/libipmi/libipmi.la

dist_libfacprovipmimod_la_SOURCES = \
	$(USER_C)
