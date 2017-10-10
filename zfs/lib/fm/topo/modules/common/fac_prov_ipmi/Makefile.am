include $(top_srcdir)/config/Rules.am

libfacprovipmi_ladir=/usr/local/lib/topo/plugins

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include \
	-I$(top_srcdir)/lib/fm/topo/libtopo/common \
	-I$(top_srcdir)/lib/libipmi

libfacprovipmi_la_LTLIBRARIES = libfacprovipmi.la

USER_C = \
	fac_prov_ipmi.c

libfacprovipmi_la_LIBADD = $(top_builddir)/lib/libnvpair/libnvpair.la \
			$(top_builddir)/lib/libipmi/libipmi.la

dist_libfacprovipmi_la_SOURCES = \
	$(USER_C)
