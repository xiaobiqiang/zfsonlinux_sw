include $(top_srcdir)/config/Rules.am

liblink_ladir=/usr/local/lib/topo/plugins

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include \
	-I$(top_srcdir)/lib/fm/topo/libtopo/common 

liblink_la_LTLIBRARIES = liblink.la

USER_C = \
	link_enum.c	\
	link_methods.c	\
	conn_node.c	

liblink_la_LIBADD = $(top_builddir)/lib/libnvpair/libnvpair.la \
			$(top_builddir)/lib/libipmi/libipmi.la

dist_liblink_la_SOURCES = \
	$(USER_C)
