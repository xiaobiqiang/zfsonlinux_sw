include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
        -I$(top_srcdir)/include \
        -I$(top_srcdir)/lib/libspl/include \
        -I$(top_srcdir)/lib/fm/topo/libtopo/common/

sbin_PROGRAMS = fmtopo

fmtopo_SOURCES =		\
	fmtopo.c	

fmtopo_LDADD = \
        $(top_builddir)/lib/libnvpair/libnvpair.la		\
	$(top_builddir)/lib/libzfs/libzfs.la			\
        $(top_builddir)/lib/fm/libfmd_log/common/libfmd_log.la	\
        $(top_builddir)/lib/fm/topo/libtopo/common/libtopo.la 	\
	$(top_builddir)/lib/libstmf/libstmf.la

fmtopo_LDFLAGS = -ldl -lxml2 
