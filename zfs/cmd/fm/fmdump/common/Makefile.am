include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
        -I$(top_srcdir)/include \
        -I$(top_srcdir)/lib/libspl/include \
        -I$(top_srcdir)/lib/fm/topo/libtopo/common/	\
        -I$(top_srcdir)/lib/fm/libfmd_log/common/	\
        -I$(top_srcdir)/lib/fm/libfmd_msg/common/	\
        -I$(top_srcdir)/lib/fm/libexacct/common		\
        -I$(top_srcdir)/cmd/fm/fmd/common/

sbin_PROGRAMS = fmdump

fmdump_SOURCES =		\
	asru.c			\
	error.c			\
	fault.c			\
	fmdump.c		\
	scheme.c

fmdump_LDADD = \
        $(top_builddir)/lib/libnvpair/libnvpair.la		\
        $(top_builddir)/lib/fm/topo/libtopo/common/libtopo.la	\
        $(top_builddir)/lib/fm/libfmd_log/common/libfmd_log.la	\
        $(top_builddir)/lib/fm/libfmd_msg/common/libfmd_msg.la	\
	$(top_builddir)/lib/libzfs/libzfs.la			\
	$(top_builddir)/lib/libstmf/libstmf.la

fmdump_LDADD += -ldl -lxml2
