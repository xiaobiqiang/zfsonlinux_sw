include $(top_srcdir)/config/Rules.am

VPATH = \
	$(top_srcdir)/cmd/common

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include \
	-I$(top_srcdir)/cmd/common \
	-I/usr/include/libxml2

sbin_PROGRAMS = perf_stat

perf_stat_SOURCES = \
	parse_cmd.c \
	parse_cmd.h \
	systemd_util.c \
	perf_stat.c \
	perf_stat_cpu.c \
	perf_stat.h \
	perf_stat_lun.c \
	perf_stat_mem.c \
	perf_stat_net.c \
	perf_stat_nfs.c \
	perf_stat_zpool.c \
	perf_stat_fc.c \
	perf_util.c \
	perf_util.h

perf_stat_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	$(top_builddir)/lib/libzfs/libzfs.la \
	$(top_builddir)/lib/libzfs_core/libzfs_core.la \
	$(top_builddir)/lib/libstmf/libstmf.la

perf_stat_LDADD += $(ZLIB) -lrt -lxml2 -lm
perf_stat_LDFLAGS = -pthread
