include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

sbin_PROGRAMS = clusterd

clusterd_SOURCES = \
	clusterd.c \
	clusterd.h \
	cn_cluster.c \
	cn_cluster.h \
	deflt.c \
	deflt.h \
	if_util/dnet_ntop.c \
	if_util/dnet_pton.c \
	if_util/hlist.h \
	if_util/if_util.c \
	if_util/if_util.h \
	if_util/inet_proto.c \
	if_util/ipx_ntop.c \
	if_util/ipx_pton.c \
	if_util/libgenl.c \
	if_util/libgenl.h \
	if_util/libnetlink.c \
	if_util/libnetlink.h \
	if_util/ll_addr.c \
	if_util/ll_map.c \
	if_util/ll_map.h \
	if_util/ll_proto.c \
	if_util/ll_types.c \
	if_util/namespace.c \
	if_util/namespace.h \
	if_util/rtm_map.h \
	if_util/rt_names.c \
	if_util/rt_names.h \
	if_util/utils.c \
	if_util/utils.h

clusterd_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	$(top_builddir)/lib/libzfs/libzfs.la \
	$(top_builddir)/lib/libzfs_core/libzfs_core.la \
	$(top_builddir)/lib/libstmf/libstmf.la

clusterd_LDADD += $(ZLIB)
clusterd_LDFLAGS = -pthread
