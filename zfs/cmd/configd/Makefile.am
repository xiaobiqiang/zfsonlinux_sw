include $(top_srcdir)/config/Rules.am

VPATH = \
	$(top_srcdir)/cmd/common

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include \
	-I$(top_srcdir)/cmd/common

sbin_PROGRAMS = configd

configd_SOURCES = \
	systemd_util.c \
	configd.c \
	configd_stmf.c \
	store.c \
	db_store.c

configd_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libcomm/libcomm.la \
	$(top_builddir)/lib/libspl/libspl.la

configd_LDADD += -lsqlite3
