include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

sbin_PROGRAMS = configd

configd_SOURCES = \
	configd.c \
	configd_stmf.c \
	store.c \
	db_store.c

configd_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libcomm/libcomm.la \
	$(top_builddir)/lib/libspl/libspl.la

configd_LDADD += -lsqlite3
