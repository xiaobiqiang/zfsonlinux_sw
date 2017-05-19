include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

lib_LTLIBRARIES = libstmf.la

USER_C = \
	stmf.c \
	store.c \
	db_store.c

KERNEL_C =

nodist_libstmf_la_SOURCES = \
	$(USER_C) \
	$(KERNEL_C)

libstmf_la_LIBADD = \
	$(top_builddir)/lib/libshare/libshare.la \
	$(top_builddir)/lib/libnvpair/libnvpair.la 

libstmf_la_LIBADD += -lsqlite3

EXTRA_DIST = $(USER_C)
