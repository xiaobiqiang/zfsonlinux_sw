include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include\
	-I/usr/include/libxml2

sbin_PROGRAMS = clumgt

clumgt_SOURCES = \
	clumgt.c \
	clu_cmd.c \
	clu_link.c \
	clu_sync.c

clumgt_LDADD = \
	$(top_builddir)/lib/libclumgt/libclumgt.la \
	$(top_builddir)/lib/libnvpair/libnvpair.la
clumgt_LDADD += -lnanomsg -lclumgt -lxml2 -lreadline -ltermcap
clumgt_LDFLAGS = -pthread
