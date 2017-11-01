include $(top_srcdir)/config/Rules.am
VPATH = \
        $(top_srcdir)/cmd/common

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include\
	-I/usr/include/libxml2	\
	-I$(top_srcdir)/cmd/common

sbin_PROGRAMS = clumgt

clumgt_SOURCES = \
	clumgt.c \
	clu_cmd.c \
	clu_link.c \
	clu_sync.c

clumgt_files = \
	clumgt_cmdlist.config \
	clumgt.config

clumgt_LDADD = \
	$(top_builddir)/lib/libclumgt/libclumgt.la \
	$(top_builddir)/lib/libnvpair/libnvpair.la
clumgt_LDADD += -lnanomsg -lclumgt -lxml2 -lreadline -ltermcap
clumgt_LDFLAGS = -pthread

install:all
	@/usr/bin/install -cv .libs/$(sbin_PROGRAMS) $(sbindir)
	@/usr/bin/ln -svf $(sbindir)/$(sbin_PROGRAMS) $(sbindir)/clumgtd
	@/usr/bin/install -cv $(clumgt_files) /etc
