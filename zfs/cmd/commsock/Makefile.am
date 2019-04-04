include $(top_srcdir)/config/Rules.am

VPATH = \
	$(top_srcdir)/cmd/common

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include \
	-I$(top_srcdir)/cmd/common

sbin_PROGRAMS = commsock

commsock_SOURCES = \
	commsock.c

commsock_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libspl/libspl.la

commsock_LDADD += $(ZLIB) -lrt
