include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

lib_LTLIBRARIES = libstmf.la

USER_C = \
	stmf.c \
	stmf_comm.c 

KERNEL_C =

nodist_libstmf_la_SOURCES = \
	$(USER_C) \
	$(KERNEL_C)

libstmf_la_LIBADD = \
	$(top_builddir)/lib/libshare/libshare.la \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libcomm/libcomm.la 

EXTRA_DIST = $(USER_C)
