include $(top_srcdir)/config/Rules.am

libclumgt_pcdir = $(datarootdir)/pkgconfig

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

lib_LTLIBRARIES = libclumgt.la

USER_C = \
	libclumgt.c

KERNEL_C =

nodist_libclumgt_la_SOURCES = \
	$(USER_C) \
	$(KERNEL_C)


libclumgt_la_LIBADD = -lm -ldl $(LIBBLKID) -lnanomsg
libclumgt_la_LDFLAGS = -pthread -version-info 2:0:0

EXTRA_DIST =  $(USER_C)
