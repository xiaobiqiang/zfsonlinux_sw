include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

lib_LTLIBRARIES = libdiagcode.la

USER_C = \
	diagcode.c
USER_H = \
	diagcode.h

dist_libdiagcode_la_SOURCES = \
	$(USER_C)
