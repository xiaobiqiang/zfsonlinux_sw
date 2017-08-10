include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

lib_LTLIBRARIES = libcomm.la

USER_C = \
	comm.c 

KERNEL_C =

nodist_libcomm_la_SOURCES = \
	$(USER_C) \
	$(KERNEL_C)

libcomm_la_LIBADD = -lrt

EXTRA_DIST = $(USER_C)
