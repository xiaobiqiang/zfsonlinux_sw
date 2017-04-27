include $(top_srcdir)/config/Rules.am

AM_CFLAGS += $(DEBUG_STACKFLAGS) $(FRAME_LARGER_THAN)

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libdiskmgt/include \
	-I$(top_srcdir)/lib/libspl/include

noinst_LTLIBRARIES = libdiskmgt.la

USER_C = \
	disklist.c	\
	entry.c		\
	partition.c	\
	slices.c	\
	libsysenv.c	\
	bus.c		\
	cache.c		\
	media.c		\
	drive.c		\
	inuse_mnt.c \
	events.c	\
	slice.c		\
	alias.c		\
	path.c		\
	controller.c \
	assoc_types.c

KERNEL_C =

nodist_libdiskmgt_la_SOURCES = \
	$(USER_C) \
	$(KERNEL_C)

libdiskmgt_la_LIBADD = $(LIBUUID) $(ZLIB)

EXTRA_DIST = $(USER_C)
