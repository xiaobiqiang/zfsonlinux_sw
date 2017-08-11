include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include	\
	-I$(top_srcdir)/cmd/fm/modules/common/eversholt	\
	-I$(top_srcdir)/cmd/fm/fmd/common/		\
	-I$(top_srcdir)/lib/fm/topo/libtopo/common/

lib_LTLIBRARIES = libeversholt.la

USER_C = \
	eft.c		\
	alloc.c		\
	config.c	\
	eval.c		\
	evnv.c		\
	fme.c		\
	iexpr.c		\
	io.c		\
	ipath.c		\
	itree.c		\
	platform.c	\
	stats.c		\
	check.c		\
	esclex.c	\
	literals.c	\
	lut.c		\
	out.c		\
	ptree.c		\
	stable.c	\
	tree.c		\
	eftread.c	\
	y_tab.c

libeversholt_la_LIBADD = 				\
	$(top_builddir)/lib/libuutil/libuutil.la	
	$(top_builddir)/lib/libzfs/libzfs.la 

dist_libeversholt_la_SOURCES = \
	$(USER_C)
