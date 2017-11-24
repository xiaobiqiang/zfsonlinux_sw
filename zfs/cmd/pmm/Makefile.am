include $(top_srcdir)/config/Rules.am
VPATH = \
        $(top_srcdir)/cmd/common

sbin_PROGRAMS = pmm

pmm_SOURCES = \
	cm_pmm.c

pmm_files = \
	ceres_pmm.conf

pmm_LDADD = -lpthread
pmm_LDFLAGS = -pthread

install:all
	@/usr/bin/install -cv $(sbin_PROGRAMS) $(sbindir)
	@/usr/bin/install -cv $(pmm_files) /etc
