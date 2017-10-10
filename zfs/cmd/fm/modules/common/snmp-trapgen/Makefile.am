include $(top_srcdir)/config/Rules.am

libsnmp_trapgen_ladir=/usr/local/lib/fmd

ROOTNETSNMPDIR = /etc/net-snmp/snmp
NETSNMPCONFS = fmd-trapgen.conf

ROOTNETSNMPCONFS = $(NETSNMPCONFS:%=$(ROOTNETSNMPDIR)/%)

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include	\
	-I$(top_srcdir)/lib/libspl/include	\
	-I$(top_srcdir)/cmd/fm/fmd/common	\
	-I$(top_srcdir)/lib/libdiskmgt/include \
	-I$(top_srcdir)/lib/fm/libfmd_msg/common \
	-I$(top_srcdir)/lib/fm/topo/libtopo/common	\
	-I$(top_srcdir)/lib/fm/topo/modules/common/disk \
	-I/usr/include/libxml2

libsnmp_trapgen_la_LTLIBRARIES = libsnmp_trapgen.la

USER_C = \
	snmp-trapgen.c

libsnmp_trapgen_la_LIBADD = 					\
	$(top_builddir)/lib/fm/topo/libtopo/common/libtopo.la

libsnmp_trapgen_la_LIBADD +=  -lxml2 -lnetsnmp -lnetsnmpagent

dist_libsnmp_trapgen_la_SOURCES = \
	$(USER_C)
$(ROOTNETSNMPDIR)/%: %
        $(INS.file)

