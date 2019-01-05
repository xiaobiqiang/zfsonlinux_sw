include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include

sbin_PROGRAMS = sas3show

sas3show_SOURCES = 	\
	sas3show.c


sas3show_LDADD = $(ZLIB) -lrt
sas3show_LDFLAGS = -pthread
