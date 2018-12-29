include $(top_srcdir)/config/Rules.am

DEFAULT_INCLUDES += \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/lib/libspl/include \
	-I$(top_srcdir)/lib/libdiskmgt/include \
	-I/usr/include/libxml2

sbin_PROGRAMS = disk 

disk_SOURCES = 	\
	disk.c

disk_LDADD = \
	$(top_builddir)/lib/libnvpair/libnvpair.la \
	$(top_builddir)/lib/libuutil/libuutil.la \
	$(top_builddir)/lib/libdiskmgt/libdiskmgt.la \
	$(top_builddir)/lib/libzfs_core/libzfs_core.la \
	$(top_builddir)/lib/libzpool/libzpool.la \
	$(top_builddir)/lib/libzfs/libzfs.la \
	$(top_builddir)/lib/libstmf/libstmf.la

disk_LDADD += $(ZLIB) -lxml2 -lrt
disk_LDFLAGS = -pthread

install-exec-hook:
	cp $(top_srcdir)/cmd/disk/sas2ircu /usr/local/sbin
	chmod a+x /usr/local/sbin/sas2ircu
	cp $(top_srcdir)/cmd/disk/sas3ircu /usr/local/sbin
	chmod a+x /usr/local/sbin/sas3ircu
	cp $(top_srcdir)/cmd/disk/get_en_slot.sh /usr/local/bin
	chmod a+x /usr/local/bin/get_en_slot.sh
	rm -rf /tmp/megacli/
	mkdir /tmp/megacli/
	tar jxvf $(top_srcdir)/cmd/disk/lsiraid-2018-03-05.tar.bz2 -C /tmp/megacli/ 
	cp -rf /tmp/megacli/lsiraid-2018-03-05/megacli/qemu-x86_64 /usr/local/bin/qemu-x86_64
	chmod u+x  /usr/local/bin/qemu-x86_64
	rm -rf /usr/gnemul
	mkdri /usr/gnemul
	tar zxvf /tmp/megacli/lsiraid-2018-03-05/megacli/qemu-x86_64.tar.gz -C /usr/gnemul
	mkdir /usr/gnemul/qemu-x86_64/bin/
	cp -rf /tmp/megacli/lsiraid-2018-03-05/megacli/MegaCli64 /usr/gnemul/qemu-x86_64/bin/MegaCli64
	chmod u+x  /usr/gnemul/qemu-x86_64/bin/MegaCli64

