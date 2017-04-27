COMMON_H = 

KERNEL_H = \
	$(top_srcdir)/include/sys/scsi/impl/commands.h \
	$(top_srcdir)/include/sys/scsi/impl/inquiry.h \
	$(top_srcdir)/include/sys/scsi/impl/sense.h \
	$(top_srcdir)/include/sys/scsi/impl/status.h 

USER_H =

EXTRA_DIST = $(COMMON_H) $(KERNEL_H) $(USER_H)

if CONFIG_KERNEL
kerneldir = @prefix@/src/zfs-$(VERSION)/include/sys/scsi/impl/
kernel_HEADERS = $(COMMON_H) $(KERNEL_H)
endif
