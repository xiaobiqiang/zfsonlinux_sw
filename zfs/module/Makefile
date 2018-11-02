subdir-m += avl
subdir-m += cn_hbx
subdir-m += nvpair
subdir-m += unicode
subdir-m += zcommon
subdir-m += zfs
subdir-m += vmpt3sas
subdir-m += zpios
subdir-m += fct
subdir-m += stmf
subdir-m += qlt
#subdir-m += qlf
subdir-m += qlf_hengwei
subdir-m += stmf_sbd
subdir-m += pppt
subdir-m += fmd_transport

INSTALL_MOD_DIR ?= extra

ZFS_MODULE_CFLAGS += -include /root/wzy/zfsonlinux/spl/spl_config.h -DUNIQUE_FW_NAME
ZFS_MODULE_CFLAGS += -include /root/wzy/zfsonlinux/zfs/zfs_config.h
ZFS_MODULE_CFLAGS += -I/root/wzy/zfsonlinux/zfs/include -I/root/wzy/zfsonlinux/spl/include -I/root/wzy/zfsonlinux/spl
export ZFS_MODULE_CFLAGS

modules:
	@# Make the exported SPL symbols available to these modules.
	@# They may be in the root of SPL_OBJ when building against
	@# installed devel headers, or they may be in the module
	@# subdirectory when building against the spl source tree.
	@if [ -f /root/wzy/zfsonlinux/spl/Module.symvers ]; then \
		/bin/cp /root/wzy/zfsonlinux/spl/Module.symvers .; \
	elif [ -f /root/wzy/zfsonlinux/spl/module/Module.symvers ]; then \
		/bin/cp /root/wzy/zfsonlinux/spl/module/Module.symvers .; \
	else \
		echo -e "\n" \
		"*** Missing spl symbols ensure you have built the spl:\n" \
		"*** - /root/wzy/zfsonlinux/spl/Module.symvers, or\n" \
		"*** - /root/wzy/zfsonlinux/spl/module/Module.symvers\n"; \
		exit 1; \
	fi
	$(MAKE) -C /root/testlinux/kernels/4.4.15-aere+ SUBDIRS=`pwd`  CONFIG_ZFS=m $@

clean:
	@# Only cleanup the kernel build directories when CONFIG_KERNEL
	@# is defined.  This indicates that kernel modules should be built.
	$(MAKE) -C /root/testlinux/kernels/4.4.15-aere+ SUBDIRS=`pwd`  $@

	if [ -f Module.symvers ]; then $(RM) Module.symvers; fi
	if [ -f Module.symvers ]; then $(RM) Module.symvers; fi
	if [ -f Module.markers ]; then $(RM) Module.markers; fi

modules_install:
	@# Install the kernel modules
	$(MAKE) -C /root/testlinux/kernels/4.4.15-aere+ SUBDIRS=`pwd` $@ \
		INSTALL_MOD_PATH=$(DESTDIR)$(INSTALL_MOD_PATH) \
		INSTALL_MOD_DIR=$(INSTALL_MOD_DIR) \
		KERNELRELEASE=4.4.15-aere+
	@# Remove extraneous build products when packaging
	kmoddir=$(DESTDIR)$(INSTALL_MOD_PATH)/lib/modules/4.4.15-aere+; \
	if [ -n "$(DESTDIR)" ]; then \
		find $$kmoddir -name 'modules.*' | xargs $(RM); \
	fi
	sysmap=$(DESTDIR)$(INSTALL_MOD_PATH)/boot/System.map-4.4.15-aere+; \
	if [ -f $$sysmap ]; then \
		depmod -ae -F $$sysmap 4.4.15-aere+; \
	fi

modules_uninstall:
	@# Uninstall the kernel modules
	kmoddir=$(DESTDIR)$(INSTALL_MOD_PATH)/lib/modules/4.4.15-aere+
	list='$(subdir-m)'; for subdir in $$list; do \
		$(RM) -R $$kmoddir/$(INSTALL_MOD_DIR)/$$subdir; \
	done

distdir:
	list='$(subdir-m)'; for subdir in $$list; do \
		(find ../module/$$subdir -name '*.c' -o -name '*.h' |\
		xargs /bin/cp -t $$distdir/$$subdir); \
	done

distclean maintainer-clean: clean
install: modules_install
uninstall: modules_uninstall
all: modules
check:
