fmd_eft_filesdir = /usr/local/lib/fmd/eft
dist_fmd_eft_files_SCRIPTS = 	\
		amd64.eft	\
		disk.eft	\
		gcpu_amd.eft	\
		gcpu.eft	\
		intel.eft	\
		neptune_xaui.eft\
		neptune_xfp.eft	\
		pci.eft		\
		pciex.eft	\
		sca1000.eft	\
		sca500.eft	\
		sensor.eft
install: 
	@mkdir -p $(fmd_eft_filesdir)
	@cp -rvf $(dist_fmd_eft_files_SCRIPTS) $(fmd_eft_filesdir)
