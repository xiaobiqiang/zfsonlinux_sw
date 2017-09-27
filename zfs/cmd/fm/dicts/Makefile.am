fm_dictsdir = /var/fm/dict
dist_fm_dicts_SCRIPTS = 		\
			AMD.dict	\
			DISK.dict	\
			FMD.dict	\
			GMCA.dict	\
			INTEL.dict	\
			NXGE.dict	\
			PCI.dict	\
			PCIEX.dict	\
			SCA1000.dict	\
		 	SCA500.dict	\
			SCF.dict	\
			SENSOR.dict	\
			SUN4.dict	\
			SUN4U.dict	\
			SUN4V.dict	\
			SUNOS.dict	\
			TEST.dict	\
			ZFS.dict
install: 
	@mkdir -p $(fm_dictsdir)
	@cp -rvf $(dist_fm_dicts_SCRIPTS) $(fm_dictsdir) 
