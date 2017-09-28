fmd_topo_mapsdir = /usr/local/lib/topo/maps
dist_fmd_topo_maps_SCRIPTS = 			\
		i86pc-hc-topology.xml		\
		i86pc-legacy-hc-topology.xml
install: 
	@mkdir -p $(fmd_topo_mapsdir)
	@cp -rvf $(dist_fmd_topo_maps_SCRIPTS) $(fmd_topo_mapsdir)
