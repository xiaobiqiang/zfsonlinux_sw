/*
 * This file is part of the ZFS Linux port.
 *
 * Copyright (c) 2009 Lawrence Livermore National Security, LLC.
 * Produced at Lawrence Livermore National Laboratory
 * Written by:
 *         Brian Behlendorf <behlendorf1@llnl.gov>,
 *         Herb Wartens <wartens2@llnl.gov>,
 *         Jim Garlick <garlick@llnl.gov>
 * LLNL-CODE-403049
 *
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

AC_INIT(m4_esyscmd(grep Name META | cut -d ':' -f 2 | tr -d ' \n'),
	m4_esyscmd(grep Version META | cut -d ':' -f 2 | tr -d ' \n'))
AC_LANG(C)
ZFS_AC_META
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIR([config])
AC_CANONICAL_SYSTEM
AM_MAINTAINER_MODE
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_HEADERS([zfs_config.h], [
	(mv zfs_config.h zfs_config.h.tmp &&
	awk -f ${ac_srcdir}/config/config.awk zfs_config.h.tmp >zfs_config.h &&
	rm zfs_config.h.tmp) || exit 1])

AC_ARG_ENABLE(hengwei, 
		AS_HELP_STRING([--enable-hengwei],
			[use hengwei platform]))
if test "$enable_hengwei" = yes; then
	echo "use hengwei platform"
	AC_DEFINE([USE_HENGWEI], [], [Use hengwei platform])
fi

AC_PROG_INSTALL
AC_PROG_CC
AC_PROG_LIBTOOL
AM_PROG_AS

ZFS_AC_LICENSE
ZFS_AC_PACKAGE
ZFS_AC_CONFIG
ZFS_AC_DEBUG
ZFS_AC_DEBUG_DMU_TX

AC_CONFIG_FILES([ 
	Makefile
	udev/Makefile
	udev/rules.d/Makefile
	etc/Makefile
	etc/init.d/Makefile
	etc/zfs/Makefile
	etc/systemd/Makefile
	etc/systemd/system/Makefile
	etc/modules-load.d/Makefile
	man/Makefile
	man/man1/Makefile
	man/man5/Makefile
	man/man8/Makefile
	lib/Makefile
	lib/libspl/Makefile
	lib/libspl/asm-generic/Makefile
	lib/libspl/asm-i386/Makefile
	lib/libspl/asm-x86_64/Makefile
	lib/libspl/include/Makefile
	lib/libspl/include/ia32/Makefile
	lib/libspl/include/ia32/sys/Makefile
	lib/libspl/include/rpc/Makefile
	lib/libspl/include/sys/Makefile
	lib/libspl/include/sys/sysevent/Makefile
	lib/libspl/include/sys/dktp/Makefile
	lib/libspl/include/util/Makefile
	lib/libdiskmgt/Makefile
	lib/libfmd/Makefile
	lib/libavl/Makefile
	lib/libefi/Makefile
	lib/libnvpair/Makefile
	lib/libunicode/Makefile
	lib/libuutil/Makefile
	lib/libcomm/Makefile
	lib/libzpool/Makefile
	lib/libzfs/libzfs.pc
	lib/libzfs/libzfs_core.pc
	lib/libzfs/Makefile
	lib/libzfs_core/Makefile
	lib/libstmf/Makefile
	lib/libshare/Makefile
	lib/libclumgt/Makefile
	lib/fm/Makefile
	lib/fm/libdiagcode/Makefile
	lib/fm/libdiagcode/common/Makefile
	lib/fm/libfmd_msg/Makefile
	lib/fm/libfmd_msg/common/Makefile
	lib/fm/libfmd_log/Makefile
	lib/fm/libfmd_log/common/Makefile
	lib/fm/libfmd_adm/Makefile
	lib/fm/libfmd_adm/common/Makefile
	lib/fm/libdiskstatus/Makefile
	lib/fm/libdiskstatus/common/Makefile
	lib/fm/libexacct/Makefile
	lib/fm/libexacct/common/Makefile
	lib/fm/topo/Makefile
	lib/fm/topo/libtopo/Makefile
	lib/fm/topo/libtopo/common/Makefile
	lib/fm/topo/modules/Makefile
	lib/fm/topo/modules/common/Makefile
	lib/fm/topo/modules/common/ipmi/Makefile
	lib/fm/topo/modules/common/fac_prov_ipmi/Makefile
	lib/fm/topo/modules/common/fanpsu/Makefile
	lib/fm/topo/modules/common/link/Makefile
	lib/fm/topo/modules/common/disk/Makefile
	lib/fm/topo/maps/Makefile
	lib/fm/topo/maps/i86pc/Makefile
	lib/libipmi/Makefile
	cmd/Makefile
	cmd/zdb/Makefile
	cmd/zhack/Makefile
	cmd/zfs/Makefile
	cmd/zinject/Makefile
	cmd/zpool/Makefile
	cmd/zstreamdump/Makefile
	cmd/ztest/Makefile
	cmd/zpios/Makefile
	cmd/mount_zfs/Makefile
	cmd/fsck_zfs/Makefile
	cmd/zvol_id/Makefile
	cmd/vdev_id/Makefile
	cmd/arcstat/Makefile
	cmd/dbufstat/Makefile
    	cmd/iostat/Makefile
	cmd/arc_summary/Makefile
	cmd/zed/Makefile
	cmd/sas3show/Makefile
	cmd/perf_stat/Makefile
	cmd/clusterd/Makefile
	cmd/clumgt/Makefile
	cmd/pmm/Makefile
	cmd/disk/Makefile
	cmd/synckey/Makefile
	cmd/fm/Makefile
	cmd/fm/fmd/Makefile
	cmd/fm/fmd/common/Makefile
	cmd/fm/fmtopo/Makefile
	cmd/fm/fmtopo/common/Makefile
	cmd/fm/fmdump/Makefile
	cmd/fm/fmdump/common/Makefile
	cmd/fm/fmadm/Makefile
	cmd/fm/fmadm/common/Makefile
	cmd/fm/modules/Makefile
	cmd/fm/modules/common/Makefile
	cmd/fm/modules/common/zfs-retire/Makefile
	cmd/fm/modules/common/zfs-diagnosis/Makefile
	cmd/fm/modules/common/fanpsu-transport/Makefile
	cmd/fm/modules/common/disk-transport/Makefile
	cmd/fm/modules/common/snmp-trapgen/Makefile
	cmd/fm/modules/common/link-transport/Makefile
	cmd/fm/modules/common/pool-transport/Makefile
	cmd/fm/modules/common/eversholt/Makefile
	cmd/fm/modules/common/eversholt/files/Makefile
	cmd/fm/fmd/schemes/Makefile
	cmd/fm/fmd/schemes/zfs/Makefile
	cmd/fm/dicts/Makefile
	cmd/stmfadm/Makefile
	cmd/configd/Makefile
	cmd/stmfsvc/Makefile
	cmd/lunadm/Makefile
	cmd/sethostid/Makefile
	cmd/scripts/Makefile
	contrib/Makefile
	contrib/bash_completion.d/Makefile
	contrib/dracut/Makefile
	contrib/dracut/90zfs/Makefile
	contrib/initramfs/Makefile
	module/Makefile
	module/avl/Makefile
	module/cn_hbx/Makefile
	module/fmd_transport/Makefile
	module/nvpair/Makefile
	module/unicode/Makefile
	module/zcommon/Makefile
	module/zfs/Makefile
	module/vmpt3sas/Makefile
	module/zpios/Makefile
	module/fct/Makefile
	module/qlt/Makefile
	module/qlf/Makefile
	module/qlf_hengwei/Makefile
	module/stmf/Makefile
	module/stmf_sbd/Makefile
	module/pppt/Makefile
	include/Makefile
	include/linux/Makefile
	include/sys/Makefile
	include/sys/fs/Makefile
	include/sys/fm/Makefile
	include/sys/fm/fs/Makefile
	scripts/Makefile
	scripts/zpios-profile/Makefile
	scripts/zpios-test/Makefile
	scripts/zpool-config/Makefile
	scripts/common.sh
	rpm/Makefile
	rpm/redhat/Makefile
	rpm/redhat/zfs.spec
	rpm/redhat/zfs-kmod.spec
	rpm/redhat/zfs-dkms.spec
	rpm/generic/Makefile
	rpm/generic/zfs.spec
	rpm/generic/zfs-kmod.spec
	rpm/generic/zfs-dkms.spec
	zfs-script-config.sh
	zfs.release
])

AC_OUTPUT
