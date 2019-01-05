/*
 * Management Module Support for MPT (Message Passing Technology) based
 * controllers
 *
 * This code is based on drivers/scsi/mpt3sas/mpt3sas_ctl.h
 * Copyright (C) 2012-2014  LSI Corporation
 * Copyright (C) 2013-2014 Avago Technologies
 *  (mailto: MPT-FusionLinux.pdl@avagotech.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * NO WARRANTY
 * THE PROGRAM IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED INCLUDING, WITHOUT
 * LIMITATION, ANY WARRANTIES OR CONDITIONS OF TITLE, NON-INFRINGEMENT,
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE. Each Recipient is
 * solely responsible for determining the appropriateness of using and
 * distributing the Program and assumes all risks associated with its
 * exercise of rights under this Agreement, including but not limited to
 * the risks and costs of program errors, damage to or loss of data,
 * programs or equipment, and unavailability or interruption of operations.

 * DISCLAIMER OF LIABILITY
 * NEITHER RECIPIENT NOR ANY CONTRIBUTORS SHALL HAVE ANY LIABILITY FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING WITHOUT LIMITATION LOST PROFITS), HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OR DISTRIBUTION OF THE PROGRAM OR THE EXERCISE OF ANY RIGHTS GRANTED
 * HEREUNDER, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGES

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#ifndef MPT3SAS_CTL_H_INCLUDED
#define MPT3SAS_CTL_H_INCLUDED

#ifdef __KERNEL__
#include <linux/miscdevice.h>
#endif

#ifndef MPT2SAS_MINOR
#define MPT2SAS_MINOR		(MPT_MINOR + 1)
#endif
#ifndef MPT3SAS_MINOR
#define MPT3SAS_MINOR		(MPT_MINOR + 2)
#endif
#define MPT2SAS_DEV_NAME	"mpt2ctl"
#define MPT3SAS_DEV_NAME	"mpt3ctl"
#define MPT3_MAGIC_NUMBER	'L'
#define MPT3_IOCTL_DEFAULT_TIMEOUT (10) /* in seconds */

/**
 * IOCTL opcodes
 */
#define MPT3IOCINFO	_IOWR(MPT3_MAGIC_NUMBER, 17, \
	struct mpt3_ioctl_iocinfo)
#define MPT3COMMAND	_IOWR(MPT3_MAGIC_NUMBER, 20, \
	struct mpt3_ioctl_command)
#ifdef CONFIG_COMPAT
#define MPT3COMMAND32	_IOWR(MPT3_MAGIC_NUMBER, 20, \
	struct mpt3_ioctl_command32)
#endif
#define MPT3EVENTQUERY	_IOWR(MPT3_MAGIC_NUMBER, 21, \
	struct mpt3_ioctl_eventquery)
#define MPT3EVENTENABLE	_IOWR(MPT3_MAGIC_NUMBER, 22, \
	struct mpt3_ioctl_eventenable)
#define MPT3EVENTREPORT	_IOWR(MPT3_MAGIC_NUMBER, 23, \
	struct mpt3_ioctl_eventreport)
#define MPT3HARDRESET	_IOWR(MPT3_MAGIC_NUMBER, 24, \
	struct mpt3_ioctl_diag_reset)
#define MPT3BTDHMAPPING	_IOWR(MPT3_MAGIC_NUMBER, 31, \
	struct mpt3_ioctl_btdh_mapping)

/* diag buffer support */
#define MPT3DIAGREGISTER _IOWR(MPT3_MAGIC_NUMBER, 26, \
	struct mpt3_diag_register)
#define MPT3DIAGRELEASE	_IOWR(MPT3_MAGIC_NUMBER, 27, \
	struct mpt3_diag_release)
#define MPT3DIAGUNREGISTER _IOWR(MPT3_MAGIC_NUMBER, 28, \
	struct mpt3_diag_unregister)
#define MPT3DIAGQUERY	_IOWR(MPT3_MAGIC_NUMBER, 29, \
	struct mpt3_diag_query)
#define MPT3DIAGREADBUFFER _IOWR(MPT3_MAGIC_NUMBER, 30, \
	struct mpt3_diag_read_buffer)

#define MPT3GETSASDEVINFO   _IOWR(MPT3_MAGIC_NUMBER, 31, \
	struct mpt3_sas_devinfo_buffer)

/**
 * struct mpt3_ioctl_header - main header structure
 * @ioc_number -  IOC unit number
 * @port_number - IOC port number
 * @max_data_size - maximum number bytes to transfer on read
 */
struct mpt3_ioctl_header {
	uint32_t ioc_number;
	uint32_t port_number;
	uint32_t max_data_size;
};

/**
 * struct mpt3_ioctl_diag_reset - diagnostic reset
 * @hdr - generic header
 */
struct mpt3_ioctl_diag_reset {
	struct mpt3_ioctl_header hdr;
};


/**
 * struct mpt3_ioctl_pci_info - pci device info
 * @device - pci device id
 * @function - pci function id
 * @bus - pci bus id
 * @segment_id - pci segment id
 */
struct mpt3_ioctl_pci_info {
	union {
		struct {
			uint32_t device:5;
			uint32_t function:3;
			uint32_t bus:24;
		} bits;
		uint32_t  word;
	} u;
	uint32_t segment_id;
};


#define MPT2_IOCTL_INTERFACE_SCSI	(0x00)
#define MPT2_IOCTL_INTERFACE_FC		(0x01)
#define MPT2_IOCTL_INTERFACE_FC_IP	(0x02)
#define MPT2_IOCTL_INTERFACE_SAS	(0x03)
#define MPT2_IOCTL_INTERFACE_SAS2	(0x04)
#define MPT2_IOCTL_INTERFACE_SAS2_SSS6200	(0x05)
#define MPT3_IOCTL_INTERFACE_SAS3	(0x06)
#define MPT2_IOCTL_VERSION_LENGTH	(32)

/**
 * struct mpt3_ioctl_iocinfo - generic controller info
 * @hdr - generic header
 * @adapter_type - type of adapter (spi, fc, sas)
 * @port_number - port number
 * @pci_id - PCI Id
 * @hw_rev - hardware revision
 * @sub_system_device - PCI subsystem Device ID
 * @sub_system_vendor - PCI subsystem Vendor ID
 * @rsvd0 - reserved
 * @firmware_version - firmware version
 * @bios_version - BIOS version
 * @driver_version - driver version - 32 ASCII characters
 * @rsvd1 - reserved
 * @scsi_id - scsi id of adapter 0
 * @rsvd2 - reserved
 * @pci_information - pci info (2nd revision)
 */
struct mpt3_ioctl_iocinfo {
	struct mpt3_ioctl_header hdr;
	uint32_t adapter_type;
	uint32_t port_number;
	uint32_t pci_id;
	uint32_t hw_rev;
	uint32_t subsystem_device;
	uint32_t subsystem_vendor;
	uint32_t rsvd0;
	uint32_t firmware_version;
	uint32_t bios_version;
	uint8_t driver_version[MPT2_IOCTL_VERSION_LENGTH];
	uint8_t rsvd1;
	uint8_t scsi_id;
	uint16_t rsvd2;
	struct mpt3_ioctl_pci_info pci_information;
};


/* number of event log entries */
#define MPT3SAS_CTL_EVENT_LOG_SIZE (50)

/**
 * struct mpt3_ioctl_eventquery - query event count and type
 * @hdr - generic header
 * @event_entries - number of events returned by get_event_report
 * @rsvd - reserved
 * @event_types - type of events currently being captured
 */
struct mpt3_ioctl_eventquery {
	struct mpt3_ioctl_header hdr;
	uint16_t event_entries;
	uint16_t rsvd;
	uint32_t event_types[4];
};

/**
 * struct mpt3_ioctl_eventenable - enable/disable event capturing
 * @hdr - generic header
 * @event_types - toggle off/on type of events to be captured
 */
struct mpt3_ioctl_eventenable {
	struct mpt3_ioctl_header hdr;
	uint32_t event_types[4];
};

#define MPT3_EVENT_DATA_SIZE (192)
/**
 * struct MPT3_IOCTL_EVENTS -
 * @event - the event that was reported
 * @context - unique value for each event assigned by driver
 * @data - event data returned in fw reply message
 */
struct MPT3_IOCTL_EVENTS {
	uint32_t event;
	uint32_t context;
	uint8_t data[MPT3_EVENT_DATA_SIZE];
};

/**
 * struct mpt3_ioctl_eventreport - returing event log
 * @hdr - generic header
 * @event_data - (see struct MPT3_IOCTL_EVENTS)
 */
struct mpt3_ioctl_eventreport {
	struct mpt3_ioctl_header hdr;
	struct MPT3_IOCTL_EVENTS event_data[1];
};

/**
 * struct mpt3_ioctl_command - generic mpt firmware passthru ioctl
 * @hdr - generic header
 * @timeout - command timeout in seconds. (if zero then use driver default
 *  value).
 * @reply_frame_buf_ptr - reply location
 * @data_in_buf_ptr - destination for read
 * @data_out_buf_ptr - data source for write
 * @sense_data_ptr - sense data location
 * @max_reply_bytes - maximum number of reply bytes to be sent to app.
 * @data_in_size - number bytes for data transfer in (read)
 * @data_out_size - number bytes for data transfer out (write)
 * @max_sense_bytes - maximum number of bytes for auto sense buffers
 * @data_sge_offset - offset in words from the start of the request message to
 * the first SGL
 * @mf[1];
 */
struct mpt3_ioctl_command {
	struct mpt3_ioctl_header hdr;
	uint32_t timeout;
	void  *reply_frame_buf_ptr;
	void  *data_in_buf_ptr;
	void  *data_out_buf_ptr;
	void  *sense_data_ptr;
	uint32_t max_reply_bytes;
	uint32_t data_in_size;
	uint32_t data_out_size;
	uint32_t max_sense_bytes;
	uint32_t data_sge_offset;
	uint8_t mf[1];
};



/* application flags for mpt3_diag_register, mpt3_diag_query */
#define MPT3_APP_FLAGS_APP_OWNED	(0x0001)
#define MPT3_APP_FLAGS_BUFFER_VALID	(0x0002)
#define MPT3_APP_FLAGS_FW_BUFFER_ACCESS	(0x0004)

/* flags for mpt3_diag_read_buffer */
#define MPT3_FLAGS_REREGISTER		(0x0001)

#define MPT3_PRODUCT_SPECIFIC_DWORDS		23


/**
 * struct mpt3_sas_devinfo_buffer - request for copy of the sas device info
 * @hdr - generic header
 * @enclosure - disk enclosure id
 * @slot - disk slot number
 */

struct mpt3sas_dev_info {
    uint64_t  sas_address;
    uint64_t  wwid;
    uint64_t enclosure_id;
	uint64_t  slot;
};

struct mpt3_sas_devinfo_buffer {
	struct mpt3_ioctl_header hdr;
    uint32_t sas_dev_cnt;
    struct mpt3sas_dev_info  buffer[0];
};


#endif /* MPT3SAS_CTL_H_INCLUDED */
