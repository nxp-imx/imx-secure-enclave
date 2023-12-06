// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2021, 2023 NXP
 */

#ifndef ELE_MU_IOCTL_H
#define ELE_MU_IOCTL_H

/* IOCTL definitions. */

struct ele_mu_ioctl_setup_iobuf {
	uint8_t *user_buf;
	uint32_t length;
	uint32_t flags;
	uint64_t ele_addr;
};

struct ele_mu_ioctl_shared_mem_cfg {
	uint32_t base_offset;
	uint32_t size;
};

struct ele_mu_ioctl_get_mu_info {
	uint8_t ele_mu_id;
	uint8_t interrupt_idx;
	uint8_t tz;
	uint8_t did;
	uint8_t cmd_tag;
	uint8_t rsp_tag;
	uint8_t success_tag;
	uint8_t base_api_ver;
	uint8_t fw_api_ver;
};

struct ele_mu_ioctl_signed_message {
	uint8_t *message;
	uint32_t msg_size;
	uint32_t error_code;
};

#define ELE_MU_IO_FLAGS_IS_INTPUT		(0x01u)
#define ELE_MU_IO_FLAGS_USE_SEC_MEM		(0x02u)
#define ELE_MU_IO_FLAGS_USE_SHORT_ADDR	(0x04u)

#define ELE_MU_IOCTL			0x0A /* like MISC_MAJOR. */
#define ELE_MU_IOCTL_ENABLE_CMD_RCV	_IO(ELE_MU_IOCTL, 0x01)
#define ELE_MU_IOCTL_SHARED_BUF_CFG	_IOW(ELE_MU_IOCTL, 0x02, \
					struct ele_mu_ioctl_shared_mem_cfg)
#define ELE_MU_IOCTL_SETUP_IOBUF	_IOWR(ELE_MU_IOCTL, 0x03, \
					struct ele_mu_ioctl_setup_iobuf)
#define ELE_MU_IOCTL_GET_MU_INFO	_IOR(ELE_MU_IOCTL, 0x04, \
					struct ele_mu_ioctl_get_mu_info)
#define ELE_MU_IOCTL_SIGNED_MESSAGE	_IOWR(ELE_MU_IOCTL, 0x05, \
					struct ele_mu_ioctl_signed_message)

#endif
