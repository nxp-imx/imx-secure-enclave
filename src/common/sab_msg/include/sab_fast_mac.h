// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_FAST_MAC_H
#define SAB_FAST_MAC_H

#include <internal/she_fast_mac.h>
#include "sab_msg_def.h"

/* MAC generation / verify */
struct sab_she_fast_mac_msg {
	struct sab_mu_hdr hdr;
	uint32_t utils_handle;
	uint16_t key_id;
	uint16_t data_length;
	uint16_t data_offset;
	uint8_t mac_length;
	uint8_t flags;
};

struct sab_she_v2x_fast_mac_msg {
	struct sab_mu_hdr hdr;
	uint32_t utils_handle;
	uint16_t key_id;
	uint16_t data_length;
	uint16_t rsrv;
	uint8_t mac_length;
	uint8_t flags;
	uint32_t m1;
	uint32_t m2;
	uint32_t m3;
	uint32_t m4;
	uint32_t crc;
};

struct sab_she_fast_mac_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t verification_status;
};

uint32_t prepare_msg_fast_mac(void *phdl,
			      void *cmd_buf, void *rsp_buf,
			      uint32_t *cmd_msg_sz,
			      uint32_t *rsp_msg_sz,
			      uint32_t msg_hdl,
			      void *args);

uint32_t proc_msg_rsp_fast_mac(void *rsp_buf, void *args);

uint32_t prepare_msg_v2x_fast_mac(void *phdl,
				  void *cmd_buf, void *rsp_buf,
				  uint32_t *cmd_msg_sz,
				  uint32_t *rsp_msg_sz,
				  uint32_t msg_hdl,
				  void *args);

uint32_t proc_msg_rsp_v2x_fast_mac(void *rsp_buf, void *args);

#endif
