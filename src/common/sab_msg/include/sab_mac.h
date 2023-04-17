// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#ifndef SAB_MAC_H
#define SAB_MAC_H

#include "sab_msg_def.h"

struct sab_cmd_mac_open_msg {
	struct sab_mu_hdr hdr;
	uint32_t key_store_handle;
	uint32_t input_address_ext;
	uint32_t output_address_ext;
	uint8_t flags;
	uint8_t rsv[3];
	uint32_t crc;
};

struct sab_cmd_mac_open_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t mac_handle;
};

struct sab_cmd_mac_close_msg {
	struct sab_mu_hdr hdr;
	uint32_t mac_handle;
};

struct sab_cmd_mac_close_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
};

struct sab_cmd_mac_one_go_msg {
	struct sab_mu_hdr hdr;
	uint32_t mac_handle;
	uint32_t key_id;
	uint32_t payload_address;
	uint32_t mac_address;
#ifdef PSA_COMPLIANT
	uint32_t payload_size;
#else
	uint16_t payload_size;
#endif
	uint16_t mac_size;
	uint8_t  flags;
#ifdef PSA_COMPLIANT
#define SAB_CMD_MAC_ONE_GO_RESV_SZ     1
	uint8_t  rsv[SAB_CMD_MAC_ONE_GO_RESV_SZ];
	uint32_t  algorithm;
#else
#define SAB_CMD_MAC_ONE_GO_RESV_SZ     2
	uint8_t  algorithm;
	uint8_t  rsv[SAB_CMD_MAC_ONE_GO_RESV_SZ];
#endif
	uint32_t crc;
};

struct sab_cmd_mac_one_go_rsp {
	struct sab_mu_hdr hdr;
	uint32_t rsp_code;
	uint32_t verification_status;
#ifdef PSA_COMPLIANT
	uint16_t output_mac_size;
	uint16_t rsv;
#endif
};

#define SAB_HSM_MAC_ONE_GO_IND_VERIFICATION_STATUS_OK  (0x6C1AA1C6u)
#define SAB_HSM_MAC_ONE_GO_IND_VERIFICATION_STATUS_KO  (0u)

uint32_t prepare_msg_mac_one_go(void *phdl,
				 void *cmd_buf, void *rsp_buf,
				 uint32_t *cmd_msg_sz,
				 uint32_t *rsp_msg_sz,
				 uint32_t msg_hdl,
				 void *args);

uint32_t proc_msg_rsp_mac_one_go(void *rsp_buf, void *args);

uint32_t prepare_msg_mac_open_req(void *phdl,
				   void *cmd_buf, void *rsp_buf,
				   uint32_t *cmd_msg_sz,
				   uint32_t *rsp_msg_sz,
				   uint32_t msg_hdl,
				   void *args);

uint32_t proc_msg_rsp_mac_open_req(void *rsp_buf, void *args);

uint32_t prepare_msg_mac_close_req(void *phdl,
				    void *cmd_buf, void *rsp_buf,
				    uint32_t *cmd_msg_sz,
				    uint32_t *rsp_msg_sz,
				    uint32_t msg_hdl,
				    void *args);

uint32_t proc_msg_rsp_mac_close_req(void *rsp_buf, void *args);
#endif
