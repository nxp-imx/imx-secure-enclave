// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#ifndef SAB_DELETE_KEY_H
#define SAB_DELETE_KEY_H

#include <stdint.h>

#include "sab_msg_def.h"

struct sab_cmd_delete_key_msg {
	struct sab_mu_hdr hdr;//(see Table 10)
	uint32_t key_management_hdl;
	uint32_t key_identifier;
	uint16_t rsv1;
	uint8_t flags;
	uint8_t rsv2;
};

struct sab_cmd_delete_key_rsp {
	struct sab_mu_hdr hdr;//(see Table 10)
	uint32_t rsp_code;
};


uint32_t prepare_msg_del_key(void *phdl,
			     void *cmd_buf, void *rsp_buf,
			     uint32_t *cmd_msg_sz,
			     uint32_t *rsp_msg_sz,
			     uint32_t msg_hdl,
			     void *args);

uint32_t proc_msg_rsp_del_key(void *rsp_buf, void *args);
#endif
