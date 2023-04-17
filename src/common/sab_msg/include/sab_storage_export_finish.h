// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_STORAGE_FINISH_EXPORT_H
#define SAB_STORAGE_FINISH_EXPORT_H

#include "sab_nvm.h"
#include "sab_msg_def.h"

struct sab_cmd_key_store_export_finish_msg {
	struct sab_mu_hdr hdr;
	uint32_t storage_handle;
	uint32_t export_status;
};
#define SAB_EXPORT_STATUS_SUCCESS (0xBA2CC2ABu)

struct sab_cmd_key_store_export_finish_rsp {
	struct sab_mu_hdr hdr;
	uint32_t storage_handle;
	uint32_t rsp_code;
};

uint32_t parse_cmd_prep_rsp_storage_finish_export(struct nvm_ctx_st *nvm_ctx_param,
						  void *cmd_buf,
						  void *rsp_buf,
						  uint32_t *cmd_len,
						  uint32_t *rsp_msg_info,
						  void **data,
						  uint32_t *data_sz,
						  uint8_t *prev_cmd_id,
						  uint8_t *next_cmd_id);

#endif
