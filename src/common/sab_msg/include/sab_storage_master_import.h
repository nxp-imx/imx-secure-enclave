// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_STORAGE_MASTER_IMPORT_H
#define SAB_STORAGE_MASTER_IMPORT_H

#include "sab_msg_def.h"

struct sab_cmd_key_store_import_msg {
    struct sab_mu_hdr hdr;
    uint32_t storage_handle;
    uint32_t key_store_address;
    uint32_t key_store_size;
};

struct sab_cmd_key_store_import_rsp {
    struct sab_mu_hdr hdr;
    uint32_t rsp_code;
};

uint32_t prepare_msg_storage_master_import(void *phdl,
					   void *cmd_buf, void *rsp_buf,
					   uint32_t *cmd_msg_sz,
					   uint32_t *rsp_msg_sz,
					   uint32_t msg_hdl,
					   void *args);

uint32_t proc_msg_rsp_storage_master_import(void *rsp_buf, void *args);
#endif
