/*
 * Copyright 2023 NXP
 *
 * NXP Confidential.
 * This software is owned or controlled by NXP and may only be used strictly
 * in accordance with the applicable license terms.  By expressly accepting
 * such terms or by downloading, installing, activating and/or otherwise using
 * the software, you are agreeing that you have read, and that you agree to
 * comply with and are bound by, such license terms.  If you do not agree to be
 * bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
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
