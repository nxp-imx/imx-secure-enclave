// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SAB_NVM_H
#define SAB_NVM_H

#include "plat_os_abs_def.h"

#define	NEXT_EXPECTED_CMD_NONE		SAB_STORAGE_NVM_LAST_CMD

struct nvm_header_s {
	uint32_t size;
	uint32_t crc;
	struct sab_blob_id blob_id;
};

#define NVM_HEADER_SZ	16u

struct nvm_ctx_st {
	uint32_t status;
	struct plat_os_abs_hdl *phdl;
	uint32_t session_handle;
	uint32_t storage_handle;
	uint32_t mu_type;
	uint8_t nvm_fname[MAX_FNAME_DNAME_SZ];
	uint8_t nvm_dname[MAX_FNAME_DNAME_SZ];
	void *last_data;
	uint32_t last_data_sz;
	uint8_t prev_cmd_id;
	uint8_t next_cmd_id;
#if MT_SAB_STORAGE_KEY_DB_REQ
	struct key_db_fd key_db[MAX_KEY_STORE];
#endif
};

struct nvm_chunk_hdr {
	struct sab_blob_id blob_id;
	uint32_t len;
	uint8_t *data;
};

#define NVM_CHUNK_HDR_SZ	13u

#endif
