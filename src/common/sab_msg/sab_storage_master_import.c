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

#include <errno.h>
#include <stdint.h>

#include "sab_storage_master_import.h"
#include "sab_nvm.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_storage_master_import(void *phdl,
					   void *cmd_buf, void *rsp_buf,
					   uint32_t *cmd_msg_sz,
					   uint32_t *rsp_msg_sz,
					   uint32_t msg_hdl,
					   void *args)
{
	uint32_t ret = SAB_SUCCESS_STATUS;
	uint32_t err = 1u;
	uint64_t plat_addr;
	struct nvm_header_s *blob_hdr = (struct nvm_header_s *)args;
	void *data = (void *)args;
	struct sab_cmd_key_store_import_msg *msg
		= (struct sab_cmd_key_store_import_msg *)cmd_buf;
	struct sab_cmd_key_store_import_rsp *rsp
		= (struct sab_cmd_key_store_import_rsp *)rsp_buf;

	plat_addr = plat_os_abs_data_buf(phdl,
					 data + sizeof(struct nvm_header_s),
					 blob_hdr->size,
					 DATA_BUF_IS_INPUT);

	msg->storage_handle = msg_hdl;
	msg->key_store_address = (uint32_t)(plat_addr & 0xFFFFFFFFu);
	msg->key_store_size = blob_hdr->size;

	*cmd_msg_sz = sizeof(struct sab_cmd_key_store_import_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_key_store_import_rsp);

	return ret;
}

uint32_t proc_msg_rsp_storage_master_import(void *rsp_buf, void *args)
{
	return SAB_SUCCESS_STATUS;
}
