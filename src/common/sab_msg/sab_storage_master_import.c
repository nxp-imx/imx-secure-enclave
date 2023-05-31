// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <errno.h>
#include <stdint.h>

#include "sab_storage_master_import.h"
#include "sab_nvm.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"

uint32_t prepare_msg_storage_master_import(void *phdl,
					   void *cmd_buf, void *rsp_buf,
					   uint32_t *cmd_msg_sz,
					   uint32_t *rsp_msg_sz,
					   uint32_t msg_hdl,
					   void *args)
{
	uint32_t ret = SAB_SUCCESS_STATUS;
	struct nvm_header_s *blob_hdr = (struct nvm_header_s *)args;
	void *data = (void *)args;
	struct sab_cmd_key_store_import_msg *msg
		= (struct sab_cmd_key_store_import_msg *)cmd_buf;

	if (!blob_hdr || !data)
		return SAB_FAILURE_STATUS;

	set_phy_addr_to_words(&msg->key_store_address,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   data + NVM_HEADER_SZ,
						   blob_hdr->size,
						   DATA_BUF_IS_INPUT));

	msg->storage_handle = msg_hdl;
	msg->key_store_size = blob_hdr->size;

	*cmd_msg_sz = sizeof(struct sab_cmd_key_store_import_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_key_store_import_rsp);

	return ret;
}

uint32_t proc_msg_rsp_storage_master_import(void *rsp_buf, void *args)
{
	return SAB_SUCCESS_STATUS;
}
