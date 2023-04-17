// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include "internal/hsm_key_recovery.h"

#include "sab_key_recovery.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_key_recovery(void *phdl,
				 void *cmd_buf, void *rsp_buf,
				 uint32_t *cmd_msg_sz,
				 uint32_t *rsp_msg_sz,
				 uint32_t msg_hdl,
				 void *args)
{
	uint32_t ret = 0;
	struct sab_cmd_pub_key_recovery_msg *cmd =
		(struct sab_cmd_pub_key_recovery_msg *) cmd_buf;
	op_pub_key_recovery_args_t *op_args = (op_pub_key_recovery_args_t *) args;

	cmd->key_store_handle = msg_hdl;
	cmd->key_identifier = op_args->key_identifier;
	cmd->out_key_addr_ext = 0u;
	set_phy_addr_to_words(&cmd->out_key_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->out_key,
						   op_args->out_key_size,
						   DATA_BUF_IS_OUTPUT));

	cmd->out_key_size = op_args->out_key_size;
#ifndef PSA_COMPLIANT
	cmd->key_type = op_args->key_type;
	cmd->flags = op_args->flags;
#endif

	*cmd_msg_sz = sizeof(struct sab_cmd_pub_key_recovery_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_pub_key_recovery_rsp);

	cmd->crc = 0u;

	return ret;
}

uint32_t proc_msg_rsp_key_recovery(void *rsp_buf, void *args)
{
	op_pub_key_recovery_args_t *op_args = (op_pub_key_recovery_args_t *) args;
	struct sab_cmd_pub_key_recovery_rsp *rsp =
		(struct sab_cmd_pub_key_recovery_rsp *) rsp_buf;

#ifdef PSA_COMPLIANT
	op_args->out_key_size = rsp->out_key_size;
#endif

	return SAB_SUCCESS_STATUS;
}
