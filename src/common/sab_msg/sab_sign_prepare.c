// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "internal/hsm_sign_prepare.h"

#include "sab_sign_prepare.h"

uint32_t prepare_msg_prep_signature(void *phdl,
				    void *cmd_buf, void *rsp_buf,
				    uint32_t *cmd_msg_sz,
				    uint32_t *rsp_msg_sz,
				    uint32_t msg_hdl,
				    void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_prepare_signature_msg *cmd =
				(struct sab_prepare_signature_msg *)cmd_buf;
	op_prepare_sign_args_t *op_args = (op_prepare_sign_args_t *)args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->sig_gen_hdl = msg_hdl;
	cmd->scheme_id = op_args->scheme_id;
	cmd->flags = op_args->flags;

	*cmd_msg_sz = sizeof(struct sab_prepare_signature_msg);
	*rsp_msg_sz = sizeof(struct sab_prepare_signature_rsp);

	return ret;
}

uint32_t proc_msg_rsp_prep_signature(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	return err;
}
