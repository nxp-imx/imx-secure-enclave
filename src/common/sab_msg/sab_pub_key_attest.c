// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include "internal/hsm_pub_key_attest.h"
#include "sab_pub_key_attest.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_pub_key_attest(void *phdl,
				    void *cmd_buf, void *rsp_buf,
				    uint32_t *cmd_msg_sz,
				    uint32_t *rsp_msg_sz,
				    uint32_t msg_hdl,
				    void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_pub_key_attest_msg *cmd =
				(struct sab_cmd_pub_key_attest_msg *)cmd_buf;
	op_pub_key_attest_args_t *op_args = (op_pub_key_attest_args_t *)args;

	if (!op_args)
		return SAB_ENGN_FAIL;

	cmd->sig_gen_hdl = msg_hdl;
	cmd->key_identifier = op_args->key_identifier;
	cmd->key_attestation_id = op_args->key_attestation_id;
	cmd->sign_algo = op_args->sign_algo;
	set_phy_addr_to_words(&cmd->auth_challenge_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->auth_challenge,
						   op_args->auth_challenge_size,
						   DATA_BUF_IS_INPUT));
	set_phy_addr_to_words(&cmd->certificate_addr,
			      0u,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   op_args->certificate,
						   op_args->certificate_size,
						   DATA_BUF_IS_OUTPUT));
	cmd->auth_challenge_size = op_args->auth_challenge_size;
	cmd->certificate_size = op_args->certificate_size;

	*cmd_msg_sz = sizeof(struct sab_cmd_pub_key_attest_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_pub_key_attest_rsp);

	return ret;
}

uint32_t proc_msg_rsp_pub_key_attest(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	op_pub_key_attest_args_t *op_args =
			(op_pub_key_attest_args_t *)args;
	struct sab_cmd_pub_key_attest_rsp *rsp =
			(struct sab_cmd_pub_key_attest_rsp *)rsp_buf;

	if (!op_args) {
		err = SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);
		goto exit;
	}

	op_args->exp_certificate_size = rsp->output_certificate_size;
exit:
	return err;
}
