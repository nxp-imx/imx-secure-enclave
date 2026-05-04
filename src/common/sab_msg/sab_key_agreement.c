// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "internal/hsm_key_agreement.h"

#include "sab_key_agreement.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_key_agreement(void *phdl,
				   void *cmd_buf,
				   void *rsp_buf,
				   uint32_t *cmd_msg_sz,
				   uint32_t *rsp_msg_sz,
				   uint32_t msg_hdl,
				   void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);
	struct sab_cmd_key_agreement_msg *cmd =
			(struct sab_cmd_key_agreement_msg *)cmd_buf;
	struct sab_key_agreement_algo_ecdh_args_t sab_ecdh_args = {0};
	op_key_agreement_args_t *op_args = (op_key_agreement_args_t *)args;
	op_key_agreement_algo_ecdh_args_t *op_ecdh_args;
	uint64_t phy_addr = 0;
	uint32_t ret;

	if (!op_args)
		return err;

	op_ecdh_args = op_args->key_agreement_algo_args;
	if (!op_ecdh_args)
		return err;

	cmd->key_management_handle = msg_hdl;
	cmd->algorithm = op_args->algorithm;
	cmd->flags = op_args->flags;

	/* For key store arguments, using the same user provided structure,
	 * which is expected to be word aligned, as per the user exposed struture
	 * format of Key Agreement structure for key store.
	 */
	cmd->key_store_args_size = op_args->key_store_args_size;

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      (uint8_t *)op_args->key_store_args,
				      op_args->key_store_args_size,
				      DATA_BUF_IS_INPUT);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		return err;
	}

	set_phy_addr_to_words(&cmd->key_store_args_addr,
			      0u,
			      phy_addr);

	/* Copy the user key agreement (ECDH) algorithm arguments to SAB layer
	 * structure to prepare corresponding the FW aligned structure, with the
	 * required physical addresses.
	 */
	sab_ecdh_args.vers = op_ecdh_args->vers;
	sab_ecdh_args.peer_pub_key_size = op_ecdh_args->peer_pub_key_size;
	sab_ecdh_args.priv_key_size = op_ecdh_args->priv_key_size;
	sab_ecdh_args.shared_secret_size = op_ecdh_args->shared_secret_size;

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_ecdh_args->peer_pub_key,
				      op_ecdh_args->peer_pub_key_size,
				      DATA_BUF_IS_INPUT);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		return err;
	}

	set_phy_addr_to_words(&sab_ecdh_args.peer_pub_key_addr,
			      0u,
			      phy_addr);

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_ecdh_args->priv_key,
				      op_ecdh_args->priv_key_size,
				      DATA_BUF_IS_INPUT);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		return err;
	}

	set_phy_addr_to_words(&sab_ecdh_args.priv_key_addr,
			      0u,
			      phy_addr);

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_ecdh_args->shared_secret,
				      op_ecdh_args->shared_secret_size,
				      DATA_BUF_IS_OUTPUT);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		return err;
	}

	set_phy_addr_to_words(&sab_ecdh_args.shared_secret_addr,
			      0u,
			      phy_addr);

	cmd->key_agreement_algo_args_size =
		sizeof(struct sab_key_agreement_algo_ecdh_args_t);

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      (uint8_t *)&sab_ecdh_args,
				      cmd->key_agreement_algo_args_size,
				      DATA_BUF_IS_INPUT);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		return err;
	}

	set_phy_addr_to_words(&cmd->key_agreement_algo_args_addr,
			      0u,
			      phy_addr);

	*cmd_msg_sz = sizeof(struct sab_cmd_key_agreement_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_key_agreement_rsp);

	err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	return err;
}

uint32_t proc_msg_rsp_key_agreement(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	struct sab_cmd_key_agreement_rsp *rsp =
			(struct sab_cmd_key_agreement_rsp *)rsp_buf;
	op_key_agreement_args_t *op_args = (op_key_agreement_args_t *)args;

	if (!op_args)
		return SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);

	op_args->shared_secret_key_id = rsp->shared_secret_key_id;

	return err;
}
