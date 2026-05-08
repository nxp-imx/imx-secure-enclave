// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include "internal/hsm_key_derivation.h"

#include "sab_key_derivation.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"
#include "plat_utils.h"

uint32_t prepare_msg_key_derivation(void *phdl,
				    void *cmd_buf,
				    void *rsp_buf,
				    uint32_t *cmd_msg_sz,
				    uint32_t *rsp_msg_sz,
				    uint32_t msg_hdl,
				    void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_CMD_MSG_PREP_FAIL);
	struct sab_cmd_key_derivation_msg *cmd =
			(struct sab_cmd_key_derivation_msg *)cmd_buf;
	struct sab_key_derivation_algo_hkdf_args_t sab_hkdf_args = {0};
	op_key_derivation_args_t *op_args = (op_key_derivation_args_t *)args;
	op_key_derivation_algo_hkdf_args_t *op_hkdf_args;
	uint64_t phy_addr = 0;
	uint32_t ret;

	if (!op_args)
		return err;

	op_hkdf_args = op_args->key_derivation_algo_args;
	if (!op_hkdf_args)
		return err;

	cmd->key_management_handle = msg_hdl;
	cmd->algorithm = op_args->algorithm;
	cmd->flags = op_args->flags;

	/* For key store arguments, using the same user provided structure,
	 * which is expected to be word aligned, as per the user exposed struture
	 * format of Key Derivation structure for key store.
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

	/* Copy the user key derivation (HKDF) algorithm arguments to SAB layer
	 * structure to prepare corresponding the FW aligned structure, with the
	 * required physical addresses.
	 */
	sab_hkdf_args.vers = op_hkdf_args->vers;
	sab_hkdf_args.ikm_size = op_hkdf_args->ikm_size;
	sab_hkdf_args.salt_size = op_hkdf_args->salt_size;
	sab_hkdf_args.fixed_info_size = op_hkdf_args->fixed_info_size;
	sab_hkdf_args.okm_size = op_hkdf_args->okm_size;

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_hkdf_args->ikm,
				      op_hkdf_args->ikm_size,
				      DATA_BUF_IS_INPUT);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		return err;
	}

	set_phy_addr_to_words(&sab_hkdf_args.ikm_addr,
			      0u,
			      phy_addr);

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_hkdf_args->salt,
				      op_hkdf_args->salt_size,
				      DATA_BUF_IS_INPUT);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		return err;
	}

	set_phy_addr_to_words(&sab_hkdf_args.salt_addr,
			      0u,
			      phy_addr);

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_hkdf_args->fixed_info,
				      op_hkdf_args->fixed_info_size,
				      DATA_BUF_IS_INPUT);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		return err;
	}

	set_phy_addr_to_words(&sab_hkdf_args.fixed_info_addr,
			      0u,
			      phy_addr);

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      op_hkdf_args->okm,
				      op_hkdf_args->okm_size,
				      DATA_BUF_IS_OUTPUT);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		return err;
	}

	set_phy_addr_to_words(&sab_hkdf_args.okm_addr,
			      0u,
			      phy_addr);

	cmd->key_derivation_algo_args_size =
		sizeof(struct sab_key_derivation_algo_hkdf_args_t);

	ret = plat_os_abs_data_buf_v2((struct plat_os_abs_hdl *)phdl,
				      &phy_addr,
				      (uint8_t *)&sab_hkdf_args,
				      cmd->key_derivation_algo_args_size,
				      DATA_BUF_IS_INPUT);
	if (ret != PLAT_SUCCESS) {
		err |= ret;
		return err;
	}

	set_phy_addr_to_words(&cmd->key_derivation_algo_args_addr,
			      0u,
			      phy_addr);

	*cmd_msg_sz = sizeof(struct sab_cmd_key_derivation_msg);
	*rsp_msg_sz = sizeof(struct sab_cmd_key_derivation_rsp);

	err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);

	return err;
}

uint32_t proc_msg_rsp_key_derivation(void *rsp_buf, void *args)
{
	uint32_t err = SAB_LIB_STATUS(SAB_LIB_SUCCESS);
	struct sab_cmd_key_derivation_rsp *rsp =
			(struct sab_cmd_key_derivation_rsp *)rsp_buf;
	op_key_derivation_args_t *op_args = (op_key_derivation_args_t *)args;

	if (!op_args)
		return SAB_LIB_STATUS(SAB_LIB_RSP_PROC_FAIL);

	op_args->derived_key_id = rsp->derived_key_id;

	return err;
}
