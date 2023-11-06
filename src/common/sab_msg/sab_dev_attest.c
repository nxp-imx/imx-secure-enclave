// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "internal/hsm_dev_attest.h"
#include "internal/hsm_utils.h"

#include "sab_dev_attest.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"

static uint32_t prepare_msg_dev_attest_v1(void *phdl, void *cmd_buf, void *rsp_buf,
					  uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
					  uint32_t msg_hdl, void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_dev_attest_msg_v1 *cmd =
		(struct sab_cmd_dev_attest_msg_v1 *)cmd_buf;
	struct sab_cmd_dev_attest_rsp_w_data_v1 *rsp_w_data =
		(struct sab_cmd_dev_attest_rsp_w_data_v1 *)rsp_buf;
	op_dev_attest_args_t *op_args = (op_dev_attest_args_t *)args;

	if (!op_args || !op_args->nounce)
		return SAB_ENGN_FAIL;

	*cmd_msg_sz = sizeof(struct sab_cmd_dev_attest_msg_v1);
	*rsp_msg_sz = sizeof(struct sab_cmd_dev_attest_rsp);

	plat_os_abs_memcpy(cmd->nounce,
			   op_args->nounce,
			   op_args->nounce_sz);

	/* size of the buffer would be 2 words less.
	 * first word for hdr
	 * second word for response code.
	 */
	cmd->buf_sz = sizeof(struct dev_info) +
		      DEV_ATTEST_NOUNCE_SIZE_V1 +
		      DEV_ATTEST_SIGN_SIZE;

	/* Copy the get_info_response to the word,
	 * next to response.
	 */
	set_phy_addr_to_words(&cmd->rsp_data_addr_lo,
			      &cmd->rsp_data_addr_hi,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   (uint8_t *)&rsp_w_data->d_info,
						   cmd->buf_sz,
						   DATA_BUF_IS_OUTPUT));

	cmd->crc = 0u;

	return ret;
}

static uint32_t prepare_msg_dev_attest_v2(void *phdl, void *cmd_buf, void *rsp_buf,
					  uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
					  uint32_t msg_hdl, void *args)
{
	uint32_t ret = SAB_ENGN_PASS;
	struct sab_cmd_dev_attest_msg_v2 *cmd =
		(struct sab_cmd_dev_attest_msg_v2 *)cmd_buf;
	struct sab_cmd_dev_attest_rsp_w_data_v2 *rsp_w_data =
		(struct sab_cmd_dev_attest_rsp_w_data_v2 *)rsp_buf;
	op_dev_attest_args_t *op_args = (op_dev_attest_args_t *)args;

	if (!op_args || !op_args->nounce)
		return SAB_ENGN_FAIL;

	*cmd_msg_sz = sizeof(struct sab_cmd_dev_attest_msg_v2);
	*rsp_msg_sz = sizeof(struct sab_cmd_dev_attest_rsp);

	plat_os_abs_memcpy(cmd->nounce,
			   op_args->nounce,
			   op_args->nounce_sz);

	cmd->buf_sz = sizeof(struct dev_info) +
		      sizeof(struct dev_addn_info) +
		      DEV_ATTEST_NOUNCE_SIZE_V2 +
		      DEV_ATTEST_SIGN_SIZE;

	/**
	 * Copy the get_info_response to the word,
	 * next to response.
	 */
	set_phy_addr_to_words(&cmd->rsp_data_addr_lo,
			      &cmd->rsp_data_addr_hi,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   (uint8_t *)&rsp_w_data->d_info,
						   cmd->buf_sz,
						   DATA_BUF_IS_OUTPUT));

	cmd->crc = 0u;

	return ret;
}

uint32_t prepare_msg_dev_attest(void *phdl, void *cmd_buf, void *rsp_buf,
				uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
				uint32_t msg_hdl, void *args)
{
	uint32_t ret = SAB_ENGN_FAIL;

	if (hsm_get_dev_attest_api_ver() == HSM_API_VERSION_1)
		ret = prepare_msg_dev_attest_v1(phdl, cmd_buf, rsp_buf, cmd_msg_sz,
						rsp_msg_sz, msg_hdl, args);
	else if (hsm_get_dev_attest_api_ver() == HSM_API_VERSION_2)
		ret = prepare_msg_dev_attest_v2(phdl, cmd_buf, rsp_buf, cmd_msg_sz,
						rsp_msg_sz, msg_hdl, args);

	return ret;
}

uint32_t proc_msg_rsp_dev_attest(void *rsp_buf, void *args)
{
	op_dev_attest_args_t *op_args = (op_dev_attest_args_t *)args;
	struct sab_cmd_dev_attest_rsp *rsp =
		(struct sab_cmd_dev_attest_rsp *) rsp_buf;
	struct sab_cmd_dev_attest_rsp_w_data_v1 *rsp_w_data_v1 =
		(struct sab_cmd_dev_attest_rsp_w_data_v1 *)rsp_buf;
	struct sab_cmd_dev_attest_rsp_w_data_v2 *rsp_w_data_v2 =
		(struct sab_cmd_dev_attest_rsp_w_data_v2 *)rsp_buf;
	/**
	 * Variables for handling assignments of buffer pointers and
	 * buffer sizes on the basis of Version 1 or Version 2 support.
	 */
	uint16_t rsp_nounce_data_buf_sz;
	uint8_t *rsp_nounce_data_buf;
	uint8_t *signature_data_buf;
	uint16_t info_data_buf_sz;
	uint8_t *info_data_buf;

	if (!op_args)
		return SAB_FAILURE_STATUS;

	if (rsp->rsp_code != SAB_SUCCESS_STATUS)
		goto exit;

	op_args->soc_id = rsp_w_data_v1->d_info.soc_id;
	op_args->soc_rev = rsp_w_data_v1->d_info.soc_rev;
	op_args->lmda_val = rsp_w_data_v1->d_info.lmda_val;
	op_args->ssm_state = rsp_w_data_v1->d_info.ssm_state;

	op_args->uid = plat_os_abs_malloc(MAX_UID_SIZE);
	if (!op_args->uid)
		goto exit;

	op_args->uid_sz = MAX_UID_SIZE;
	plat_os_abs_memcpy((uint8_t *)op_args->uid,
			   (uint8_t *)rsp_w_data_v1->d_info.uid,
			   MAX_UID_SIZE);

	op_args->sha_rom_patch = plat_os_abs_malloc(DEV_GETINFO_ROM_PATCH_SHA_SZ);
	if (!op_args->sha_rom_patch) {
		plat_os_abs_free(op_args->uid);
		goto exit;
	}

	op_args->rom_patch_sha_sz = DEV_GETINFO_ROM_PATCH_SHA_SZ;
	plat_os_abs_memcpy(op_args->sha_rom_patch,
			   rsp_w_data_v1->d_info.sha_rom_patch,
			   DEV_GETINFO_ROM_PATCH_SHA_SZ);

	op_args->sha_fw = plat_os_abs_malloc(DEV_GETINFO_FW_SHA_SZ);
	if (!op_args->sha_fw) {
		plat_os_abs_free(op_args->uid);
		plat_os_abs_free(op_args->sha_rom_patch);
		goto exit;
	}

	op_args->sha_fw_sz = DEV_GETINFO_FW_SHA_SZ;
	plat_os_abs_memcpy(op_args->sha_fw,
			   rsp_w_data_v1->d_info.sha_fw,
			   DEV_GETINFO_FW_SHA_SZ);
	/**
	 * Filled op args with common fields between version 1 and version 2 of
	 * this API, now the version dependent fields have to be filled based on
	 * the version supported.
	 */
	if (hsm_get_dev_attest_api_ver() == HSM_API_VERSION_1) {
		rsp_nounce_data_buf_sz = DEV_ATTEST_NOUNCE_SIZE_V1;
		rsp_nounce_data_buf = rsp_w_data_v1->nounce;
		signature_data_buf = rsp_w_data_v1->signature;
		info_data_buf_sz = sizeof(struct dev_info) +
				   DEV_ATTEST_NOUNCE_SIZE_V1;
		info_data_buf = (uint8_t *)(&rsp_w_data_v1->d_info);
	} else {
		rsp_nounce_data_buf_sz = DEV_ATTEST_NOUNCE_SIZE_V2;
		rsp_nounce_data_buf = rsp_w_data_v2->nounce;
		signature_data_buf = rsp_w_data_v2->signature;
		info_data_buf_sz = sizeof(struct dev_info) +
				   sizeof(struct dev_addn_info) +
				   DEV_ATTEST_NOUNCE_SIZE_V2;
		info_data_buf = (uint8_t *)(&rsp_w_data_v2->d_info);
	}

	op_args->rsp_nounce = plat_os_abs_malloc(rsp_nounce_data_buf_sz);
	if (!op_args->rsp_nounce) {
		plat_os_abs_free(op_args->uid);
		plat_os_abs_free(op_args->sha_rom_patch);
		plat_os_abs_free(op_args->sha_fw);
		goto exit;
	}

	op_args->rsp_nounce_sz = rsp_nounce_data_buf_sz;
	plat_os_abs_memcpy(op_args->rsp_nounce,
			   rsp_nounce_data_buf,
			   rsp_nounce_data_buf_sz);

	op_args->signature = plat_os_abs_malloc(DEV_ATTEST_SIGN_SIZE);
	if (!op_args->signature) {
		plat_os_abs_free(op_args->uid);
		plat_os_abs_free(op_args->sha_rom_patch);
		plat_os_abs_free(op_args->sha_fw);
		plat_os_abs_free(op_args->rsp_nounce);
		goto exit;
	}

	op_args->sign_sz = DEV_ATTEST_SIGN_SIZE;
	plat_os_abs_memcpy(op_args->signature,
			   signature_data_buf,
			   DEV_ATTEST_SIGN_SIZE);

	/**
	 * Info Buffer:
	 * Get Info Buffer + Nounce buffer
	 *
	 * Copying the required info to op args, from starting
	 * address of d_info, and till nounce buffer end.
	 * As per the defined structure, the memory being accessed here
	 * beyond the d_info field is sure to be available and the
	 * required one till Nounce buffer end.
	 */
	op_args->info_buf = plat_os_abs_malloc(info_data_buf_sz);
	if (!op_args->info_buf) {
		plat_os_abs_free(op_args->uid);
		plat_os_abs_free(op_args->sha_rom_patch);
		plat_os_abs_free(op_args->sha_fw);
		plat_os_abs_free(op_args->rsp_nounce);
		plat_os_abs_free(op_args->signature);
		goto exit;
	}

	op_args->info_buf_sz = info_data_buf_sz;
	plat_os_abs_memcpy(op_args->info_buf,
			   info_data_buf,
			   info_data_buf_sz);

	if (hsm_get_dev_attest_api_ver() == HSM_API_VERSION_2) {
		op_args->oem_srkh = plat_os_abs_malloc(DEV_GETINFO_OEM_SRKH_SZ);
		if (!op_args->oem_srkh) {
			plat_os_abs_free(op_args->uid);
			plat_os_abs_free(op_args->sha_rom_patch);
			plat_os_abs_free(op_args->sha_fw);
			plat_os_abs_free(op_args->rsp_nounce);
			plat_os_abs_free(op_args->signature);
			plat_os_abs_free(op_args->info_buf);
			goto exit;
		}
		op_args->oem_srkh_sz = DEV_GETINFO_OEM_SRKH_SZ;
		plat_os_abs_memcpy(op_args->oem_srkh,
				   rsp_w_data_v2->d_addn_info.oem_srkh,
				   DEV_GETINFO_OEM_SRKH_SZ);

		op_args->imem_state = rsp_w_data_v2->d_addn_info.imem_state;
		op_args->csal_state = rsp_w_data_v2->d_addn_info.csal_state;
		op_args->trng_state = rsp_w_data_v2->d_addn_info.trng_state;
	}
exit:
	return SAB_SUCCESS_STATUS;
}
