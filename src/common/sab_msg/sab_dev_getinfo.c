// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "internal/hsm_dev_getinfo.h"

#include "sab_dev_getinfo.h"
#include "sab_messaging.h"

#include "plat_os_abs.h"

uint32_t prepare_msg_dev_getinfo(void *phdl, void *cmd_buf, void *rsp_buf,
				 uint32_t *cmd_msg_sz, uint32_t *rsp_msg_sz,
				 uint32_t msg_hdl, void *args)
{
	uint32_t ret = 0;
	struct sab_cmd_dev_getinfo_msg *cmd =
		(struct sab_cmd_dev_getinfo_msg *) cmd_buf;
	struct sab_cmd_dev_getinfo_rsp_w_data *rsp_w_data =
		(struct sab_cmd_dev_getinfo_rsp_w_data *) rsp_buf;

	/* size of the buffer would be.
	 * size of device info structure "dev_info" and
	 * size of device info structure "dev_addn_info".
	 */
	cmd->buf_sz = sizeof(struct dev_info)
			+ sizeof(struct dev_addn_info);

	/* Copy the get_info_response to the word,
	 * next to response.
	 */
	set_phy_addr_to_words(&cmd->rsp_data_addr_lo,
			      &cmd->rsp_data_addr_hi,
			      plat_os_abs_data_buf((struct plat_os_abs_hdl *)phdl,
						   (uint8_t *)&rsp_w_data->d_info,
						   cmd->buf_sz,
						   DATA_BUF_IS_OUTPUT));

	*rsp_msg_sz = sizeof(struct sab_cmd_dev_getinfo_rsp);
	*cmd_msg_sz = sizeof(struct sab_cmd_dev_getinfo_msg);

	return ret;
}

uint32_t proc_msg_rsp_dev_getinfo(void *rsp_buf, void *args)
{
	op_dev_getinfo_args_t *op_args = (op_dev_getinfo_args_t *) args;
	struct sab_cmd_dev_getinfo_rsp_w_data *rsp_w_data =
		(struct sab_cmd_dev_getinfo_rsp_w_data *) rsp_buf;
	struct sab_cmd_dev_getinfo_rsp *rsp =
		(struct sab_cmd_dev_getinfo_rsp *) rsp_buf;

	if (rsp->rsp_code != SAB_SUCCESS_STATUS)
		goto exit;

	op_args->soc_id = rsp_w_data->d_info.soc_id;
	op_args->soc_rev = rsp_w_data->d_info.soc_rev;
	op_args->lmda_val = rsp_w_data->d_info.lmda_val;
	op_args->ssm_state = rsp_w_data->d_info.ssm_state;

	op_args->uid = plat_os_abs_malloc(MAX_UID_SIZE);
	if (op_args->uid == NULL)
		goto exit;

	op_args->uid_sz = MAX_UID_SIZE;
	plat_os_abs_memcpy((uint8_t *)op_args->uid,
			   (uint8_t *)rsp_w_data->d_info.uid,
			   MAX_UID_SIZE);

	op_args->sha_rom_patch = plat_os_abs_malloc(DEV_GETINFO_ROM_PATCH_SHA_SZ);
	if (op_args->sha_rom_patch == NULL) {
		plat_os_abs_free(op_args->uid);
		goto exit;
	}

	op_args->rom_patch_sha_sz = DEV_GETINFO_ROM_PATCH_SHA_SZ;
	plat_os_abs_memcpy(op_args->sha_rom_patch,
			   rsp_w_data->d_info.sha_rom_patch, DEV_GETINFO_ROM_PATCH_SHA_SZ);

	op_args->sha_fw = plat_os_abs_malloc(DEV_GETINFO_FW_SHA_SZ);
	if (op_args->sha_fw == NULL) {
		plat_os_abs_free(op_args->uid);
		plat_os_abs_free(op_args->sha_rom_patch);
		goto exit;
	}

	op_args->sha_fw_sz = DEV_GETINFO_FW_SHA_SZ;
	plat_os_abs_memcpy(op_args->sha_fw,
			   rsp_w_data->d_info.sha_fw, DEV_GETINFO_FW_SHA_SZ);

	op_args->oem_srkh_sz = DEV_GETINFO_OEM_SRKH_SZ;
	op_args->oem_srkh = plat_os_abs_malloc(DEV_GETINFO_OEM_SRKH_SZ);
	if (op_args->oem_srkh == NULL) {
		plat_os_abs_free(op_args->uid);
		plat_os_abs_free(op_args->sha_rom_patch);
		plat_os_abs_free(op_args->sha_fw);
		goto exit;
	}
	plat_os_abs_memcpy(op_args->oem_srkh,
			   rsp_w_data->d_addn_info.oem_srkh, DEV_GETINFO_OEM_SRKH_SZ);

	op_args->imem_state = rsp_w_data->d_addn_info.imem_state;
	op_args->csal_state = rsp_w_data->d_addn_info.csal_state;
	op_args->trng_state = rsp_w_data->d_addn_info.trng_state;
exit:
	return SAB_SUCCESS_STATUS;
}
