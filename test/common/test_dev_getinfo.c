/*
 * Copyright 2022 NXP
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

#include <stdio.h>
#include <stdint.h>

#include "hsm_api.h"
#include "common.h"

void get_device_info(hsm_hdl_t sess_hdl)
{
	op_dev_getinfo_args_t dev_getinfo_args = {0};
	hsm_err_t err;

	printf("\n---------------------------------------------------\n");
	printf("Fetching Device Information.\n");
	printf("---------------------------------------------------\n");

	err = hsm_dev_getinfo(sess_hdl, &dev_getinfo_args);
	if (err != HSM_NO_ERROR)
		printf("hsm_dev_getinfo failed err:0x%x\n", err);
	else {
		printf("hsm_dev_getinfo message exchange is successful.\n\n");
		printf("SoC ID = 0x%x\n", dev_getinfo_args.soc_id);
		printf("SoC Rev = 0x%x\n", dev_getinfo_args.soc_rev);
		printf("LMDA Val = 0x%x\n", dev_getinfo_args.lmda_val);
		printf("SSM State = 0x%x\n", dev_getinfo_args.ssm_state);
		printf("UID:");
		hexdump((uint32_t *)dev_getinfo_args.uid,
			dev_getinfo_args.uid_sz);

		printf("ROM Patch SHA Digest:");
		hexdump((uint32_t *)dev_getinfo_args.sha_rom_patch,
			dev_getinfo_args.sha_rom_sz/sizeof(uint32_t));

		printf("FW SHA Digest:");
		hexdump((uint32_t *)dev_getinfo_args.sha_fw,
			dev_getinfo_args.sha_fw_sz/sizeof(uint32_t));
	}
	printf("---------------------------------------------------\n\n");

}
