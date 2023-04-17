// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022 NXP
 */

#include <stdio.h>
#include <stdint.h>

#include "hsm_api.h"
#include "common.h"

void perform_dev_attestation(hsm_hdl_t sess_hdl)
{
#if HSM_DEV_ATTEST
	op_dev_attest_args_t dev_attest_args = {0};
	hsm_err_t err;
	int i = 0;

	printf("\n---------------------------------------------------\n");
	printf("Performing Device Attestation\n");
	printf("---------------------------------------------------\n");

	dev_attest_args.nounce = 0xdeadbeef;
	err = hsm_dev_attest(sess_hdl, &dev_attest_args);
	if (err != HSM_NO_ERROR)
		printf("hsm_dev_attest failed err:0x%x\n", err);
	else {
		printf("hsm_dev_attest exchange Passed.\n\n");
		printf("SoC ID = 0x%x\n", dev_attest_args.soc_id);
		printf("SoC Rev = 0x%x\n", dev_attest_args.soc_rev);
		printf("LMDA Val = 0x%x\n", dev_attest_args.lmda_val);
		printf("SSM State = 0x%x\n", dev_attest_args.ssm_state);
		printf("UID:");
		hexdump((uint32_t *)dev_attest_args.uid,
			dev_attest_args.uid_sz/sizeof(uint32_t));

		printf("ROM Patch SHA Digest:");
		hexdump((uint32_t *)dev_attest_args.sha_rom_patch,
			dev_attest_args.rom_patch_sha_sz/sizeof(uint32_t));

		printf("FW SHA Digest:");
		hexdump((uint32_t *)dev_attest_args.sha_fw,
			dev_attest_args.sha_fw_sz/sizeof(uint32_t));

		printf("USR Nounce = 0x%x\n", dev_attest_args.nounce);
		printf("FW Nounce = 0x%x\n", dev_attest_args.rsp_nounce);
		printf("Attest Result = 0x%x\n", dev_attest_args.attest_result);
		printf("Signature:");
		hexdump((uint32_t *)dev_attest_args.signature,
			dev_attest_args.sign_sz/sizeof(uint32_t));

		if (dev_attest_args.attest_result)
			printf("hsm_dev_attest: Attestation Result = Fail\n");
		else
			printf("hsm_dev_attest: Attestation Result = Pass\n");
	}
	printf("---------------------------------------------------\n\n");
#endif
}
