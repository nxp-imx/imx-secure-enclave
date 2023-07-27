// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <stdio.h>
#include <stdint.h>

#include "hsm_api.h"
#include "common.h"

uint8_t nounce_buf[16] = {0x1D, 0xAF, 0xAA, 0xEB, 0x19, 0x4D, 0xCA, 0xBE,
			  0xEF, 0xAE, 0xCB, 0xDD, 0x42, 0x2E, 0x1F, 0xCE};

void perform_dev_attestation(hsm_hdl_t sess_hdl)
{
#if HSM_DEV_ATTEST
	op_dev_attest_args_t dev_attest_args = {0};
	hsm_err_t err;
	int i = 0;

	printf("\n---------------------------------------------------\n");
	printf("Performing Device Attestation\n");
	printf("---------------------------------------------------\n");

	if (global_info.ver == HSM_API_VERSION_1) {
		dev_attest_args.nounce = 0xdeadbeef;
	} else if (global_info.ver == HSM_API_VERSION_2) {
		dev_attest_args.nounce_buf_sz = sizeof(nounce_buf);
		dev_attest_args.nounce_buf = nounce_buf;
	}

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

		if (global_info.ver == HSM_API_VERSION_1) {
			printf("USR Nounce = 0x%x\n", dev_attest_args.nounce);
			printf("FW Nounce = 0x%x\n", dev_attest_args.rsp_nounce);

		} else if (global_info.ver == HSM_API_VERSION_2) {
			printf("USR Nounce =");
			hexdump((uint32_t *)dev_attest_args.nounce_buf,
				dev_attest_args.nounce_buf_sz / sizeof(uint32_t));

			printf("FW Nounce =");
			hexdump((uint32_t *)dev_attest_args.rsp_nounce_buf,
				dev_attest_args.rsp_nounce_buf_sz / sizeof(uint32_t));

			printf("FW OEM SRKH:");
			hexdump((uint32_t *)dev_attest_args.oem_srkh,
				dev_attest_args.oem_srkh_sz / sizeof(uint32_t));

			printf("IMEM state = 0x%x.\n", dev_attest_args.imem_state);
			printf("CSAL state = 0x%x.\n", dev_attest_args.csal_state);
			printf("TRNG state = 0x%x.\n", dev_attest_args.trng_state);
		}

		printf("\nGet Info Buffer:");
		hexdump((uint32_t *)dev_attest_args.info_buf,
			dev_attest_args.info_buf_sz / sizeof(uint32_t));

		printf("Attest Result = 0x%x\n\n", dev_attest_args.attest_result);
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
