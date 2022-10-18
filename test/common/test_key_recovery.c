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

#include "hsm_api.h"

hsm_err_t do_key_recovery_test(uint32_t key_id, hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl)
{
	op_pub_key_recovery_args_t args = {0};
	uint8_t pub_key[64];
	hsm_err_t err;

	// key recovery test
	printf("\n---------------------------------------------------\n");
	printf("PUB KEY RECOVERY Test:\n");
	printf("---------------------------------------------------\n\n");

	args.key_identifier = key_id;
	args.out_key_size = 64;
	args.out_key      = pub_key;
	args.key_type     = HSM_KEY_TYPE_ECDSA_NIST_P256;
	args.flags        = 0;

	err = hsm_pub_key_recovery(key_store_hdl, &args);

	if (err)
		printf("hsm_pub_key_recovery ret:0x%x\n", err);

	printf("\n---------------------------------------------------\n");
	printf("PUB KEY RECOVERY Test: Complete\n");
	printf("---------------------------------------------------\n\n");

	return err;
}
