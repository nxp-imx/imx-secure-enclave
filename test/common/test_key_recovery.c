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

hsm_err_t do_key_recovery_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl,
				uint32_t key_id, uint8_t *pub_key, uint32_t pub_key_sz)
{
	op_pub_key_recovery_args_t args = {0};
	uint8_t loc_pub_key[64];
	hsm_err_t err;

	memset(loc_pub_key, 0, sizeof(loc_pub_key));

	// key recovery test
	printf("\n---------------------------------------------------\n");
	printf("PUB KEY RECOVERY Test:\n");
	printf("---------------------------------------------------\n\n");

	args.key_identifier = key_id;

	if (pub_key == NULL) {
		args.out_key_size = sizeof(loc_pub_key);
		args.out_key      = loc_pub_key;
	} else {
		args.out_key_size = pub_key_sz;
		args.out_key      = pub_key;
	}
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
