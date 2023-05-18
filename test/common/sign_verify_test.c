// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "common.h"
#include "hsm_api.h"

void hsm_sign_verify_tests(hsm_hdl_t sess_hdl, hsm_hdl_t key_store_hdl,
			   uint32_t key_id,
			   uint8_t *signature_data, uint32_t sign_data_sz,
			   uint8_t *hash_data, uint32_t hash_data_sz,
			   uint8_t *pub_key, uint32_t pub_key_sz)
{
	printf("\n---------------------------------------------------\n");
	printf("Secondary API Test: HSM_DO_SIGN then HSM_VERIFY_SIGN.\n");
	printf("-----------------------------------------------------\n");

	op_generate_sign_args_t sig_gen_args = {0};
	op_verify_sign_args_t sig_ver_args = {0};
	hsm_verification_status_t verif_status;
	hsm_err_t hsmret;
#ifndef PSA_COMPLIANT
	sig_gen_args.svc_flags = 0;
#endif
	sig_gen_args.key_identifier = key_id;
#ifdef PSA_COMPLIANT
	sig_gen_args.salt_len = 0;
	sig_gen_args.scheme_id = HSM_SIGNATURE_SCHEME_ECDSA_SHA256;
#else
	sig_gen_args.scheme_id = HSM_SIGNATURE_SCHEME_ECDSA_NIST_P256_SHA_256;
#endif
	sig_gen_args.message = hash_data;
	sig_gen_args.signature = signature_data;
	sig_gen_args.message_size = hash_data_sz;
	sig_gen_args.signature_size = sign_data_sz;
	sig_gen_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_DIGEST;
	hsmret = hsm_do_sign(key_store_hdl, &sig_gen_args);
	if (hsmret)
		printf("hsm_do_sign failed ret:0x%x\n", hsmret);

	sig_ver_args.key = pub_key;
	sig_ver_args.message = hash_data;
	sig_ver_args.signature = signature_data;
	sig_ver_args.key_size = pub_key_sz;
	sig_ver_args.signature_size = sign_data_sz;
	sig_ver_args.message_size = hash_data_sz;
#ifdef PSA_COMPLIANT
	sig_ver_args.salt_len = 0;
	sig_ver_args.pkey_type = HSM_PUBKEY_TYPE_ECC_NIST;
	sig_ver_args.key_sz   = HSM_KEY_SIZE_ECC_NIST_256;
	sig_ver_args.scheme_id = HSM_SIGNATURE_SCHEME_ECDSA_SHA256;
#else
	sig_ver_args.scheme_id = HSM_SIGNATURE_SCHEME_ECDSA_NIST_P256_SHA_256;
#endif
	sig_ver_args.flags = HSM_OP_VERIFY_SIGN_FLAGS_INPUT_DIGEST;
	hsmret = hsm_verify_sign(sess_hdl,
				 &sig_ver_args,
				 &verif_status);
	if (hsmret)
		printf("hsm_verify_signature ret:0x%x\n", hsmret);

	if (verif_status == HSM_VERIFICATION_STATUS_SUCCESS)
		printf("Verification PASS\n");
	else
		printf("Verification FAIL, status:0x%x\n", verif_status);
	printf("-----------------------------------------------------\n");
}
