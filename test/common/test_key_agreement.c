// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>

#include "test_common.h"
#include "hsm_api.h"

#ifdef PSA_COMPLIANT
/* Key Agreement operation - Plaintext mode */
static uint8_t test_key_agreement_subtest_01(uint32_t key_mgmt_hdl, uint32_t key_store_id)
{
	hsm_err_t err;
	op_key_agreement_args_t args = {0};
	op_key_agreement_algo_ecdh_args_t ecdh_args = {0};
	uint8_t priv_key[32] = {0};
	uint8_t pub_key[64] = {0};
	uint8_t peer_priv_key[32] = {0};
	uint8_t peer_pub_key[64] = {0};
	uint8_t shared_secret[32] = {0};

	/* Generate 1st ECC Key-Pair (plaintext keys) for Key Agreement */
	err = generate_test_key(key_mgmt_hdl,
				HSM_KEY_TYPE_ECC_NIST,
				HSM_KEY_SIZE_ECC_NIST_256,
				0, 0, 0, 0,
				HSM_OP_KEY_GENERATION_FLAGS_PLAINTEXT_KEY,
				0,
				sizeof(priv_key), priv_key,
				sizeof(pub_key), pub_key,
				NULL);
	if (err != HSM_NO_ERROR)
		return TEST_FAILED;

	/* Generate PEER ECC Key-Pair (plaintext keys) for Key Agreement */
	err = generate_test_key(key_mgmt_hdl,
				HSM_KEY_TYPE_ECC_NIST,
				HSM_KEY_SIZE_ECC_NIST_256,
				0, 0, 0, 0,
				HSM_OP_KEY_GENERATION_FLAGS_PLAINTEXT_KEY,
				0,
				sizeof(peer_priv_key), peer_priv_key,
				sizeof(peer_pub_key), peer_pub_key,
				NULL);
	if (err != HSM_NO_ERROR)
		return TEST_FAILED;

	/* Populate ECDH algorithm arguments */
	ecdh_args.vers = HSM_KEY_AGREEMENT_ALGO_ARGS_ECDH_FORMAT_VERS;
	ecdh_args.peer_pub_key = peer_pub_key;
	ecdh_args.peer_pub_key_size = sizeof(peer_pub_key);
	ecdh_args.priv_key = priv_key;
	ecdh_args.priv_key_size = sizeof(priv_key);
	ecdh_args.shared_secret = shared_secret;
	ecdh_args.shared_secret_size = sizeof(shared_secret);

	/* Key Agreement command arguments */
	args.algorithm = HSM_KEY_AGREEMENT_ECDH;
	args.flags = HSM_OP_KEY_AGREEMENT_FLAGS_PLAINTEXT;
	args.key_agreement_algo_args = &ecdh_args;
	args.key_agreement_algo_args_size = sizeof(op_key_agreement_algo_ecdh_args_t);

	err = hsm_key_agreement(get_se_lib_serv_hdl(), &args);
	if (err != HSM_NO_ERROR) {
		printf("\nhsm_key_agreement (plaintext) err: 0x%x. --> FAILED\n",
		       err);
		return TEST_FAILED;
	}

	printf("\nhsm_key_agreement (plaintext) [key_id=0x%x] --> SUCCESS\n",
	       args.shared_secret_key_id);

	printf("\n::Shared Secret::\n");
	dump_hex(ecdh_args.shared_secret, ecdh_args.shared_secret_size);

	return TEST_SUCCESS;
}

uint8_t test_key_agreement(uint32_t key_mgmt_hdl, uint32_t key_store_id)
{
	uint8_t ret = TEST_SUCCESS;

	printf("\n----------------------------------------------------------\n");
	printf("Key Agreement (ECDH)");
	printf("\n----------------------------------------------------------\n");

	ret |= test_key_agreement_subtest_01(key_mgmt_hdl, key_store_id);

	printf("\n----------------------------------------------------------\n");

	return ret;
}
#endif
