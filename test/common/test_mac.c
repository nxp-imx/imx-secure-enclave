// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2025 NXP
 */

#include <stdio.h>

#include "hsm_api.h"
#include "test_utils.h"

#define MAC_KEY_GROUP	50

static uint8_t  test_msg[300] = {
	/* Note that the first 32 Bytes are the "Z" value
	 * that can be retrieved.
	 */
	0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E,
	0xD8, 0xDB, 0x7A, 0x26,	0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,
	0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3, 0x6D, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x20, 0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B,
	0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26, 0x2B, 0x9D, 0xA7, 0xE0,
	0x7C, 0xCB, 0x0E, 0xA9,	0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,
	0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,	0xB2, 0xE1, 0x4C, 0x5C,
	0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,
	0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9, 0xF4, 0x74, 0x7B, 0x8C,
	0xCD, 0xA8, 0xA4, 0xF3,	0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,
	0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E,
	0xD8, 0xDB, 0x7A, 0x26, 0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,
	0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3, 0x6D, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x20,	0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B,
	0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,	0x2B, 0x9D, 0xA7, 0xE0,
	0x7C, 0xCB, 0x0E, 0xA9, 0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,
	0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20, 0xB2, 0xE1, 0x4C, 0x5C,
	0x79, 0xC6, 0xDF, 0x5B,	0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26,
	0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,	0xF4, 0x74, 0x7B, 0x8C,
	0xCD, 0xA8, 0xA4, 0xF3, 0x6D, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x20,
	0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B, 0x85, 0xF4, 0xFE, 0x7E,
	0xD8, 0xDB, 0x7A, 0x26,	0x2B, 0x9D, 0xA7, 0xE0, 0x7C, 0xCB, 0x0E, 0xA9,
	0xF4, 0x74, 0x7B, 0x8C, 0xCD, 0xA8, 0xA4, 0xF3,	0x6D, 0x65, 0x73, 0x73,
	0x61, 0x67, 0x65, 0x20, 0xB2, 0xE1, 0x4C, 0x5C, 0x79, 0xC6, 0xDF, 0x5B,
	0x85, 0xF4, 0xFE, 0x7E, 0xD8, 0xDB, 0x7A, 0x26, 0x2B, 0x9D, 0xA7, 0xE0,
};

static uint8_t test_key_128[16] = {
	0xcc, 0x7d, 0xad, 0xf9, 0xd9, 0xe8, 0x02, 0xe5,
	0x4f, 0x4d, 0xf5, 0x2f, 0x84, 0x97, 0xb6, 0x47,
};

static uint8_t test_key_256[32] = {
	0xc6, 0xcd, 0xfc, 0x78, 0x0d, 0xc5, 0x48, 0xc8,
	0xf8, 0xdd, 0x96, 0x80, 0x4b, 0xa1, 0xbb, 0xae,
	0x63, 0x62, 0xc4, 0x55, 0x28, 0x66, 0x07, 0xd8,
	0x9b, 0xf9, 0x57, 0xb2, 0xa7, 0x89, 0x82, 0xb5,
};

static uint8_t test_key_384[48] = {
	0x77, 0xc2, 0x0d, 0x0d, 0x1b, 0x96, 0x8c, 0xf8,
	0xa8, 0xfa, 0x3c, 0x76, 0xf5, 0x2b, 0x9f, 0x73,
	0x7d, 0x28, 0x21, 0x8f, 0xd8, 0xe5, 0x37, 0x6f,
	0xf2, 0x09, 0xb8, 0x85, 0x22, 0xe8, 0xa2, 0x57,
	0x20, 0x20, 0xe9, 0xe6, 0x55, 0xdf, 0x60, 0x45,
	0x59, 0x65, 0xfa, 0xaf, 0x65, 0xe3, 0xd1, 0x97,
};

static hsm_err_t generate_key(hsm_hdl_t key_mgmt_hdl,
#ifndef PSA_COMPLIANT
			      hsm_key_info_t key_info,
#else
			      hsm_key_lifetime_t key_lifetime,
			      hsm_key_usage_t key_usage,
			      hsm_permitted_algo_t permitted_algo,
					hsm_bit_key_sz_t bit_key_sz,
					hsm_key_lifecycle_t key_lifecycle,
#endif
			      hsm_key_type_t key_type,
			      uint32_t *key_identifier)
{
	op_generate_key_args_t key_gen_args = {0};

	key_gen_args.key_identifier = key_identifier;
	key_gen_args.out_size = 0;
	key_gen_args.key_group = MAC_KEY_GROUP;
#ifndef PSA_COMPLIANT
	key_gen_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
	key_gen_args.key_info = key_info;
#else
	key_gen_args.key_lifetime = key_lifetime;
	key_gen_args.key_usage = key_usage;
	key_gen_args.permitted_algo = permitted_algo;
	key_gen_args.bit_key_sz = bit_key_sz;
	key_gen_args.key_lifecycle = key_lifecycle;
#endif
	key_gen_args.key_type = key_type;
	key_gen_args.out_key = NULL;

	return hsm_generate_key(key_mgmt_hdl, &key_gen_args);
}

hsm_err_t mac_one_go_test(uint32_t key_identifier, hsm_hdl_t sg0_mac_hdl,
			  hsm_op_mac_one_go_algo_t algo,
			  uint16_t payload_size, uint16_t mac_size,
			  uint16_t verify_mac_size)
{
	op_mac_one_go_args_t mac_one_go;
	hsm_mac_verification_status_t mac_status;
	hsm_err_t err;
	uint8_t work_area[128] = {0};

	mac_one_go.key_identifier = key_identifier;
	mac_one_go.algorithm = algo;
	mac_one_go.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION;
	mac_one_go.payload = test_msg;
	mac_one_go.mac = work_area;
	mac_one_go.payload_size = payload_size;
	mac_one_go.mac_size = mac_size;
	err = hsm_mac_one_go(sg0_mac_hdl, &mac_one_go, &mac_status);
	if (err)
		printf("\n\terr: 0x%x hsm_mac_one_go GEN hdl: 0x%08x\n",
				err, sg0_mac_hdl);

	mac_one_go.key_identifier = key_identifier;
	mac_one_go.algorithm = algo;
	mac_one_go.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION;
	mac_one_go.payload = test_msg;
	mac_one_go.mac = work_area;
	mac_one_go.payload_size = payload_size;
	mac_one_go.mac_size = verify_mac_size;
	err = hsm_mac_one_go(sg0_mac_hdl, &mac_one_go, &mac_status);
	if (err)
		printf("\n\terr: 0x%x hsm_mac_one_go GEN hdl: 0x%08x\n",
				err, sg0_mac_hdl);

	if (mac_status == HSM_MAC_VERIFICATION_STATUS_SUCCESS) {
		printf(" --> SUCCESS\n");
	} else {
		printf("\t --> FAILURE\n");
	}
}

hsm_err_t do_mac_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl)
{
	hsm_err_t err;
	open_svc_mac_args_t mac_srv_args;
	hsm_hdl_t sg0_mac_hdl;
	uint32_t sym_key_id = 0;

	if (!key_store_hdl)
		return -1;

	// mac test
	printf("\n---------------------------------------------------\n");
	printf("MAC ONE GO Test:\n");
	printf("---------------------------------------------------\n");
#ifndef PSA_COMPLIANT
	mac_srv_args.flags = 0u;
#endif
	err = hsm_open_mac_service(key_store_hdl, &mac_srv_args, &sg0_mac_hdl);
	if (err)
		printf("err: 0x%x hsm_open_mac_service err: hdl: 0x%08x\n",
				err, sg0_mac_hdl);

	printf("HSM_KEY_TYPE_AES_256 & HSM_OP_MAC_ONE_GO_ALGO_AES_CMAC:");
	generate_key(key_mgmt_hdl,
#ifndef PSA_COMPLIANT
			HSM_KEY_INFO_TRANSIENT,
			HSM_KEY_TYPE_AES_256,
#else
			HSM_SE_KEY_STORAGE_VOLATILE,
			HSM_KEY_USAGE_SIGN_MSG | HSM_KEY_USAGE_VERIFY_MSG,
			PERMITTED_ALGO_CMAC,
			HSM_KEY_SIZE_AES_256,
			0,
			HSM_KEY_TYPE_AES,
#endif
			&sym_key_id);

	mac_one_go_test(sym_key_id, sg0_mac_hdl,
#ifdef PSA_COMPLIANT
			PERMITTED_ALGO_CMAC, 32, 16, 16);
#else
			HSM_OP_MAC_ONE_GO_ALGO_AES_CMAC, 32, 16, 8);
#endif

	printf("HSM_KEY_TYPE_AES_128 & HSM_OP_MAC_ONE_GO_ALGO_AES_CMAC:");
	sym_key_id = 0;
	generate_key(key_mgmt_hdl,
#ifndef PSA_COMPLIANT
			HSM_KEY_INFO_TRANSIENT,
			HSM_KEY_TYPE_AES_128,
#else
			HSM_SE_KEY_STORAGE_VOLATILE,
			HSM_KEY_USAGE_SIGN_MSG | HSM_KEY_USAGE_VERIFY_MSG,
			PERMITTED_ALGO_CMAC,
			HSM_KEY_SIZE_AES_128,
			0,
			HSM_KEY_TYPE_AES,
#endif
			&sym_key_id);

	mac_one_go_test(sym_key_id, sg0_mac_hdl,
#ifdef PSA_COMPLIANT
			PERMITTED_ALGO_CMAC, 16, 16, 16);
#else
			HSM_OP_MAC_ONE_GO_ALGO_AES_CMAC, 16, 16, 8);
#endif

	if (se_get_soc_id() == SOC_IMX95)
		goto out;

#if PLAT_ELE_FEAT_NOT_SUPPORTED
	printf("HSM_KEY_TYPE_HMAC_224 & HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_224:");
	sym_key_id = 0;
	generate_key(key_mgmt_hdl,
#ifndef PSA_COMPLIANT
			HSM_KEY_INFO_TRANSIENT,
			HSM_KEY_TYPE_HMAC_224,
#else
			HSM_SE_KEY_STORAGE_VOLATILE,
			HSM_KEY_USAGE_SIGN_MSG | HSM_KEY_USAGE_VERIFY_MSG,
			PERMITTED_ALGO_HMAC_SHA224, // Not supported on ELE
			HSM_KEY_SIZE_HMAC_224,
			0,
			HSM_KEY_TYPE_HMAC,
#endif
			&sym_key_id);

	mac_one_go_test(sym_key_id, sg0_mac_hdl,
			HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_224, 28, 28, 28);
#endif

	printf("HSM_KEY_TYPE_HMAC_256 & HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_256:");
	sym_key_id = 0;
	generate_key(key_mgmt_hdl,
#ifndef PSA_COMPLIANT
			HSM_KEY_INFO_TRANSIENT,
			HSM_KEY_TYPE_HMAC_256,
#else
			HSM_SE_KEY_STORAGE_VOLATILE,
			HSM_KEY_USAGE_SIGN_MSG | HSM_KEY_USAGE_VERIFY_MSG,
			PERMITTED_ALGO_HMAC_SHA256,
			HSM_KEY_SIZE_HMAC_256,
			0,
			HSM_KEY_TYPE_HMAC,
#endif
			&sym_key_id);

	mac_one_go_test(sym_key_id, sg0_mac_hdl,
#ifdef PSA_COMPLIANT
			PERMITTED_ALGO_HMAC_SHA256, 32, 32, 32);
#else
			HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_256, 32, 32, 32);
#endif

	printf("HSM_KEY_TYPE_HMAC_384 & HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_384:");
	sym_key_id = 0;
	generate_key(key_mgmt_hdl,
#ifndef PSA_COMPLIANT
			HSM_KEY_INFO_TRANSIENT,
			HSM_KEY_TYPE_HMAC_384,
#else
			HSM_SE_KEY_STORAGE_VOLATILE,
			HSM_KEY_USAGE_SIGN_MSG | HSM_KEY_USAGE_VERIFY_MSG,
			PERMITTED_ALGO_HMAC_SHA384,
			HSM_KEY_SIZE_HMAC_384,
			0,
			HSM_KEY_TYPE_HMAC,
#endif
			&sym_key_id);

	mac_one_go_test(sym_key_id, sg0_mac_hdl,
#ifdef PSA_COMPLIANT
			PERMITTED_ALGO_HMAC_SHA384, 32, 48, 48);
#else
			HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_384, 32, 16, 8);
#endif

#if PLAT_ELE_FEAT_NOT_SUPPORTED
	printf("HSM_KEY_TYPE_HMAC_512 & HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_512:");
	sym_key_id = 0;
	generate_key(key_mgmt_hdl,
#ifndef PSA_COMPLIANT
			HSM_KEY_INFO_TRANSIENT,
			HSM_KEY_TYPE_HMAC_512,
#else
			HSM_SE_KEY_STORAGE_VOLATILE,
			HSM_KEY_USAGE_SIGN_MSG | HSM_KEY_USAGE_VERIFY_MSG,
			PERMITTED_ALGO_HMAC_SHA512, // Not supported on ELE
			HSM_KEY_SIZE_HMAC_512,
			0,
			HSM_KEY_TYPE_HMAC,
#endif
			&sym_key_id);
	mac_one_go_test(sym_key_id, sg0_mac_hdl,
			HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_512, 32, 16, 8);
#endif
out:
	err = hsm_close_mac_service(sg0_mac_hdl);
	printf("0x%x hsm_close_mac_service hdl: 0x%x\n", err, sg0_mac_hdl);
	printf("---------------------------------------------------\n\n");

	return err;

}

static void status(op_mac_one_go_args_t *mac_one_go)
{
	if (mac_one_go->verification_status == HSM_MAC_VERIFICATION_STATUS_SUCCESS)
		printf(" --> SUCCESS\n");
	else
		printf("\t --> FAILURE\n");
}

hsm_err_t hsm_mac_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl)
{
	hsm_err_t err;
	op_mac_one_go_args_t mac_one_go = {0};
	hsm_hdl_t sg0_mac_hdl;

	uint8_t work_area[128] = {0};
	uint32_t sym_key_id = 0;
#ifndef PSA_COMPLIANT
	mac_one_go.svc_flags = 0u;
#endif

	// mac test
	printf("\n---------------------------------------------------\n");
	printf("SECONDARY API: DO MAC Test Start\n");
	printf("---------------------------------------------------\n");

	printf("HSM_KEY_TYPE_AES_256 & HSM_OP_MAC_ONE_GO_ALGO_AES_CMAC:");
	generate_key(key_mgmt_hdl,
#ifndef PSA_COMPLIANT
			HSM_KEY_INFO_TRANSIENT,
			HSM_KEY_TYPE_AES_256,
#else
			HSM_SE_KEY_STORAGE_VOLATILE,
			HSM_KEY_USAGE_SIGN_MSG | HSM_KEY_USAGE_VERIFY_MSG,
			PERMITTED_ALGO_CMAC,
			HSM_KEY_SIZE_AES_256,
			0,
			HSM_KEY_TYPE_AES,
#endif
			&sym_key_id);

	mac_one_go.key_identifier = sym_key_id;
#ifdef PSA_COMPLIANT
	mac_one_go.algorithm = PERMITTED_ALGO_CMAC;
#else
	mac_one_go.algorithm = HSM_OP_MAC_ONE_GO_ALGO_AES_CMAC;
#endif
	mac_one_go.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION;
	mac_one_go.payload = test_msg;
	mac_one_go.mac = work_area;
	mac_one_go.payload_size = 32;
	mac_one_go.mac_size = 16;

	err = hsm_do_mac(key_store_hdl, &mac_one_go);

	mac_one_go.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION;
	mac_one_go.mac_size = 16;

	err = hsm_do_mac(key_store_hdl, &mac_one_go);
	status(&mac_one_go);

	printf("HSM_KEY_TYPE_AES_128 & HSM_OP_MAC_ONE_GO_ALGO_AES_CMAC:");
	sym_key_id = 0;
	generate_key(key_mgmt_hdl,
#ifndef PSA_COMPLIANT
			HSM_KEY_INFO_TRANSIENT,
			HSM_KEY_TYPE_AES_128,
#else
			HSM_SE_KEY_STORAGE_VOLATILE,
			HSM_KEY_USAGE_SIGN_MSG | HSM_KEY_USAGE_VERIFY_MSG,
			PERMITTED_ALGO_CMAC,
			HSM_KEY_SIZE_AES_128,
			0,
			HSM_KEY_TYPE_AES,
#endif
			&sym_key_id);

	mac_one_go.key_identifier = sym_key_id;
#ifdef PSA_COMPLIANT
	mac_one_go.algorithm = PERMITTED_ALGO_CMAC;
#else
	mac_one_go.algorithm = HSM_OP_MAC_ONE_GO_ALGO_AES_CMAC;
#endif
	mac_one_go.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION;
	mac_one_go.payload = test_msg;
	mac_one_go.mac = work_area;
	mac_one_go.payload_size = 16;
	mac_one_go.mac_size = 16;

	err = hsm_do_mac(key_store_hdl, &mac_one_go);

	mac_one_go.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION;
	mac_one_go.mac_size = 16;

	err = hsm_do_mac(key_store_hdl, &mac_one_go);
	status(&mac_one_go);

	if (se_get_soc_id() == SOC_IMX95)
		goto out;

#if PLAT_ELE_FEAT_NOT_SUPPORTED
	printf("HSM_KEY_TYPE_HMAC_224 & HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_224:");
	sym_key_id = 0;
	generate_key(key_mgmt_hdl,
#ifndef PSA_COMPLIANT
			HSM_KEY_INFO_TRANSIENT,
			HSM_KEY_TYPE_HMAC_224,
#else
			HSM_SE_KEY_STORAGE_VOLATILE,
			HSM_KEY_USAGE_SIGN_MSG | HSM_KEY_USAGE_VERIFY_MSG,
			PERMITTED_ALGO_HMAC_SHA224, // Not supported on ELE
			HSM_KEY_SIZE_HMAC_224,
			0,
			HSM_KEY_TYPE_HMAC,
#endif
			&sym_key_id);

	mac_one_go.key_identifier = sym_key_id;
	mac_one_go.algorithm = HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_224;
	mac_one_go.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION;
	mac_one_go.payload = test_msg;
	mac_one_go.mac = work_area;
	mac_one_go.payload_size = 28;
	mac_one_go.mac_size = 28;

	err = hsm_do_mac(key_store_hdl, &mac_one_go);

	mac_one_go.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION;
	mac_one_go.mac_size = 28;

	err = hsm_do_mac(key_store_hdl, &mac_one_go);
	status(&mac_one_go);
#endif

	printf("HSM_KEY_TYPE_HAMC_256 & HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_256:");
	sym_key_id = 0;
	generate_key(key_mgmt_hdl,
#ifndef PSA_COMPLIANT
			HSM_KEY_INFO_TRANSIENT,
			HSM_KEY_TYPE_HMAC_256,
#else
			HSM_SE_KEY_STORAGE_VOLATILE,
			HSM_KEY_USAGE_SIGN_MSG | HSM_KEY_USAGE_VERIFY_MSG,
			PERMITTED_ALGO_HMAC_SHA256,
			HSM_KEY_SIZE_HMAC_256,
			0,
			HSM_KEY_TYPE_HMAC,
#endif
			&sym_key_id);

	mac_one_go.key_identifier = sym_key_id;
#ifdef PSA_COMPLIANT
	mac_one_go.algorithm = PERMITTED_ALGO_HMAC_SHA256;
#else
	mac_one_go.algorithm = HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_256;
#endif
	mac_one_go.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION;
	mac_one_go.payload = test_msg;
	mac_one_go.mac = work_area;
	mac_one_go.payload_size = 32;
	mac_one_go.mac_size = 32;

	err = hsm_do_mac(key_store_hdl, &mac_one_go);

	mac_one_go.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION;
	mac_one_go.mac_size = 32;

	err = hsm_do_mac(key_store_hdl, &mac_one_go);
	status(&mac_one_go);

	printf("HSM_KEY_TYPE_HAMC_384 & HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_384:");
	sym_key_id = 0;
	generate_key(key_mgmt_hdl,
#ifndef PSA_COMPLIANT
			HSM_KEY_INFO_TRANSIENT,
			HSM_KEY_TYPE_HMAC_384,
#else
			HSM_SE_KEY_STORAGE_VOLATILE,
			HSM_KEY_USAGE_SIGN_MSG | HSM_KEY_USAGE_VERIFY_MSG,
			PERMITTED_ALGO_HMAC_SHA384,
			HSM_KEY_SIZE_HMAC_384,
			0,
			HSM_KEY_TYPE_HMAC,
#endif
			&sym_key_id);

	mac_one_go.key_identifier = sym_key_id;
#ifdef PSA_COMPLIANT
	mac_one_go.algorithm = PERMITTED_ALGO_HMAC_SHA384;
#else
	mac_one_go.algorithm = HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_384;
#endif
	mac_one_go.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION;
	mac_one_go.payload = test_msg;
	mac_one_go.mac = work_area;
	mac_one_go.payload_size = 32;
	mac_one_go.mac_size = 48;

	err = hsm_do_mac(key_store_hdl, &mac_one_go);

	mac_one_go.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION;
	mac_one_go.mac_size = 48;

	err = hsm_do_mac(key_store_hdl, &mac_one_go);
	status(&mac_one_go);
#if PLAT_ELE_FEAT_NOT_SUPPORTED
	printf("HSM_KEY_TYPE_HAMC_512 & HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_512:");
	sym_key_id = 0;
	generate_key(key_mgmt_hdl,
#ifndef PSA_COMPLIANT
			HSM_KEY_INFO_TRANSIENT,
			HSM_KEY_TYPE_HMAC_512,
#else
			HSM_SE_KEY_STORAGE_VOLATILE,
			HSM_KEY_USAGE_SIGN_MSG | HSM_KEY_USAGE_VERIFY_MSG,
			PERMITTED_ALGO_HMAC_SHA512, // Not supporetd on ELE
			HSM_KEY_SIZE_HMAC_512,
			0,
			HSM_KEY_TYPE_HMAC,
#endif
			&sym_key_id);

	mac_one_go.key_identifier = sym_key_id;
	mac_one_go.algorithm = HSM_OP_MAC_ONE_GO_ALGO_HMAC_SHA_512;
	mac_one_go.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION;
	mac_one_go.payload = test_msg;
	mac_one_go.mac = work_area;
	mac_one_go.payload_size = 32;
	mac_one_go.mac_size = 16;

	err = hsm_do_mac(key_store_hdl, &mac_one_go);

	mac_one_go.flags = HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION;
	mac_one_go.mac_size = 8;

	err = hsm_do_mac(key_store_hdl, &mac_one_go);
	status(&mac_one_go);
#endif
out:
	printf("\n---------------------------------------------------\n");
	printf("SECONDARY API: DO MAC Test Complete\n");
	printf("---------------------------------------------------\n\n");

	return err;
}

#ifdef PSA_COMPLIANT
hsm_err_t hsm_mac_plainkey_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl)
{
	hsm_err_t err;
	op_mac_args_t args = {0};
	uint8_t work_area[128] = {0};

	printf("\n---------------------------------------------------\n");
	printf("SECONDARY API: DO MAC Test Start (Plaintext Key)\n");
	printf("---------------------------------------------------\n");

	printf("HSM_KEY_SIZE_AES_256 & PERMITTED_ALGO_CMAC:");

	memset(&args, 0, sizeof(op_mac_args_t));
	args.flags = HSM_OP_MAC_FLAGS_MAC_GENERATION | HSM_OP_MAC_FLAGS_PLAINTEXT_KEY;
	args.key = test_key_256;
	args.key_size = sizeof(test_key_256);
	args.key_type = HSM_KEY_TYPE_AES;
	args.algorithm = PERMITTED_ALGO_CMAC;
	args.payload = test_msg;
	args.mac = work_area;
	args.payload_size = 32;
	args.mac_size = 16;

	err = hsm_do_mac(key_store_hdl, &args);
	if (err != HSM_NO_ERROR)
		printf("\nhsm_do_mac (gen) err: 0x%x\n", err);

	args.flags = HSM_OP_MAC_FLAGS_MAC_VERIFICATION | HSM_OP_MAC_FLAGS_PLAINTEXT_KEY;
	args.mac_size = 16;

	err = hsm_do_mac(key_store_hdl, &args);
	if (err != HSM_NO_ERROR)
		printf("\nhsm_do_mac (verify) err: 0x%x\n", err);

	status(&args);

	printf("HSM_KEY_SIZE_AES_128 & PERMITTED_ALGO_CMAC:");

	memset(work_area, 0, sizeof(work_area));
	memset(&args, 0, sizeof(op_mac_args_t));
	args.flags = HSM_OP_MAC_FLAGS_MAC_GENERATION | HSM_OP_MAC_FLAGS_PLAINTEXT_KEY;
	args.key = test_key_128;
	args.key_size = sizeof(test_key_128);
	args.key_type = HSM_KEY_TYPE_AES;
	args.algorithm = PERMITTED_ALGO_CMAC;
	args.payload = test_msg;
	args.mac = work_area;
	args.payload_size = 16;
	args.mac_size = 16;

	err = hsm_do_mac(key_store_hdl, &args);
	if (err != HSM_NO_ERROR)
		printf("\nhsm_do_mac (gen) err: 0x%x\n", err);

	args.flags = HSM_OP_MAC_FLAGS_MAC_VERIFICATION | HSM_OP_MAC_FLAGS_PLAINTEXT_KEY;
	args.mac_size = 16;

	err = hsm_do_mac(key_store_hdl, &args);
	if (err != HSM_NO_ERROR)
		printf("\nhsm_do_mac (verify) err: 0x%x\n", err);

	status(&args);

	if (se_get_soc_id() == SOC_IMX95)
		goto out;

	printf("HSM_KEY_SIZE_HMAC_256 & PERMITTED_ALGO_HMAC_SHA256:");

	memset(work_area, 0, sizeof(work_area));
	memset(&args, 0, sizeof(op_mac_args_t));
	args.flags = HSM_OP_MAC_FLAGS_MAC_GENERATION | HSM_OP_MAC_FLAGS_PLAINTEXT_KEY;
	args.key = test_key_256;
	args.key_size = sizeof(test_key_256);
	args.key_type = HSM_KEY_TYPE_HMAC;
	args.algorithm = PERMITTED_ALGO_HMAC_SHA256;
	args.payload = test_msg;
	args.mac = work_area;
	args.payload_size = 32;
	args.mac_size = 32;

	err = hsm_do_mac(key_store_hdl, &args);
	if (err != HSM_NO_ERROR)
		printf("\nhsm_do_mac (gen) err: 0x%x\n", err);

	args.flags = HSM_OP_MAC_FLAGS_MAC_VERIFICATION | HSM_OP_MAC_FLAGS_PLAINTEXT_KEY;
	args.mac_size = 32;

	err = hsm_do_mac(key_store_hdl, &args);
	if (err != HSM_NO_ERROR)
		printf("\nhsm_do_mac (verify) err: 0x%x\n", err);

	status(&args);

	printf("HSM_KEY_SIZE_HMAC_384 & PERMITTED_ALGO_HMAC_SHA384:");

	memset(work_area, 0, sizeof(work_area));
	memset(&args, 0, sizeof(op_mac_args_t));
	args.flags = HSM_OP_MAC_FLAGS_MAC_GENERATION | HSM_OP_MAC_FLAGS_PLAINTEXT_KEY;
	args.key = test_key_384;
	args.key_size = sizeof(test_key_384);
	args.key_type = HSM_KEY_TYPE_HMAC;
	args.algorithm = PERMITTED_ALGO_HMAC_SHA384;
	args.payload = test_msg;
	args.mac = work_area;
	args.payload_size = 32;
	args.mac_size = 48;

	err = hsm_do_mac(key_store_hdl, &args);
	if (err != HSM_NO_ERROR)
		printf("\nhsm_do_mac (gen) err: 0x%x\n", err);

	args.flags = HSM_OP_MAC_FLAGS_MAC_VERIFICATION | HSM_OP_MAC_FLAGS_PLAINTEXT_KEY;
	args.mac_size = 48;

	err = hsm_do_mac(key_store_hdl, &args);
	if (err != HSM_NO_ERROR)
		printf("\nhsm_do_mac (verify) err: 0x%x\n", err);

	status(&args);
out:
	printf("\n---------------------------------------------------\n");
	printf("SECONDARY API: DO MAC Test Complete\n");
	printf("---------------------------------------------------\n");

	return err;
}

hsm_err_t hsm_mac_stream_test(hsm_hdl_t key_store_hdl, hsm_hdl_t key_mgmt_hdl)
{
	hsm_err_t err;
	hsm_hdl_t mac_hdl = 0;
	op_mac_args_t args = {0};
	open_svc_mac_args_t mac_srv_args = {0};
	uint8_t work_area[128] = {0};
	uint32_t key_id = 0;

	printf("-------------------------------------------------------------\n");
	printf("MAC Stream Test Start (Opaque Key)\n");
	printf("---------------------------------------------------------------\n");

	printf("HSM_KEY_SIZE_AES_256 & PERMITTED_ALGO_CMAC:");

	generate_key(key_mgmt_hdl,
		     HSM_SE_KEY_STORAGE_VOLATILE,
		     HSM_KEY_USAGE_SIGN_MSG | HSM_KEY_USAGE_VERIFY_MSG,
		     PERMITTED_ALGO_CMAC,
		     HSM_KEY_SIZE_AES_256,
		     0,
		     HSM_KEY_TYPE_AES,
		     &key_id);

	err = hsm_open_mac_service(key_store_hdl, &mac_srv_args, &mac_hdl);
	if (err != HSM_NO_ERROR) {
		printf("\nhsm_open_mac_service err: 0x%x\n", err);
		goto out;
	}

	/* MAC Generation */

	/* INIT */
	memset(&args, 0, sizeof(op_mac_args_t));
	args.flags = HSM_OP_MAC_FLAGS_INIT;
	args.algorithm = PERMITTED_ALGO_CMAC;
	args.key_identifier = key_id;

	err = hsm_mac(mac_hdl, &args, &args.verification_status);
	if (err != HSM_NO_ERROR) {
		printf("\nhsm_mac (gen) (INIT) err: 0x%x\n", err);
		goto out;
	}

	/* UPDATE DATA  */
	memset(&args, 0, sizeof(op_mac_args_t));
	args.flags = HSM_OP_MAC_FLAGS_UPDATE_DATA;
	args.algorithm = PERMITTED_ALGO_CMAC;
	args.payload = test_msg;
	args.payload_size = 32;

	err = hsm_mac(mac_hdl, &args, &args.verification_status);
	if (err != HSM_NO_ERROR) {
		printf("\nhsm_mac (gen) (UPDATE DATA) err: 0x%x\n", err);
		goto out;
	}

	/* FINALIZE */
	memset(&args, 0, sizeof(op_mac_args_t));
	args.flags = HSM_OP_MAC_FLAGS_FINALIZE;
	args.algorithm = PERMITTED_ALGO_CMAC;
	args.mac = work_area;
	args.mac_size = 16;

	err = hsm_mac(mac_hdl, &args, &args.verification_status);
	if (err != HSM_NO_ERROR) {
		printf("\nhsm_mac (gen) (FINALIZE) err: 0x%x\n", err);
		goto out;
	}

	/* MAC Verification */

	/* INIT */
	memset(&args, 0, sizeof(op_mac_args_t));
	args.flags = HSM_OP_MAC_FLAGS_INIT;
	args.algorithm = PERMITTED_ALGO_CMAC;
	args.key_identifier = key_id;

	err = hsm_mac(mac_hdl, &args, &args.verification_status);
	if (err != HSM_NO_ERROR) {
		printf("\nhsm_mac (verify) (INIT) err: 0x%x\n", err);
		goto out;
	}

	/* UPDATE DATA  */
	memset(&args, 0, sizeof(op_mac_args_t));
	args.flags = HSM_OP_MAC_FLAGS_UPDATE_DATA;
	args.algorithm = PERMITTED_ALGO_CMAC;
	args.payload = test_msg;
	args.payload_size = 32;

	err = hsm_mac(mac_hdl, &args, &args.verification_status);
	if (err != HSM_NO_ERROR) {
		printf("\nhsm_mac (verify) (UPDATE DATA) err: 0x%x\n", err);
		goto out;
	}

	/* FINALIZE VERIFY */
	memset(&args, 0, sizeof(op_mac_args_t));
	args.flags = HSM_OP_MAC_FLAGS_FINALIZE_VERIFY;
	args.algorithm = PERMITTED_ALGO_CMAC;
	args.mac = work_area;
	args.mac_size = 16;

	err = hsm_mac(mac_hdl, &args, &args.verification_status);
	if (err != HSM_NO_ERROR) {
		printf("\nhsm_mac (verify) (FINALIZE VERIFY) err: 0x%x\n", err);
		goto out;
	}

	err = hsm_close_mac_service(mac_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_close_mac_service err: 0x%x\n", err);
		goto out;
	}

	status(&args);

out:
	if (key_id)
		delete_test_key(key_mgmt_hdl, key_id, 0);

	printf("\n---------------------------------------------------\n");
	printf("MAC Stream Test Complete\n");
	printf("---------------------------------------------------\n\n");

	return err;
}
#endif
