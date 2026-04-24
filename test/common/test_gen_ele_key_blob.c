// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include <stdint.h>

#include "hsm_api.h"
#include "test_common.h"

hsm_op_gen_ele_key_blob_algo_t
	gen_ele_key_blob_get_algo(hsm_op_gen_ele_key_blob_flags_t flag, char *str)
{
#ifdef PSA_COMPLIANT
	if (flag & HSM_OP_GEN_ELE_KEY_BLOB_FLAG_BLOB_TYPE_OTFAD_CONF) {
		if (!memcmp(GEN_ELE_KEY_BLOB_FORMAT_ALGO_AES_CTR, str, strlen(str)))
			return HSM_OP_GEN_ELE_KEY_BLOB_ALGO_AES_CTR;
	}
	if (flag & HSM_OP_GEN_ELE_KEY_BLOB_FLAG_BLOB_TYPE_DEK) {
		if (!memcmp(GEN_ELE_KEY_BLOB_FORMAT_ALGO_AES_CBC, str, strlen(str)))
			return HSM_OP_GEN_ELE_KEY_BLOB_ALGO_AES_CBC;
		if (!memcmp(GEN_ELE_KEY_BLOB_FORMAT_ALGO_SM4_CBC, str, strlen(str)))
			return HSM_OP_GEN_ELE_KEY_BLOB_ALGO_SM4_CBC;
	}
#endif

	return 0;
}

uint16_t gen_ele_key_blob_get_keysize(hsm_op_gen_ele_key_blob_flags_t flag, char *str)
{
#ifdef PSA_COMPLIANT
	if (flag & HSM_OP_GEN_ELE_KEY_BLOB_FLAG_BLOB_TYPE_DEK) {
		if (!memcmp(GEN_ELE_KEY_BLOB_FORMAT_ALGO_KEY_SZ_AES128, str, strlen(str)))
			return 16;
		if (!memcmp(GEN_ELE_KEY_BLOB_FORMAT_ALGO_KEY_SZ_AES192, str, strlen(str)))
			return 24;
		if (!memcmp(GEN_ELE_KEY_BLOB_FORMAT_ALGO_KEY_SZ_AES256, str, strlen(str)))
			return 32;
		if (!memcmp(GEN_ELE_KEY_BLOB_FORMAT_ALGO_KEY_SZ_SM4128, str, strlen(str)))
			return 16;
	}
	if (flag & HSM_OP_GEN_ELE_KEY_BLOB_FLAG_BLOB_TYPE_OTFAD_CONF)
		return OP_GEN_ELE_KEY_BLOB_PAYLOAD_OTFAD_SZ;
#endif

	return 0;
}

static char *get_gen_ele_key_blob_algo_name(hsm_op_gen_ele_key_blob_algo_t algo)
{
#ifdef PSA_COMPLIANT
	switch (algo) {
	case HSM_OP_GEN_ELE_KEY_BLOB_ALGO_AES_CBC: return "AES_CBC"; break;
	case HSM_OP_GEN_ELE_KEY_BLOB_ALGO_AES_CTR: return "AES_CTR"; break;
	case HSM_OP_GEN_ELE_KEY_BLOB_ALGO_SM4_CBC: return "SM4_CBC"; break;
	case HSM_OP_GEN_ELE_KEY_BLOB_ALGO_AES_XTS: return "AES_XTS"; break;
	}

#endif
	return "Unknown-algo";
}

hsm_err_t test_gen_ele_key_blob(hsm_hdl_t sess_hdl,
				hsm_op_gen_ele_key_blob_flags_t flag, uint32_t key_id,
				hsm_op_gen_ele_key_blob_algo_t algo, uint8_t *payload,
				uint8_t payload_len, uint8_t *ele_key_blob,
				uint8_t *ele_key_blob_sz)
{
#ifdef PSA_COMPLIANT
	op_gen_ele_key_blob_format_t blob_format = {
		.tag = GEN_ELE_KEY_BLOB_FORMAT_TAG,
		.vers = GEN_ELE_KEY_BLOB_FORMAT_VERS,
		.algo = algo,
		.raw_data_sz = payload_len,
		.flag = flag,
	};
	op_gen_ele_key_blob_msg_args_t args;
	hsm_err_t err = HSM_LIB_ERROR;
	uint16_t total_len;
	const char *option = "DEK";

	if (!payload_len)
		return err;

	if (payload_len > OP_GEN_ELE_KEY_BLOB_PAYLOAD_MAX_SZ)
		return err;

	blob_format.raw_data_sz = payload_len;
	if (!payload)
		return err;
	memcpy(blob_format.payload, payload, blob_format.raw_data_sz);

	if (flag & HSM_OP_GEN_ELE_KEY_BLOB_FLAG_BLOB_TYPE_OTFAD_CONF)
		option = "OTFAD";

	total_len = OP_GEN_ELE_KEY_BLOB_FORMAT_SZ_WO_PAYLOAD + blob_format.raw_data_sz;
	set_blob_format_len(&blob_format, total_len);

	printf("\nGenerating ELE %s key blob for algo: %s, key-size: %d bits.\n",
	       option, get_gen_ele_key_blob_algo_name(algo),
	       blob_format.raw_data_sz << 3);

	*ele_key_blob_sz = total_len + GEN_ELE_KEY_BLOB_OVERHEAD_SZ;

	if (!ele_key_blob || *ele_key_blob_sz < total_len + GEN_ELE_KEY_BLOB_OVERHEAD_SZ)
		return err;

	printf("\nInput Blob Format:");
	hexdump((uint32_t *)&blob_format,
		(OP_GEN_ELE_KEY_BLOB_FORMAT_SZ_WO_PAYLOAD +
		 blob_format.raw_data_sz) >> 2);

	args.load_addr_sz = *ele_key_blob_sz;

	args.key_id = key_id;
	args.load_addr = (uint8_t *)&blob_format;
	args.store_addr = ele_key_blob;

	args.max_export_sz = *ele_key_blob_sz;
	args.store_addr_sz = args.max_export_sz;

	err = hsm_gen_ele_key_blob(sess_hdl, &args);
	if (err != HSM_NO_ERROR) {
		printf("hsm_gen_ele_key_blob failed err:0x%x\n", err);
	} else {
		printf("\nGenerated Blob:");
		hexdump((uint32_t *)ele_key_blob, *ele_key_blob_sz >> 2);
	}

	return err;
#else
	printf("GEN ELE KEY BLOB feature is not supported on non-PSA.\n");
	return HSM_NO_ERROR;
#endif
}
