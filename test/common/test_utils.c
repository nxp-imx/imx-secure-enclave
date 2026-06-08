// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2026 NXP
 */

#include <stdint.h>
#include <stdio.h>

#include "hsm_api.h"
#include "plat_utils.h"

#include "test_common.h"
#include "test_utils.h"

hsm_err_t generate_test_key(hsm_hdl_t key_mgmt_hdl,
			    hsm_key_type_t key_type,
#ifdef PSA_COMPLIANT
			    hsm_bit_key_sz_t bit_key_sz,
			    hsm_key_lifetime_t key_lifetime,
			    hsm_key_usage_t key_usage,
			    hsm_permitted_algo_t permitted_algo,
			    hsm_key_lifecycle_t key_lifecycle,
#else
			    hsm_key_info_t key_info,
#endif
			    hsm_op_key_gen_flags_t flags,
			    hsm_key_group_t key_group,
#ifdef PSA_COMPLIANT
			    uint16_t priv_out_key_sz,
			    uint8_t *priv_out_key,
#endif
			    uint16_t out_size,
			    uint8_t *out_key,
			    uint32_t *key_id)
{
	hsm_err_t ret;
	op_generate_key_args_t key_gen_args;

	memset(&key_gen_args, 0, sizeof(op_generate_key_args_t));

	key_gen_args.key_identifier = key_id;
	key_gen_args.key_type = key_type;
	key_gen_args.key_group = key_group;
	key_gen_args.flags = flags;
#ifdef PSA_COMPLIANT
	key_gen_args.key_lifetime = key_lifetime;
	key_gen_args.key_usage = key_usage;
	key_gen_args.permitted_algo = permitted_algo;
	key_gen_args.bit_key_sz = bit_key_sz;
	key_gen_args.key_lifecycle = key_lifecycle;
	key_gen_args.priv_out_key_sz = priv_out_key_sz;
	key_gen_args.priv_out_key = priv_out_key;
#else
	key_gen_args.key_info = key_info;
#endif
	key_gen_args.out_size = out_size;
	key_gen_args.out_key = out_key;

	ret = hsm_generate_key(key_mgmt_hdl, &key_gen_args);
	if (ret != HSM_NO_ERROR)
		printf("hsm_generate_key ret: 0x%x. [key_id 0x%x]\n", ret, *key_id);

	return ret;
}

#ifdef PSA_COMPLIANT
hsm_err_t delete_test_key(hsm_hdl_t key_mgmt_hdl,
			  uint32_t key_id,
			  hsm_op_delete_key_flags_t flags)
{
	hsm_err_t ret;
	op_delete_key_args_t args;

	memset(&args, 0, sizeof(op_delete_key_args_t));

	args.key_identifier = key_id;
	args.flags = flags;

	ret = hsm_delete_key(key_mgmt_hdl, &args);
	if (ret != HSM_NO_ERROR)
		printf("hsm_delete_key ret: 0x%x\n", ret);

	return ret;
}
#endif

void set_signed_tests_en_status(uint8_t *oem_srkh, uint16_t len)
{
	if (memcmp(test_oem_srkh_secp384, oem_srkh,
		   sizeof(test_oem_srkh_secp384)) == 0) {
		signed_tests_en_status = SIGNED_TESTS_STATUS_ENABLED;
		signed_tests_key_type = SIGNED_TESTS_KEYS_TYPE_SECP384;
	} else if (memcmp(test_oem_srkh_secp521, oem_srkh,
			  sizeof(test_oem_srkh_secp521)) == 0) {
		signed_tests_en_status = SIGNED_TESTS_STATUS_ENABLED;
		signed_tests_key_type = SIGNED_TESTS_KEYS_TYPE_SECP521;
	}
}

uint8_t get_signed_tests_en_status(void)
{
	return signed_tests_en_status;
}

uint8_t get_signed_tests_key_type(void)
{
	return signed_tests_key_type;
}

void hexdump(uint32_t buf[], uint32_t size)
{
	int i = 0;

	for (; i < size; i++) {
		if ((i % 10) == 0)
			printf("\n");
		printf("%08x ", buf[i]);
	}
	printf("\n\n");
}

/* hexdump which dumps byte-by-byte.
 * correctly reflecting the content
 * at the specific byte location.
 */
void hexdump_bb(uint8_t buf[], uint32_t size)
{
#if ELE_DEBUG
	int i = 0;

	for (i = 0; i < size; i++) {
		if ((i != 0) && (i % 16 == 0))
			printf("\n");
		printf("%02x ", buf[i]);
	}
	printf("\n");
#endif
}

void bytes_swap(uint8_t *ptr, uint32_t size)
{
	uint8_t tmp[size];

	for (uint32_t i = 0; i < size; i++)
		tmp[i] = ptr[size - 1 - i];

	memcpy(ptr, tmp, size);
}

void word_byteswap(uint32_t *buf, uint32_t buf_len)
{
	int i = 0;
	uint32_t word;

	for (; i < buf_len; i++) {
		word = buf[i];
		buf[i] = ((uint8_t *) &word)[3];
		buf[i] |= ((uint8_t *) &word)[2] << 8;
		buf[i] |= ((uint8_t *) &word)[1] << 16;
		buf[i] |= ((uint8_t *) &word)[0] << 24;
	}
}

void key_management(uint32_t key_op,
		    hsm_hdl_t key_mgmt_hdl,
		    uint32_t *key_id,
		    hsm_key_group_t key_group,
		    hsm_key_type_t key_type)
{
	hsm_err_t hsmret;
#ifdef HSM_MANAGE_KEY
	op_manage_key_args_t mng_args;
#endif
#ifdef HSM_DELETE_KEY
	op_delete_key_args_t del_args;
#endif
#ifdef HSM_GET_KEY_ATTR
	op_get_key_attr_args_t keyattr_args;
#endif

	switch (key_op) {
	case DELETE:
#ifdef HSM_MANAGE_KEY
		memset(&mng_args, 0, sizeof(mng_args));
		mng_args.key_identifier = key_id;
		mng_args.flags = HSM_OP_MANAGE_KEY_FLAGS_DELETE;
		mng_args.key_type = key_type;
		mng_args.key_group = key_group;
		hsmret = hsm_manage_key(key_mgmt_hdl, &mng_args);
		printf("hsm_manage_key ret:0x%x\n", hsmret);
#endif
#ifdef HSM_DELETE_KEY
		memset(&del_args, 0, sizeof(del_args));
		del_args.key_identifier = *key_id;
		del_args.flags = 0;
		hsmret = hsm_delete_key(key_mgmt_hdl, &del_args);
		se_info("hsm_delete_key ret:0x%x\n", hsmret);
#endif
		break;
	case KEYATTR:
#ifdef HSM_GET_KEY_ATTR
		memset(&keyattr_args, 0, sizeof(keyattr_args));
		keyattr_args.key_identifier = *key_id;
		hsmret = hsm_get_key_attr(key_mgmt_hdl, &keyattr_args);
		if (hsmret != HSM_NO_ERROR) {
			printf("hsm_get_key_attr failed:0x%x\n", hsmret);
		} else {
			printf("Key Type           : 0x%04x\n",
			       keyattr_args.key_type);
			printf("Key Size           : %d\n",
			       keyattr_args.bit_key_sz);
			printf("Key Lifetime       : 0x%08x\n",
			       keyattr_args.key_lifetime);
			printf("Key Usage          : 0x%08x\n",
			       keyattr_args.key_usage);
			printf("Key Algorithm      : 0x%08x\n",
			       keyattr_args.permitted_algo);
			printf("Key Lifecycle      : 0x%08x\n",
			       keyattr_args.lifecycle);
		}
#endif
		break;
	default:
		break;
	}
}

#ifdef PSA_COMPLIANT
void print_hsm_storage_status(hsm_storage_status_t storage_status)
{
	if (storage_status == HSM_STORAGE_STATUS_FETCH_FAILED)
		printf("Failed to fetch storage status.\n");
	else if (storage_status == HSM_STORAGE_STATUS_NOT_OPENED)
		printf("Storage status: Not opened.\n");
	else if (storage_status == HSM_STORAGE_STATUS_OPENED)
		printf("Storage status: Opened.\n");
	else
		printf("Unknown storage status[0x%x].\n", storage_status);
}
#endif

void print_global_info(void)
{
	printf("-----------------------------------------------------------\n");
	printf("Global Info:\n");
	printf("-----------------------------------------------------------\n");

	printf("%s %s\n", get_soc_id_str(se_get_soc_id()),
	       get_soc_rev_str(se_get_soc_rev()));
	if (se_get_chip_lifecycle())
		printf("%s Lifecycle\n", get_soc_lf_str(se_get_chip_lifecycle()));
	printf("Fips mode 0x%x\n", se_get_fips_mode());
	printf("LIB Version: %s\n", se_get_lib_version());
	printf("NVM Version: %s\n", se_get_nvm_version());
	printf("Build ID: %s\n", se_get_commit_id());
	printf("-----------------------------------------------------------\n");
}
