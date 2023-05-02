// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2022-2023 NXP
 */

#include <stdint.h>
#include <stdio.h>

#include "hsm_api.h"
#include "plat_utils.h"

#include "common.h"

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
