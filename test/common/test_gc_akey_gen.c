// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdio.h>

#include "internal/hsm_key.h"

#include "hsm_api.h"

#ifdef PSA_COMPLIANT
hsm_err_t gc_akey_gen_test(hsm_hdl_t session_hdl)
{
	hsm_err_t err = HSM_GENERAL_ERROR;
	op_gc_akey_gen_args_t gc_akey_gen_args = {0};
	uint8_t modulus[256];
	uint8_t priv_buff[512];
	uint8_t pub_buff[5] = {0x1, 0x0, 0x0, 0x0, 0x1};

	printf("\n------------------------------------------------\n");
	printf("Generic Crypto - Asymmetric Key Generate API Test:");
	printf("\n------------------------------------------------\n");

	memset(modulus, 0, sizeof(modulus));
	memset(priv_buff, 0, sizeof(priv_buff));

	/*
	 * Test added for RSA keypair 2048 bits.
	 */
	gc_akey_gen_args.modulus = modulus;
	gc_akey_gen_args.modulus_size = 256;
	gc_akey_gen_args.priv_buff = priv_buff;
	gc_akey_gen_args.priv_buff_size = 512;
	gc_akey_gen_args.pub_buff = pub_buff;
	gc_akey_gen_args.pub_buff_size = 5;
	gc_akey_gen_args.key_type = HSM_KEY_TYPE_RSA;
	gc_akey_gen_args.bit_key_sz = 2048;

	err = hsm_gc_akey_gen(session_hdl, &gc_akey_gen_args);
	printf("\nhsm_gc_akey_gen ret: 0x%x\n", err);

	printf("\n------------------------------------------------\n");
	printf("Test Complete");
	printf("\n------------------------------------------------\n");

	return err;
}
#endif
