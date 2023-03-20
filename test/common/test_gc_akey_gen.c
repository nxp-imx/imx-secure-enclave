/*
 * Copyright 2023 NXP
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

#include "internal/hsm_key.h"

#include "hsm_api.h"

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
