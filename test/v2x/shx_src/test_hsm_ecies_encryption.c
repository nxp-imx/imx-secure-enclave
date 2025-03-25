// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_ecies_encryption.h"

uint32_t test_hsm_ecies_encryption(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	uint32_t index;
	op_ecies_enc_args_t args;
	uint32_t key_id_number;

	index                    = READ_VALUE(fp, uint32_t);
	args.input_size          = READ_VALUE(fp, uint32_t);
	args.input               = READ_INPUT_BUFFER(fp, args.input_size);
	key_id_number            = READ_VALUE(fp, uint32_t);

	if (key_id_number == 0xFF) {
		/* Not use stored pub key , but one defined in shx */
		args.pub_key_size        = READ_VALUE(fp, uint16_t);
		args.pub_key             = READ_INPUT_BUFFER(fp, args.pub_key_size);
	} else if (key_id_number == BAD_0) {  // parameter size, Addr = 0x0
		args.pub_key_size          = READ_VALUE(fp, uint32_t);
		args.pub_key               = 0x0;
	} else if (key_id_number == BAD_1) {  // parameter size, Addr = 0xBADBAD
		args.pub_key_size          = READ_VALUE(fp, uint32_t);
		args.pub_key               = (uint8_t *)(uintptr_t)BAD_ADDR;
	} else if (key_id_number == BAD_2) {
		args.pub_key_size          = READ_VALUE(fp, uint32_t);
		uint32_t *key_id = (uint32_t *)malloc(sizeof(uint32_t));
		*key_id = BAD_VAL;
		args.pub_key = (uint8_t *)(uintptr_t)key_id;
	} else {
		args.pub_key_size = testCtx->pub_key_size[key_id_number];
		args.pub_key      = testCtx->pub_key_address[key_id_number];
	}

	args.p1_size             = READ_VALUE(fp, uint16_t);
	args.p1                  = READ_INPUT_BUFFER(fp, args.p1_size);
	args.p2_size             = READ_VALUE(fp, uint16_t);
	args.p2                  = READ_INPUT_BUFFER(fp, args.p2_size);
	args.out_size            = READ_VALUE(fp, uint32_t);
	args.output              = READ_OUTPUT_BUFFER(fp, args.out_size);
	args.mac_size            = READ_VALUE(fp, uint16_t);
	args.key_type            = READ_VALUE(fp, hsm_key_type_t);
	args.flags               = READ_VALUE(fp, hsm_op_ecies_dec_flags_t);
	hsm_err_t err = hsm_ecies_encryption(testCtx->hdl[index], &args);

	READ_CHECK_VALUE(testCtx, fp, err);
	READ_CHECK_BUFFER(testCtx, fp, args.output, args.out_size);
	if (err == HSM_NO_ERROR) {
		/* Store output VCT */
		testCtx->vct_size[key_id_number] = args.out_size;
		testCtx->vct_address[key_id_number] = args.output;
	}

	if (args.input)
		free(args.input);
	if (args.p1)
		free(args.p1);
	if (args.p2)
		free(args.p2);
	if (key_id_number == 0xFF && args.pub_key)
		free(args.pub_key);

	return fails;
}
