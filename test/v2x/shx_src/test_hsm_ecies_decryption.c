// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_ecies_decryption.h"

uint32_t test_hsm_ecies_decryption(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	uint32_t index;
	op_ecies_dec_args_t args;
	uint32_t key_id_number;
	uint16_t key_id_number_lsb, key_id_number_msb;

	index                    = READ_VALUE(fp, uint32_t);
	key_id_number            = READ_VALUE(fp, uint32_t);
	/* Always read something for input (default=None)*/
	args.input_size          = READ_VALUE(fp, uint32_t);
	args.input               = READ_INPUT_BUFFER(fp, args.input_size);

	/* special test code
	 * 1- key_id==0xFDnn: check input Addr = 0x0
	 * 2- key_id==0xFEnn: check input Addr valid but wrong
	 * 3- key_id==0xFFnn: Get the input value from shx
	 * 4- key_id==0xnn: Get the input value from previous encryption (vct array)

	 * Normal use case is number 4.
	 */
	key_id_number_lsb = key_id_number & 0xFF;
	key_id_number_msb = (key_id_number & 0xFF00) >> 8;

	if (testCtx->key_id[key_id_number_lsb] == 0x0)
		args.key_identifier = 0;
	else
		args.key_identifier = *testCtx->key_id[key_id_number_lsb];

	if (key_id_number_msb == 0xFD) {
		args.input               = 0x0;
	} else if (key_id_number_msb == 0xFE) {
		args.input               = (uint8_t *)(uintptr_t)BAD_ADDR;
	} else if (key_id_number_msb != 0xFF) {  // parameter size and buffer
		args.input_size          = testCtx->vct_size[key_id_number_lsb];
		args.input               = testCtx->vct_address[key_id_number_lsb];
	}

	args.p1_size             = READ_VALUE(fp, uint16_t);
	args.p1                  = READ_INPUT_BUFFER(fp, args.p1_size);
	args.p2_size             = READ_VALUE(fp, uint16_t);
	args.p2                  = READ_INPUT_BUFFER(fp, args.p2_size);
	args.output_size         = READ_VALUE(fp, uint32_t);
	args.output              = READ_OUTPUT_BUFFER(fp, args.output_size);
	args.mac_size            = READ_VALUE(fp, uint16_t);
	args.key_type            = READ_VALUE(fp, hsm_key_type_t);
	args.flags               = READ_VALUE(fp, hsm_op_ecies_dec_flags_t);

	hsm_err_t err = hsm_ecies_decryption(testCtx->hdl[index], &args);

	READ_CHECK_VALUE(testCtx, fp, err);
	READ_CHECK_BUFFER(testCtx, fp, args.output, args.output_size);

	if (args.p1)
		free(args.p1);
	if (args.p2)
		free(args.p2);
	if (key_id_number == 0xFF && args.input)
		free(args.input);

	return fails;
}
