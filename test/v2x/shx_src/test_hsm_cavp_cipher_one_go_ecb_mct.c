// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <sys/types.h>

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_cavp_cipher_one_go_ecb_mct.h"
#include "test_hsm_manage_key.h"

uint32_t test_hsm_cavp_cipher_one_go_ecb_mct(hsm_test_struct_t *testCtx, FILE *fp)
{
	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	uint32_t fails = 0;
	uint32_t index;
	uint32_t key_id_number;
	uint32_t key_size;
	uint8_t cipher_store_index;
	op_cipher_one_go_args_t args;
	uint8_t *KEY;

	uint16_t i;

	// read the cipher index.
	index                    = READ_VALUE(fp, uint32_t);
	key_id_number            = READ_VALUE(fp, uint32_t);
	if (key_id_number == BAD_VAL) {
		args.key_identifier = BAD_VAL;
	} else if (!testCtx->key_id[key_id_number]) {
		args.key_identifier = BAD_VAL;
		slt_print(SLT_WARNING, "Saw invalid key id pointer\n");
	} else {
		args.key_identifier = *testCtx->key_id[key_id_number];
		slt_print(SLT_INFO, "key id 0x%x\n", args.key_identifier);
	}

	args.iv_size             = READ_VALUE(fp, uint16_t);
	args.iv                  = READ_INPUT_BUFFER(fp, args.iv_size);
	args.cipher_algo         = READ_VALUE(fp, hsm_op_cipher_one_go_algo_t);
	args.flags               = READ_VALUE(fp, hsm_op_cipher_one_go_flags_t);

	/* Get input and input sizetest_hsm_cavp_cipher_one_go_ecb_mct.c
	 * But for DECRYPT case we replace it by:
	 * - Addr = 0xBADBAD (size: 0) if specific cipher_store_index=0xBADBAD is used
	 * - Addr/size taken from internal array (if previously filled by ENCRYPT process)
	 */
	args.input_size          = READ_VALUE(fp, uint32_t);
	args.input               = READ_INPUT_BUFFER(fp, args.input_size);
	args.output_size         = READ_VALUE(fp, uint32_t);
	args.output              = READ_INPUT_BUFFER(fp, args.output_size);

	while ((read = getline(&line, &len, fp)) != -1) {
		slt_print(SLT_DEBUG, "line: %s", line);
		if (memcmp(line, "CURRENT_KEY_VALUE", strlen("CURRENT_KEY_VALUE")) == 0) {
			slt_print(SLT_DEBUG, "test: %s", line);
			slt_print(SLT_NOTICE, "Key:\n");
			key_size = READ_VALUE(fp, uint32_t);
			KEY = READ_INPUT_BUFFER(fp, key_size);
			DISPLAY_BUFFER(KEY, key_size);
			FREE_BUFFER(KEY);
			slt_print(SLT_DEBUG, "\n\n");
		} else if (memcmp(line, "HSM_MANAGE_KEY",
				  strlen("HSM_MANAGE_KEY")) == 0) {
			slt_print(SLT_DEBUG, "test: %s", line);
			test_hsm_manage_key(testCtx, fp);
			slt_print(SLT_DEBUG, "\n");
		} else if (memcmp(line, "AES_MCT_1000_START",
				  strlen("AES_MCT_1000_START")) == 0) {
			slt_print(SLT_DEBUG, "test: %s", line);
			DISPLAY_BUFFER(args.input, args.input_size);
			for (i = 0; i < 1000; i++) {
				hsm_cipher_one_go(testCtx->hdl[index], &args);
				memcpy(args.input, args.output, args.input_size);
			}
			DISPLAY_BUFFER(args.output, args.output_size);
			slt_print(SLT_DEBUG, "\n");
		} else if  (memcmp(line, "MCT_CIPHER_ONE_GO",
				   strlen("MCT_CIPHER_ONE_GO")) == 0) {
			slt_print(SLT_DEBUG, "test: %s\n", line);
		} else if (memcmp(line,
				  "END_OF_CIPHER_ONE_GO_MCT",
				  strlen("END_OF_CIPHER_ONE_GO_MCT")) == 0) {
			slt_print(SLT_DEBUG, "test: %s\n", line);
			break;
		}
	}

	FREE_BUFFER(args.iv);
	FREE_BUFFER(args.input);
	FREE_BUFFER(args.output);

	return fails;
}
