// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */
#include <sys/types.h>

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_cavp_cipher_one_go_cbc_mct.h"
#include "test_hsm_manage_key.h"

uint32_t test_hsm_cavp_cipher_one_go_cbc_mct(hsm_test_struct_t *testCtx, FILE *fp)
{
	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	uint32_t fails = 0;
	uint32_t index;
	uint32_t key_id_number;
	uint32_t key_size;
	uint8_t cipher_store_index;
	uint8_t *IV, *PREV_OUTPUT, *KEY;
	op_cipher_one_go_args_t args;

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
		// key gen cmd to be executed before
		args.key_identifier = *testCtx->key_id[key_id_number];
		slt_print(SLT_INFO, "key id 0x%x\n", args.key_identifier);
	}

	args.iv_size             = READ_VALUE(fp, uint16_t);
	args.iv                  = malloc(args.iv_size);
	IV                       = READ_INPUT_BUFFER(fp, args.iv_size);
	memcpy(args.iv, IV, args.iv_size);

	args.cipher_algo = READ_VALUE(fp, hsm_op_cipher_one_go_algo_t);
	args.flags       = READ_VALUE(fp, hsm_op_cipher_one_go_flags_t);

	/* Get input and input size
	 * But for DECRYPT case we replace it by:
	 * - Addr = 0xBADBAD (size: 0) if specific cipher_store_index=0xBADBAD is used
	 * - Addr/size taken from internal array (if previously filled by ENCRYPT process)
	 */
	args.input_size  = READ_VALUE(fp, uint32_t);
	args.input       = READ_INPUT_BUFFER(fp, args.input_size);

	args.output_size = READ_VALUE(fp, uint32_t);
	args.output      = READ_INPUT_BUFFER(fp, args.output_size);

	PREV_OUTPUT      = malloc(args.output_size);

	while ((read = getline(&line, &len, fp)) != -1) {
		slt_print(SLT_DEBUG, "line: %s", line);
		if (memcmp(line, "CURRENT_KEY_VALUE",
			   strlen("CURRENT_KEY_VALUE")) == 0) {
			slt_print(SLT_DEBUG, "%s", line);
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
			slt_print(SLT_NOTICE, "Init Vector:\n");
			DISPLAY_BUFFER(args.iv, args.iv_size);
			slt_print(SLT_NOTICE, "Input:\n");
			DISPLAY_BUFFER(args.input, args.input_size);
			for (i = 0; i < 1000; i++) {
				hsm_cipher_one_go(testCtx->hdl[index], &args);

				if ((args.flags & HSM_CIPHER_ONE_GO_MASK_OP_TYPE)
				    == HSM_CIPHER_ONE_GO_FLAGS_DECRYPT) /* DECRYPT */
					memcpy(args.iv, args.input, args.input_size);

				else if ((args.flags & HSM_CIPHER_ONE_GO_MASK_OP_TYPE)
					 == HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT)
					memcpy(args.iv, args.output, args.output_size);

				if (i == 0)
					memcpy(args.input, IV, args.input_size);
				else
					memcpy(args.input, PREV_OUTPUT, args.input_size);

				memcpy(PREV_OUTPUT, args.output, args.input_size);
			}
			slt_print(SLT_NOTICE, "Output:\n");
			DISPLAY_BUFFER(args.output, args.output_size);
			slt_print(SLT_DEBUG, "\n");

			memcpy(args.iv, args.output, args.output_size);
			memcpy(IV, args.output, args.output_size);

		} else if  (memcmp(line, "MCT_CIPHER_ONE_GO",
				   strlen("MCT_CIPHER_ONE_GO")) == 0) {
			slt_print(SLT_DEBUG, "test: %s\n", line);
		} else if (memcmp(line, "END_OF_CIPHER_ONE_GO_MCT",
				  strlen("END_OF_CIPHER_ONE_GO_MCT")) == 0) {
			slt_print(SLT_DEBUG, "test: %s\n", line);
			break;
		}
	}

	FREE_BUFFER(args.iv);
	FREE_BUFFER(args.input);
	FREE_BUFFER(args.output);
	FREE_BUFFER(PREV_OUTPUT);
	FREE_BUFFER(IV);

	return fails;
}
