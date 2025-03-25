// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_verify_signature.h"

uint32_t test_hsm_verify_signature(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint32_t index;
	uint32_t key_id_number;
	op_verify_sign_args_t args;
	uint8_t signature_storage_index;

	signature_storage_index    = READ_VALUE(fp, uint8_t); // 0xFF not stored
	// signature verification index.
	index               = READ_VALUE(fp, uint32_t);
	key_id_number       = READ_VALUE(fp, uint32_t);
	if (key_id_number == 0x10AD) { // pub key is in the test, load it
		args.key_size = READ_VALUE(fp, uint32_t);
		args.key = READ_INPUT_BUFFER(fp, args.key_size);
	} else if (key_id_number == BAD_0) {  // parameter size, Addr = 0x0
		args.key_size          = READ_VALUE(fp, uint32_t);
		args.key               = 0x0;
	} else if (key_id_number == BAD_1) {  // parameter size, Addr = 0xBADBAD
		args.key_size          = READ_VALUE(fp, uint32_t);
		args.key               = (uint8_t *)(uintptr_t)BAD_ADDR;
	} else if (key_id_number == BAD_2) {
		args.key_size          = READ_VALUE(fp, uint32_t);
		uint32_t *key_id = (uint32_t *)malloc(sizeof(uint32_t));
		*key_id = BAD_VAL;
		args.key = (uint8_t *)(uintptr_t)key_id;
	} else {
		args.key_size       = testCtx->pub_key_size[key_id_number];
		args.key            = testCtx->pub_key_address[key_id_number];
	}

	args.message_size   = READ_VALUE(fp, uint32_t);
	args.message        = READ_INPUT_BUFFER(fp, args.message_size);
	if (signature_storage_index == 0xFF) {
		args.signature_size = READ_VALUE(fp, uint16_t);
		args.signature      = READ_INPUT_BUFFER(fp, args.signature_size);
	} else {
		args.signature_size =
			(uint16_t)testCtx->signature_size[signature_storage_index];
		args.signature = testCtx->signature_address[signature_storage_index];
	}
	args.scheme_id      = READ_VALUE(fp, hsm_signature_scheme_id_t);
	args.flags          = READ_VALUE(fp, hsm_op_verify_sign_flags_t);
	hsm_verification_status_t *status =
		(hsm_verification_status_t *)READ_OUTPUT_BUFFER
				(fp, sizeof(hsm_verification_status_t));

	hsm_err_t err = hsm_verify_signature(testCtx->hdl[index], &args, status);

	READ_CHECK_VALUE(testCtx, fp, err);
	uint8_t *status_byte = (uint8_t *)status;

	READ_CHECK_BUFFER(testCtx, fp, status_byte, sizeof(hsm_verification_status_t));

#ifdef CAVP_SUPPORT
	if (*status != 0x5A3CC3A5)
		slt_print(SLT_ERROR, "<OUTPUT_DATA>\nFAIL\n</OUTPUT_DATA>\n");
	else
		slt_print(SLT_NOTICE, "<OUTPUT_DATA>\nPASS\n</OUTPUT_DATA>\n");
#endif
	if (args.message)
		free(args.message);
	if (signature_storage_index == 0xFF && args.signature)
		free(args.signature);

	return fails;
}
