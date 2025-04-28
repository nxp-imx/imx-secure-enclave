// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_generate_signature.h"

uint32_t test_hsm_generate_signature(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint32_t index;
	uint32_t key_id_number;
	uint8_t signature_storage_index;

	op_generate_sign_args_t args;

	index               = READ_VALUE(fp, uint32_t);
	key_id_number       = READ_VALUE(fp, uint32_t);
	if (key_id_number == BAD_VAL) {
		args.key_identifier = BAD_VAL;
	} else if ((key_id_number & 0xF0) == 0xA0) {
		args.key_identifier = key_id_number & 0x0F;
	} else if (!testCtx->key_id[key_id_number]) {
		args.key_identifier = BAD_VAL;
		slt_print(SLT_WARNING, "Saw invalid key id pointer\n");
	} else {
		args.key_identifier = *testCtx->key_id[key_id_number];
	}
	args.message_size   = READ_VALUE(fp, uint32_t);
	args.message        = READ_INPUT_BUFFER(fp, args.message_size);
	signature_storage_index = READ_VALUE(fp, uint8_t);
	args.signature_size = READ_VALUE(fp, uint16_t);
	args.signature      = READ_INPUT_BUFFER(fp, args.signature_size);
	args.scheme_id      = READ_VALUE(fp, hsm_signature_scheme_id_t);
	args.flags          = READ_VALUE(fp, hsm_op_generate_sign_flags_t);

	hsm_err_t err = hsm_generate_signature(testCtx->hdl[index], &args);

	READ_CHECK_VALUE(testCtx, fp, err);
	READ_CHECK_BUFFER(testCtx, fp, args.signature, args.signature_size);

#ifdef CAVP_SUPPORT
	DISPLAY_BUFFER(args.signature, args.signature_size);
#endif

	testCtx->signature_address[signature_storage_index] = args.signature;
	testCtx->signature_size[signature_storage_index] = (uint32_t)args.signature_size;

	if (args.message)
		free(args.message);
	// if (args.signature != NULL)
	//     free(args.signature);

	return fails;
}
