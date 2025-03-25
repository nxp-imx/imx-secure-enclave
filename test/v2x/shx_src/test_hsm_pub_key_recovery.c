// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_pub_key_recovery.h"

uint32_t test_hsm_pub_key_recovery(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint32_t index;
	uint32_t key_id_number;
	uint8_t pub_key_check;
	op_pub_key_recovery_args_t args;

	// key store index
	index = READ_VALUE(fp, uint32_t);
	key_id_number = READ_VALUE(fp, uint32_t);
	if (key_id_number == BAD_VAL) {
		args.key_identifier = BAD_VAL;
	} else if (!testCtx->key_id[key_id_number]) {
		args.key_identifier = BAD_VAL;
		slt_print(SLT_WARNING, "Saw invalid key id pointer\n");
	} else {
		args.key_identifier = *testCtx->key_id[key_id_number];
	}
	args.out_key_size = READ_VALUE(fp, uint16_t);
	args.out_key      = READ_INPUT_BUFFER(fp, args.out_key_size);
	args.key_type     = READ_VALUE(fp, hsm_key_type_t);
	args.flags        = READ_VALUE(fp, hsm_op_pub_key_recovery_flags_t);

	hsm_err_t err = hsm_pub_key_recovery(testCtx->hdl[index], &args);

	READ_CHECK_VALUE(testCtx, fp, err);
#ifdef CAVP_SUPPORT
	DISPLAY_BUFFER(args.out_key, args.out_key_size);
#endif
	if (err == HSM_NO_ERROR) {
		/* case not previously stored pubkey (use manage_key to create it)*/
		slt_print(SLT_NOTICE, "testCtx->pub_key_size[%d] = %d\n",
			  key_id_number, testCtx->pub_key_size[key_id_number]);
		if (testCtx->pub_key_size[key_id_number] == 0) {
			testCtx->pub_key_size[key_id_number] = args.out_key_size;
			testCtx->pub_key_address[key_id_number] = args.out_key;

			READ_CHECK_BUFFER(testCtx, fp, args.out_key, args.out_key_size);
		} else {
			CHECK_BUFFER(testCtx, args.out_key,
				     (testCtx->pub_key_address[key_id_number]),
				     args.out_key_size);
		}
	} else {
		READ_CHECK_BUFFER(testCtx, fp, args.out_key, args.out_key_size);
	}

	return fails;
}
