// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_sm2_get_z.h"

uint32_t test_hsm_sm2_get_z(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint32_t index;

	op_sm2_get_z_args_t args;

	// read the cipher index.
	index = READ_VALUE(fp, uint32_t);
	args.public_key_size = READ_VALUE(fp, uint16_t);
	args.public_key = READ_INPUT_BUFFER(fp, args.public_key_size);
	args.id_size = READ_VALUE(fp, uint8_t);
	args.identifier = READ_INPUT_BUFFER(fp, args.id_size);
	args.z_size = READ_VALUE(fp, uint8_t);
	args.z_value = READ_OUTPUT_BUFFER(fp, args.z_size);
	args.key_type     = READ_VALUE(fp, hsm_key_type_t);
	args.flags        = READ_VALUE(fp, hsm_op_sm2_get_z_flags_t);

	hsm_err_t err = hsm_sm2_get_z(testCtx->hdl[index], &args);

	READ_CHECK_VALUE(testCtx, fp, err);
	if (err == HSM_NO_ERROR)
		READ_CHECK_BUFFER(testCtx, fp, args.z_value, args.z_size);

	return fails;
}

uint32_t test_hsm_sm2_eces_open(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint32_t index, eces_hdl_index;

	open_svc_sm2_eces_args_t args;

	// read the key store index.
	index = READ_VALUE(fp, uint32_t);
	args.flags = READ_VALUE(fp, uint8_t);
	eces_hdl_index = READ_VALUE(fp, uint32_t);

	hsm_err_t err = hsm_open_sm2_eces_service(testCtx->hdl[index],
						  &args, &testCtx->hdl[eces_hdl_index]);

	READ_CHECK_VALUE(testCtx, fp, err);
	READ_CHECK_POINTER(testCtx, fp, testCtx->hdl[eces_hdl_index]);

	return fails;
}

uint32_t test_hsm_sm2_eces_enc(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint32_t index;

	op_sm2_eces_enc_args_t args;

	// read the session index.
	index = READ_VALUE(fp, uint32_t);
	args.input_size = READ_VALUE(fp, uint32_t);
	args.input = READ_INPUT_BUFFER(fp, args.input_size);
	args.output_size = READ_VALUE(fp, uint32_t);
	args.output = READ_INPUT_BUFFER(fp, args.output_size);
	args.pub_key_size = READ_VALUE(fp, uint16_t);
	args.pub_key = READ_OUTPUT_BUFFER(fp, args.pub_key_size);
	args.key_type     = READ_VALUE(fp, hsm_key_type_t);
	args.flags        = READ_VALUE(fp, hsm_op_sm2_eces_enc_flags_t);

	hsm_err_t err = hsm_sm2_eces_encryption(testCtx->hdl[index], &args);

	READ_CHECK_VALUE(testCtx, fp, err);
	if (err == HSM_NO_ERROR)
		READ_CHECK_BUFFER(testCtx, fp, args.output, args.output_size);

	return fails;
}
