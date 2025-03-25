// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_butterfly_key_expansion.h"

uint32_t test_hsm_butterfly_key_expansion(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	uint8_t index;
	uint32_t key_id_number, key_dest_id_number;
	op_butt_key_exp_args_t args;

	index         = READ_VALUE(fp, uint8_t);
	key_id_number = READ_VALUE(fp, uint32_t);
	if (key_id_number == BAD_VAL) {
		args.key_identifier = BAD_VAL;
	} else if (!testCtx->key_id[key_id_number]) {
		args.key_identifier = BAD_VAL;
		slt_print(SLT_WARNING, "Saw invalid key id pointer\n");
	} else {
		// key gen cmd to be executed before
		args.key_identifier = *testCtx->key_id[key_id_number];
	}

	key_dest_id_number = READ_VALUE(fp, uint8_t);

	args.expansion_function_value_size = READ_VALUE(fp, uint8_t);
	args.hash_value_size               = READ_VALUE(fp, uint8_t);
	args.pr_reconstruction_value_size  = READ_VALUE(fp, uint8_t);
	args.expansion_function_value      = READ_INPUT_BUFFER
						(fp, args.expansion_function_value_size);
	args.hash_value                    = READ_INPUT_BUFFER(fp, args.hash_value_size);
	args.pr_reconstruction_value       = READ_INPUT_BUFFER
						(fp, args.pr_reconstruction_value_size);
	args.flags                         = READ_VALUE(fp, hsm_op_but_key_exp_flags_t);
	if (args.flags & HSM_OP_BUTTERFLY_KEY_FLAGS_UPDATE)
		args.dest_key_identifier = testCtx->key_id[key_dest_id_number];
	else if (args.flags & HSM_OP_BUTTERFLY_KEY_FLAGS_CREATE)
		args.dest_key_identifier = (uint32_t *)READ_OUTPUT_BUFFER(fp,
						sizeof(uint32_t));
	else
		args.dest_key_identifier = 0;

	args.output_size = READ_VALUE(fp, uint16_t);
	args.output      = READ_OUTPUT_BUFFER(fp, args.output_size);
	args.key_type    = READ_VALUE(fp, hsm_key_type_t);
	args.reserved    = READ_VALUE(fp, uint8_t);
	args.key_group   = READ_VALUE(fp, uint16_t);
	args.key_info    = READ_VALUE(fp, uint16_t);
	hsm_err_t err = hsm_butterfly_key_expansion(testCtx->hdl[index], &args);

	READ_CHECK_VALUE(testCtx, fp, err);

	if (err == HSM_NO_ERROR) {
		slt_print(SLT_INFO, "new destination key id %x\n",
			  *args.dest_key_identifier);
		if (args.flags & HSM_OP_BUTTERFLY_KEY_FLAGS_CREATE) {
			testCtx->key_id[key_dest_id_number] = args.dest_key_identifier;
			testCtx->key_group[key_dest_id_number] = args.key_group;

			testCtx->pub_key_size[key_dest_id_number] = args.output_size;
			testCtx->pub_key_address[key_dest_id_number] = args.output;
		} else if (args.flags & HSM_OP_BUTTERFLY_KEY_FLAGS_UPDATE) {
			testCtx->key_group[key_dest_id_number] = args.key_group;

			testCtx->pub_key_size[key_dest_id_number] = args.output_size;
			testCtx->pub_key_address[key_dest_id_number] = args.output;
		}
	}

	slt_print(SLT_INFO, "args.output_size = %d\n", args.output_size);
	READ_CHECK_BUFFER(testCtx, fp, args.output, args.output_size);

	if (args.expansion_function_value)
		free(args.expansion_function_value);
	if (args.hash_value)
		free(args.hash_value);
	if (args.pr_reconstruction_value)
		free(args.pr_reconstruction_value);

	return fails;
}

uint32_t test_hsm_standalone_butterfly_key_expansion(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	uint8_t index;
	uint32_t key_id_number, exp_key_id, key_dest_id_number;
	op_st_butt_key_exp_args_t args;

	index         = READ_VALUE(fp, uint8_t);
	key_id_number = READ_VALUE(fp, uint32_t);
	if (key_id_number == BAD_VAL) {
		args.key_identifier = BAD_VAL;
	} else if (!testCtx->key_id[key_id_number]) {
		args.key_identifier = BAD_VAL;
		slt_print(SLT_WARNING, "Saw invalid key id pointer\n");
	} else {
		// key gen cmd to be executed before
		args.key_identifier = *testCtx->key_id[key_id_number];
	}

	exp_key_id = READ_VALUE(fp, uint32_t);
	if (exp_key_id == BAD_VAL) {
		args.key_identifier = BAD_VAL;
	} else if (!testCtx->key_id[exp_key_id]) {
		args.key_identifier = BAD_VAL;
		slt_print(SLT_WARNING, "Saw invalid key id pointer\n");
	} else {
		// key gen cmd to be executed before
		args.expansion_fct_key_identifier = *testCtx->key_id[exp_key_id];
	}

	key_dest_id_number                = READ_VALUE(fp, uint8_t);

	args.expansion_fct_input_size     = READ_VALUE(fp, uint8_t);
	args.hash_value_size              = READ_VALUE(fp, uint8_t);
	args.pr_reconstruction_value_size = READ_VALUE(fp, uint8_t);
	args.expansion_fct_input          = READ_INPUT_BUFFER
						(fp, args.expansion_fct_input_size);
	args.hash_value                   = READ_INPUT_BUFFER(fp, args.hash_value_size);
	args.pr_reconstruction_value      = READ_INPUT_BUFFER
						(fp, args.pr_reconstruction_value_size);
	args.flags                        = READ_VALUE(fp, hsm_op_but_key_exp_flags_t);
	if (args.flags & HSM_OP_BUTTERFLY_KEY_FLAGS_UPDATE)
		args.dest_key_identifier = testCtx->key_id[key_dest_id_number];
	else if (args.flags & HSM_OP_BUTTERFLY_KEY_FLAGS_CREATE)
		args.dest_key_identifier = (uint32_t *)READ_OUTPUT_BUFFER
						(fp, sizeof(uint32_t));
	else
		args.dest_key_identifier = 0;

	args.output_size        = READ_VALUE(fp, uint16_t);
	args.output             = READ_OUTPUT_BUFFER(fp, args.output_size);
	args.key_type           = READ_VALUE(fp, hsm_key_type_t);
	args.expansion_fct_algo = READ_VALUE(fp, uint8_t);
	args.key_group          = READ_VALUE(fp, uint16_t);
	args.key_info           = READ_VALUE(fp, uint16_t);
	hsm_err_t err = hsm_standalone_butterfly_key_expansion(testCtx->hdl[index],
							       &args);

	READ_CHECK_VALUE(testCtx, fp, err);

	if (err == HSM_NO_ERROR) {
		slt_print(SLT_INFO, "new destination key id %x\n",
			  *args.dest_key_identifier);
		if (args.flags & HSM_OP_BUTTERFLY_KEY_FLAGS_CREATE) {
			testCtx->key_id[key_dest_id_number] = args.dest_key_identifier;
			testCtx->key_group[key_dest_id_number] = args.key_group;

			testCtx->pub_key_size[key_dest_id_number] = args.output_size;
			testCtx->pub_key_address[key_dest_id_number] = args.output;
		} else if (args.flags & HSM_OP_BUTTERFLY_KEY_FLAGS_UPDATE) {
			testCtx->key_group[key_dest_id_number] = args.key_group;

			testCtx->pub_key_size[key_dest_id_number] = args.output_size;
			testCtx->pub_key_address[key_dest_id_number] = args.output;
		}
	}

	slt_print(SLT_INFO, "args.output_size = %d\n", args.output_size);
	READ_CHECK_BUFFER(testCtx, fp, args.output, args.output_size);

	if (args.expansion_fct_input)
		free(args.expansion_fct_input);
	if (args.hash_value)
		free(args.hash_value);
	if (args.pr_reconstruction_value)
		free(args.pr_reconstruction_value);

	return fails;
}
