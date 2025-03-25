// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_generate_key.h"

uint32_t test_hsm_generate_key(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint32_t key_id_number;

	uint32_t index;
	op_generate_key_args_t args;

	index                    = READ_VALUE(fp, uint8_t);
	key_id_number            = READ_VALUE(fp, uint32_t);
	args.out_size            = READ_VALUE(fp, uint16_t);
	args.flags               = READ_VALUE(fp, hsm_op_key_gen_flags_t);

	if (args.flags & HSM_OP_KEY_GENERATION_FLAGS_UPDATE) {
		if (key_id_number == BAD_0) // Addr = 0x0
			args.key_identifier = 0x0;
		else if (key_id_number == BAD_1) // Addr = 0xBADBAD
			args.key_identifier = (uint32_t *)BAD_ADDR;
		else
			args.key_identifier = testCtx->key_id[key_id_number];
	} else {
		args.key_identifier = malloc(sizeof(uint32_t));
	}
	args.key_type            = READ_VALUE(fp, hsm_key_type_t);
	args.key_group           = READ_VALUE(fp, uint16_t);
	args.key_info            = READ_VALUE(fp, hsm_key_info_t);
	args.out_key             = READ_OUTPUT_BUFFER(fp, args.out_size);

	hsm_err_t err = hsm_generate_key(testCtx->hdl[index], &args);

	READ_CHECK_VALUE(testCtx, fp, err);

	if (err == HSM_NO_ERROR) {
		/* Store Key_id address */
		testCtx->key_id[key_id_number] = args.key_identifier;
		testCtx->key_group[key_id_number] = args.key_group;

		/* Store pub key */
		testCtx->pub_key_size[key_id_number] = args.out_size;
		testCtx->pub_key_address[key_id_number] = args.out_key;
		READ_CHECK_BUFFER(testCtx, fp, args.out_key, args.out_size);
	} else {
		FREE_BUFFER(args.out_key);
		if (!(args.flags & HSM_OP_KEY_GENERATION_FLAGS_UPDATE))
			FREE_BUFFER(args.key_identifier);
	}

	return fails;
}

uint32_t test_hsm_generate_key_ext(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint32_t key_id_number;

	uint32_t index;
	op_generate_key_ext_args_t args;

	index                    = READ_VALUE(fp, uint8_t);
	key_id_number            = READ_VALUE(fp, uint32_t);
	args.out_size            = READ_VALUE(fp, uint16_t);
	args.flags               = READ_VALUE(fp, hsm_op_key_gen_flags_t);

	if (args.flags & HSM_OP_KEY_GENERATION_FLAGS_UPDATE) {
		if (key_id_number == BAD_0) // Addr = 0x0
			args.key_identifier = 0x0;
		else if (key_id_number == BAD_1)  // Addr = 0xBADBAD
			args.key_identifier = (uint32_t *)BAD_ADDR;
		else
			args.key_identifier = testCtx->key_id[key_id_number];
	} else {
		args.key_identifier = malloc(sizeof(uint32_t));
	}
	args.key_type            = READ_VALUE(fp, hsm_key_type_t);
	args.key_group           = READ_VALUE(fp, uint16_t);
	args.key_info            = READ_VALUE(fp, hsm_key_info_t);
	args.out_key             = READ_OUTPUT_BUFFER(fp, args.out_size);
	args.min_mac_len         = READ_VALUE(fp, uint8_t);
	args.reserved[0]         = READ_VALUE(fp, uint8_t);
	args.reserved[1]         = READ_VALUE(fp, uint8_t);
	args.reserved[2]         = READ_VALUE(fp, uint8_t);

	hsm_err_t err = hsm_generate_key_ext(testCtx->hdl[index], &args);

	READ_CHECK_VALUE(testCtx, fp, err);

	if (err == HSM_NO_ERROR) {
		/* Store Key_id address */
		testCtx->key_id[key_id_number] = args.key_identifier;
		testCtx->key_group[key_id_number] = args.key_group;

		/* Store pub key */
		testCtx->pub_key_size[key_id_number] = args.out_size;
		testCtx->pub_key_address[key_id_number] = args.out_key;
		READ_CHECK_BUFFER(testCtx, fp, args.out_key, args.out_size);
	} else {
		FREE_BUFFER(args.out_key);
		if (!(args.flags & HSM_OP_KEY_GENERATION_FLAGS_UPDATE))
			FREE_BUFFER(args.key_identifier);
	}

	return fails;
}

uint32_t test_hsm_generate_n_key(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint8_t key_id_start, key_id_number_iteration;

	uint32_t index;
	op_generate_key_args_t args;

	index                    = READ_VALUE(fp, uint8_t);
	key_id_start             = READ_VALUE(fp, uint8_t);
	key_id_number_iteration  = READ_VALUE(fp, uint8_t);
	args.out_size            = READ_VALUE(fp, uint16_t);
	args.flags               = READ_VALUE(fp, hsm_op_key_gen_flags_t);
	args.key_type            = READ_VALUE(fp, hsm_key_type_t);
	args.key_group           = READ_VALUE(fp, uint16_t);
	args.key_info            = READ_VALUE(fp, hsm_key_info_t);
	args.out_key             = READ_OUTPUT_BUFFER(fp, args.out_size);

	slt_print(SLT_NOTICE, "Generate %d Keys\n", key_id_number_iteration);
	for (uint8_t i = 0; i < key_id_number_iteration; i++) {
		if (args.flags & HSM_OP_KEY_GENERATION_FLAGS_UPDATE)
			args.key_identifier = testCtx->key_id[key_id_start + i];
		else
			args.key_identifier = malloc(sizeof(uint32_t));

		hsm_err_t err = hsm_generate_key(testCtx->hdl[index], &args);

		/* TO DO HANDLE err by reading value in file fp */

		if (err == HSM_NO_ERROR) {
			/* Store Key_id address */
			testCtx->key_id[key_id_start + i] = args.key_identifier;
			testCtx->key_group[key_id_start + i] = args.key_group;

			/* Store pub key */
			testCtx->pub_key_size[key_id_start + i] = args.out_size;
			/* TODO handle different out_key */
			testCtx->pub_key_address[key_id_start + i] = args.out_key;
			//READ_CHECK_BUFFER(testCtx, fp, args.out_key, args.out_size);
		} else {
			slt_print(SLT_ERROR, "Error in generate_key API 0x%x\n", err);
			slt_print(SLT_ERROR, "Error in generate_key API iter 0x%x\n", i);
		}
	}

	return fails;
}

uint32_t test_hsm_generate_n_groups(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint32_t key_id_start, key_group_start, key_group_number_iteration;

	uint32_t index;
	op_generate_key_args_t args;

	index                       = READ_VALUE(fp, uint8_t);
	key_id_start                = READ_VALUE(fp, uint32_t);
	args.out_size               = READ_VALUE(fp, uint16_t);
	args.flags                  = HSM_OP_KEY_GENERATION_FLAGS_CREATE |
					HSM_OP_KEY_GENERATION_FLAGS_STRICT_OPERATION;
	args.key_type               = READ_VALUE(fp, hsm_key_type_t);
	key_group_start             = READ_VALUE(fp, uint32_t);
	key_group_number_iteration  = READ_VALUE(fp, uint32_t);
	args.key_info               = READ_VALUE(fp, hsm_key_info_t);
	args.out_key                = READ_OUTPUT_BUFFER(fp, args.out_size);

	slt_print(SLT_NOTICE, "Generate %d Groups\n", key_group_number_iteration);
	for (uint32_t i = 0; i < key_group_number_iteration; i++) {
		args.key_identifier = malloc(sizeof(uint32_t));
		args.key_group = key_group_start + i;
		hsm_err_t err = hsm_generate_key(testCtx->hdl[index], &args);

		/* TO DO HANDLE err by reading value in file fp */
		if (err == HSM_NO_ERROR) {
			/* Store Key_id address */
			testCtx->key_id[key_id_start + i] = args.key_identifier;
			testCtx->key_group[key_id_start + i] = args.key_group;
			/* Store pub key */
			testCtx->pub_key_size[key_id_start + i] = args.out_size;
			/* TODO handle different out_key */
			testCtx->pub_key_address[key_id_start + i] = args.out_key;
			//READ_CHECK_BUFFER(testCtx, fp, args.out_key, args.out_size);
			slt_print(SLT_NOTICE, ".");
		} else {
			//slt_print(SLT_ERROR, "Error in generate_key API 0x%x\n", err);
			//slt_print(SLT_ERROR, "Error in generate_key API itr 0x%x\n", i);
			slt_print(SLT_ERROR, "F[%d,0x%x]", i, err);
			fails++;
			FREE_BUFFER(args.out_key);
			FREE_BUFFER(args.key_identifier);
		}
	}
	return fails;
}

uint32_t test_hsm_bulk_generate_key(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint32_t key_id_start, key_id_number_iteration;
	uint32_t i = 0;
	uint32_t index;
	op_generate_key_args_t args;

	index                    = READ_VALUE(fp, uint8_t);
	key_id_start             = READ_VALUE(fp, uint32_t);
	key_id_number_iteration  = READ_VALUE(fp, uint32_t);
	args.out_size            = READ_VALUE(fp, uint16_t);
	args.flags               = READ_VALUE(fp, hsm_op_key_gen_flags_t);
	args.key_type            = READ_VALUE(fp, hsm_key_type_t);
	args.key_info            = READ_VALUE(fp, hsm_key_info_t);
	args.out_key             = READ_OUTPUT_BUFFER(fp, args.out_size);

	slt_print(SLT_NOTICE, "Bulk key generate: %u iterations\n",
		  key_id_number_iteration);

	for (i = 0; i < key_id_number_iteration; i++) {
		args.key_group = (key_id_start + i) / 100;
		if (args.flags & HSM_OP_KEY_GENERATION_FLAGS_UPDATE)
			args.key_identifier = testCtx->key_id[key_id_start + i];
		else
			args.key_identifier = malloc(sizeof(uint32_t));

		hsm_err_t err = hsm_generate_key(testCtx->hdl[index], &args);

		/* TO DO HANDLE err by reading value in file fp */
		if (err == HSM_NO_ERROR) {
			/* Store Key_id address */
			testCtx->key_id[key_id_start + i] = args.key_identifier;
			testCtx->key_group[key_id_start + i] = args.key_group;

			/* Store pub key */
			testCtx->pub_key_size[key_id_start + i] = args.out_size;
			/* TODO handle different out_key */
			testCtx->pub_key_address[key_id_start + i] = args.out_key;
			//READ_CHECK_BUFFER(testCtx, fp, args.out_key, args.out_size);
		} else {
			slt_print(SLT_ERROR, "Error in generate_key API 0x%x\n", err);
			slt_print(SLT_ERROR, "Error in generate_key API iter 0x%x\n", i);
		}

		if ((i % 1000) == 0)
			slt_print(SLT_NOTICE, "Generated %u keys\n", i);
	}

	slt_print(SLT_NOTICE, "Generated %u keys\n", i);

	return fails;
}
