// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_manage_key.h"

uint32_t test_hsm_manage_key(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	uint32_t index;
	op_manage_key_args_t args;
	uint32_t key_id_number, kek_id_number;

	index                    = READ_VALUE(fp, uint32_t);
	key_id_number            = READ_VALUE(fp, uint32_t);
	kek_id_number            = READ_VALUE(fp, uint32_t);
	args.flags               = READ_VALUE(fp, hsm_op_manage_key_flags_t);

	if ((args.flags & HSM_OP_MANAGE_KEY_FLAGS_IMPORT_UPDATE) ||
	    (args.flags & HSM_OP_MANAGE_KEY_FLAGS_DELETE)) {
		if (key_id_number == BAD_0) // Addr = 0x0
			args.key_identifier = 0x0;
		else if (key_id_number == BAD_1) // Addr = 0xBADBAD
			args.key_identifier = (uint32_t *)BAD_ADDR;
		else
			args.key_identifier = testCtx->key_id[key_id_number];

		slt_print(SLT_INFO, "update/delete: key id %x\n", *args.key_identifier);
	} else {
		args.key_identifier = malloc(sizeof(uint32_t));
	}

	if (testCtx->key_id[kek_id_number] != 0) {
		args.kek_identifier = *testCtx->key_id[kek_id_number];
		slt_print(SLT_DEBUG, "KEK is here: idx = %d, key_id %x\n",
			  kek_id_number, args.kek_identifier);
	} else {
		args.kek_identifier = 0;
		slt_print(SLT_DEBUG, "KEK not found\n");
	}

	slt_print(SLT_INFO, "KEK id %x\n", args.kek_identifier);
	args.input_size          = READ_VALUE(fp, uint16_t);
	args.key_type            = READ_VALUE(fp, hsm_key_type_t);
	args.key_group           = READ_VALUE(fp, hsm_key_group_t);
	args.key_info            = READ_VALUE(fp, hsm_key_info_t);
	args.input_data          = READ_INPUT_BUFFER(fp, args.input_size);

	hsm_err_t err = hsm_manage_key(testCtx->hdl[index], &args);

	READ_CHECK_VALUE(testCtx, fp, err);
	/* Store or delete Key_id address */
	if (err == HSM_NO_ERROR) {
		if (args.flags & HSM_OP_MANAGE_KEY_FLAGS_DELETE) {
			slt_print(SLT_INFO, "key should be deleted from ctx 0x%p\n",
				  testCtx->key_id[key_id_number]);
			//     testCtx->key_id[key_id_number] = 0;
		} else {
			/* Store Key_id address */
			testCtx->key_id[key_id_number] = args.key_identifier;
			testCtx->key_group[key_id_number] = args.key_group;
			slt_print(SLT_INFO, "new key id 0x%x\n",
				  *testCtx->key_id[key_id_number]);
		}
	}

	FREE_BUFFER(args.input_data);
	// args.key_identifier not freed as stored in testCtx

	return fails;
}

uint32_t test_hsm_manage_key_ext(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	uint32_t index;
	op_manage_key_ext_args_t args;
	uint32_t key_id_number, kek_id_number;

	index                    = READ_VALUE(fp, uint32_t);
	key_id_number            = READ_VALUE(fp, uint32_t);
	kek_id_number            = READ_VALUE(fp, uint32_t);
	args.flags               = READ_VALUE(fp, hsm_op_manage_key_flags_t);

	if ((args.flags & HSM_OP_MANAGE_KEY_FLAGS_IMPORT_UPDATE) ||
	    (args.flags & HSM_OP_MANAGE_KEY_FLAGS_DELETE)) {
		if (key_id_number == BAD_0) // Addr = 0x0
			args.key_identifier = 0x0;
		else if (key_id_number == BAD_1) // Addr = 0xBADBAD
			args.key_identifier = (uint32_t *)BAD_ADDR;
		else
			args.key_identifier = testCtx->key_id[key_id_number];
		slt_print(SLT_INFO, "update/delete: key id %x\n", *args.key_identifier);
	} else {
		args.key_identifier = malloc(sizeof(uint32_t));
	}

	if (testCtx->key_id[kek_id_number] != 0) {
		args.kek_identifier = *testCtx->key_id[kek_id_number];
		slt_print(SLT_DEBUG, "KEK is here: idx = %d, key_id %x\n",
			  kek_id_number, args.kek_identifier);
	} else {
		args.kek_identifier = 0;
		slt_print(SLT_DEBUG, "KEK not found\n");
	}

	slt_print(SLT_INFO, "KEK id %x\n", args.kek_identifier);
	args.input_size          = READ_VALUE(fp, uint16_t);
	args.key_type            = READ_VALUE(fp, hsm_key_type_t);
	args.key_group           = READ_VALUE(fp, hsm_key_group_t);
	args.key_info            = READ_VALUE(fp, hsm_key_info_t);
	args.input_data          = READ_INPUT_BUFFER(fp, args.input_size);
	args.min_mac_len         = READ_VALUE(fp, uint8_t);
	args.reserved[0]         = READ_VALUE(fp, uint8_t);
	args.reserved[1]         = READ_VALUE(fp, uint8_t);
	args.reserved[2]         = READ_VALUE(fp, uint8_t);

	hsm_err_t err = hsm_manage_key_ext(testCtx->hdl[index], &args);

	READ_CHECK_VALUE(testCtx, fp, err);
	/* Store or delete Key_id address */
	if (err == HSM_NO_ERROR) {
		if (args.flags & HSM_OP_MANAGE_KEY_FLAGS_DELETE) {
			slt_print(SLT_INFO, "key should be deleted from ctx 0x%p\n",
				  testCtx->key_id[key_id_number]);
			//     testCtx->key_id[key_id_number] = 0;
		} else {
			/* Store Key_id address */
			testCtx->key_id[key_id_number] = args.key_identifier;
			testCtx->key_group[key_id_number] = args.key_group;
			slt_print(SLT_INFO, "new key id 0x%x\n",
				  *testCtx->key_id[key_id_number]);
		}
	}

	FREE_BUFFER(args.input_data);
	// args.key_identifier not freed as stored in testCtx

	return fails;
}

uint32_t test_hsm_bulk_manage_key(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint32_t index, key_id;
	op_manage_key_args_t args;
	uint32_t key_id_start, key_id_number_iteration, kek_id_number;
	hsm_err_t expected_ret;

	index                    = READ_VALUE(fp, uint32_t);
	key_id_start             = READ_VALUE(fp, uint32_t);
	key_id_number_iteration  = READ_VALUE(fp, uint32_t);
	kek_id_number            = READ_VALUE(fp, uint32_t);
	// AES key gen cmd to be executed before, not supported yet
	args.kek_identifier      = *testCtx->key_id[kek_id_number];
	args.flags               = READ_VALUE(fp, hsm_op_manage_key_flags_t);
	args.input_size          = READ_VALUE(fp, uint16_t);
	args.key_type            = READ_VALUE(fp, hsm_key_type_t);
	args.key_info            = READ_VALUE(fp, hsm_key_info_t);
	args.input_data          = READ_INPUT_BUFFER(fp, args.input_size);
	expected_ret             = READ_VALUE(fp, hsm_err_t);

	slt_print(SLT_NOTICE, "Bulk key manage %u iterations\n", key_id_number_iteration);
	for (key_id = key_id_start;
	     key_id < key_id_start + key_id_number_iteration;
	     key_id++) {
		if ((args.flags & HSM_OP_MANAGE_KEY_FLAGS_IMPORT_UPDATE) ||
		    (args.flags & HSM_OP_MANAGE_KEY_FLAGS_DELETE)) {
			if (key_id == BAD_0) // Addr = 0x0
				args.key_identifier = 0x0;
			else if (key_id == BAD_1) // Addr = 0xBADBAD
				args.key_identifier = (uint32_t *)BAD_ADDR;
			else
				args.key_identifier = testCtx->key_id[key_id];
		} else {
			args.key_identifier = malloc(sizeof(uint32_t));
		}
		args.key_group = (key_id) / 100;

		hsm_err_t err = hsm_manage_key(testCtx->hdl[index], &args);
		/* Store or delete Key_id address */
		if (err == expected_ret) {
			if (args.flags & HSM_OP_MANAGE_KEY_FLAGS_DELETE) {
				free(testCtx->key_id[key_id]);
				testCtx->key_id[key_id] = 0;
				slt_print(SLT_INFO, "Cleared key_id %d\n", key_id);
			} else {
				testCtx->key_id[key_id] = args.key_identifier;
				slt_print(SLT_INFO, "new key id 0x%x\n",
					  *testCtx->key_id[key_id]);
			}
		} else {
			slt_print(SLT_ERROR, "Error %d\n", err);
			fails++;
		}

		FREE_BUFFER(args.input_data);

		if (key_id && ((key_id % 1000) == 0))
			slt_print(SLT_NOTICE, "Processed %u keys\n", key_id);
	}
	slt_print(SLT_NOTICE, "Processed %u keys\n", key_id);
	CHECK_VALUE(testCtx, fails, 0);

	return fails;
}
