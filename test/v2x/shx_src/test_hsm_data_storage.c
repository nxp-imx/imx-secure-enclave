// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_data_storage.h"

uint32_t test_hsm_data_storage(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint8_t data_id_number;

	uint8_t index;
	op_data_storage_args_t args;

	index                    = READ_VALUE(fp, uint8_t);
	data_id_number           = READ_VALUE(fp, uint8_t);
	args.flags               = READ_VALUE(fp, hsm_op_data_storage_flags_t);
	if (args.flags & HSM_OP_DATA_STORAGE_FLAGS_STORE) {
		args.data_id             = READ_VALUE(fp, uint16_t);
		args.data_size           = READ_VALUE(fp, uint32_t);
	} else {
		// Retrieve
		if (data_id_number == 0xFF) {
			// have possibility to test user param for retrieve
			args.data_id    = READ_VALUE(fp, uint16_t);
			args.data_size  = READ_VALUE(fp, uint32_t);
		} else {
			args.data_id    = testCtx->data_id[data_id_number];
			args.data_size  = testCtx->data_size[data_id_number];
		}
	}
	slt_print(SLT_NOTICE, "data_size 0x%x\n", args.data_size);
	if (args.data_size < 200) {
		args.data          = READ_OUTPUT_BUFFER(fp, args.data_size);
	} else {
		// big data size
		args.data               = malloc(args.data_size);
		// store
		if (args.flags & HSM_OP_DATA_STORAGE_FLAGS_STORE)
			memset(args.data, 0xAA, args.data_size);
		else
			memset(args.data, 0xBB, args.data_size);
	}

	hsm_err_t err = hsm_data_storage(testCtx->hdl[index], &args);

	READ_CHECK_VALUE(testCtx, fp, err);

	if (err == HSM_NO_ERROR) {
		if (args.flags & HSM_OP_DATA_STORAGE_FLAGS_STORE) {
			/* Store data storage info */
			testCtx->data_id[data_id_number] = args.data_id;
			testCtx->data_size[data_id_number] = args.data_size;
			testCtx->data_address[data_id_number] = args.data;
			slt_print(SLT_NOTICE, "data_address stored 0x%p\n",
				  testCtx->data_address[data_id_number]);
		} else {
			if (data_id_number == 0xFF) {
				if (args.data_size < 200) {
					slt_print(SLT_NOTICE, "compare buffer");
					READ_CHECK_BUFFER(testCtx, fp, args.data,
							  args.data_size);
				}
				/* TODO for big data size */
			} else {
				slt_print(SLT_NOTICE, "address to check data 0x%p\n",
					  testCtx->data_address[data_id_number]);
				slt_print(SLT_NOTICE, "data 0x%p\n", args.data);
				CHECK_BUFFER(testCtx, args.data,
					     testCtx->data_address[data_id_number],
					     args.data_size);
			}
		}
	}

	return fails;
}
