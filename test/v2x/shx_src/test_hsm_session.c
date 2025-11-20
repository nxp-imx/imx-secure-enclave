// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_session.h"

uint32_t test_hsm_open_session(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint32_t index;
	open_session_args_t args;

	index                  = READ_VALUE(fp, uint32_t);
	args.mu_type  = READ_VALUE(fp, uint8_t);

	hsm_err_t err = hsm_open_session(&args, &testCtx->hdl[index]);

	slt_print(SLT_DEBUG, "Check Error, expect ");
	READ_CHECK_VALUE(testCtx, fp, err);
	slt_print(SLT_DEBUG, "Check Pointer - ");
	READ_CHECK_POINTER(testCtx, fp, testCtx->hdl[index]);
	slt_print(SLT_DEBUG, "Real Handle created: 0x%x\n", testCtx->hdl[index]);

	return fails;
}

uint32_t test_hsm_close_session(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	test_keyid_t key_data;

	// read the session index.
	uint32_t index = READ_VALUE(fp, uint32_t);

	hsm_err_t err = hsm_close_session(testCtx->hdl[index]);

	READ_CHECK_VALUE(testCtx, fp, err);

	if (testCtx->fp) {
		slt_print(SLT_NOTICE, "close session : write keys\n");
		for (uint8_t i = 1; i < MAX_KEY_ID ; i++) {
			if (testCtx->key_id[i] != 0) {
				if (testCtx->idx_key[i] == 0) {
					/* If key still not in the file */
					key_data.key_group = testCtx->key_group[i];
					key_data.key_id = *testCtx->key_id[i];
					slt_print(SLT_INFO, "key data key id[%d] 0x%x\n",
						  key_data.key_id, i);
					fwrite(&key_data, sizeof(key_data),
					       1, testCtx->fp);
					testCtx->idx_key[i] = 1;
				} else {
					/*
					 * If key is already in the file (in case of
					 * multiple close session), skip it.
					 */
					continue;
				}
			} else {
				slt_print(SLT_INFO, "no more data 0x%x ", i);
				break;
			}
		}
	}

	return fails;
}

