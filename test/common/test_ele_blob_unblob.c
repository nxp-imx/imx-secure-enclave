// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>

#include "test_common.h"
#include "hsm_api.h"

static uint8_t plaintext[32] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

#ifdef PSA_COMPLIANT
uint32_t test_ele_blob_unblob(hsm_hdl_t session_hdl, uint8_t *usr_ctx_buf)
{
	op_blob_unblob_msg_args_t args = {0};
	hsm_err_t err;
	uint8_t blob_buf[80];
	uint8_t unblob_buf[32];

	if (usr_ctx_buf) {
		args.usr_ctx_addr = (uint32_t *)usr_ctx_buf;
		args.usr_ctx_size = strlen(usr_ctx_buf);
	}

	args.in_addr = (uint32_t *)plaintext;
	args.in_size = sizeof(plaintext);

	args.out_addr = (uint32_t *)blob_buf;
	args.out_size = sizeof(blob_buf);

	args.flags = HSM_OP_BLOB_UNBLOB_FLAG_USE_UUID_IN_DER_CTX;
	args.mode = HSM_OP_BLOB_UNBLOB_MODE_WRAP;
	err = hsm_blob_unblob(session_hdl, &args);
	if (err != HSM_NO_ERROR)
		printf("hsm_blob_unblob(Wrap) failed err:0x%x\n", err);

	args.in_addr = (uint32_t *)blob_buf;
	args.in_size = sizeof(blob_buf);

	args.out_addr = (uint32_t *)unblob_buf;
	args.out_size = sizeof(unblob_buf);

	args.flags |= HSM_OP_BLOB_UNBLOB_FLAG_USE_UUID_IN_DER_CTX;
	args.mode = HSM_OP_BLOB_UNBLOB_MODE_UNWRAP;
	err = hsm_blob_unblob(session_hdl, &args);
	if (err != HSM_NO_ERROR)
		printf("hsm_blob_unblob(Un-wrap) failed err:0x%x\n", err);

	if (!memcmp(plaintext, unblob_buf, sizeof(plaintext)))
		printf("ELE Blob-Unblob with FLAG_USE_UUID_IN_DER_CTX: passed.\n");
	else
		printf("ELE Blob-Unblob with FLAG_USE_UUID_IN_DER_CTX: failed.\n");

	args.in_addr = (uint32_t *)plaintext;
	args.in_size = sizeof(plaintext);

	args.out_addr = (uint32_t *)blob_buf;
	args.out_size = sizeof(blob_buf);

	args.flags |= HSM_OP_BLOB_UNBLOB_FLAG_USE_MU_IN_DER_CTX;
	args.mode = HSM_OP_BLOB_UNBLOB_MODE_WRAP;
	err = hsm_blob_unblob(session_hdl, &args);
	if (err != HSM_NO_ERROR)
		printf("hsm_blob_unblob(Wrap) failed err:0x%x\n", err);

	args.in_addr = (uint32_t *)blob_buf;
	args.in_size = sizeof(blob_buf);

	args.out_addr = (uint32_t *)unblob_buf;
	args.out_size = sizeof(unblob_buf);

	args.flags |= HSM_OP_BLOB_UNBLOB_FLAG_USE_MU_IN_DER_CTX;
	args.mode = HSM_OP_BLOB_UNBLOB_MODE_UNWRAP;
	err = hsm_blob_unblob(session_hdl, &args);
	if (err != HSM_NO_ERROR)
		printf("hsm_blob_unblob(Un-wrap) failed err:0x%x\n", err);

	if (!memcmp(plaintext, unblob_buf, sizeof(plaintext)))
		printf("ELE Blob-Unblob with FLAG_USE_MU_IN_DER_CTX: passed.\n");
	else
		printf("ELE Blob-Unblob with FLAG_USE_MU_IN_DER_CTX: failed.\n");

	return 0;
}
#endif
