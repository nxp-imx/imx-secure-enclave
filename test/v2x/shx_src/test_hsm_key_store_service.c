// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <fcntl.h>

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_key_store_service.h"

#define SIGNED_MESSAGE_KEY_STORE_SEC_PROV_SIZE 0x360

uint32_t test_hsm_open_key_store_service(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	char *file = "/etc/v2x_hsm/key_store_sec_reprov_sign_msg.bin";
	int32_t fd = -1;
	int32_t l = 0;
	uint8_t *signed_message = malloc(SIGNED_MESSAGE_KEY_STORE_SEC_PROV_SIZE);

	uint32_t index, new_hdl_index;
	open_svc_key_store_args_t args;

	index                     = READ_VALUE(fp, uint32_t);
	args.signed_message       = NULL;
	args.signed_msg_size      = 0;
	args.key_store_identifier = READ_VALUE(fp, uint32_t);
	args.authentication_nonce = READ_VALUE(fp, uint32_t);
	args.max_updates_number   = READ_VALUE(fp, uint16_t);
	args.flags                = READ_VALUE(fp, hsm_svc_key_store_flags_t);
	args.min_mac_length       = READ_VALUE(fp, uint8_t);
	new_hdl_index             = READ_VALUE(fp, uint32_t);

	fd = open(file, O_RDONLY);
	if (fd >= 0) {
		l = (int32_t)read(fd, signed_message,
				  SIGNED_MESSAGE_KEY_STORE_SEC_PROV_SIZE);
		if (l == SIGNED_MESSAGE_KEY_STORE_SEC_PROV_SIZE) {
			args.signed_message = signed_message;
			args.signed_msg_size = SIGNED_MESSAGE_KEY_STORE_SEC_PROV_SIZE;
		}
	}

	(void)close(fd);

	hsm_err_t err = hsm_open_key_store_service(testCtx->hdl[index],
						   &args,
						   &testCtx->hdl[new_hdl_index]);
	if (err == HSM_KEY_STORE_CONFLICT) {
		args.flags &= ~HSM_SVC_KEY_STORE_FLAGS_CREATE;
		err = hsm_open_key_store_service(testCtx->hdl[index],
						 &args,	&testCtx->hdl[new_hdl_index]);
	}

	slt_print(SLT_DEBUG, "Check Error, expect ");
	READ_CHECK_VALUE(testCtx, fp, err);

	return fails;
}

uint32_t test_hsm_close_key_store_service(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	// read the session index.
	uint32_t index = READ_VALUE(fp, uint32_t);

	hsm_err_t err = hsm_close_key_store_service(testCtx->hdl[index]);

	READ_CHECK_VALUE(testCtx, fp, err);

	return fails;
}
