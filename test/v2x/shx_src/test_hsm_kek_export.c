// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */
#include <fcntl.h>

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_kek_export.h"

#define SIGNED_MESSAGE_KEK_EXPORT_EN_SIZE 0x358

uint32_t test_hsm_root_kek_export(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	uint32_t index;
	op_export_root_kek_args_t args;

	char *file = "/etc/seco_hsm/kek_export_en_sign_msg.bin";
	int32_t fd = -1;
	int32_t l = 0;
	uint8_t *signed_message = malloc(SIGNED_MESSAGE_KEK_EXPORT_EN_SIZE);

	index                 = READ_VALUE(fp, uint32_t);
	args.signed_message   = NULL;
	args.signed_msg_size  = 0;
	args.root_kek_size    = READ_VALUE(fp, uint16_t);
	args.flags            = READ_VALUE(fp, hsm_op_export_root_kek_flags_t);
	args.reserved[0]      = READ_VALUE(fp, uint8_t);
	args.reserved[1]      = READ_VALUE(fp, uint8_t);
	args.reserved[2]      = READ_VALUE(fp, uint8_t);
	args.out_root_kek     = READ_OUTPUT_BUFFER(fp, args.root_kek_size);

	fd = open(file, O_RDONLY);
	if (fd >= 0) {
		l = (int32_t)read(fd, signed_message, SIGNED_MESSAGE_KEK_EXPORT_EN_SIZE);
		if (l == SIGNED_MESSAGE_KEK_EXPORT_EN_SIZE) {
			args.signed_message = signed_message;
			args.signed_msg_size = SIGNED_MESSAGE_KEK_EXPORT_EN_SIZE;
		}
	}
	if (!args.signed_message)
		slt_print(SLT_WARNING, "Signed message not sent 0x%x\n", l);

	(void)close(fd);

	hsm_err_t err = hsm_export_root_key_encryption_key(testCtx->hdl[index], &args);
	if (err == HSM_INVALID_MESSAGE) {
		slt_print(SLT_WARNING, "Command not supported\n");
	} else {
		READ_CHECK_VALUE(testCtx, fp, err);
		READ_CHECK_BUFFER(testCtx, fp, args.out_root_kek, args.root_kek_size);
	}

	free(signed_message);

	return fails;
}
