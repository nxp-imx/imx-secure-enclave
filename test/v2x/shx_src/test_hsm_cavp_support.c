// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "hsm_exec.h"
#include "shx_test_macros.h"
#include "test_hsm_cavp_support.h"

#ifdef CAVP_SUPPORT
#include "cavp_support_api.h"

static int cavp_function_requires_privileged_mode(uint32_t cavp_function)
{
	int required;

	switch (cavp_function) {
	case SAB_HSM_CAVP_FUNCTION_SIGN_VERIF:
	case SAB_HSM_CAVP_FUNCTION_DRBG_SHA:
	case SAB_HSM_CAVP_FUNCTION_GET_ENTROPY:
		required = 1;
		break;
	default:
		required = 0;
		break;
	}
	return required;
}

void place_hsm_in_privileged_mode(void)
{
	int32_t scu_device_fd = -1;
	struct seco_mu_ioctl_signed_message msg;
	uint8_t dummy_message[4] = {0, 1, 2, 3};

	scu_device_fd = open(SCU_DEVICE_PATH, O_RDWR);
	if (scu_device_fd < 0) {
		slt_print(SLT_ERROR, "Error opening SCU device\n");
		return;
	}

	msg.message = dummy_message;
	msg.msg_size = sizeof(dummy_message);

	if (ioctl(scu_device_fd, SECO_MU_IOCTL_SIGNED_MESSAGE, &msg) == -1)
		slt_print(SLT_ERROR, "Error sending SCU message\n");

	if (close(scu_device_fd) < 0)
		slt_print(SLT_ERROR, "Error closing SCU device\n");
}

uint32_t test_hsm_cavp_support(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	uint32_t sess_index;
	uint32_t serv_index;
	uint32_t key_index;
	uint32_t operation_result;
	op_cavp_support_args_t args;

	sess_index                  = READ_VALUE(fp, uint32_t);
	serv_index                  = READ_VALUE(fp, uint32_t);
	args.service_handle         = testCtx->hdl[serv_index];
	args.cavp_function          = READ_VALUE(fp, uint32_t);
	key_index                   = READ_VALUE(fp, uint32_t);
	if (testCtx->key_id[key_index])
		args.key_id         = *testCtx->key_id[key_index];
	else
		args.key_id             = 0;
	args.value1                 = READ_VALUE(fp, uint32_t);
	args.value2                 = READ_VALUE(fp, uint32_t);
	args.input_size             = READ_VALUE(fp, uint32_t);
	args.output_size            = READ_VALUE(fp, uint32_t);
	args.params_size            = READ_VALUE(fp, uint32_t);
	args.input                  = READ_OUTPUT_BUFFER(fp, args.input_size);
	args.output                 = READ_OUTPUT_BUFFER(fp, args.output_size);
	args.params                 = READ_OUTPUT_BUFFER(fp, args.params_size);

	if (testCtx->operating_mode == 0) {
		if (cavp_function_requires_privileged_mode(args.cavp_function))
			place_hsm_in_privileged_mode();
	} else {
		printf("%s: skip privileged mode, mode = %x\n",
		       __func__, testCtx->operating_mode);
	}

	hsm_err_t err = hsm_cavp_support(testCtx->hdl[sess_index],
					 &args, &operation_result);

	READ_CHECK_VALUE(testCtx, fp, err);
	READ_CHECK_BUFFER(testCtx, fp, args.output, args.output_size);
	READ_CHECK_VALUE(testCtx, fp, operation_result);

	if (operation_result != 0) {
		if (operation_result != 0x01 && operation_result != 0x02)
			slt_print(SLT_ERROR, "<OUTPUT_DATA>\nFAIL\n</OUTPUT_DATA>\n");
		else
			slt_print(SLT_NOTICE, "<OUTPUT_DATA>\nPASS\n</OUTPUT_DATA>\n");
	}
	if (args.output_size != 0)
		DISPLAY_BUFFER(args.output, args.output_size);

	FREE_BUFFER(args.input);
	FREE_BUFFER(args.output);
	FREE_BUFFER(args.params);

	return fails;
}

uint32_t test_hsm_cavp_support_mct(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;

	uint32_t sess_index;
	uint32_t serv_index;
	uint32_t key_index;
	uint32_t operation_result;

	uint8_t *seed;
	uint8_t *MD0, *MD1, *MD2;
	uint8_t *msg;
	uint32_t seed_size;
	uint16_t i, j, k;

	op_cavp_support_args_t args;

	sess_index                  = READ_VALUE(fp, uint32_t);
	serv_index                  = READ_VALUE(fp, uint32_t);
	args.service_handle         = testCtx->hdl[serv_index];
	args.cavp_function          = READ_VALUE(fp, uint32_t);
	key_index                   = READ_VALUE(fp, uint32_t);
	if (testCtx->key_id[key_index])
		args.key_id         = *testCtx->key_id[key_index];
	else
		args.key_id             = 0;
	args.value1                 = READ_VALUE(fp, uint32_t);
	args.value2                 = READ_VALUE(fp, uint32_t);

	seed_size                   = READ_VALUE(fp, uint32_t);

	args.output_size            = READ_VALUE(fp, uint32_t);
	args.params_size            = READ_VALUE(fp, uint32_t);
	seed                        = READ_OUTPUT_BUFFER(fp, seed_size);
	args.output                 = READ_OUTPUT_BUFFER(fp, args.output_size);
	args.params                 = READ_OUTPUT_BUFFER(fp, args.params_size);

	args.input_size             = 3 * seed_size;

	msg = malloc(3 * seed_size);
	MD0 = malloc(seed_size);
	MD1 = malloc(seed_size);
	MD2 = malloc(seed_size);

	for (i = 0; i < 100; i++) {
		memcpy(MD0, seed, seed_size);
		memcpy(MD1, seed, seed_size);
		memcpy(MD2, seed, seed_size);

		for (j = 0; j < 1000; j++) {
			memcpy(msg, MD2, seed_size);
			memcpy(&msg[seed_size], MD1, seed_size);
			memcpy(&msg[2 * seed_size], MD0, seed_size);

			args.input = msg;

			if (cavp_function_requires_privileged_mode(args.cavp_function))
				place_hsm_in_privileged_mode();

			hsm_err_t err = hsm_cavp_support(testCtx->hdl[sess_index],
							 &args, &operation_result);

			memcpy(MD2, MD1, seed_size);
			memcpy(MD1, MD0, seed_size);
			memcpy(MD0, args.output, seed_size);
		}
		printf("Count %d =>\n", i);
		DISPLAY_BUFFER(args.output, seed_size);
		printf("\n");

		memcpy(seed, MD0, seed_size);
	}

	FREE_BUFFER(msg);
	FREE_BUFFER(MD0);
	FREE_BUFFER(MD1);
	FREE_BUFFER(MD2);
	FREE_BUFFER(args.output);

	return fails;
}
#else
uint32_t test_hsm_cavp_support(hsm_test_struct_t *testCtx, FILE *fp)
{
	slt_print(SLT_ERROR, "ERROR: cavp support not enabled\n");
	return 1;
}

uint32_t test_hsm_cavp_support_mct(hsm_test_struct_t *testCtx, FILE *fp)
{
	printf("ERROR: cavp support not enabled\n");
	return 1;
}
#endif
