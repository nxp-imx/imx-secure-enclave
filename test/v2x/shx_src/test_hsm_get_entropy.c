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
#include "test_hsm_get_entropy.h"

#ifdef CAVP_SUPPORT
#include "cavp_support_api.h"

static FILE *entropy_file;
static uint32_t num_retries;

uint32_t test_hsm_get_entropy(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint32_t sess_index;
	uint32_t operation_result;
	op_cavp_support_args_t args;
	int i;

	sess_index                  = READ_VALUE(fp, uint32_t);
	args.service_handle         = 0;
	args.cavp_function          = SAB_HSM_CAVP_FUNCTION_GET_ENTROPY;
	args.key_id                 = 0;
	args.value1                 = READ_VALUE(fp, uint32_t);
	args.value2                 = READ_VALUE(fp, uint32_t);
	args.input_size             = 0;
	args.output_size            = READ_VALUE(fp, uint32_t);
	args.params_size            = 0;
	args.input                  = 0;
	args.output                 = malloc(args.output_size);
	args.params                 = 0;

	/* Entropy collection requires privileged mode on seco */
	if (testCtx->operating_mode == 0)
		place_hsm_in_privileged_mode();

	hsm_err_t err = hsm_cavp_support(testCtx->hdl[sess_index],
					 &args, &operation_result);

	READ_CHECK_VALUE(testCtx, fp, err);

	/* Print data to file (must have already been opened) */
	fwrite(args.output, args.output_size, sizeof(uint8_t), entropy_file);

	if (operation_result != 0) {
		printf("WARNING: saw retries for entropy: %d\n", operation_result);
		num_retries += operation_result;
	}

	FREE_BUFFER(args.output);

	return fails;
}

uint32_t test_hsm_open_entropy_file(hsm_test_struct_t *testCtx, FILE *fp)
{
	char *line = NULL;
	size_t len = 0;
	char filename[80];
	uint32_t num_errors = 1;

	if (getline(&line, &len, fp) > 0) {
		if (sscanf(line, "%79s", filename) > 0) {
			entropy_file = fopen(filename, "w");
			if (entropy_file) {
				printf("Created entropy file %s\n", filename);
				num_errors = 0;
			}
		}
	}
	free(line);

	if (num_errors)
		printf("Error creating entropy file\n");

	/* Track number of retries per file */
	num_retries = 0;

	return num_errors;
}

uint32_t test_hsm_close_entropy_file(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t num_errors = 1;

	if (fclose(entropy_file) != 0)
		printf("Error closing entropy file\n");
	else
		num_errors = 0;

	printf("Number of retries for file: %d\n", num_retries);

	return num_errors;
}

#define MAX_BLOCK_SIZE  4096
uint32_t test_hsm_sweep_noise_counter(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint32_t sess_index;
	uint32_t output_size;
	uint32_t operation_result;
	uint8_t *output_buff;
	op_cavp_support_args_t args;
	uint32_t curr_ent, start_ent, end_ent, ent_inc, extra_flags;
	uint32_t block_size;
	uint32_t size_collected;
	hsm_err_t err;

	sess_index             = READ_VALUE(fp, uint32_t);
	output_size            = READ_VALUE(fp, uint32_t);
	start_ent              = READ_VALUE(fp, uint32_t);
	end_ent                = READ_VALUE(fp, uint32_t);
	ent_inc                = READ_VALUE(fp, uint32_t);
	output_buff            = malloc(MAX_BLOCK_SIZE);
	extra_flags            = READ_VALUE(fp, uint32_t);

	for (curr_ent = start_ent; curr_ent <= end_ent; curr_ent += ent_inc) {
		printf("Collecting noise samples for entropy delay: %d\n", curr_ent);
		//write header in file (ent_delay; size of buffer in bytes)
		fwrite(&curr_ent, 1, sizeof(curr_ent), entropy_file);
		fwrite(&output_size, 1, sizeof(output_size), entropy_file);

		//enable mode
		args.service_handle         = 0;
		args.cavp_function          = SAB_HSM_CAVP_FUNCTION_GET_ENTROPY;
		args.key_id                 = 0;
		args.value1                 = GET_ENTROPY_FIELD_NOISE_COUNTER |
						GET_ENTROPY_FIELD_NOISE_INIT |
						extra_flags;
		args.value2                 = curr_ent;
		args.input_size             = 0;
		args.output_size            = 0;
		args.params_size            = 0;
		args.input                  = 0;
		args.output                 = output_buff;
		args.params                 = 0;

		/* Entropy collection requires privileged mode on seco */
		if (testCtx->operating_mode == 0)
			place_hsm_in_privileged_mode();

		err = hsm_cavp_support(testCtx->hdl[sess_index], &args,
				       &operation_result);
		if (err) {
			printf("ERROR: hsm_cavp_support fail: %d\n", err);
			fails++;
		}
		if (operation_result != 0) {
			printf("WARN: saw retries for entropy: %d\n", operation_result);
			num_retries += operation_result;
		}

		size_collected = 0;
		while (size_collected < output_size) {
			block_size = output_size - size_collected;
			if (block_size > MAX_BLOCK_SIZE)
				block_size = MAX_BLOCK_SIZE;

			//get data in 4096 max byte blocks
			args.service_handle = 0;
			args.cavp_function  = SAB_HSM_CAVP_FUNCTION_GET_ENTROPY;
			args.key_id         = 0;
			args.value1   = GET_ENTROPY_FIELD_NOISE_COUNTER | extra_flags;
			args.value2         = curr_ent;
			args.input_size     = 0;
			args.output_size    = block_size;
			args.params_size    = 0;
			args.input          = 0;
			args.output         = output_buff;
			args.params         = 0;

			/* Entropy collection requires privileged mode on seco */
			if (testCtx->operating_mode == 0)
				place_hsm_in_privileged_mode();

			err = hsm_cavp_support(testCtx->hdl[sess_index],
					       &args, &operation_result);
			if (err) {
				printf("ERROR: hsm_cavp_support fail: %d\n", err);
				fails++;
			}
			if (operation_result != 0) {
				printf("WARNING: saw retries for entropy %d: %d\n",
				       curr_ent, operation_result);
				num_retries += operation_result;
			}
			/* Print data to file (must have already been opened) */
			fwrite(output_buff, block_size, sizeof(uint8_t), entropy_file);
			size_collected += block_size;
		}

		// disable mode
		args.service_handle = 0;
		args.cavp_function  = SAB_HSM_CAVP_FUNCTION_GET_ENTROPY;
		args.key_id         = 0;
		args.value1         = GET_ENTROPY_FIELD_NOISE_COUNTER |
					GET_ENTROPY_FIELD_NOISE_DEINIT | extra_flags;
		args.value2         = curr_ent;
		args.input_size     = 0;
		args.output_size    = 0;
		args.params_size    = 0;
		args.input          = 0;
		args.output         = output_buff;
		args.params         = 0;

		/* Entropy collection requires privileged mode on seco */
		if (testCtx->operating_mode == 0)
			place_hsm_in_privileged_mode();

		err = hsm_cavp_support(testCtx->hdl[sess_index],
				       &args, &operation_result);
		if (err) {
			printf("ERROR: hsm_cavp_support fail: %d\n", err);
			fails++;
		}
		if (operation_result != 0) {
			printf("WARN: saw retries for entropy during disable(?): %d\n",
			       operation_result);
			num_retries += operation_result;
		}
	}

	FREE_BUFFER(output_buff);

	return fails;
}

uint32_t test_hsm_sweep_error_counter(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t sess_index;
	uint32_t error_count;
	uint32_t fails = 0;
	op_cavp_support_args_t args;
	uint32_t curr_ent, start_ent, end_ent, ent_inc, extra_flags;
	hsm_err_t err;

	sess_index             = READ_VALUE(fp, uint32_t);
	start_ent              = READ_VALUE(fp, uint32_t);
	end_ent                = READ_VALUE(fp, uint32_t);
	ent_inc                = READ_VALUE(fp, uint32_t);
	extra_flags            = READ_VALUE(fp, uint32_t);

	for (curr_ent = start_ent; curr_ent <= end_ent; curr_ent += ent_inc) {
		printf("Doing ent_delay %d\n", curr_ent);
		//enable mode
		args.service_handle = 0;
		args.cavp_function  = SAB_HSM_CAVP_FUNCTION_GET_ENTROPY;
		args.key_id         = 0;
		args.value1         = GET_ENTROPY_FIELD_ERROR_INIT |
					GET_ENTROPY_FIELD_ERROR_COUNTER |
					GET_ENTROPY_FIELD_ERROR_DEINIT |
					extra_flags;
		args.value2         = curr_ent;
		args.input_size     = 0;
		args.output_size    = 0;
		args.params_size    = 0;
		args.input          = 0;
		args.output         = 0;
		args.params         = 0;

		/* Entropy collection requires privileged mode on seco */
		if (testCtx->operating_mode == 0)
			place_hsm_in_privileged_mode();

		err = hsm_cavp_support(testCtx->hdl[sess_index], &args, &error_count);
		if (err) {
			printf("ERROR: hsm_cavp_support fail for ent %d: %d\n",
			       curr_ent, err);
			fails++;
		} else {
			fwrite(&curr_ent, 1, sizeof(curr_ent), entropy_file);
			fwrite(&error_count, 1, sizeof(error_count), entropy_file);
		}
	}
	return fails;
}

uint32_t test_hsm_sweep_error_variance(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t sess_index;
	uint32_t error_count;
	uint32_t fails = 0;
	op_cavp_support_args_t args;
	uint32_t curr_ent, start_ent, end_ent, ent_inc, extra_flags;
	hsm_err_t err;
	uint32_t sum_array[2];

	sess_index             = READ_VALUE(fp, uint32_t);
	start_ent              = READ_VALUE(fp, uint32_t);
	end_ent                = READ_VALUE(fp, uint32_t);
	ent_inc                = READ_VALUE(fp, uint32_t);
	extra_flags            = READ_VALUE(fp, uint32_t);

	for (curr_ent = start_ent; curr_ent <= end_ent; curr_ent += ent_inc) {
		printf("Doing ent_delay %d\n", curr_ent);
		//enable mode
		args.service_handle = 0;
		args.cavp_function  = SAB_HSM_CAVP_FUNCTION_GET_ENTROPY;
		args.key_id         = 0;
		args.value1         = GET_ENTROPY_FIELD_ERROR_INIT |
					GET_ENTROPY_FIELD_ERR_VARIANCE |
					GET_ENTROPY_FIELD_ERROR_DEINIT |
					extra_flags;
		args.value2         = curr_ent;
		args.input_size     = 0;
		args.output_size    = 8;
		args.params_size    = 0;
		args.input          = 0;
		args.output         = (uint8_t *)sum_array;
		args.params         = 0;

		/* Entropy collection requires privileged mode on seco */
		if (testCtx->operating_mode == 0)
			place_hsm_in_privileged_mode();

		err = hsm_cavp_support(testCtx->hdl[sess_index], &args, &error_count);
		if (err) {
			printf("ERROR: hsm_cavp_support fail for ent %d: %d\n",
			       curr_ent, err);
			fails++;
		} else {
			fwrite(&curr_ent, 1, sizeof(curr_ent), entropy_file);
			fwrite(sum_array, 1, sizeof(sum_array), entropy_file);
		}
	}
	return fails;
}

uint32_t test_hsm_get_trng_freq(hsm_test_struct_t *testCtx, FILE *fp)
{
	uint32_t fails = 0;
	uint32_t sess_index;
	uint32_t operation_result;
	op_cavp_support_args_t args;
	int i;

	sess_index                  = READ_VALUE(fp, uint32_t);
	args.service_handle         = 0;
	args.cavp_function          = SAB_HSM_CAVP_FUNCTION_GET_ENTROPY;
	args.key_id                 = 0;
	args.value1                 = READ_VALUE(fp, uint32_t);
	args.value2                 = READ_VALUE(fp, uint32_t);
	args.input_size             = 0;
	args.output_size            = 0;
	args.params_size            = 0;
	args.input                  = 0;
	args.output                 = 0;
	args.params                 = 0;

	/* Entropy collection requires privileged mode on seco */
	if (testCtx->operating_mode == 0)
		place_hsm_in_privileged_mode();

	hsm_err_t err = hsm_cavp_support(testCtx->hdl[sess_index],
					 &args, &operation_result);

	READ_CHECK_VALUE(testCtx, fp, err);

	/* Log ent_dly and freq_count */
	fwrite(&args.value2, 1, sizeof(args.value2), entropy_file);
	fwrite(&operation_result, 1, sizeof(operation_result), entropy_file);

	return fails;
}

#else
uint32_t test_hsm_get_entropy(hsm_test_struct_t *testCtx, FILE *fp)
{
	printf("ERROR: cavp support not enabled, required for entropy collection\n");
	return 1;
}

uint32_t test_hsm_open_entropy_file(hsm_test_struct_t *testCtx, FILE *fp)
{
	printf("ERROR: cavp support not enabled, required for entropy file handling\n");
	return 1;
}

uint32_t test_hsm_close_entropy_file(hsm_test_struct_t *testCtx, FILE *fp)
{
	printf("ERROR: cavp support not enabled, required for entropy file handling\n");
	return 1;
}

uint32_t test_hsm_sweep_noise_counter(hsm_test_struct_t *testCtx, FILE *fp)
{
	printf("ERROR: cavp support not enabled, required for noise counter sweep\n");
	return 1;
}

uint32_t test_hsm_sweep_error_counter(hsm_test_struct_t *testCtx, FILE *fp)
{
	printf("ERROR: cavp support not enabled, required for error counter sweep\n");
	return 1;
}

uint32_t test_hsm_sweep_error_variance(hsm_test_struct_t *testCtx, FILE *fp)
{
	printf("ERROR: cavp support not enabled, required for error counter sweep\n");
	return 1;
}

uint32_t test_hsm_get_trng_freq(hsm_test_struct_t *testCtx, FILE *fp)
{
	printf("ERROR: cavp support not enabled, required for trng freq measurement\n");
	return 1;
}
#endif
