// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdio.h>
#include <stdint.h>

#include "hsm_api.h"
#include "test_common.h"

void fuse_SHE_SECRET_key(hsm_hdl_t sess_hdl)
{
#if HSM_DEV_WRITE_FUSE
	op_dev_write_fuse_args_t *dev_write_fuse_args = NULL;
	hsm_err_t err;
	uint32_t arr[4] = {0xcafecafe, 0x1234567, 0xdeadbeef, 0x89101112};

	dev_write_fuse_args = malloc(sizeof(op_dev_write_fuse_args_t) + sizeof(arr));

	/* In this example, key is: 0xcafecafe 0x1234567 0xdeadbeef 0x89101112
	 * 0x17d60706 0x00802300 0xcafecafe 0x1234567 0xdeadbeef 0x89101112 0x8b360462
	 * SHE_SECRET_KEY is 128 bit long, starts at word 280 in i.MX95
	 */
	dev_write_fuse_args->word_pos = 280; // (280 * 32 = 0x2300)
	dev_write_fuse_args->bit_pos = 0;
	dev_write_fuse_args->bit_len = 32 * 4; // (= 0x80)

	dev_write_fuse_args->payload[0] = arr[0];
	dev_write_fuse_args->payload[1] = arr[1];
	dev_write_fuse_args->payload[2] = arr[2];
	dev_write_fuse_args->payload[3] = arr[3];

	err = hsm_dev_write_fuse(sess_hdl, dev_write_fuse_args);
	if (err != HSM_NO_ERROR)
		printf("Failed to write SHE_SECRET_KEY, err:0x%x\n", err);
	else
		printf("last processed_idx = 0x%x\n", dev_write_fuse_args->processed_idx);
#endif
}

void fuse_PRNG_key(hsm_hdl_t sess_hdl)
{
#if HSM_DEV_WRITE_FUSE
	op_dev_write_fuse_args_t *dev_write_fuse_args = NULL;
	hsm_err_t err;
	uint32_t arr[4] = {0x11111111, 0x22222222, 0x33333333, 0x44444444};

	dev_write_fuse_args = malloc(sizeof(op_dev_write_fuse_args_t) + sizeof(arr));

	/* In this example, key is: 0x11111111 0x22222222 0x33333333 0x44444444
	 * 0x17d60706 0x00802380 0x11111111 0x22222222 0x33333333 0x44444444 0x531260C2
	 * PRNG_KEY is 128 bit long, starts at word 284 in i.MX95
	 */
	dev_write_fuse_args->word_pos = 284; // ( 284 * 32 = 0x2380)
	dev_write_fuse_args->bit_pos = 0;
	dev_write_fuse_args->bit_len = 32 * 4; // (= 0x80)

	dev_write_fuse_args->payload[0] = arr[0];
	dev_write_fuse_args->payload[1] = arr[1];
	dev_write_fuse_args->payload[2] = arr[2];
	dev_write_fuse_args->payload[3] = arr[3];

	err = hsm_dev_write_fuse(sess_hdl, dev_write_fuse_args);
	if (err != HSM_NO_ERROR)
		printf("Failed to write PRNG_KEY, err:0x%x\n", err);
	else
		printf("last processed_idx = 0x%x\n", dev_write_fuse_args->processed_idx);
#endif
}

void fuse_bits(hsm_hdl_t sess_hdl)
{
#if HSM_DEV_WRITE_FUSE
	op_dev_write_fuse_args_t *dev_write_fuse_args = NULL;
	hsm_err_t err;

	dev_write_fuse_args = malloc(sizeof(op_dev_write_fuse_args_t) + sizeof(uint32_t));

	/* Write bit 5 and 7 of fuse word index 10 */
	dev_write_fuse_args->word_pos = 10; // ( 10 * 32 = 0x140)
	dev_write_fuse_args->bit_pos = 5;
	dev_write_fuse_args->bit_len = 3; // (3 bits)

	dev_write_fuse_args->payload[0] = 0x5;

	err = hsm_dev_write_fuse(sess_hdl, dev_write_fuse_args);
	if (err != HSM_NO_ERROR)
		printf("Failed to write fuse, err:0x%x\n", err);
	else
		printf("last processed_idx = 0x%x\n", dev_write_fuse_args->processed_idx);
#endif
}

void write_fuse(hsm_hdl_t sess_hdl)
{
	printf("\n---------------------------------------------------\n");
	printf("Writing FUSES\n");
	printf("---------------------------------------------------\n");

	printf("Writing SHE_SECRET_KEY FUSE\n");
	fuse_SHE_SECRET_key(sess_hdl);

	printf("Writing PRNG_KEY\n");
	fuse_PRNG_key(sess_hdl);

	printf("Writing bits\n");
	fuse_bits(sess_hdl);
	printf("------------------------------------------------------\n");
}
