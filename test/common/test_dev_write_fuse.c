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
	op_dev_write_fuse_args_t dev_write_fuse_args = {0};
	hsm_err_t err;
	/* In this example, key is: 0xcafecafe 0x1234567 0xdeadbeef 0x89101112
	 * 0x17d60706 0x00802300 0xcafecafe 0x1234567 0xdeadbeef 0x89101112 0x8b360462
	 * SHE_SECRET_KEY is 128 bit long, starts at word 280 in i.MX95
	 */
	dev_write_fuse_args.bit_pos = 32 * 280; // ( = 0x2300)
	dev_write_fuse_args.bit_len = 32 * 4; // (= 0x80)
	dev_write_fuse_args.payload1 = 0xcafecafe;
	dev_write_fuse_args.payload2 = 0x1234567;
	dev_write_fuse_args.payload3 = 0xdeadbeef;
	dev_write_fuse_args.payload4 = 0x89101112;

	err = hsm_dev_write_fuse(sess_hdl, &dev_write_fuse_args);
	if (err != HSM_NO_ERROR)
		printf("Failed to write SHE_SECRET_KEY, err:0x%x\n", err);
	else
		printf("last processed_idx = 0x%x\n", dev_write_fuse_args.processed_idx);
#endif
}

void fuse_PRNG_key(hsm_hdl_t sess_hdl)
{
#if HSM_DEV_WRITE_FUSE
	op_dev_write_fuse_args_t dev_write_fuse_args = {0};
	hsm_err_t err;
	/* In this example, key is: 0x11111111 0x22222222 0x33333333 0x44444444
	 * 0x17d60706 0x00802380 0x11111111 0x22222222 0x33333333 0x44444444 0x531260C2
	 * PRNG_KEY is 128 bit long, starts at word 284 in i.MX95
	 */
	dev_write_fuse_args.bit_pos = 32 * 284; // ( = 0x2380)
	dev_write_fuse_args.bit_len = 32 * 4; // (= 0x80)
	dev_write_fuse_args.payload1 = 0x11111111;
	dev_write_fuse_args.payload2 = 0x22222222;
	dev_write_fuse_args.payload3 = 0x33333333;
	dev_write_fuse_args.payload4 = 0x44444444;

	err = hsm_dev_write_fuse(sess_hdl, &dev_write_fuse_args);
	if (err != HSM_NO_ERROR)
		printf("Failed to write PRNG_KEY, err:0x%x\n", err);
	else
		printf("last processed_idx = 0x%x\n", dev_write_fuse_args.processed_idx);
#endif
}

void write_fuse(hsm_hdl_t sess_hdl)
{
	printf("\n---------------------------------------------------\n");
	printf("Writing FUSES\n");
	printf("---------------------------------------------------\n");

#ifdef WRITE_SHE_KEYS
	printf("Writing SHE_SECRET_KEY FUSE\n");
	fuse_SHE_SECRET_key(sess_hdl);

	printf("Writing PRNG_KEY\n");
	fuse_PRNG_key(sess_hdl);
#endif
	printf("------------------------------------------------------\n");
}
