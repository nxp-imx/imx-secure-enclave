// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <stdint.h>

#include "hsm_api.h"
#include "test_common.h"

#ifdef PSA_COMPLIANT
void write_monotonic_counter(hsm_hdl_t sess_hdl,
			     uint8_t ele_hsm_count,
			     uint8_t v2x_hsm_count,
			     uint8_t v2x_she_count,
			     uint8_t enforce_fuse)
{
	op_dev_mono_counter_args_t args = {0};
	hsm_err_t err;

	args.ele_hsm_fuse_word = ele_hsm_count;
	args.v2x_hsm_fuse_word = v2x_hsm_count;
	args.v2x_she_fuse_word = v2x_she_count;
	args.enforce_fuse = enforce_fuse;

	err = hsm_dev_mono_counter(sess_hdl, &args);

	if (err != HSM_NO_ERROR) {
		printf("Failed to set Monotonic counter err:0x%x\n", err);
		return;
	}

	if (args.warning) {
		printf("A valid configuration already exists 0x%x\n", args.warning);
		printf("ELE HSM counter %d\n", args.ele_hsm_fuse_word);
		printf("V2X HSM counter %d\n", args.v2x_hsm_fuse_word);
		printf("V2X SHE counter %d\n", args.v2x_she_fuse_word);
	}
}

void read_monotonic_counter(hsm_hdl_t sess_hdl)
{
	op_dev_mono_counter_args_t args = {0};
	hsm_err_t err;

	err = hsm_dev_mono_counter(sess_hdl, &args);

	if (err != HSM_NO_ERROR)
		printf("Failed to read Monotonic counter err:0x%x\n", err);

	printf("ELE HSM counter %d\n", args.ele_hsm_fuse_word);
	printf("V2X HSM counter %d\n", args.v2x_hsm_fuse_word);
	printf("V2X SHE counter %d\n", args.v2x_she_fuse_word);
}

void test_mono_counter(hsm_hdl_t sess_hdl)
{
	/* Read monotonic counteri but counter is not yet configured */
	read_monotonic_counter(sess_hdl);

	/* Test with one 0 , but enforce_fuse is not set */
	write_monotonic_counter(sess_hdl, 0, 42, 12, 0);

	/* Test with one 0 , but enforce_fuse is not set */
	write_monotonic_counter(sess_hdl, 42, 0, 12, 0);

	/* Test with one 0 , but enforce_fuse is not set */
	write_monotonic_counter(sess_hdl, 42, 12, 0, 0);

	/*
	 * Test with one 0 , and enforce_fuse set, FW will return error
	 * total fuse is 62 on i.MX95, and here sum is 54
	 */
	write_monotonic_counter(sess_hdl, 42, 12, 0, 1);

#ifdef PROGRAM_MONOTONIC_COUNTER
	/* Test with valid configuration, monotonic counter should not reconfigure */
	write_monotonic_counter(sess_hdl, 40, 11, 11, 1);

	/* Test with valid configuration, sum is 62 but one 0, with enforce flag set */
	write_monotonic_counter(sess_hdl, 40, 22, 0, 1);

	/* Read Monotonic counter values */
	read_monotonic_counter(sess_hdl);
#endif
}
#endif
