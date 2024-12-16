// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "test_common.h"

static void she_test_usage(void)
{
	printf("------------------------------------------------------------------\n");
	printf("seco_she_test can be used to run:\n");
	printf("- functional tests\n");
	printf("- Specific SHE test vectors\n");
	printf("- All SHE test vectors\n");
	printf("\nFor running SHE functional tests:\n");
	printf("seco_she_test\n");
	printf("\nFor running SHE test vectors:\n");
	printf("seco_she_test file1.shx file2.shx ....\n");
	printf("\nFor running All SHE test vectors:\n");
	printf("seco_she_test -a\n");
	printf("------------------------------------------------------------------\n");
}

/* Test entry function. */
int main(int argc, char *argv[])
{
	int8_t supported_mu;

	supported_mu = get_supported_mu(HSM1);

	if (supported_mu < 0) {
		printf("Failed to fetch board details\n");
		return 0;
	}

	if (supported_mu == V2X_SHE) {
		printf("WARNING: SECO in FIPS mode, cannot open SHE session\n");
		return 0;
	} else if (supported_mu != SHE1) {
		printf("WARNING: SECO, V2X in FIPS mode, cannot open SHE session\n");
		return 0;
	}

	if (argc == 1) {
		she_tests(0, SHE1, 1, 0);
		return 0;
	}

	if (argc == 2 &&
	    (strcmp("--help", argv[1]) == 0 || strcmp("-h", argv[1]) == 0)) {
		she_test_usage();
		return 0;
	}

	if (argc == 2 && strcmp("-a", argv[1]) == 0) {
		shx_tests_run();
		return 0;
	}

	shx_she_tests(argc, argv);

	return 0;
}
