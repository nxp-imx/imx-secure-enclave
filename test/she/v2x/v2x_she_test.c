// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "test_common.h"

static void v2x_she_test_usage(void)
{
	printf("------------------------------------------------------------------\n");
	printf("v2x_she_test can be used to run:\n");
	printf("- functional tests\n");
	printf("- Specific SHE test vectors\n");
	printf("- All SHE test vectors\n");
	printf("\nFor running SHE functional tests:\n");
	printf("v2x_she_test [options]\n");
	printf("---- Options for i.MX95 ----\n");
	printf("1: <Choose SHE session Identifier, out of two SHE Sessions, (0, 1>\n");
	printf("2: <Count of keystores to open, (<=5, Max)>\n");
	printf("3: <Count of Key Stores to be opened as Shared, (<= <arg 2, Max>)>\n");
	printf("\n---- Options for i.MX8DXL ----\n");
	printf("1: <Choose SHE session Identifier, (0)>\n");
	printf("2: <Count of keystores to open, (1)>\n");
	printf("3: <Count of Key Stores to be opened as Shared, (0)>\n");
	printf("\nFor running SHE test vectors:\n");
	printf("v2x_she_test file1.shx file2.shx ....\n");
	printf("\nFor running All SHE test vectors:\n");
	printf("v2x_she_test -a\n");
	printf("------------------------------------------------------------------\n");
}

/* Test entry function. */
int main(int argc, char *argv[])
{
	uint8_t SHE_id;
	uint8_t num_of_keystores;
	uint8_t shared_keystore;
	uint8_t mu_type;
	int8_t supported_mu;
	int8_t  sess_type;

	if (argc == 2 && strcmp("-a", argv[1]) == 0) {
		shx_tests_run();
		return 0;
	}
	if ((argc == 2 &&
	     (strcmp("--help", argv[1]) == 0 || strcmp("-h", argv[1]) == 0)) ||
	    argc == 1) {
		v2x_she_test_usage();
		return 0;
	}

	if (argc == 4 && isdigit(argv[1][0])) {
		SHE_id = atoi(argv[1]);
		num_of_keystores = atoi(argv[2]);
		shared_keystore = atoi(argv[3]);

		if (SHE_id)
			/* Open SHE1 session */
			mu_type = V2X_SV1;
		else
			mu_type = V2X_SHE;

		if (mu_type == V2X_SHE) {
			/* check for 8DXL board type */
			supported_mu = get_supported_mu(V2X_SV0);

			if (supported_mu < 0) {
				printf("Failed to fetch board details\n");
				return 0;
			}

			if (supported_mu == V2X_SHE)
				she_tests(SHE_id,
					  mu_type,
					  num_of_keystores,
					  shared_keystore);
			else if (supported_mu == SHE1)
				printf("WARNING: V2X in FIPS mode\n");
			else
				printf("WARNING: SECO, V2X in FIPS mode\n");
		} else {
			she_tests(SHE_id,
				  mu_type,
				  num_of_keystores,
				  shared_keystore);
		}

		return 0;
	}

	shx_she_tests(argc, argv);

	return 0;
}
