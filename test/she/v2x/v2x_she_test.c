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
	printf("1: <Choose SHE session Identifier, out of two SHE Sessions, (0, 1>\n");
	printf("2: <Count of keystores to open, (<=5, Max)>\n");
	printf("3: <Count of Key Stores to be opened as Shared, (<= <arg 2, Max>)\n");
	printf("\nFor running SHE test vectors:\n");
	printf("v2x_she_test file1.shx file2.shx ....\n");
	printf("\nFor running All SHE test vectors:\n");
	printf("v2x_she_test\n");
	printf("------------------------------------------------------------------\n");
}

/* Test entry function. */
int main(int argc, char *argv[])
{
	uint8_t session_id;
	uint8_t num_of_keystores;
	uint8_t shared_keystore;

	if (argc == 1) {
		shx_tests_run();
		return 0;
	}
	if (argc == 2 &&
	    (strcmp("--help", argv[1]) == 0 || strcmp("-h", argv[1]) == 0)) {
		v2x_she_test_usage();
		return 0;
	}

	if (argc == 4 && isdigit(argv[1][0])) {
		session_id = atoi(argv[1]);
		num_of_keystores = atoi(argv[2]);
		shared_keystore = atoi(argv[3]);

		she_tests(session_id, num_of_keystores, shared_keystore);

		return 0;
	}

	shx_she_tests(argc, argv);

	return 0;
}
