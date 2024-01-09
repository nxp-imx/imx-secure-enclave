// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdio.h>
#include <string.h>

#include "common.h"

static void v2x_she_test_usage(void)
{
	printf("v2x_she_test usage: v2x_she_test [options]\n");
	printf("Options:\n");
	printf("1: <SHE session (0,1)>\n");
	printf("2: <no. of keystores (<=5)>\n");
	printf("3: <shared key store (<= no. of keystores)>\n");
}

/* Test entry function. */
int main(int argc, char *argv[])
{
	uint8_t session_id;
	uint8_t num_of_keystores;
	uint8_t shared_keystore;

	if (argc == 2 &&
	    (strcmp("--help", argv[1]) == 0 || strcmp("-h", argv[1]) == 0)) {
		v2x_she_test_usage();
		return 0;
	}

	if (argc < 4) {
		v2x_she_test_usage();
		return 0;
	}

	session_id = atoi(argv[1]);
	num_of_keystores = atoi(argv[2]);
	shared_keystore = atoi(argv[3]);

	she_tests(session_id, num_of_keystores, shared_keystore);

	return 0;
}
