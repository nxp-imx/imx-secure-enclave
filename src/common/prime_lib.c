// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include "sab_prime_process_msg.h"
#include "internal/v2x_version.h"

void __attribute__((constructor)) lib_prime_start(void)
{
	v2x_version_t v2x_version;

	get_v2x_version(&v2x_version);

	printf("V2X version : %d.%d.%d\nCommit Id : 0x%x\n",
	       v2x_version.major, v2x_version.minor,
	       v2x_version.patch, v2x_version.commit_id);

	v2x_prime_init();
}

void __attribute__((destructor)) lib_prime_end(void)
{
	v2x_prime_deinit();
}
