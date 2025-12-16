// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include "sab_prime_process_msg.h"

void __attribute__((constructor)) lib_prime_start(void)
{
	v2x_prime_init();
}

void __attribute__((destructor)) lib_prime_end(void)
{
	v2x_prime_deinit();
}
