// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include "sab_fce_process_msg.h"

void __attribute__((constructor)) libv2x_fce_start(void)
{
	v2x_prime_init();
}

void __attribute__((destructor)) libv2x_fce_end(void)
{
	v2x_prime_deinit();
}
