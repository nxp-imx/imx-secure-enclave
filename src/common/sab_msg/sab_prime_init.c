// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#include <stdio.h>
#include "uio.h"

static struct uio_prime_mu *prime_mu;

void v2x_prime_init(void)
{
	prime_mu = prime_mu_open();
	if (!prime_mu) {
		perror("Failed to open V2X PRIME MU Device.\n");
		return;
	}

	if (v2x_prime_mmap() < 0)
		perror("Failed to map ATU memory\n");
}

void v2x_prime_deinit(void)
{
	v2x_prime_munmap();
	prime_mu_close(prime_mu->fd);
	prime_mu = NULL;
}

struct uio_prime_mu *get_uio_prime_mu(void)
{
	return prime_mu;
}
