// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#include <stdio.h>
#include "internal/prime_info.h"
#include "sab_prime_service.h"
#include "uio.h"

static struct uio_prime_mu *prime_mu;

void v2x_prime_init(void)
{
	prime_info_t prime_info;

	prime_mu = prime_mu_open();
	if (!prime_mu) {
		perror("Failed to open V2X PRIME MU Device.\n");
		return;
	}

	if (v2x_prime_mmap() < 0)
		perror("Failed to map ATU memory\n");

	// Open the prime service
	if (prime_service_open(prime_mu->base) != PRIME_ERR_NONE) {
		printf("Prime Service: Failed to open service\n");
		return;
	}

	if (!get_prime_info(0, &prime_info))
		printf("PRIME API version : %d.%d.%d\nNumber of FIFO entries : %d\n",
		       prime_info.major, prime_info.minor, prime_info.patch,
		       prime_info.num_fifo_entries);

	// Close the prime service
	prime_service_close(prime_mu->base);
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
