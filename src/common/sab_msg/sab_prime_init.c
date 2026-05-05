// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#include <stdio.h>
#include "uio.h"
#include "sab_prime_process_msg.h"
#include "sab_prime_service.h"
#include "sab_prime_api.h"

/* Global variables for tracking request IDs */
uint32_t producer_req_id_index;
uint32_t consumer_req_id_index;

static struct uio_prime_mu *prime_mu;

void v2x_prime_init(void)
{
	prime_mu = prime_mu_open();
	if (!prime_mu) {
		perror("Failed to open V2X PRIME MU Device.\n");
		return;
	}

	// Open the prime service
	if (prime_service_open(prime_mu->base)) {
		printf("Failed to open prime service\n");
		return;
	}

	if (v2x_prime_mmap() < 0)
		perror("Failed to map ATU memory\n");

	/* Read starting value for producer_req_id_index */
	producer_req_id_index = read_req_id();
	if (!producer_req_id_index)
		producer_req_id_index = PRIME_PRODUCE_INDEX_INIT_VAL;
}

void v2x_prime_deinit(void)
{
	v2x_prime_munmap();

	// Close the prime service
	prime_service_close(prime_mu->base);

	prime_mu_close(prime_mu->fd);
	prime_mu = NULL;
}

struct uio_prime_mu *get_uio_prime_mu(void)
{
	return prime_mu;
}
