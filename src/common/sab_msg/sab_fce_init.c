// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include "fce_uio.h"

static struct uio_fce_mu *fce_mu;

void v2x_prime_init(void)
{
	fce_mu = fce_mu_open();
	if (!fce_mu) {
		perror("Failed to open V2X PRIME MU Device.\n");
		return;
	}

	if (v2x_prime_mmap() < 0)
		perror("Failed to map V2X PRIME reserved memory\n");
}

void v2x_prime_deinit(void)
{
	v2x_prime_munmap();
	fce_mu_close(fce_mu->fd);
	fce_mu = NULL;
}

struct uio_fce_mu *get_uio_fce_mu(void)
{
	return fce_mu;
}
