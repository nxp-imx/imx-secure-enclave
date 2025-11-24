/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#include "sab_fce_process_msg.h"
#include "sab_fce_service.h"
#include "fce_uio.h"

fce_err_t v2x_prime_service_init(void)
{
	struct uio_fce_mu *fce_mu = get_uio_fce_mu();

	return fce_service_open(fce_mu->base);
}

void v2x_prime_service_deinit(void)
{
	struct uio_fce_mu *fce_mu = get_uio_fce_mu();

	fce_service_close(fce_mu->base);
}
