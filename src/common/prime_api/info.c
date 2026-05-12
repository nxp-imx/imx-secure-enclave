/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2026 NXP
 */

#include <stdio.h>
#include <errno.h>

#include "sab_prime_process_msg.h"
#include "sab_prime_info.h"

prime_err_t prime_get_info(prime_hdl_t serv_hdl, prime_info_t *args)
{
	struct uio_prime_mu *prime_mu = get_uio_prime_mu();

	if (!serv_hdl) {
		printf("Prime handle argument is NULL\n");
		return -EINVAL;
	}

	if (!args) {
		printf("input argument is NULL\n");
		return -EINVAL;
	}

	return process_prime_get_info(prime_mu->base, args);
}
