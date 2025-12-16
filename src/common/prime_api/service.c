/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#include "internal/prime_handle.h"
#include "internal/prime_service.h"

#include "sab_prime_process_msg.h"
#include "sab_prime_service.h"
#include "uio.h"

prime_err_t prime_open_service(open_service_args_t *op_serv_args,
				prime_hdl_t *serv_hdl)
{
	struct uio_prime_mu *prime_mu = get_uio_prime_mu();

	op_serv_args->service_hdl = PRIME_HANDLE_NONE;
	*serv_hdl = PRIME_HANDLE_NONE;

	return prime_service_open(prime_mu->base);
}

void prime_close_service(prime_hdl_t ser_hdl)
{
	struct uio_prime_mu *prime_mu = get_uio_prime_mu();

	prime_service_close(prime_mu->base);
}
