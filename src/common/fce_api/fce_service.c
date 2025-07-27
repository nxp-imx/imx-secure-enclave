/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#include "internal/prime_handle.h"
#include "internal/prime_service.h"

#include "sab_fce_process_msg.h"
#include "sab_fce_service.h"
#include "fce_uio.h"

prime_err_t prime_open_service(open_service_args_t *op_serv_args, prime_hdl_t *serv_hdl)
{
	struct uio_fce_mu *fce_mu = get_uio_fce_mu();

	op_serv_args->service_hdl = PRIME_HANDLE_NONE;
	*serv_hdl = PRIME_HANDLE_NONE;

	return fce_service_open(fce_mu->base);
}

void prime_close_service(prime_hdl_t ser_hdl)
{
	struct uio_fce_mu *fce_mu = get_uio_fce_mu();

	fce_service_close(fce_mu->base);
}
