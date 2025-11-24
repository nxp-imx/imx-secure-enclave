/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#include "internal/fce_handle.h"
#include "internal/fce_service.h"

#include "sab_fce_process_msg.h"
#include "sab_fce_service.h"
#include "fce_uio.h"

fce_err_t v2x_prime_open_service(open_service_args_t *op_serv_args, fce_hdl_t *serv_hdl)
{
	struct uio_fce_mu *fce_mu = get_uio_fce_mu();

	op_serv_args->service_hdl = FCE_HANDLE_NONE;
	*serv_hdl = FCE_HANDLE_NONE;

	return fce_service_open(fce_mu->base);
}

void v2x_prime_close_service(fce_hdl_t ser_hdl)
{
	struct uio_fce_mu *fce_mu = get_uio_fce_mu();

	fce_service_close(fce_mu->base);
}
