/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2025 NXP
 */

#include "internal/fce_handle.h"
#include "sab_fce_process_msg.h"
#include "sab_fce_service.h"
#include "fce_uio.h"

fce_err_t v2x_prime_service_init(struct fce_service_hdl_s *service_hdl_ptr)
{
	struct uio_fce_mu *fce_mu = get_uio_fce_mu();

	service_hdl_ptr->service_hdl = FCE_HANDLE_NONE;

	return fce_service_open(fce_mu->base);
}

void v2x_prime_service_deinit(struct fce_service_hdl_s *service_hdl_ptr)
{
	struct uio_fce_mu *fce_mu = get_uio_fce_mu();

	service_hdl_ptr->service_hdl = FCE_HANDLE_NONE;

	fce_service_close(fce_mu->base);
}
