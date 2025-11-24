// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef FCE_SERVICE_H
#define FCE_SERVICE_H

#include "internal/fce_utils.h"
#include "internal/fce_handle.h"

fce_err_t v2x_prime_service_init(struct fce_service_hdl_s *service_hdl_ptr);
void v2x_prime_service_deinit(struct fce_service_hdl_s *service_hdl_ptr);

#endif
