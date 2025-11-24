// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef FCE_SERVICE_H
#define FCE_SERVICE_H

#include "internal/fce_utils.h"
#include "internal/fce_handle.h"

enum service_type {
	SERVICE_TYPE_NONE,
	SERVICE_TYPE_ALL = 7,
};

/**
 * Structure detailing the open session operation member arguments
 */
typedef struct {
	uint32_t service_hdl;
	//!< Session handle.
	enum service_type serv_type;
	//!< MU with associated functionality on which service session will be opened
} open_service_args_t;

fce_err_t v2x_prime_open_service(open_service_args_t *op_serv_args, fce_hdl_t *serv_hdl);
void v2x_prime_close_service(fce_hdl_t ser_hdl);

#endif
