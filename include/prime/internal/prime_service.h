// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#ifndef PRIME_SERVICE_H
#define PRIME_SERVICE_H

#include "prime_utils.h"
#include "prime_handle.h"
#include <stdbool.h>
#include <stdint.h>

enum service_type {
	SERVICE_TYPE_NONE,
	SERVICE_TYPE_ALL = 7,
};

/**
 * Structure detailing the open session operation member arguments
 */
typedef struct {
	uint32_t service_hdl;
	//!< Service handle.
	enum service_type serv_type;
	//!< MU with associated functionality on which service session will be opened
	uint64_t physical_addr;
	//!< Physical memory address
	uint64_t virtual_addr;
	//!< Virtual memory address
	uint32_t size;
	//!< Input requested buffer size
} open_service_args_t;

prime_err_t prime_open_service(open_service_args_t *op_serv_args, prime_hdl_t *serv_hdl);

void prime_close_service(prime_hdl_t ser_hdl);

#endif
