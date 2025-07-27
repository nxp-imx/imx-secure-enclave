// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef PRIME_HANDLE_H
#define PRIME_HANDLE_H

#include <stdint.h>

#define PRIME_HANDLE_NONE		(0x0)

/**
 *  Define the HSM handle type
 */
typedef uint32_t prime_hdl_t;

/**
 * Structure describing the service handle members
 */
struct prime_service_hdl_s {
	uint32_t service_hdl;
};

struct prime_service_hdl_s *service_hdl_to_ptr(uint32_t hdl);

#endif
