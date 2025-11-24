// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#ifndef FCE_HANDLE_H
#define FCE_HANDLE_H

#include <stdint.h>

#define FCE_HANDLE_NONE		(0x0)

/**
 * Structure describing the service handle members
 */
struct fce_service_hdl_s {
	uint32_t service_hdl;
};

struct fce_service_hdl_s *service_hdl_to_ptr(uint32_t hdl);

#endif
