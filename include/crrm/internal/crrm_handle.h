// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#ifndef CRRM_HANDLE_H
#define CRRM_HANDLE_H

#include <stdint.h>
#include "internal/hsm_utils.h"

#define CRRM_HANDLE_NONE		(0x0)

/**
 *  @defgroup group5 Handle
 *  @{
 */

/**
 *  Define the CRRM handle type
 */
typedef uint32_t crrm_hdl_t;

/**
 *  Define the CRRM error type.
 *  Please refer ELE API guide for error codes.
 */
typedef hsm_err_t crrm_err_t;

/**
 * Return CRRM handle to be used while requesting CRRM services\n
 * Check if you have received a valid (non-zero) session handle before continuing.\n
 * This is the first API to be called.
 * \return CRRM handle
 */
crrm_hdl_t get_session_handle(void);

/** @} end of handle group */
#endif
