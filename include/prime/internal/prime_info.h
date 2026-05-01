// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2026 NXP
 */

#ifndef PRIME_INFO_H
#define PRIME_INFO_H

#include "prime_handle.h"
#include "prime_utils.h"

/**
 * Structure detailing the open session operation member arguments
 */
typedef struct {
	uint8_t major;
	//!< major number.
	uint8_t minor;
	//!< minor number.
	uint8_t patch;
	//!< patch number.
	uint32_t num_fifo_entries;
	//!< Number of FIFO entries
} prime_info_t;

prime_err_t prime_get_info(prime_hdl_t serv_hdl, prime_info_t *prime_info);

#endif
