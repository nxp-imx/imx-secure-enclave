// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#ifndef SHE_LOAD_PLAIN_KEY_H
#define SHE_LOAD_PLAIN_KEY_H

#include "internal/she_handle.h"
#include "internal/she_utils.h"
#include "internal/she_key.h"

/**
 * @defgroup group13 CMD_LOAD_PLAIN_KEY
 * \ingroup group100
 * Key is handed over in plaintext. A plain key can only be loaded
 * into the RAM_KEY slot.
 * @{
 */

/**
 * Structure describing the plain key load operation arguments
 */
typedef struct {
	uint8_t key[SHE_KEY_SIZE_IN_BYTES];
	//!< pointer to plain key
} op_load_plain_key_args_t;

/**
 * Load a key as plaintext to the RAM_KEY slot without encryption and verification.
 *
 * \param utils_handle pointer to the SHE utils handle
 * \param args pointer to structure contaiing function arguments
 *
 * \return error code
 */
she_err_t she_load_plain_key(she_hdl_t utils_handle, op_load_plain_key_args_t *args);

/** @} end of CMD_LOAD_PLAIN_KEY group */
#endif
