// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef SHE_LOAD_PLAIN_KEY_H
#define SHE_LOAD_PLAIN_KEY_H

#include "internal/she_handle.h"
#include "internal/she_utils.h"
#include "internal/she_key.h"

/**
 * @defgroup group13 CMD_LOAD_PLAIN_KEY
 * \ingroup group100
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
 * \param hdl pointer to the SHE utils handle
 * \param key pointer to the plaintext key to be loaded - 128bits
 *
 * \return error code
 */
she_err_t she_load_plain_key(she_hdl_t utils_handle, op_load_plain_key_args_t *args);

/** @} end of CMD_LOAD_PLAIN_KEY group */
#endif
