// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#ifndef HSM_PUB_KEY_DECOMPRESSION_H
#define HSM_PUB_KEY_DECOMPRESSION_H

#include "internal/hsm_common_def.h"
#include "internal/hsm_utils.h"
#include "internal/hsm_handle.h"
#include "internal/hsm_key.h"

/**
 *  @defgroup group10 Public key decompression
 * @{
 */

/**
 * Bit map indicating the public key decompression attributes
 */
typedef uint8_t hsm_op_pub_key_dec_flags_t;

/**
 * Structure describing the public key decompression operation arguments
 */
typedef struct {
	uint8_t *key;
	//!< pointer to the compressed ECC public key.
	//!< The expected key format is x||lsb_y where lsb_y is 1 byte having value:
	//!< 1 if least-significant bit of original (uncompressed) y coordinate is set.
	//!< 0 otherwise.
	uint8_t *out_key;
	//!< pointer to the output area where the decompressed public key must be written.
	uint16_t key_size;
	//!< length in bytes of the input compressed public key
	uint16_t out_key_size;
	//!< length in bytes of the resulting public key
	hsm_key_type_t key_type;
	//!< indicates the type of the manged keys.
	hsm_op_pub_key_dec_flags_t flags;
	//!< bitmap specifying the operation attributes.
	uint16_t reserved;
} op_pub_key_dec_args_t;

/**
 * Decompress an ECC public key \n
 * The expected key format is x||lsb_y where lsb_y is 1 byte having value:
 *  1 if the least-significant bit of the original (uncompressed) y coordinate is set.
 *  0 otherwise.
 * User can call this function only after having opened a session
 *
 * \param session_hdl handle identifying the current session.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_pub_key_decompression(hsm_hdl_t session_hdl,
				    op_pub_key_dec_args_t *args);

/**
 *\addtogroup qxp_specific
 * \ref group10
 *
 * - \ref This feature is disabled when part is running in FIPS approved mode.
 *        Any call to this API will results in a HSM_FEATURE_DISABLED error.
 */
/** @} end of public key decompression operation */

#endif
