/*
 * Copyright 2022 NXP
 *
 * NXP Confidential.
 * This software is owned or controlled by NXP and may only be used strictly
 * in accordance with the applicable license terms.  By expressly accepting
 * such terms or by downloading, installing, activating and/or otherwise using
 * the software, you are agreeing that you have read, and that you agree to
 * comply with and are bound by, such license terms.  If you do not agree to be
 * bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
 */

#ifndef HSM_KEY_RECOVERY_H
#define HSM_KEY_RECOVERY_H

#include "internal/hsm_utils.h"
#include "internal/hsm_handle.h"
#include "internal/hsm_key.h"

/**
 *  @defgroup group12 Public key recovery
 * @{
 */
typedef uint8_t hsm_op_pub_key_recovery_flags_t;
typedef struct {
	//!< pointer to the identifier of the key to be used for the operation
	uint32_t key_identifier;
	//!< pointer to the output area where the generated public key must be written
	uint8_t *out_key;
	//!< length in bytes of the output key
	uint16_t out_key_size;
	//!< indicates the type of the key to be recovered
	hsm_key_type_t key_type;
	//!< bitmap specifying the operation attributes, mandatory for non-PSA compliant platforms
	hsm_op_pub_key_recovery_flags_t flags;
	 //!< derived from key_type
	hsm_psa_key_type_t psa_key_type;
	hsm_bit_key_sz_t bit_key_sz;
} op_pub_key_recovery_args_t;

/**
 * Recover Public key from private key present in key store \n
 * User can call this function only after having opened a key store.\n
 *
 * \param key_store_hdl handle identifying the current key store.
 * \param args pointer to the structure containing the function arguments.
 *
 * \return error code
 */
hsm_err_t hsm_pub_key_recovery(hsm_hdl_t key_store_hdl, op_pub_key_recovery_args_t *args);
/** @} end of Public key recovery operation */

#endif